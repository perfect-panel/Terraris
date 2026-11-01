// SPDX-License-Identifier: GPL-3.0-only

use std::{
    sync::{Arc, Barrier},
    thread,
};
use terraris::{
    buffer::{BufferLayout, BufferPool, BufferScope, Error, PoolConfig},
    resource::{Budget, Limits},
};

fn layout(bytes: usize) -> BufferLayout {
    BufferLayout::new(0, bytes, 0).unwrap()
}
fn setup(bytes: usize, slots: usize, config: PoolConfig) -> (Budget, BufferPool, BufferScope) {
    let budget = Budget::new(Limits::new(bytes, slots).unwrap());
    let pool = BufferPool::new(budget.clone(), config).unwrap();
    let scope = pool
        .scope(
            budget.scope(Limits::new(bytes, slots).unwrap()).unwrap(),
            bytes,
        )
        .unwrap();
    (budget, pool, scope)
}
fn config(bytes: usize, slots: usize, per_class: usize) -> PoolConfig {
    PoolConfig::new(vec![8, 16, 32, 64], bytes, slots, per_class).unwrap()
}

#[test]
fn rounded_capacity_remains_charged_while_idle_and_is_not_double_charged_on_reuse() {
    let (budget, pool, scope) = setup(8, 1, config(8, 1, 1));
    let mut lease = scope
        .try_lease(BufferLayout::new(1, 3, 1).unwrap())
        .unwrap();
    assert_eq!(lease.capacity(), 8);
    assert_eq!(lease.layout().capacity(), 5);
    lease.append_payload(b"abc").unwrap();
    assert!(lease.append_payload(b"d").is_err());
    let view = lease.freeze().slice(1..2).unwrap();
    assert_eq!(pool.snapshot().leased_bytes, 8);
    assert_eq!(scope.snapshot().resident().bytes(), 8);
    drop(view);
    assert_eq!(scope.snapshot().used().bytes(), 0);
    assert_eq!(budget.snapshot().resident().bytes(), 8);
    assert_eq!(pool.snapshot().idle_allocations, 1);
    let other = pool
        .scope(budget.scope(Limits::new(8, 1).unwrap()).unwrap(), 8)
        .unwrap();
    let reused = other.try_lease(layout(3)).unwrap();
    assert_eq!(pool.snapshot().hits, 1);
    assert_eq!(budget.snapshot().resident().allocations(), 1);
    assert_eq!(other.snapshot().resident().bytes(), 8);
    drop(reused);
    pool.close();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn bytes_owner_delays_recycling_until_the_last_nonempty_external_view() {
    let (budget, pool, scope) = setup(64, 4, config(64, 4, 4));
    let mut lease = scope.try_lease(layout(20)).unwrap();
    lease.append_payload(b"sensitive payload").unwrap();
    let external = lease.freeze().into_bytes();
    let last = external.slice(0..1);
    drop(external);
    assert_eq!(pool.snapshot().idle_allocations, 0);
    assert_eq!(scope.snapshot().resident().bytes(), 32);
    drop(last);
    assert_eq!(pool.snapshot().idle_bytes, 32);
    assert_eq!(scope.snapshot().used().bytes(), 0);
    pool.close();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn idle_limits_bound_bytes_slots_and_each_class_independently() {
    for (cfg, expected_bytes, expected_slots) in [
        (config(16, 8, 8), 16, 2),
        (config(64, 1, 8), 8, 1),
        (config(64, 8, 1), 8, 1),
    ] {
        let (budget, pool, scope) = setup(128, 16, cfg);
        let leases = scope.try_lease_many(&[layout(8); 4]).unwrap();
        drop(leases);
        assert_eq!(pool.snapshot().idle_bytes, expected_bytes);
        assert_eq!(pool.snapshot().idle_allocations, expected_slots);
        assert_eq!(budget.snapshot().resident().bytes(), expected_bytes);
        assert_eq!(scope.snapshot().used().bytes(), 0);
        pool.close();
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}

#[test]
fn large_dedicated_allocations_and_disabled_retention_do_not_remain_in_cache() {
    let (budget, pool, scope) = setup(256, 8, config(256, 8, 8));
    let lease = scope.try_lease(layout(100)).unwrap();
    assert_eq!(lease.capacity(), 100);
    drop(lease);
    assert_eq!(pool.snapshot().idle_bytes, 0);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    let (budget, pool, scope) = setup(64, 4, config(0, 0, 0));
    drop(scope.try_lease(layout(9)).unwrap());
    assert_eq!(pool.snapshot().idle_allocations, 0);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn class_rounding_does_not_exceed_explicit_per_block_or_scope_limits() {
    let (budget, pool, scope) = setup(64, 8, PoolConfig::new(vec![16, 32], 64, 8, 8).unwrap());
    let tiny = scope.child(Limits::new(8, 2).unwrap()).unwrap();
    let lease = tiny.try_lease(layout(5)).unwrap();
    assert_eq!(lease.capacity(), 5);
    drop(lease);
    assert_eq!(pool.snapshot().idle_allocations, 0);
    let capped = pool
        .scope(budget.scope(Limits::new(64, 4).unwrap()).unwrap(), 10)
        .unwrap();
    let lease = capped.try_lease(layout(9)).unwrap();
    assert_eq!(lease.capacity(), 9);
    drop(lease);
    assert_eq!(pool.snapshot().idle_allocations, 0);
}

#[test]
fn wrong_class_idle_storage_is_evicted_under_byte_or_allocation_pressure() {
    for (bytes, slots, old, new) in [(32, 4, 32, 16), (64, 1, 8, 16)] {
        let (budget, pool, scope) = setup(bytes, slots, config(bytes, slots, slots));
        drop(scope.try_lease(layout(old)).unwrap());
        let lease = scope.try_lease(layout(new)).unwrap();
        assert_eq!(lease.capacity(), new);
        assert_eq!(pool.snapshot().evictions, 1);
        assert_eq!(budget.snapshot().resident().bytes(), new);
        drop(lease);
        pool.close();
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}

#[test]
fn mixed_cached_and_new_batch_reserves_full_scoped_capacity_atomically() {
    let (budget, pool, scope) = setup(64, 8, config(64, 8, 8));
    drop(scope.try_lease(layout(8)).unwrap());
    let small = scope.child(Limits::new(8, 2).unwrap()).unwrap();
    let before = pool.snapshot();
    assert!(small.try_lease_many(&[layout(8), layout(16)]).is_err());
    assert_eq!(pool.snapshot().idle_bytes, before.idle_bytes);
    assert_eq!(small.snapshot().used().bytes(), 0);
    let leases = scope.try_lease_many(&[layout(8), layout(16)]).unwrap();
    assert_eq!(pool.snapshot().hits, 1);
    assert_eq!(pool.snapshot().leased_bytes, 24);
    assert_eq!(pool.snapshot().pending_bytes, 0);
    assert_eq!(scope.snapshot().resident().bytes(), 24);
    assert_eq!(budget.snapshot().resident().bytes(), 24);
    assert_eq!(budget.snapshot().reserved().bytes(), 0);
    drop(leases);
    pool.close();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn oversized_batch_does_not_evict_cache_that_cannot_make_it_fit() {
    let (budget, pool, scope) = setup(32, 4, config(32, 4, 4));
    drop(scope.try_lease(layout(8)).unwrap());
    assert!(scope.try_lease_many(&[layout(32); 2]).is_err());
    assert_eq!(pool.snapshot().evictions, 0);
    assert_eq!(pool.snapshot().idle_bytes, 8);
    assert_eq!(budget.snapshot().used().bytes(), 8);
}

#[test]
fn trim_frees_process_capacity_and_leaves_cache_reusable() {
    let (budget, pool, scope) = setup(64, 8, config(64, 8, 8));
    drop(scope.try_lease(layout(8)).unwrap());
    pool.trim().unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
    drop(scope.try_lease(layout(8)).unwrap());
    assert_eq!(pool.snapshot().idle_bytes, 8);
    drop(scope.try_lease(layout(8)).unwrap());
    assert_eq!(pool.snapshot().hits, 1);
    pool.close();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn closing_or_dropping_pool_preserves_live_views_but_frees_idle_storage() {
    let (budget, pool, scope) = setup(64, 8, config(64, 8, 8));
    let lease = scope.try_lease(layout(16)).unwrap();
    drop(scope.try_lease(layout(8)).unwrap());
    let view = lease.freeze();
    pool.close();
    pool.close();
    assert_eq!(budget.snapshot().resident().bytes(), 16);
    assert!(matches!(scope.try_lease(layout(1)), Err(Error::PoolClosed)));
    drop(view);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(pool.snapshot().leased_bytes, 0);
    let lease_setup = setup(64, 8, config(64, 8, 8));
    let (budget, pool, scope) = lease_setup;
    let lease = scope.try_lease(layout(16)).unwrap();
    drop(scope.try_lease(layout(8)).unwrap());
    drop(pool);
    assert_eq!(budget.snapshot().resident().bytes(), 16);
    assert!(matches!(scope.try_lease(layout(1)), Err(Error::PoolClosed)));
    drop(lease);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn pool_rejects_other_budgets_and_closed_resource_scopes() {
    let (budget, pool, scope) = setup(64, 8, config(64, 8, 8));
    let foreign = Budget::new(Limits::new(64, 8).unwrap());
    assert!(pool.scope(foreign.root_scope(), 64).is_err());
    drop(scope.try_lease(layout(8)).unwrap());
    scope.close();
    assert!(scope.try_lease(layout(8)).is_err());
    assert_eq!(pool.snapshot().idle_bytes, 8);
    budget.close();
    assert!(
        pool.scope(budget.root_scope(), 64)
            .unwrap()
            .try_lease(layout(8))
            .is_err()
    );
    pool.close();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn concurrent_view_drops_racing_pool_close_release_the_allocation_once() {
    let (budget, pool, scope) = setup(64, 8, config(64, 8, 8));
    let view = scope.try_lease(layout(32)).unwrap().freeze();
    let barrier = Arc::new(Barrier::new(9));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (view, barrier) = (view.clone(), barrier.clone());
            thread::spawn(move || {
                barrier.wait();
                drop(view);
            })
        })
        .collect();
    drop(view);
    barrier.wait();
    pool.close();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(scope.snapshot().used().bytes(), 0);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(pool.snapshot().leased_allocations, 0);
}

#[tokio::test]
async fn reused_allocation_is_zeroed_before_exposing_a_readbuf_to_a_new_scope() {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, ReadBuf};
    struct InitializedReader;
    impl AsyncRead for InitializedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let n = b.remaining();
            b.advance(n);
            Poll::Ready(Ok(()))
        }
    }
    let (_, pool, scope) = setup(64, 8, config(64, 8, 8));
    let mut old = scope.try_lease(layout(8)).unwrap();
    old.append_payload(b"SECRET!!").unwrap();
    drop(old);
    let mut new = scope
        .child(Limits::new(32, 4).unwrap())
        .unwrap()
        .try_lease(layout(8))
        .unwrap();
    assert_eq!(new.read_from(&mut InitializedReader).await.unwrap(), 8);
    assert_eq!(new.as_slice(), &[0; 8]);
    assert_eq!(pool.snapshot().hits, 1);
}

#[test]
fn pool_classes_and_zero_size_leases_have_explicit_limits() {
    for classes in [vec![0], vec![16, 8], vec![8, 8], vec![usize::MAX]] {
        assert!(PoolConfig::new(classes, 64, 8, 8).is_err());
    }
    let (budget, pool, scope) = setup(8, 2, config(8, 2, 2));
    let empty = scope.try_lease_many(&[layout(0); 2]).unwrap();
    assert_eq!(budget.snapshot().resident().allocations(), 2);
    assert!(scope.try_lease(layout(0)).is_err());
    drop(empty);
    assert_eq!(pool.snapshot().idle_allocations, 0);
    assert_eq!(budget.snapshot().used().allocations(), 0);
}

#[test]
fn concurrent_cached_batch_checkout_never_bypasses_connection_or_global_quotas() {
    let (budget, pool, scope) = setup(32, 2, config(32, 2, 2));
    let layouts = [layout(16); 2];
    drop(scope.try_lease_many(&layouts).unwrap());
    let start = Arc::new(Barrier::new(8));
    let held = Arc::new(Barrier::new(9));
    let release = Arc::new(Barrier::new(9));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (scope, start, held, release) =
                (scope.clone(), start.clone(), held.clone(), release.clone());
            thread::spawn(move || {
                start.wait();
                let batch = scope.try_lease_many(&layouts);
                let won = batch.is_ok();
                held.wait();
                release.wait();
                drop(batch);
                won
            })
        })
        .collect();
    held.wait();
    let observed = (budget.snapshot(), scope.snapshot(), pool.snapshot());
    release.wait();
    let winners = handles
        .into_iter()
        .map(|h| usize::from(h.join().unwrap()))
        .sum::<usize>();
    assert_eq!(winners, 1);
    assert_eq!(observed.0.resident().bytes(), 32);
    assert_eq!(observed.1.resident().bytes(), 32);
    assert_eq!(observed.2.leased_allocations, 2);
    assert_eq!(scope.snapshot().used().bytes(), 0);
    pool.close();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
