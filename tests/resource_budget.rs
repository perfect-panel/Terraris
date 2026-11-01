// SPDX-License-Identifier: GPL-3.0-only

use std::{
    sync::{Arc, Barrier},
    thread,
};

use terraris::resource::{Budget, Dimension, Error, Limits, MAX_SCOPE_DEPTH};

fn limits(bytes: usize, allocations: usize) -> Limits {
    Limits::new(bytes, allocations).unwrap()
}

#[test]
fn reservation_commit_and_drop_keep_reserved_and_resident_separate() {
    let budget = Budget::new(limits(100, 4));
    let connection = budget.scope(limits(80, 3)).unwrap();
    let reservation = connection.try_reserve(60).unwrap();
    assert_eq!(budget.snapshot().reserved().bytes(), 60);
    assert_eq!(connection.snapshot().used().allocations(), 1);
    let permit = reservation.commit();
    assert_eq!(permit.bytes(), 60);
    assert_eq!(budget.snapshot().reserved().bytes(), 0);
    assert_eq!(connection.snapshot().resident().bytes(), 60);
    let waiting = connection.try_reserve(20).unwrap();
    assert_eq!(connection.snapshot().used().bytes(), 80);
    drop(waiting);
    assert_eq!(connection.snapshot().resident().bytes(), 60);
    assert_eq!(connection.snapshot().reserved().bytes(), 0);
    drop(permit);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(connection.snapshot().used().allocations(), 0);
}

#[test]
fn sibling_scopes_share_the_process_budget_and_descendants_charge_ancestors() {
    let budget = Budget::new(limits(100, 10));
    let parent = budget.scope(limits(80, 8)).unwrap();
    let left = parent.child(limits(60, 6)).unwrap();
    let right = parent.child(limits(60, 6)).unwrap();
    let other = budget.scope(limits(100, 10)).unwrap();
    let left_permit = left.try_reserve(50).unwrap().commit();
    assert_eq!(left.snapshot().resident().bytes(), 50);
    assert_eq!(parent.snapshot().resident().bytes(), 50);
    assert_eq!(budget.snapshot().resident().bytes(), 50);
    let before = parent.snapshot();
    assert!(matches!(
        right.try_reserve(40),
        Err(Error::Exhausted {
            depth: 1,
            dimension: Dimension::Bytes,
            ..
        })
    ));
    assert_eq!(parent.snapshot(), before);
    assert_eq!(right.snapshot().used().bytes(), 0);
    let sibling = other.try_reserve(50).unwrap();
    assert!(matches!(
        right.try_reserve(1),
        Err(Error::Exhausted { depth: 0, .. })
    ));
    drop(sibling);
    let right_permit = right.try_reserve(30).unwrap().commit();
    assert_eq!(parent.snapshot().used().bytes(), 80);
    drop(left_permit);
    assert_eq!(parent.snapshot().resident().bytes(), 30);
    drop(right_permit);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn batch_failure_is_atomic_across_global_and_all_ancestor_limits() {
    let budget = Budget::new(limits(100, 8));
    let parent = budget.scope(limits(80, 6)).unwrap();
    let child = parent.child(limits(60, 4)).unwrap();
    let retained = child.try_reserve(20).unwrap().commit();
    let before = [budget.snapshot(), parent.snapshot(), child.snapshot()];
    for request in [&[30, 20][..], &[0, 0, 0, 0][..], &[usize::MAX, 1][..]] {
        assert!(child.try_reserve_many(request).is_err());
        assert_eq!(
            [budget.snapshot(), parent.snapshot(), child.snapshot()],
            before
        );
    }
    let reservations = child.try_reserve_many(&[10, 20, 10]).unwrap();
    assert_eq!(child.snapshot().reserved().bytes(), 40);
    assert_eq!(child.snapshot().used().bytes(), 60);
    assert_eq!(child.snapshot().used().allocations(), 4);
    drop(reservations);
    assert_eq!(
        [budget.snapshot(), parent.snapshot(), child.snapshot()],
        before
    );
    drop(retained);
}

#[test]
fn batch_owners_can_commit_and_release_independently() {
    let budget = Budget::new(limits(128, 4));
    let scope = budget.root_scope();
    let mut reservations = scope.try_reserve_many(&[10, 20, 30]).unwrap();
    let thirty = reservations.pop().unwrap().commit();
    let twenty = reservations.pop().unwrap();
    assert_eq!(budget.snapshot().resident().bytes(), 30);
    assert_eq!(budget.snapshot().reserved().bytes(), 30);
    drop(twenty);
    assert_eq!(budget.snapshot().reserved().bytes(), 10);
    drop(reservations);
    assert_eq!(budget.snapshot().reserved().bytes(), 0);
    assert_eq!(budget.snapshot().used().allocations(), 1);
    drop(thirty);
    assert_eq!(budget.snapshot().used().allocations(), 0);
}

#[test]
fn zero_byte_requests_still_consume_allocation_slots() {
    let budget = Budget::new(limits(1, 2));
    let scope = budget.root_scope();
    assert!(scope.try_reserve_many(&[]).unwrap().is_empty());
    let reservations = scope.try_reserve_many(&[0, 0]).unwrap();
    assert_eq!(scope.snapshot().used().bytes(), 0);
    assert_eq!(scope.snapshot().used().allocations(), 2);
    assert!(matches!(
        scope.try_reserve(0),
        Err(Error::Exhausted {
            dimension: Dimension::Allocations,
            ..
        })
    ));
    drop(reservations);
    assert_eq!(scope.snapshot().used().allocations(), 0);
}

#[test]
fn arithmetic_at_usize_limit_never_wraps() {
    let budget = Budget::new(limits(usize::MAX, 3));
    let scope = budget.root_scope();
    let reservation = scope.try_reserve(usize::MAX).unwrap();
    assert_eq!(scope.snapshot().used().bytes(), usize::MAX);
    assert!(scope.try_reserve(1).is_err());
    assert_eq!(
        scope.try_reserve_many(&[usize::MAX, 1]).unwrap_err(),
        Error::SizeOverflow
    );
    let permit = reservation.commit();
    assert_eq!(scope.snapshot().resident().bytes(), usize::MAX);
    drop(permit);
    assert_eq!(scope.snapshot().used().bytes(), 0);
}

#[test]
fn close_blocks_new_grants_but_does_not_revoke_existing_owners() {
    let budget = Budget::new(limits(128, 8));
    let parent = budget.scope(limits(64, 4)).unwrap();
    let child = parent.child(limits(32, 2)).unwrap();
    let sibling = budget.scope(limits(64, 4)).unwrap();
    let reservation = child.try_reserve(16).unwrap();
    parent.close();
    parent.close();
    assert!(child.snapshot().is_closed());
    assert_eq!(child.try_reserve(1).unwrap_err(), Error::Closed);
    assert_eq!(child.try_reserve_many(&[]).unwrap_err(), Error::Closed);
    assert_eq!(parent.child(limits(8, 1)).unwrap_err(), Error::Closed);
    assert!(!budget.snapshot().is_closed());
    let other = sibling.try_reserve(16).unwrap();
    let resident = reservation.commit();
    assert_eq!(child.snapshot().resident().bytes(), 16);
    budget.close();
    assert!(sibling.snapshot().is_closed());
    assert_eq!(sibling.try_reserve(0).unwrap_err(), Error::Closed);
    drop(resident);
    drop(other);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(child.snapshot().used().allocations(), 0);
}

#[test]
fn permits_keep_ancestor_accounting_alive_after_scope_handles_are_dropped() {
    let budget = Budget::new(limits(64, 4));
    let parent = budget.scope(limits(64, 4)).unwrap();
    let child = parent.child(limits(32, 2)).unwrap();
    let permit = child.try_reserve(24).unwrap().commit();
    drop(child);
    drop(parent);
    assert_eq!(budget.snapshot().resident().bytes(), 24);
    thread::spawn(move || drop(permit)).join().unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn invalid_limits_and_scope_depth_are_rejected() {
    assert_eq!(Limits::new(0, 1).unwrap_err(), Error::InvalidLimits);
    assert_eq!(Limits::new(1, 0).unwrap_err(), Error::InvalidLimits);
    let budget = Budget::new(limits(64, 4));
    assert_eq!(
        budget.scope(limits(65, 4)).unwrap_err(),
        Error::ChildLimitExceedsParent
    );
    assert_eq!(
        budget.scope(limits(64, 5)).unwrap_err(),
        Error::ChildLimitExceedsParent
    );
    let mut scope = budget.root_scope();
    for depth in 1..=MAX_SCOPE_DEPTH {
        scope = scope.child(limits(64, 4)).unwrap();
        assert_eq!(scope.depth(), depth);
    }
    assert_eq!(
        scope.child(limits(64, 4)).unwrap_err(),
        Error::ScopeDepthExceeded
    );
    let permit = scope.try_reserve(1).unwrap();
    assert_eq!(budget.snapshot().reserved().bytes(), 1);
    drop(permit);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn concurrent_batches_never_take_partial_capacity_or_exceed_the_limit() {
    const WORKERS: usize = 16;
    let budget = Budget::new(limits(128, 2));
    let scope = budget.scope(limits(128, 2)).unwrap();
    let start = Arc::new(Barrier::new(WORKERS));
    let hold = Arc::new(Barrier::new(WORKERS + 1));
    let release = Arc::new(Barrier::new(WORKERS + 1));
    let threads: Vec<_> = (0..WORKERS)
        .map(|_| {
            let (scope, start, hold, release) =
                (scope.clone(), start.clone(), hold.clone(), release.clone());
            thread::spawn(move || {
                start.wait();
                let reservation = scope.try_reserve_many(&[64, 64]);
                let won = reservation.is_ok();
                hold.wait();
                release.wait();
                drop(reservation);
                won
            })
        })
        .collect();
    hold.wait();
    let held = (budget.snapshot(), scope.snapshot());
    release.wait();
    let winners = threads
        .into_iter()
        .map(|t| usize::from(t.join().unwrap()))
        .sum::<usize>();
    assert_eq!(winners, 1);
    assert_eq!(held.0.reserved().bytes(), 128);
    assert_eq!(held.1.used().allocations(), 2);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn close_and_reserve_race_leaves_every_grant_owned_or_rejected() {
    let budget = Budget::new(limits(4096, 64));
    let scope = budget.scope(limits(4096, 64)).unwrap();
    let start = Arc::new(Barrier::new(17));
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let (scope, start) = (scope.clone(), start.clone());
            thread::spawn(move || {
                start.wait();
                scope.try_reserve_many(&[16, 16])
            })
        })
        .collect();
    start.wait();
    budget.close();
    let mut grants = Vec::new();
    for thread in threads {
        match thread.join().unwrap() {
            Ok(items) => grants.extend(items),
            Err(error) => assert_eq!(error, Error::Closed),
        }
    }
    assert_eq!(scope.snapshot().reserved().bytes(), grants.len() * 16);
    drop(grants);
    assert_eq!(budget.snapshot().used().allocations(), 0);
}

#[tokio::test]
async fn cancelling_a_task_drops_its_reservations_without_explicit_release() {
    let budget = Budget::new(limits(128, 4));
    let scope = budget.root_scope();
    let (ready, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let reservations = scope.try_reserve_many(&[32, 32]).unwrap();
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(reservations);
    });
    received.await.unwrap();
    assert_eq!(budget.snapshot().reserved().bytes(), 64);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(budget.snapshot().used().allocations(), 0);
}
