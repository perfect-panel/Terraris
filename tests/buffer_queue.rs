// SPDX-License-Identifier: GPL-3.0-only

use bytes::Bytes;
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Barrier},
    task::{Context, Poll, Waker},
    thread,
    time::Duration,
};
use terraris::{
    buffer::{
        BufferLayout, BufferScope, QueueError, QueueItem, QueueLimits, SharedBuffer, bounded_queue,
    },
    resource::{Budget, Limits},
};
use tokio::time::Instant;

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}
fn limits(bytes: usize, messages: usize, waiters: usize) -> QueueLimits {
    QueueLimits::new(bytes, messages, waiters).unwrap()
}
fn scope() -> (Budget, BufferScope) {
    let b = Budget::new(Limits::new(256, 16).unwrap());
    let s = BufferScope::new(b.scope(Limits::new(256, 16).unwrap()).unwrap(), 64).unwrap();
    (b, s)
}
fn frame(scope: &BufferScope, body: &[u8]) -> SharedBuffer {
    let mut b = scope
        .try_lease(BufferLayout::new(0, 32, 0).unwrap())
        .unwrap();
    b.append_payload(body).unwrap();
    b.freeze()
}

#[test]
fn both_limits_apply_and_failed_try_send_returns_the_original_owner() {
    let (budget, scope) = scope();
    let (sender, mut queue) = bounded_queue(limits(5, 2, 2)).unwrap();
    sender.try_send(frame(&scope, b"abc")).unwrap();
    let rejected = sender.try_send(frame(&scope, b"def")).unwrap_err();
    assert_eq!(rejected.error, QueueError::Full);
    assert_eq!(rejected.item.as_slice(), b"def");
    assert!(!format!("{rejected:?}").contains("def"));
    drop(rejected);
    sender.try_send(frame(&scope, b"d")).unwrap();
    let empty = sender.try_send(frame(&scope, b"")).unwrap_err();
    assert_eq!(empty.error, QueueError::Full);
    drop(empty);
    let first = queue.try_recv().unwrap();
    assert_eq!(first.as_slice(), b"abc");
    assert_eq!(sender.snapshot().queued_bytes, 1);
    assert_eq!(budget.snapshot().resident().bytes(), 64); // dequeued owner still pins its allocation
    drop(first);
    drop(queue.try_recv().unwrap());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert!(matches!(queue.try_recv(), Err(QueueError::Empty)));
    drop(sender);
    assert!(matches!(queue.try_recv(), Err(QueueError::Closed)));
}

#[test]
fn empty_views_consume_slots_while_retaining_their_original_physical_capacity() {
    let (budget, scope) = scope();
    let original = frame(&scope, b"payload");
    let empty = original.slice(0..0).unwrap();
    drop(original);
    let (sender, mut queue) = bounded_queue(limits(0, 1, 0)).unwrap();
    sender.try_send(empty).unwrap();
    assert_eq!(sender.snapshot().queued_bytes, 0);
    assert_eq!(sender.snapshot().queued_messages, 1);
    assert_eq!(budget.snapshot().resident().bytes(), 32);
    assert_eq!(sender.try_reserve(0).unwrap_err(), QueueError::Full);
    drop(queue.try_recv().unwrap());
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn reservation_is_atomic_in_bytes_and_slots_and_size_mismatch_refunds_it() {
    let (sender, _queue) = bounded_queue::<Bytes>(limits(10, 2, 2)).unwrap();
    let large = sender.try_reserve(8).unwrap();
    assert_eq!(sender.try_reserve(3).unwrap_err(), QueueError::Full);
    let zero = sender.try_reserve(0).unwrap();
    assert_eq!(sender.try_reserve(0).unwrap_err(), QueueError::Full);
    let rejected = large.send(Bytes::from_static(b"short")).unwrap_err();
    assert_eq!(rejected.error, QueueError::SizeMismatch);
    assert_eq!(&rejected.item[..], b"short");
    assert_eq!(sender.snapshot().reserved_bytes, 0);
    assert_eq!(sender.snapshot().reserved_messages, 1);
    drop(zero);
    assert_eq!(sender.snapshot().reserved_messages, 0);
}

#[tokio::test(start_paused = true)]
async fn cancelled_waiter_releases_its_place_without_taking_capacity() {
    let (sender, mut queue) = bounded_queue::<Bytes>(limits(4, 1, 1)).unwrap();
    sender.try_send(Bytes::from_static(b"full")).unwrap();
    let mut pending = Box::pin(sender.reserve(4, deadline()));
    assert!(poll_once(pending.as_mut()).is_pending());
    assert_eq!(sender.snapshot().waiting, 1);
    assert_eq!(
        sender.reserve(1, deadline()).await.unwrap_err(),
        QueueError::WaiterLimit
    );
    drop(pending);
    assert_eq!(sender.snapshot().waiting, 0);
    assert_eq!(sender.snapshot().reserved_messages, 0);
    drop(queue.try_recv().unwrap());
    assert!(sender.try_reserve(4).is_ok());
}

#[tokio::test(start_paused = true)]
async fn cancelling_a_granted_but_unconsumed_waiter_refunds_and_grants_the_next() {
    let (sender, mut queue) = bounded_queue::<Bytes>(limits(4, 1, 2)).unwrap();
    sender.try_send(Bytes::from_static(b"full")).unwrap();
    let mut first = Box::pin(sender.reserve(4, deadline()));
    assert!(poll_once(first.as_mut()).is_pending());
    let mut second = Box::pin(sender.reserve(4, deadline()));
    assert!(poll_once(second.as_mut()).is_pending());
    drop(queue.try_recv().unwrap());
    assert_eq!(sender.snapshot().waiting, 1);
    assert_eq!(sender.snapshot().reserved_bytes, 4);
    drop(first);
    assert_eq!(sender.snapshot().waiting, 0);
    assert_eq!(sender.snapshot().reserved_bytes, 4);
    let permit = second.await.unwrap();
    permit.send(Bytes::from_static(b"next")).unwrap();
    assert_eq!(&queue.recv().await.unwrap()[..], b"next");
    assert_eq!(sender.snapshot().reserved_messages, 0);
}

#[tokio::test(start_paused = true)]
async fn fifo_reservations_do_not_allow_small_requests_to_skip_the_head() {
    let (sender, mut queue) = bounded_queue::<Bytes>(limits(10, 4, 4)).unwrap();
    sender.try_send(Bytes::from_static(b"12345678")).unwrap();
    let mut large = Box::pin(sender.reserve(8, deadline()));
    assert!(poll_once(large.as_mut()).is_pending());
    let mut small = Box::pin(sender.reserve(2, deadline()));
    assert!(poll_once(small.as_mut()).is_pending());
    assert_eq!(sender.try_reserve(1).unwrap_err(), QueueError::Full);
    drop(queue.try_recv().unwrap());
    assert_eq!(sender.snapshot().reserved_bytes, 10);
    assert_eq!(sender.snapshot().waiting, 0);
    large
        .await
        .unwrap()
        .send(Bytes::from_static(b"abcdefgh"))
        .unwrap();
    small
        .await
        .unwrap()
        .send(Bytes::from_static(b"ij"))
        .unwrap();
    assert_eq!(&queue.recv().await.unwrap()[..], b"abcdefgh");
    assert_eq!(&queue.recv().await.unwrap()[..], b"ij");
}

#[tokio::test(start_paused = true)]
async fn cancelling_a_large_head_wakes_a_smaller_waiter_that_can_already_fit() {
    let (sender, _queue) = bounded_queue::<Bytes>(limits(10, 3, 3)).unwrap();
    sender.try_send(Bytes::from_static(b"12345678")).unwrap();
    let mut large = Box::pin(sender.reserve(8, deadline()));
    assert!(poll_once(large.as_mut()).is_pending());
    let mut small = Box::pin(sender.reserve(2, deadline()));
    assert!(poll_once(small.as_mut()).is_pending());
    drop(large);
    let permit = small.await.unwrap();
    assert_eq!(sender.snapshot().reserved_bytes, 2);
    drop(permit);
    assert_eq!(sender.snapshot().reserved_messages, 0);
}

#[tokio::test(start_paused = true)]
async fn timeout_cleans_up_waiting_and_already_granted_reservations() {
    for grant_before_timeout in [false, true] {
        let (sender, mut queue) = bounded_queue::<Bytes>(limits(4, 1, 1)).unwrap();
        sender.try_send(Bytes::from_static(b"full")).unwrap();
        let mut pending = Box::pin(sender.reserve(4, Instant::now() + Duration::from_secs(1)));
        assert!(poll_once(pending.as_mut()).is_pending());
        if grant_before_timeout {
            drop(queue.try_recv().unwrap());
            assert_eq!(sender.snapshot().reserved_bytes, 4);
        }
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(pending.await.unwrap_err(), QueueError::Timeout);
        assert_eq!(sender.snapshot().waiting, 0);
        assert_eq!(sender.snapshot().reserved_bytes, 0);
        assert_eq!(sender.snapshot().reserved_messages, 0);
    }
}

#[tokio::test(start_paused = true)]
async fn closure_wakes_waiters_rejects_old_permits_and_drains_accepted_items() {
    let (sender, mut queue) = bounded_queue::<Bytes>(limits(8, 2, 2)).unwrap();
    sender.try_send(Bytes::from_static(b"data")).unwrap();
    let permit = sender.try_reserve(4).unwrap();
    let mut waiting = Box::pin(sender.reserve(4, deadline()));
    assert!(poll_once(waiting.as_mut()).is_pending());
    queue.close();
    assert_eq!(waiting.await.unwrap_err(), QueueError::Closed);
    let rejected = permit.send(Bytes::from_static(b"more")).unwrap_err();
    assert_eq!(rejected.error, QueueError::Closed);
    assert_eq!(&rejected.item[..], b"more");
    assert_eq!(sender.snapshot().reserved_messages, 0);
    assert_eq!(&queue.recv().await.unwrap()[..], b"data");
    assert!(queue.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn close_between_grant_and_consumption_refunds_the_grant() {
    let (sender, mut queue) = bounded_queue::<Bytes>(limits(4, 1, 2)).unwrap();
    sender.try_send(Bytes::from_static(b"full")).unwrap();
    let mut waiting = Box::pin(sender.reserve(4, deadline()));
    assert!(poll_once(waiting.as_mut()).is_pending());
    drop(queue.try_recv().unwrap());
    assert_eq!(sender.snapshot().reserved_bytes, 4);
    sender.close();
    assert_eq!(waiting.await.unwrap_err(), QueueError::Closed);
    assert_eq!(sender.snapshot().reserved_messages, 0);
    assert!(queue.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn receiver_drop_discards_items_and_wakes_producers_without_leaking_buffer_owners() {
    let (budget, scope) = scope();
    let (sender, queue) = bounded_queue(limits(4, 1, 2)).unwrap();
    sender.try_send(frame(&scope, b"full")).unwrap();
    let mut pending = Box::pin(sender.send(frame(&scope, b"next"), deadline()));
    assert!(poll_once(pending.as_mut()).is_pending());
    assert_eq!(budget.snapshot().resident().bytes(), 64);
    drop(queue);
    let rejected = pending.await.unwrap_err();
    assert_eq!(rejected.error, QueueError::Closed);
    assert_eq!(budget.snapshot().resident().bytes(), 32);
    drop(rejected);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(sender.snapshot().waiting, 0);
}

#[tokio::test(start_paused = true)]
async fn dropping_async_send_drops_its_item_and_waiter_together() {
    let (budget, scope) = scope();
    let (sender, queue) = bounded_queue(limits(4, 1, 2)).unwrap();
    sender.try_send(frame(&scope, b"full")).unwrap();
    let mut sending = Box::pin(sender.send(frame(&scope, b"next"), deadline()));
    assert!(poll_once(sending.as_mut()).is_pending());
    assert_eq!(budget.snapshot().resident().bytes(), 64);
    drop(sending);
    assert_eq!(budget.snapshot().resident().bytes(), 32);
    assert_eq!(sender.snapshot().waiting, 0);
    drop(queue);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[tokio::test]
async fn outstanding_permit_keeps_receiver_open_after_all_senders_drop() {
    let (sender, mut queue) = bounded_queue::<Bytes>(limits(4, 1, 0)).unwrap();
    let permit = sender.try_reserve(4).unwrap();
    drop(sender);
    assert!(matches!(queue.try_recv(), Err(QueueError::Empty)));
    assert!(!queue.snapshot().closed);
    permit.send(Bytes::from_static(b"last")).unwrap();
    assert_eq!(&queue.recv().await.unwrap()[..], b"last");
    assert!(queue.recv().await.is_none());
    let (sender, mut queue) = bounded_queue::<Bytes>(limits(4, 1, 0)).unwrap();
    let permit = sender.try_reserve(4).unwrap();
    drop(sender);
    let receiver = tokio::spawn(async move { queue.recv().await });
    drop(permit);
    assert!(receiver.await.unwrap().is_none());
}

#[tokio::test(start_paused = true)]
async fn invalid_or_unfulfillable_requests_never_join_the_waiter_list() {
    assert!(QueueLimits::new(1, 0, 1).is_err());
    assert!(bounded_queue::<Bytes>(limits(1, usize::MAX, 0)).is_err());
    let (sender, _queue) = bounded_queue::<Bytes>(limits(4, 1, 0)).unwrap();
    assert_eq!(
        sender.reserve(5, deadline()).await.unwrap_err(),
        QueueError::TooLarge
    );
    assert_eq!(
        sender.reserve(0, Instant::now()).await.unwrap_err(),
        QueueError::Timeout
    );
    sender.try_send(Bytes::from_static(b"full")).unwrap();
    assert_eq!(
        sender.reserve(1, deadline()).await.unwrap_err(),
        QueueError::WaiterLimit
    );
    assert_eq!(sender.snapshot().waiting, 0);
    assert_eq!(sender.snapshot().reserved_messages, 0);
}

#[test]
fn concurrent_producers_cannot_overfill_either_dimension() {
    let (sender, mut queue) = bounded_queue::<Bytes>(limits(4, 2, 4)).unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let threads: Vec<_> = (0..16)
        .map(|_| {
            let (s, b) = (sender.clone(), barrier.clone());
            thread::spawn(move || {
                b.wait();
                s.try_send(Bytes::from_static(b"ab")).is_ok()
            })
        })
        .collect();
    let successes = threads
        .into_iter()
        .map(|t| usize::from(t.join().unwrap()))
        .sum::<usize>();
    assert_eq!(successes, 2);
    assert_eq!(sender.snapshot().queued_bytes, 4);
    assert_eq!(sender.snapshot().queued_messages, 2);
    assert_eq!(sender.snapshot().reserved_messages, 0);
    drop(queue.try_recv().unwrap());
    drop(queue.try_recv().unwrap());
    assert_eq!(sender.snapshot().queued_bytes, 0);
}

#[test]
fn user_destructors_run_outside_the_queue_mutex() {
    struct Item {
        sender: Option<terraris::buffer::BufferSender<Item>>,
    }
    impl QueueItem for Item {
        fn queue_bytes(&self) -> usize {
            0
        }
    }
    impl Drop for Item {
        fn drop(&mut self) {
            if let Some(sender) = &self.sender {
                sender.close();
            }
        }
    }
    let (sender, queue) = bounded_queue::<Item>(limits(0, 1, 0)).unwrap();
    sender
        .try_send(Item {
            sender: Some(sender.clone()),
        })
        .unwrap();
    drop(queue);
    assert!(sender.snapshot().closed);
    assert_eq!(sender.snapshot().senders, 1);
}

#[test]
fn very_large_logical_cost_does_not_overflow_queue_accounting() {
    struct Logical(usize);
    impl QueueItem for Logical {
        fn queue_bytes(&self) -> usize {
            self.0
        }
    }
    let (sender, mut queue) = bounded_queue::<Logical>(limits(usize::MAX, 2, 0)).unwrap();
    sender.try_send(Logical(usize::MAX)).unwrap();
    assert_eq!(sender.try_reserve(1).unwrap_err(), QueueError::Full);
    drop(sender.try_reserve(0).unwrap());
    assert_eq!(queue.try_recv().unwrap().0, usize::MAX);
    assert_eq!(sender.snapshot().queued_bytes, 0);
}

#[tokio::test]
async fn aborting_a_waiting_sender_task_releases_queue_and_pool_ownership() {
    use terraris::buffer::{BufferPool, PoolConfig};
    let budget = Budget::new(Limits::new(128, 8).unwrap());
    let pool = BufferPool::new(
        budget.clone(),
        PoolConfig::new(vec![32], 128, 8, 8).unwrap(),
    )
    .unwrap();
    let scope = pool
        .scope(budget.scope(Limits::new(128, 8).unwrap()).unwrap(), 64)
        .unwrap();
    let (sender, queue) = bounded_queue(limits(4, 1, 2)).unwrap();
    sender.try_send(frame(&scope, b"full")).unwrap();
    let other = sender.clone();
    let pending_frame = frame(&scope, b"next");
    let (ready, started) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        ready.send(()).unwrap();
        other.send(pending_frame, deadline()).await
    });
    started.await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while sender.snapshot().waiting == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(sender.snapshot().waiting, 0);
    assert_eq!(sender.snapshot().reserved_messages, 0);
    assert_eq!(scope.snapshot().resident().bytes(), 32);
    assert_eq!(pool.snapshot().idle_bytes, 32);
    drop(queue);
    assert_eq!(scope.snapshot().used().bytes(), 0);
    assert_eq!(pool.snapshot().idle_bytes, 64);
    pool.close();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
