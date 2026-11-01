// SPDX-License-Identifier: GPL-3.0-only

use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, UNIX_EPOCH},
};
use terraris::{
    buffer::{BufferLayout, BufferScope},
    resource::{Budget, Limits},
    task::{CancellationToken, SpawnError, TaskFailure, TaskGroup, TaskOutcome},
    telemetry::{Counter, Gauge, Metrics},
    time::{Deadline, OperationContext, StopReason, UnixMillis},
};

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn wall_clock_units_are_milliseconds_and_pre_epoch_is_rejected() {
    let value = UNIX_EPOCH + Duration::from_millis(1_800_000_000_123);
    assert_eq!(
        UnixMillis::from_system_time(value).unwrap().get(),
        1_800_000_000_123
    );
    assert_eq!(UnixMillis::from_system_time(UNIX_EPOCH).unwrap().get(), 0);
    assert!(UnixMillis::from_system_time(UNIX_EPOCH - Duration::from_secs(1)).is_err());
    assert!(Deadline::after(Duration::MAX).is_err());
}

#[tokio::test(start_paused = true)]
async fn cancelled_and_expired_contexts_never_poll_ready_work() {
    let count = AtomicUsize::new(0);
    let token = CancellationToken::new();
    token.cancel();
    let cancelled = OperationContext::new(token, Some(Deadline::after(Duration::ZERO).unwrap()));
    let work = std::future::poll_fn(|_| {
        count.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(7)
    });
    assert_eq!(
        cancelled.run(work).await.unwrap_err(),
        StopReason::Cancelled
    );
    let expired = OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::ZERO).unwrap()),
    );
    assert_eq!(
        expired
            .run(std::future::poll_fn(|_| {
                count.fetch_add(1, Ordering::Relaxed);
                Poll::Ready(7)
            }))
            .await
            .unwrap_err(),
        StopReason::DeadlineExceeded
    );
    assert_eq!(count.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn monotonic_deadline_stops_pending_work_and_children_cannot_extend_it() {
    let token = CancellationToken::new();
    let deadline = Deadline::after(Duration::from_secs(3)).unwrap();
    let parent = OperationContext::new(token.clone(), Some(deadline));
    let child = parent.child_with_deadline(Deadline::after(Duration::from_secs(20)).unwrap());
    assert_eq!(child.deadline(), Some(deadline));
    let short = parent.child_with_deadline(Deadline::after(Duration::from_secs(1)).unwrap());
    assert!(short.deadline().unwrap() < deadline);
    assert_eq!(
        child.run(std::future::pending::<()>()).await.unwrap_err(),
        StopReason::DeadlineExceeded
    );
    assert!(deadline.is_elapsed());
    assert!(!token.is_cancelled());
}

#[tokio::test]
async fn child_cancellation_is_isolated_and_completed_results_are_retained() {
    let parent = OperationContext::new(CancellationToken::new(), None);
    let child = parent.child();
    child.cancellation().cancel();
    assert_eq!(child.check().unwrap_err(), StopReason::Cancelled);
    assert!(parent.check().is_ok());
    let token = parent.cancellation().clone();
    assert_eq!(
        parent
            .run(async move {
                token.cancel();
                42
            })
            .await
            .unwrap(),
        42
    );
    assert_eq!(parent.check().unwrap_err(), StopReason::Cancelled);
}

#[test]
fn task_group_rejects_invalid_limits_and_spawning_without_runtime() {
    let parent = CancellationToken::new();
    let metrics = Metrics::default();
    assert!(matches!(
        TaskGroup::new(&parent, 0, metrics.clone()),
        Err(SpawnError::InvalidLimit)
    ));
    let mut group = TaskGroup::new(&parent, 1, metrics.clone()).unwrap();
    assert_eq!(
        group.spawn("work", |_| async { Ok(()) }).unwrap_err(),
        SpawnError::NoRuntime
    );
    assert_eq!(
        group.spawn("bad\nname", |_| async { Ok(()) }).unwrap_err(),
        SpawnError::InvalidName
    );
    assert_eq!(metrics.snapshot().counter(Counter::TasksSpawned), 0);
}

#[tokio::test]
async fn completed_but_unjoined_tasks_still_consume_tracking_capacity() {
    let metrics = Metrics::default();
    let mut group = TaskGroup::new(&CancellationToken::new(), 1, metrics.clone()).unwrap();
    let (done, finished) = tokio::sync::oneshot::channel();
    let id = group
        .spawn("first", move |_| async move {
            done.send(()).unwrap();
            Ok(())
        })
        .unwrap();
    finished.await.unwrap();
    assert_eq!(
        group.spawn("second", |_| async { Ok(()) }).unwrap_err(),
        SpawnError::AtCapacity
    );
    let report = group.join_next().await.unwrap();
    assert_eq!(report.id, id);
    assert_eq!(report.name, "first");
    assert_eq!(report.outcome, TaskOutcome::Completed);
    assert!(group.is_empty());
    group.spawn("second", |_| async { Ok(()) }).unwrap();
    assert_eq!(
        group.join_next().await.unwrap().outcome,
        TaskOutcome::Completed
    );
    assert_eq!(metrics.snapshot().counter(Counter::TasksCompleted), 2);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveTasks), 0);
}

#[tokio::test]
async fn task_failure_and_factory_panic_are_joined_without_retaining_panic_payload() {
    let metrics = Metrics::default();
    let mut group = TaskGroup::new(&CancellationToken::new(), 2, metrics.clone()).unwrap();
    group
        .spawn("failure", |_| async {
            Err(TaskFailure::Failed("fixture_failure"))
        })
        .unwrap();
    group
        .spawn(
            "panic",
            |_| -> std::future::Ready<Result<(), TaskFailure>> {
                panic!("synthetic private panic body")
            },
        )
        .unwrap();
    let reports = [
        group.join_next().await.unwrap(),
        group.join_next().await.unwrap(),
    ];
    assert!(reports.iter().any(|r| r.outcome == TaskOutcome::Panicked));
    assert!(
        reports
            .iter()
            .any(|r| r.outcome == TaskOutcome::Failed(TaskFailure::Failed("fixture_failure")))
    );
    assert!(!format!("{reports:?}").contains("synthetic private panic body"));
    assert_eq!(metrics.snapshot().counter(Counter::TasksPanicked), 1);
    assert_eq!(metrics.snapshot().counter(Counter::TasksFailed), 1);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveTasks), 0);
}

#[tokio::test]
async fn a_task_cannot_cancel_siblings_or_parent_with_its_child_token() {
    let parent = CancellationToken::new();
    let mut group = TaskGroup::new(&parent, 2, Metrics::default()).unwrap();
    group
        .spawn("self_cancel", |token| async move {
            token.cancel();
            Err(TaskFailure::Cancelled)
        })
        .unwrap();
    group
        .spawn("sibling", |token| async move {
            assert!(!token.is_cancelled());
            Ok(())
        })
        .unwrap();
    let reports = [
        group.join_next().await.unwrap(),
        group.join_next().await.unwrap(),
    ];
    assert!(reports.iter().any(|r| r.outcome == TaskOutcome::Completed));
    assert!(!group.is_closed());
    assert!(!parent.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn shutdown_cancels_cooperative_tasks_and_waits_for_buffer_reclamation() {
    let budget = Budget::new(Limits::new(128, 4).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 64).unwrap();
    let metrics = Metrics::default();
    let parent = CancellationToken::new();
    let mut group = TaskGroup::new(&parent, 2, metrics.clone()).unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    group
        .spawn("worker", move |token| async move {
            let _lease = scope
                .try_lease(BufferLayout::new(0, 32, 0).unwrap())
                .unwrap();
            ready.send(()).unwrap();
            token.cancelled().await;
            Err(TaskFailure::Cancelled)
        })
        .unwrap();
    started.await.unwrap();
    assert_eq!(budget.snapshot().resident().bytes(), 32);
    let report = group
        .shutdown(Deadline::after(Duration::from_secs(1)).unwrap())
        .await;
    assert!(!report.abort_requested);
    assert_eq!(
        report.tasks[0].outcome,
        TaskOutcome::Failed(TaskFailure::Cancelled)
    );
    assert!(group.is_empty());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveTasks), 0);
    assert!(!parent.is_cancelled());
    assert_eq!(
        group.spawn("late", |_| async { Ok(()) }).unwrap_err(),
        SpawnError::Closed
    );
}

#[tokio::test(start_paused = true)]
async fn shutdown_aborts_uncooperative_pending_tasks_and_joins_their_drops() {
    let budget = Budget::new(Limits::new(64, 2).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 64).unwrap();
    let metrics = Metrics::default();
    let mut group = TaskGroup::new(&CancellationToken::new(), 1, metrics.clone()).unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    group
        .spawn("pending", move |_| async move {
            let _lease = scope
                .try_lease(BufferLayout::new(0, 32, 0).unwrap())
                .unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
            Ok(())
        })
        .unwrap();
    started.await.unwrap();
    let report = group
        .shutdown(Deadline::after(Duration::from_secs(2)).unwrap())
        .await;
    assert!(report.abort_requested);
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Aborted);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().counter(Counter::TasksAborted), 1);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveTasks), 0);
}

#[tokio::test(start_paused = true)]
async fn cancelling_shutdown_future_keeps_task_handles_owned_for_a_later_join() {
    let mut group = TaskGroup::new(&CancellationToken::new(), 1, Metrics::default()).unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    group
        .spawn("pending", move |_| async move {
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
            Ok(())
        })
        .unwrap();
    started.await.unwrap();
    let mut closing = Box::pin(group.shutdown(Deadline::after(Duration::from_secs(60)).unwrap()));
    assert!(poll_once(closing.as_mut()).is_pending());
    drop(closing);
    assert_eq!(group.len(), 1);
    assert!(group.is_closed());
    let report = group
        .shutdown(Deadline::after(Duration::ZERO).unwrap())
        .await;
    assert!(report.abort_requested);
    assert_eq!(report.tasks[0].outcome, TaskOutcome::Aborted);
}

#[tokio::test]
async fn drop_aborts_tasks_but_explicit_completion_is_still_needed_to_observe_cleanup() {
    struct NotifyDrop(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for NotifyDrop {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    let mut group = TaskGroup::new(&CancellationToken::new(), 1, Metrics::default()).unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    let (done, dropped) = tokio::sync::oneshot::channel();
    group
        .spawn("pending", move |_| async move {
            let _guard = NotifyDrop(Some(done));
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
            Ok(())
        })
        .unwrap();
    started.await.unwrap();
    drop(group);
    tokio::time::timeout(Duration::from_secs(2), dropped)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn parent_cancellation_stops_new_spawns_and_unstarted_factories() {
    let parent = CancellationToken::new();
    let count = Arc::new(AtomicUsize::new(0));
    let mut group = TaskGroup::new(&parent, 1, Metrics::default()).unwrap();
    let captured = count.clone();
    group
        .spawn("not_started", move |_| async move {
            captured.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap();
    parent.cancel();
    assert_eq!(
        group.spawn("late", |_| async { Ok(()) }).unwrap_err(),
        SpawnError::Closed
    );
    assert_eq!(
        group.join_next().await.unwrap().outcome,
        TaskOutcome::Failed(TaskFailure::Cancelled)
    );
    assert_eq!(count.load(Ordering::Relaxed), 0);
}
