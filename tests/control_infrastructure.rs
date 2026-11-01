// SPDX-License-Identifier: GPL-3.0-only

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use terraris::{
    panel::{SubscriptionId, Traffic},
    reports::{self, Reports},
    scheduler::{self, JobFailure, JobSpec, Lane, Limits, Schedule, Scheduler},
    task::CancellationToken,
    time::{Deadline, OperationContext, Revocation, StopReason},
};
use tokio::{sync::Notify, time::Instant};
fn id(value: i64) -> SubscriptionId {
    SubscriptionId::new(value).unwrap()
}
fn schedule(interval: u64, timeout: u64) -> Schedule {
    Schedule::new(
        Duration::from_secs(interval),
        Duration::from_secs(timeout),
        Duration::from_secs(interval * 8),
    )
    .unwrap()
}
async fn tick() {
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
}
struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn critical_reserve_runs_renewal_while_normal_jobs_are_blocked() {
    let normal = Arc::new(AtomicUsize::new(0));
    let critical = Arc::new(AtomicUsize::new(0));
    let mut jobs = vec![];
    for index in 0..3 {
        let active = normal.clone();
        jobs.push(JobSpec::new(
            format!("normal-{index}"),
            Lane::Normal,
            schedule(1, 100),
            scheduler::job(move |_| {
                let active = active.clone();
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _guard = Active(active);
                    std::future::pending::<()>().await;
                    Ok(())
                }
            }),
        ));
    }
    let active = critical.clone();
    jobs.push(JobSpec::new(
        "renew",
        Lane::Critical,
        schedule(1, 100),
        scheduler::job(move |_| {
            let active = active.clone();
            async move {
                active.fetch_add(1, Ordering::SeqCst);
                let _guard = Active(active);
                std::future::pending::<()>().await;
                Ok(())
            }
        }),
    ));
    let scheduler = Arc::new(
        Scheduler::new(
            Limits {
                max_jobs: 4,
                concurrency: 2,
                critical_reserve: 1,
            },
            jobs,
        )
        .unwrap(),
    );
    let token = CancellationToken::new();
    let context = OperationContext::new(token.clone(), None);
    let owned = scheduler.clone();
    let run = tokio::spawn(async move { owned.run(&context).await });
    tick().await;
    assert_eq!(normal.load(Ordering::SeqCst), 1);
    assert_eq!(critical.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(10)).await;
    tick().await;
    assert_eq!(normal.load(Ordering::SeqCst), 1);
    token.cancel();
    run.await.unwrap().unwrap();
    assert_eq!(normal.load(Ordering::SeqCst), 0);
    assert_eq!(critical.load(Ordering::SeqCst), 0);
    assert!(!scheduler.is_running());
    assert!(scheduler.snapshot().iter().all(|j| !j.running));
}
#[tokio::test(start_paused = true)]
async fn per_job_backoff_is_independent_and_success_resets_it() {
    let calls = Arc::new(AtomicUsize::new(0));
    let healthy = Arc::new(AtomicUsize::new(0));
    let value = calls.clone();
    let failure = JobSpec::new(
        "flaky",
        Lane::Normal,
        schedule(1, 10),
        scheduler::job(move |_| {
            let value = value.clone();
            async move {
                let n = value.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err(JobFailure::Failed("fixture"))
                } else {
                    Ok(())
                }
            }
        }),
    );
    let value = healthy.clone();
    let healthy_job = JobSpec::new(
        "healthy",
        Lane::Critical,
        schedule(1, 10),
        scheduler::job(move |_| {
            let value = value.clone();
            async move {
                value.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }),
    );
    let scheduler = Arc::new(
        Scheduler::new(
            Limits {
                max_jobs: 2,
                concurrency: 2,
                critical_reserve: 1,
            },
            vec![failure, healthy_job],
        )
        .unwrap(),
    );
    let owned = scheduler.clone();
    let cancel = CancellationToken::new();
    let context = OperationContext::new(cancel.clone(), None);
    let run = tokio::spawn(async move { owned.run(&context).await });
    tick().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(1)).await;
    tick().await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(healthy.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    tick().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(3)).await;
    tick().await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    tick().await;
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(scheduler.snapshot()[0].failures, 0);
    tokio::time::advance(Duration::from_secs(1)).await;
    tick().await;
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    cancel.cancel();
    run.await.unwrap().unwrap();
}
#[tokio::test(start_paused = true)]
async fn timeouts_and_panics_are_observed_and_one_job_never_overlaps() {
    let active = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(Notify::new());
    let value = active.clone();
    let signal = started.clone();
    let hung = JobSpec::new(
        "hung",
        Lane::Normal,
        schedule(1, 2),
        scheduler::job(move |_| {
            let value = value.clone();
            let signal = signal.clone();
            async move {
                assert_eq!(value.fetch_add(1, Ordering::SeqCst), 0);
                let _guard = Active(value);
                signal.notify_one();
                std::future::pending::<()>().await;
                Ok(())
            }
        }),
    );
    let panic = JobSpec::new(
        "panic",
        Lane::Critical,
        schedule(1, 2),
        scheduler::job(|_| async { panic!("synthetic job failure") }),
    );
    let scheduler = Arc::new(
        Scheduler::new(
            Limits {
                max_jobs: 2,
                concurrency: 2,
                critical_reserve: 1,
            },
            vec![hung, panic],
        )
        .unwrap(),
    );
    let owned = scheduler.clone();
    let cancel = CancellationToken::new();
    let context = OperationContext::new(cancel.clone(), None);
    let run = tokio::spawn(async move { owned.run(&context).await });
    started.notified().await;
    tick().await;
    assert!(matches!(
        scheduler
            .run(&OperationContext::new(CancellationToken::new(), None))
            .await,
        Err(scheduler::Error::AlreadyRunning)
    ));
    tokio::time::advance(Duration::from_secs(2)).await;
    tick().await;
    let snapshots = scheduler.snapshot();
    assert_eq!(
        snapshots[0].last,
        Some(Err(JobFailure::Stopped(StopReason::DeadlineExceeded)))
    );
    assert_eq!(snapshots[1].last, Some(Err(JobFailure::Panicked)));
    assert_eq!(active.load(Ordering::SeqCst), 0);
    tokio::time::advance(Duration::from_secs(2)).await;
    started.notified().await;
    assert_eq!(active.load(Ordering::SeqCst), 1);
    cancel.cancel();
    run.await.unwrap().unwrap();
    assert_eq!(active.load(Ordering::SeqCst), 0);
}
#[tokio::test(start_paused = true)]
async fn aborting_scheduler_future_drops_inflight_work_and_allows_restart() {
    let active = Arc::new(AtomicUsize::new(0));
    let value = active.clone();
    let job = JobSpec::new(
        "job",
        Lane::Normal,
        schedule(1, 100),
        scheduler::job(move |_| {
            let value = value.clone();
            async move {
                value.fetch_add(1, Ordering::SeqCst);
                let _guard = Active(value);
                std::future::pending::<()>().await;
                Ok(())
            }
        }),
    );
    let scheduler = Arc::new(
        Scheduler::new(
            Limits {
                max_jobs: 1,
                concurrency: 1,
                critical_reserve: 0,
            },
            vec![job],
        )
        .unwrap(),
    );
    let owned = scheduler.clone();
    let run = tokio::spawn(async move {
        owned
            .run(&OperationContext::new(CancellationToken::new(), None))
            .await
    });
    tick().await;
    assert_eq!(active.load(Ordering::SeqCst), 1);
    run.abort();
    assert!(run.await.unwrap_err().is_cancelled());
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert!(!scheduler.is_running());
    let context =
        OperationContext::new(CancellationToken::new(), Some(Deadline::at(Instant::now())));
    scheduler.run(&context).await.unwrap();
}
#[test]
fn scheduler_rejects_unbounded_or_ambiguous_plans() {
    let limits = Limits {
        max_jobs: 2,
        concurrency: 2,
        critical_reserve: 1,
    };
    let make = |name| {
        JobSpec::new(
            name,
            Lane::Normal,
            schedule(1, 1),
            scheduler::job(|_| async { Ok(()) }),
        )
    };
    assert!(Scheduler::new(limits, vec![make("a"), make("a")]).is_err());
    assert!(Scheduler::new(limits, vec![make("secret with spaces")]).is_err());
    assert!(Scheduler::new(limits, vec![make("a"), make("b"), make("c")]).is_err());
    assert!(
        Schedule::new(
            Duration::ZERO,
            Duration::from_secs(1),
            Duration::from_secs(1)
        )
        .is_err()
    );
}
#[test]
fn traffic_ack_preserves_concurrent_delta_and_cancelled_batches() {
    let reports = Reports::new(2).unwrap();
    reports
        .record_traffic(Traffic {
            id: id(1),
            upload: 10,
            download: 20,
        })
        .unwrap();
    let batch = reports.traffic_batch(0, 10).unwrap().unwrap();
    assert!(matches!(
        reports.traffic_batch(0, 10),
        Err(reports::Error::Busy)
    ));
    reports
        .record_traffic(Traffic {
            id: id(1),
            upload: 2,
            download: 3,
        })
        .unwrap();
    drop(batch);
    assert_eq!(reports.snapshot().pending_bytes, 35);
    let batch = reports.traffic_batch(0, 10).unwrap().unwrap();
    reports
        .record_traffic(Traffic {
            id: id(1),
            upload: 4,
            download: 5,
        })
        .unwrap();
    batch.acknowledge();
    assert_eq!(reports.snapshot().pending_bytes, 9);
    let batch = reports.traffic_batch(0, 10).unwrap().unwrap();
    assert_eq!(
        batch.values(),
        &[Traffic {
            id: id(1),
            upload: 4,
            download: 5
        }]
    );
    batch.acknowledge();
    assert_eq!(reports.snapshot().pending_bytes, 0);
}
#[test]
fn bounded_traffic_chunks_rotate_fairly_and_never_saturate_billable_bytes() {
    let reports = Reports::new(2).unwrap();
    reports
        .record_traffic(Traffic {
            id: id(1),
            upload: u64::MAX,
            download: u64::MAX,
        })
        .unwrap();
    assert!(matches!(
        reports.record_traffic(Traffic {
            id: id(1),
            upload: 1,
            download: 0
        }),
        Err(reports::Error::Overflow)
    ));
    reports
        .record_traffic(Traffic {
            id: id(2),
            upload: 1,
            download: 1,
        })
        .unwrap();
    assert!(matches!(
        reports.record_traffic(Traffic {
            id: id(3),
            upload: 1,
            download: 0
        }),
        Err(reports::Error::Full)
    ));
    let batch = reports.traffic_batch(0, 1).unwrap().unwrap();
    assert_eq!(batch.values()[0].upload, 10 << 40);
    assert_eq!(batch.values()[0].download, 0);
    batch.acknowledge();
    let batch = reports.traffic_batch(0, 1).unwrap().unwrap();
    assert_eq!(batch.values()[0].id, id(2));
    batch.acknowledge();
    assert_eq!(reports.snapshot().traffic_users, 1);
}
#[test]
fn online_ack_keeps_new_short_sessions_and_stops_renewing_finished_ones() {
    let reports = Reports::new(2).unwrap();
    let ip = "127.0.0.1".parse().unwrap();
    let lease = reports.online(id(1), ip).unwrap();
    drop(lease);
    let mut batch = reports.online_batch().unwrap().unwrap();
    let second = reports
        .online(id(1), "::ffff:127.0.0.1".parse().unwrap())
        .unwrap();
    drop(second);
    batch.acknowledge_chunk(1);
    drop(batch);
    assert_eq!(reports.snapshot().online_ips, 1);
    let mut batch = reports.online_batch().unwrap().unwrap();
    assert_eq!(
        batch.next_chunk(1),
        vec![terraris::panel::OnlineUser { id: id(1), ip }]
    );
    batch.acknowledge_chunk(1);
    drop(batch);
    assert_eq!(reports.snapshot().online_ips, 0);
    let active = reports.online(id(1), ip).unwrap();
    let mut batch = reports.online_batch().unwrap().unwrap();
    batch.acknowledge_chunk(1);
    drop(batch);
    assert!(reports.online_batch().unwrap().is_some());
    drop(active);
    assert!(reports.online_batch().unwrap().is_none());
}
#[test]
fn partial_online_and_traffic_ack_only_removes_confirmed_prefix() {
    let reports = Reports::new(4).unwrap();
    for n in 1..=3 {
        reports
            .record_traffic(Traffic {
                id: id(n),
                upload: 10,
                download: 0,
            })
            .unwrap();
        drop(reports.online(id(n), "127.0.0.1".parse().unwrap()).unwrap());
    }
    let mut traffic = reports.traffic_batch(0, 3).unwrap().unwrap();
    traffic.acknowledge_chunk(1);
    drop(traffic);
    assert_eq!(reports.snapshot().pending_bytes, 20);
    let mut online = reports.online_batch().unwrap().unwrap();
    online.acknowledge_chunk(1);
    drop(online);
    assert_eq!(reports.snapshot().online_ips, 2);
}
#[tokio::test]
async fn revocation_interrupts_inflight_operation_and_propagates_to_children() {
    let signal = Revocation::default();
    let context = OperationContext::new(CancellationToken::new(), None)
        .with_revocation(signal.clone())
        .unwrap();
    assert!(
        context
            .clone()
            .with_revocation(Revocation::default())
            .is_err()
    );
    let child = context.child();
    let ready = Arc::new(Notify::new());
    let started = ready.clone();
    let pending = tokio::spawn(async move {
        started.notify_one();
        child.run(std::future::pending::<()>()).await
    });
    ready.notified().await;
    signal.revoke();
    assert_eq!(pending.await.unwrap(), Err(StopReason::Cancelled));
    assert_eq!(context.check(), Err(StopReason::Cancelled));
}

#[test]
fn counter_reservations_keep_slots_across_ack_and_refund_cancelled_writes() {
    let reports = Reports::new(1).unwrap();
    let lease = reports.traffic_lease(id(1)).unwrap();
    let mut write = lease.reserve(true, 100).unwrap();
    write.commit(30);
    let batch = reports.traffic_batch(0, 1).unwrap().unwrap();
    assert_eq!(batch.values()[0].upload, 30);
    drop(lease);
    batch.acknowledge();
    assert!(matches!(
        reports.traffic_lease(id(2)),
        Err(reports::Error::Full)
    ));
    drop(write);
    assert_eq!(reports.snapshot().traffic_users, 0);
    let lease = reports.traffic_lease(id(1)).unwrap();
    let empty = lease.reserve(false, 0).unwrap();
    drop(lease);
    drop(empty);
    assert_eq!(reports.snapshot().traffic_users, 0);
}
#[test]
fn reserved_counter_headroom_cannot_be_consumed_by_concurrent_direct_recording() {
    let reports = Reports::new(1).unwrap();
    let lease = reports.traffic_lease(id(1)).unwrap();
    let mut reserved = lease.reserve(true, u64::MAX).unwrap();
    assert!(matches!(
        reports.record_traffic(Traffic {
            id: id(1),
            upload: 1,
            download: 0
        }),
        Err(reports::Error::Overflow)
    ));
    assert!(matches!(
        lease.reserve(true, 1),
        Err(reports::Error::Overflow)
    ));
    reserved.commit(5);
    drop(reserved);
    assert_eq!(reports.snapshot().pending_bytes, 5);
    reports
        .record_traffic(Traffic {
            id: id(1),
            upload: 2,
            download: 0,
        })
        .unwrap();
    assert_eq!(reports.snapshot().pending_bytes, 7);
}
