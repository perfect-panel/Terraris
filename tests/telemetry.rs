// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::HashSet,
    sync::{Arc, Barrier},
    thread,
};
use terraris::telemetry::{Counter, Direction, Gauge, Metrics};

#[test]
fn counters_saturate_and_render_fixed_unique_names_without_labels() {
    let metrics = Metrics::default();
    metrics.add(Counter::TcpUploadBytes, u64::MAX);
    metrics.record_transfer(Direction::Upload, 1);
    assert_eq!(
        metrics.snapshot().counter(Counter::TcpUploadBytes),
        u64::MAX
    );
    let rendered = metrics.snapshot().prometheus();
    assert!(rendered.contains("terraris_tcp_upload_bytes_total 18446744073709551615"));
    assert!(!rendered.contains('{'));
    let mut names = HashSet::new();
    for counter in Counter::ALL {
        assert!(names.insert(counter.name()));
    }
    for gauge in Gauge::ALL {
        assert!(names.insert(gauge.name()));
    }
    assert_eq!(
        rendered
            .lines()
            .filter(|line| !line.starts_with('#'))
            .count(),
        names.len()
    );
}

#[test]
fn gauges_follow_owned_activity_across_threads() {
    let metrics = Metrics::default();
    let barrier = Arc::new(Barrier::new(9));
    let release = Arc::new(Barrier::new(9));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (m, b, r) = (metrics.clone(), barrier.clone(), release.clone());
            thread::spawn(move || {
                let _guard = m.guard(Gauge::ActiveTasks);
                m.increment(Counter::TasksSpawned);
                b.wait();
                r.wait();
            })
        })
        .collect();
    barrier.wait();
    let observed = metrics.snapshot();
    release.wait();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(observed.gauge(Gauge::ActiveTasks), 8);
    assert_eq!(observed.counter(Counter::TasksSpawned), 8);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveTasks), 0);
}

#[test]
fn concurrent_counter_additions_and_unwind_do_not_lose_counts_or_gauges() {
    let metrics = Metrics::default();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let m = metrics.clone();
            thread::spawn(move || {
                for _ in 0..1000 {
                    m.record_transfer(Direction::Download, 3);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(metrics.snapshot().counter(Counter::TcpDownloadBytes), 24000);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = metrics.guard(Gauge::ActiveRelays);
        panic!("synthetic activity unwind");
    }));
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveRelays), 0);
}
