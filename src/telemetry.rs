// SPDX-License-Identifier: GPL-3.0-only

//! Fixed-cardinality counters and RAII activity gauges. No user IDs, addresses,
//! credentials, payloads or free-form error messages are retained here.

use std::{
    fmt::Write,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Counter {
    TasksSpawned,
    TasksCompleted,
    TasksFailed,
    TasksPanicked,
    TasksAborted,
    TasksCancelled,
    TcpConnectAttempts,
    TcpConnectSucceeded,
    TcpUploadBytes,
    TcpDownloadBytes,
    TcpRelaysCompleted,
    UdpReceivedPackets,
    UdpReceivedBytes,
    UdpSentPackets,
    UdpSentBytes,
    UdpOversized,
    IoErrors,
    OperationTimeouts,
    OperationCancelled,
    BufferRejected,
    FramesDecoded,
    CodecRejected,
    InvalidInputs,
}
impl Counter {
    pub const ALL: [Self; 23] = [
        Self::TasksSpawned,
        Self::TasksCompleted,
        Self::TasksFailed,
        Self::TasksPanicked,
        Self::TasksAborted,
        Self::TasksCancelled,
        Self::TcpConnectAttempts,
        Self::TcpConnectSucceeded,
        Self::TcpUploadBytes,
        Self::TcpDownloadBytes,
        Self::TcpRelaysCompleted,
        Self::UdpReceivedPackets,
        Self::UdpReceivedBytes,
        Self::UdpSentPackets,
        Self::UdpSentBytes,
        Self::UdpOversized,
        Self::IoErrors,
        Self::OperationTimeouts,
        Self::OperationCancelled,
        Self::BufferRejected,
        Self::FramesDecoded,
        Self::CodecRejected,
        Self::InvalidInputs,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::TasksSpawned => "terraris_tasks_spawned_total",
            Self::TasksCompleted => "terraris_tasks_completed_total",
            Self::TasksFailed => "terraris_tasks_failed_total",
            Self::TasksPanicked => "terraris_tasks_panicked_total",
            Self::TasksAborted => "terraris_tasks_aborted_total",
            Self::TasksCancelled => "terraris_tasks_cancelled_total",
            Self::TcpConnectAttempts => "terraris_tcp_connect_attempts_total",
            Self::TcpConnectSucceeded => "terraris_tcp_connect_succeeded_total",
            Self::TcpUploadBytes => "terraris_tcp_upload_bytes_total",
            Self::TcpDownloadBytes => "terraris_tcp_download_bytes_total",
            Self::TcpRelaysCompleted => "terraris_tcp_relays_completed_total",
            Self::UdpReceivedPackets => "terraris_udp_received_packets_total",
            Self::UdpReceivedBytes => "terraris_udp_received_bytes_total",
            Self::UdpSentPackets => "terraris_udp_sent_packets_total",
            Self::UdpSentBytes => "terraris_udp_sent_bytes_total",
            Self::UdpOversized => "terraris_udp_oversized_total",
            Self::IoErrors => "terraris_io_errors_total",
            Self::OperationTimeouts => "terraris_operation_timeouts_total",
            Self::OperationCancelled => "terraris_operation_cancelled_total",
            Self::BufferRejected => "terraris_buffer_rejected_total",
            Self::FramesDecoded => "terraris_frames_decoded_total",
            Self::CodecRejected => "terraris_codec_rejected_total",
            Self::InvalidInputs => "terraris_invalid_inputs_total",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Gauge {
    ActiveTasks,
    ActiveRelays,
    ActiveTcpConnects,
    ActiveUdpReceives,
    ActiveUdpSends,
}
impl Gauge {
    pub const ALL: [Self; 5] = [
        Self::ActiveTasks,
        Self::ActiveRelays,
        Self::ActiveTcpConnects,
        Self::ActiveUdpReceives,
        Self::ActiveUdpSends,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::ActiveTasks => "terraris_active_tasks",
            Self::ActiveRelays => "terraris_active_relays",
            Self::ActiveTcpConnects => "terraris_active_tcp_connects",
            Self::ActiveUdpReceives => "terraris_active_udp_receives",
            Self::ActiveUdpSends => "terraris_active_udp_sends",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Upload,
    Download,
}

/// Optional product-side progress hook; invoked synchronously after each
/// accepted write, before the next await. Implementations must not block.
pub trait TransferObserver: Send + Sync {
    fn written(&self, direction: Direction, bytes: usize);
}

struct Inner {
    counters: [AtomicU64; Counter::ALL.len()],
    gauges: [AtomicU64; Gauge::ALL.len()],
}
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<Inner>,
}
impl Default for Metrics {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                counters: [const { AtomicU64::new(0) }; Counter::ALL.len()],
                gauges: [const { AtomicU64::new(0) }; Gauge::ALL.len()],
            }),
        }
    }
}
impl Metrics {
    /// Observability counters saturate; they are not an accounting ledger.
    pub fn add(&self, counter: Counter, value: u64) {
        let _ = self.inner.counters[counter as usize].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |old| Some(old.saturating_add(value)),
        );
    }
    pub fn increment(&self, counter: Counter) {
        self.add(counter, 1);
    }
    pub fn guard(&self, gauge: Gauge) -> GaugeGuard {
        self.inner.gauges[gauge as usize]
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("activity gauge overflow");
        GaugeGuard {
            inner: self.inner.clone(),
            gauge,
        }
    }
    /// Individual atomics are coherent; the aggregate is not a transaction.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            counters: std::array::from_fn(|i| self.inner.counters[i].load(Ordering::Relaxed)),
            gauges: std::array::from_fn(|i| self.inner.gauges[i].load(Ordering::Relaxed)),
        }
    }
}
impl Metrics {
    pub fn record_transfer(&self, direction: Direction, bytes: usize) {
        self.add(
            match direction {
                Direction::Upload => Counter::TcpUploadBytes,
                Direction::Download => Counter::TcpDownloadBytes,
            },
            bytes as u64,
        );
    }
}
impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.snapshot().fmt(f)
    }
}

#[must_use = "dropping the guard ends the activity"]
pub struct GaugeGuard {
    inner: Arc<Inner>,
    gauge: Gauge,
}
impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.inner.gauges[self.gauge as usize].fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    counters: [u64; Counter::ALL.len()],
    gauges: [u64; Gauge::ALL.len()],
}
impl Snapshot {
    pub fn counter(&self, counter: Counter) -> u64 {
        self.counters[counter as usize]
    }
    pub fn gauge(&self, gauge: Gauge) -> u64 {
        self.gauges[gauge as usize]
    }
    /// Rendering only; this module does not open an HTTP metrics listener.
    pub fn prometheus(&self) -> String {
        let mut text = String::new();
        for counter in Counter::ALL {
            let name = counter.name();
            writeln!(
                text,
                "# TYPE {name} counter\n{name} {}",
                self.counter(counter)
            )
            .expect("write to String");
        }
        for gauge in Gauge::ALL {
            let name = gauge.name();
            writeln!(text, "# TYPE {name} gauge\n{name} {}", self.gauge(gauge))
                .expect("write to String");
        }
        text
    }
}
