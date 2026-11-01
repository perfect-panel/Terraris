// SPDX-License-Identifier: GPL-3.0-only

use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use terraris::{
    buffer::BufferScope,
    dataplane::{DataPlane, IoOperation, TransferConfig, TransferFailure, TransferReport},
    network::connect_tcp,
    resource::{Budget, Limits},
    task::CancellationToken,
    telemetry::{Counter, Direction, Gauge, Metrics, TransferObserver},
    time::{Deadline, OperationContext, StopReason},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};

fn setup(idle: Option<Duration>) -> (Budget, BufferScope, Metrics, DataPlane) {
    let b = Budget::new(Limits::new(128, 8).unwrap());
    let s = BufferScope::new(b.root_scope(), 64).unwrap();
    let m = Metrics::default();
    let d = DataPlane::new(s.clone(), TransferConfig::new(8, idle).unwrap(), m.clone()).unwrap();
    (b, s, m, d)
}
fn control() -> OperationContext {
    OperationContext::new(CancellationToken::new(), None)
}
#[derive(Default)]
struct Written {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    shutdowns: usize,
}
struct TestWriter {
    state: Arc<Mutex<Written>>,
    step: usize,
    fail_after: Option<usize>,
    flush_error: bool,
    shutdown_error: bool,
    pending: bool,
}
impl TestWriter {
    fn new(step: usize) -> (Self, Arc<Mutex<Written>>) {
        let state = Arc::new(Mutex::new(Written::default()));
        (
            Self {
                state: state.clone(),
                step,
                fail_after: None,
                flush_error: false,
                shutdown_error: false,
                pending: false,
            },
            state,
        )
    }
}
impl AsyncWrite for TestWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.pending {
            return Poll::Pending;
        }
        let mut state = self.state.lock().unwrap();
        state.writes += 1;
        if self
            .fail_after
            .is_some_and(|limit| state.bytes.len() >= limit)
        {
            return Poll::Ready(Err(io::Error::other("SENSITIVE WRITE ERROR")));
        }
        let limit = self
            .fail_after
            .map_or(usize::MAX, |n| n - state.bytes.len());
        let count = self.step.min(bytes.len()).min(limit);
        state.bytes.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().flushes += 1;
        if self.flush_error {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "private flush",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.lock().unwrap().shutdowns += 1;
        if self.shutdown_error {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "private shutdown",
            )))
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
#[derive(Default)]
struct Observer {
    up: AtomicU64,
    down: AtomicU64,
}
impl TransferObserver for Observer {
    fn written(&self, direction: Direction, bytes: usize) {
        match direction {
            Direction::Upload => &self.up,
            Direction::Download => &self.down,
        }
        .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn short_writes_preserve_offsets_and_are_observed_once() {
    let (budget, _, metrics, plane) = setup(None);
    let observer = Arc::new(Observer::default());
    let plane = plane.with_observer(observer.clone());
    let (writer, state) = TestWriter::new(2);
    let report = plane
        .copy_stream(&b"abcdefghijk"[..], writer, Direction::Upload, &control())
        .await
        .unwrap();
    assert_eq!(
        report,
        TransferReport {
            upload: 11,
            download: 0
        }
    );
    let state = state.lock().unwrap();
    assert_eq!(state.bytes, b"abcdefghijk");
    assert_eq!(state.writes, 6);
    assert_eq!(state.flushes, 1);
    assert_eq!(state.shutdowns, 1);
    assert_eq!(observer.up.load(Ordering::Relaxed), 11);
    assert_eq!(metrics.snapshot().counter(Counter::TcpUploadBytes), 11);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[tokio::test]
async fn write_failure_keeps_accepted_prefix_counts_and_redacts_raw_error() {
    let (budget, _, metrics, plane) = setup(None);
    let (mut writer, state) = TestWriter::new(2);
    writer.fail_after = Some(3);
    let error = plane
        .copy_stream(&b"abcdefgh"[..], writer, Direction::Upload, &control())
        .await
        .unwrap_err();
    assert_eq!(error.progress.upload, 3);
    assert_eq!(state.lock().unwrap().bytes, b"abc");
    assert_eq!(metrics.snapshot().counter(Counter::TcpUploadBytes), 3);
    assert_eq!(metrics.snapshot().counter(Counter::IoErrors), 1);
    assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveRelays), 0);
}

#[tokio::test]
async fn write_zero_is_an_error_instead_of_a_busy_loop() {
    let (budget, _, metrics, plane) = setup(None);
    let (writer, state) = TestWriter::new(0);
    let error = plane
        .copy_stream(&b"x"[..], writer, Direction::Download, &control())
        .await
        .unwrap_err();
    assert_eq!(
        error.cause,
        TransferFailure::Io {
            operation: IoOperation::Write,
            kind: io::ErrorKind::WriteZero
        }
    );
    assert_eq!(state.lock().unwrap().writes, 1);
    assert_eq!(error.progress.download, 0);
    assert_eq!(metrics.snapshot().counter(Counter::TcpDownloadBytes), 0);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[tokio::test]
async fn flush_and_shutdown_failures_do_not_erase_successful_write_progress() {
    for fail_flush in [true, false] {
        let (budget, _, _, plane) = setup(None);
        let (mut writer, state) = TestWriter::new(8);
        writer.flush_error = fail_flush;
        writer.shutdown_error = !fail_flush;
        let error = plane
            .copy_stream(&b"data"[..], writer, Direction::Upload, &control())
            .await
            .unwrap_err();
        assert_eq!(error.progress.upload, 4);
        assert_eq!(
            error.cause,
            TransferFailure::Io {
                operation: if fail_flush {
                    IoOperation::Flush
                } else {
                    IoOperation::Shutdown
                },
                kind: io::ErrorKind::BrokenPipe
            }
        );
        let state = state.lock().unwrap();
        assert_eq!(state.flushes, 1);
        assert_eq!(state.shutdowns, usize::from(!fail_flush));
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn idle_timeout_stops_a_slow_writer_without_counting_unwritten_bytes() {
    let (budget, _, metrics, plane) = setup(Some(Duration::from_secs(2)));
    let (mut writer, state) = TestWriter::new(8);
    writer.pending = true;
    let error = plane
        .copy_stream(&b"data"[..], writer, Direction::Upload, &control())
        .await
        .unwrap_err();
    assert_eq!(error.cause, TransferFailure::IdleTimeout);
    assert_eq!(error.progress.upload, 0);
    assert!(state.lock().unwrap().bytes.is_empty());
    assert_eq!(metrics.snapshot().counter(Counter::OperationTimeouts), 1);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[tokio::test(start_paused = true)]
async fn absolute_deadline_applies_to_blocked_reads_and_writes() {
    let (budget, _, metrics, plane) = setup(Some(Duration::from_secs(30)));
    let (mut writer, _) = TestWriter::new(8);
    writer.pending = true;
    let context = OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(1)).unwrap()),
    );
    let error = plane
        .copy_stream(&b"data"[..], writer, Direction::Upload, &context)
        .await
        .unwrap_err();
    assert_eq!(
        error.cause,
        TransferFailure::Stopped(StopReason::DeadlineExceeded)
    );
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().counter(Counter::OperationTimeouts), 1);
}

#[tokio::test]
async fn cancellation_after_progress_preserves_counts_and_reclaims_the_buffer() {
    let (budget, _, metrics, plane) = setup(None);
    let (mut peer, stream) = tokio::io::duplex(16);
    let (writer, state) = TestWriter::new(2);
    let context = control();
    let owned = context.clone();
    let relay = tokio::spawn(async move {
        plane
            .copy_stream(stream, writer, Direction::Upload, &owned)
            .await
    });
    peer.write_all(b"abc").await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while metrics.snapshot().counter(Counter::TcpUploadBytes) != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    context.cancellation().cancel();
    let error = relay.await.unwrap().unwrap_err();
    assert_eq!(error.cause, TransferFailure::Stopped(StopReason::Cancelled));
    assert_eq!(error.progress.upload, 3);
    assert_eq!(state.lock().unwrap().bytes, b"abc");
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveRelays), 0);
}

#[tokio::test(start_paused = true)]
async fn opposite_direction_progress_keeps_a_quiet_half_alive_until_clean_shutdown() {
    let (budget, _, metrics, plane) = setup(Some(Duration::from_secs(1)));
    let (mut client_peer, client) = tokio::io::duplex(32);
    let (upstream, mut server_peer) = tokio::io::duplex(32);
    let context = control();
    let relay = tokio::spawn(async move { plane.relay_tcp(client, upstream, &context).await });
    for byte in b"abc" {
        server_peer.write_all(&[*byte]).await.unwrap();
        let mut received = [0];
        client_peer.read_exact(&mut received).await.unwrap();
        assert_eq!(received[0], *byte);
        tokio::time::advance(Duration::from_millis(750)).await;
    }
    assert!(!relay.is_finished());
    client_peer.shutdown().await.unwrap();
    server_peer.shutdown().await.unwrap();
    let report = relay.await.unwrap().unwrap();
    assert_eq!(
        report,
        TransferReport {
            upload: 0,
            download: 3
        }
    );
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().counter(Counter::TcpRelaysCompleted), 1);
}

struct ErrorStream;
impl AsyncRead for ErrorStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "private peer",
        )))
    }
}
impl AsyncWrite for ErrorStream {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn one_direction_error_stops_its_sibling_without_cancelling_the_parent() {
    let (budget, _, metrics, plane) = setup(None);
    let (client, _peer) = tokio::io::duplex(8);
    let context = control();
    let error = plane
        .relay_tcp(client, ErrorStream, &context)
        .await
        .unwrap_err();
    assert_eq!(
        error.cause,
        TransferFailure::Io {
            operation: IoOperation::Read,
            kind: io::ErrorKind::ConnectionReset
        }
    );
    assert!(context.check().is_ok());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().counter(Counter::IoErrors), 1);
    assert_eq!(metrics.snapshot().counter(Counter::OperationCancelled), 0);
}

struct SpyStream(Arc<AtomicUsize>);
impl AsyncRead for SpyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Poll::Pending
    }
}
impl AsyncWrite for SpyStream {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Poll::Pending
    }
}

#[tokio::test]
async fn duplex_budget_failure_happens_before_polling_either_transport() {
    let budget = Budget::new(Limits::new(8, 1).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 8).unwrap();
    let metrics = Metrics::default();
    let plane = DataPlane::new(
        scope,
        TransferConfig::new(8, None).unwrap(),
        metrics.clone(),
    )
    .unwrap();
    let polls = Arc::new(AtomicUsize::new(0));
    let error = plane
        .relay_tcp(
            SpyStream(polls.clone()),
            SpyStream(polls.clone()),
            &control(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error.cause, TransferFailure::Buffer(_)));
    assert_eq!(polls.load(Ordering::Relaxed), 0);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().counter(Counter::BufferRejected), 1);
}

#[tokio::test]
async fn aborting_the_relay_future_reclaims_both_directions_without_detached_tasks() {
    let (budget, _, metrics, plane) = setup(None);
    let (client, _client_peer) = tokio::io::duplex(8);
    let (upstream, _server_peer) = tokio::io::duplex(8);
    let context = control();
    let relay = tokio::spawn(async move { plane.relay_tcp(client, upstream, &context).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while budget.snapshot().resident().allocations() != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    relay.abort();
    assert!(relay.await.unwrap_err().is_cancelled());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveRelays), 0);
}

#[tokio::test]
async fn real_tcp_half_close_allows_the_server_response_to_flow_back() {
    let (budget, _, metrics, plane) = setup(None);
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let back = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(front.local_addr().unwrap())
        .await
        .unwrap();
    let (inbound, _) = front.accept().await.unwrap();
    let context = OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(5)).unwrap()),
    );
    let upstream = connect_tcp(back.local_addr().unwrap(), &context, &metrics)
        .await
        .unwrap();
    let (mut server, _) = back.accept().await.unwrap();
    let relay = tokio::spawn(async move { plane.relay_tcp(inbound, upstream, &context).await });
    let data = vec![42u8; 4096];
    client.write_all(&data).await.unwrap();
    client.shutdown().await.unwrap();
    let mut received = Vec::new();
    server.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, data);
    server.write_all(b"reply").await.unwrap();
    server.shutdown().await.unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"reply");
    assert_eq!(
        relay.await.unwrap().unwrap(),
        TransferReport {
            upload: 4096,
            download: 5
        }
    );
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().counter(Counter::TcpConnectSucceeded), 1);
}

#[test]
fn invalid_transfer_configuration_is_rejected() {
    assert!(TransferConfig::new(0, None).is_err());
    assert!(TransferConfig::new(1, Some(Duration::ZERO)).is_err());
    assert!(TransferConfig::new(1, Some(Duration::MAX)).is_err());
    let (_, scope, metrics, _) = setup(None);
    assert!(DataPlane::new(scope, TransferConfig::new(65, None).unwrap(), metrics).is_err());
}

#[tokio::test]
async fn precancelled_relay_neither_allocates_buffers_nor_polls_transport() {
    let (budget, _, metrics, plane) = setup(None);
    let context = control();
    context.cancellation().cancel();
    let polls = Arc::new(AtomicUsize::new(0));
    let error = plane
        .relay_tcp(SpyStream(polls.clone()), SpyStream(polls.clone()), &context)
        .await
        .unwrap_err();
    assert_eq!(error.cause, TransferFailure::Stopped(StopReason::Cancelled));
    assert_eq!(polls.load(Ordering::Relaxed), 0);
    assert_eq!(budget.snapshot().used().allocations(), 0);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveRelays), 0);
}
