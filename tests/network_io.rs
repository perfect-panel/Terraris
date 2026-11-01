// SPDX-License-Identifier: GPL-3.0-only

use std::{
    future::Future,
    io,
    net::{SocketAddr, SocketAddrV6},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use terraris::{
    buffer::BufferScope,
    network::{
        Address, AddressError, DatagramEndpoint, DatagramTransport, DomainName, Error,
        FlowMetadata, Network, canonical_socket, connect_tcp,
    },
    resource::{Budget, Limits},
    task::CancellationToken,
    telemetry::{Counter, Gauge, Metrics},
    time::{Deadline, OperationContext, StopReason},
};
use tokio::{
    io::ReadBuf,
    net::{TcpListener, UdpSocket},
};

fn setup(max: usize) -> (Budget, BufferScope) {
    let b = Budget::new(Limits::new(max * 4, 8).unwrap());
    let s = BufferScope::new(b.root_scope(), max).unwrap();
    (b, s)
}
fn control() -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(3)).unwrap()),
    )
}
fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn metadata_preserves_unresolved_domains_and_canonicalizes_only_safe_ip_mappings() {
    let destination: Address = "EXAMPLE.com.:443".parse().unwrap();
    assert_eq!(destination.domain_name().unwrap().as_str(), "example.com.");
    assert_eq!(destination.port(), 443);
    assert!(destination.socket_addr().is_none());
    let metadata = FlowMetadata::new(
        Network::Tcp,
        "[::ffff:127.0.0.1]:1234".parse().unwrap(),
        destination,
    );
    assert_eq!(metadata.source, "127.0.0.1:1234".parse().unwrap());
    let scoped = SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 443, 7, 12));
    assert_eq!(
        Address::from_socket(scoped).unwrap().socket_addr(),
        Some(scoped)
    );
    let mapped_scoped = SocketAddr::V6(SocketAddrV6::new(
        "::ffff:127.0.0.1".parse().unwrap(),
        443,
        0,
        2,
    ));
    assert_eq!(canonical_socket(mapped_scoped), mapped_scoped);
    assert!(
        "[::1]:443"
            .parse::<Address>()
            .unwrap()
            .domain_name()
            .is_none()
    );
}

#[test]
fn invalid_hostnames_authorities_and_ports_are_rejected_without_echoing_input() {
    for name in [
        "",
        ".",
        "a..b",
        "-bad.example",
        "bad-.example",
        "secret@host",
        "private\nvalue",
        "中文.example",
    ] {
        let error = DomainName::new(name).unwrap_err();
        assert!(!format!("{error} {error:?}").contains(name) || name.is_empty() || name == ".");
    }
    assert!(DomainName::new(&format!("{}.example", "a".repeat(64))).is_err());
    let name = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(name.len(), 253);
    assert!(DomainName::new(&name).is_ok());
    assert!(DomainName::new(&(name + "x")).is_err());
    for address in [
        "example.com",
        "example.com:0",
        "example.com:65536",
        "http://host:80",
        "::1:443",
        "user:password@host:443",
    ] {
        assert!(address.parse::<Address>().is_err());
    }
    assert_eq!(
        Address::from_socket("127.0.0.1:0".parse().unwrap()).unwrap_err(),
        AddressError::ZeroPort
    );
}

#[tokio::test]
async fn tcp_connect_uses_explicit_socket_addresses_and_records_outcomes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics = Metrics::default();
    let stream = connect_tcp(listener.local_addr().unwrap(), &control(), &metrics)
        .await
        .unwrap();
    let (peer, _) = listener.accept().await.unwrap();
    assert_eq!(stream.peer_addr().unwrap(), listener.local_addr().unwrap());
    drop(stream);
    drop(peer);
    assert_eq!(metrics.snapshot().counter(Counter::TcpConnectSucceeded), 1);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveTcpConnects), 0);
    let cancelled = control();
    cancelled.cancellation().cancel();
    assert!(matches!(
        connect_tcp(listener.local_addr().unwrap(), &cancelled, &metrics).await,
        Err(Error::Stopped(StopReason::Cancelled))
    ));
    assert_eq!(metrics.snapshot().counter(Counter::TcpConnectSucceeded), 1);
    assert_eq!(metrics.snapshot().counter(Counter::OperationCancelled), 1);
    assert!(
        connect_tcp("127.0.0.1:0".parse().unwrap(), &control(), &metrics)
            .await
            .is_err()
    );
    assert_eq!(metrics.snapshot().counter(Counter::InvalidInputs), 1);
}

#[tokio::test]
async fn udp_preserves_packet_boundaries_empty_packets_and_source_metadata() {
    let (budget, scope) = setup(64);
    let metrics = Metrics::default();
    let endpoint = DatagramEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        scope,
        16,
        metrics.clone(),
        &control(),
    )
    .await
    .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for payload in [&b"abcdefghijklmnop"[..], &b""[..], &b"two"[..]] {
        peer.send_to(payload, endpoint.local_addr()).await.unwrap();
        let packet = endpoint.recv(&control()).await.unwrap();
        assert_eq!(packet.payload.as_slice(), payload);
        assert_eq!(packet.source, peer.local_addr().unwrap());
        assert_eq!(packet.local_addr, endpoint.local_addr());
        assert_eq!(budget.snapshot().resident().bytes(), 17);
        drop(packet);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    endpoint
        .send_to(peer.local_addr().unwrap(), b"reply", &control())
        .await
        .unwrap();
    let mut bytes = [0u8; 32];
    let (n, source) = peer.recv_from(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..n], b"reply");
    assert_eq!(source, endpoint.local_addr());
    endpoint
        .send_to(peer.local_addr().unwrap(), b"", &control())
        .await
        .unwrap();
    assert_eq!(peer.recv_from(&mut bytes).await.unwrap().0, 0);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.counter(Counter::UdpReceivedPackets), 3);
    assert_eq!(snapshot.counter(Counter::UdpReceivedBytes), 19);
    assert_eq!(snapshot.counter(Counter::UdpSentPackets), 2);
    assert_eq!(snapshot.counter(Counter::UdpSentBytes), 5);
    assert_eq!(snapshot.gauge(Gauge::ActiveUdpReceives), 0);
}

#[tokio::test]
async fn guard_byte_rejects_truncation_and_the_next_datagram_remains_usable() {
    let (budget, scope) = setup(64);
    let metrics = Metrics::default();
    let endpoint = DatagramEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        scope,
        8,
        metrics.clone(),
        &control(),
    )
    .await
    .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    peer.send_to(&[42; 1024], endpoint.local_addr())
        .await
        .unwrap();
    assert_eq!(
        endpoint.recv(&control()).await.unwrap_err(),
        Error::DatagramTooLarge {
            limit: 8,
            observed_at_least: 9
        }
    );
    assert_eq!(budget.snapshot().used().bytes(), 0);
    peer.send_to(b"ok", endpoint.local_addr()).await.unwrap();
    assert_eq!(
        endpoint.recv(&control()).await.unwrap().payload.as_slice(),
        b"ok"
    );
    assert_eq!(metrics.snapshot().counter(Counter::UdpOversized), 1);
    assert_eq!(metrics.snapshot().counter(Counter::UdpReceivedPackets), 1);
    assert_eq!(metrics.snapshot().counter(Counter::UdpReceivedBytes), 2);
}

#[tokio::test]
async fn large_datagram_and_zero_only_endpoint_use_budgeted_storage() {
    // 8 KiB crosses common MTUs while fitting macOS's default 9216-byte UDP
    // send limit. The full adapter ceiling is tested with a transport fixture.
    let (budget, scope) = setup(32768);
    let metrics = Metrics::default();
    let endpoint = DatagramEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        scope,
        8192,
        metrics,
        &control(),
    )
    .await
    .unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let payload = vec![17; 8192];
    peer.send_to(&payload, endpoint.local_addr()).await.unwrap();
    let packet = endpoint.recv(&control()).await.unwrap();
    assert_eq!(packet.payload.as_slice(), payload);
    drop(packet);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    let (_, scope) = setup(8);
    let zero = DatagramEndpoint::bind(
        "127.0.0.1:0".parse().unwrap(),
        scope,
        0,
        Metrics::default(),
        &control(),
    )
    .await
    .unwrap();
    peer.send_to(b"", zero.local_addr()).await.unwrap();
    assert!(zero.recv(&control()).await.unwrap().payload.is_empty());
    peer.send_to(b"x", zero.local_addr()).await.unwrap();
    assert!(matches!(
        zero.recv(&control()).await,
        Err(Error::DatagramTooLarge { .. })
    ));
}

struct MockTransport {
    recv_calls: Arc<AtomicUsize>,
    send_calls: Arc<AtomicUsize>,
    read_error: bool,
    partial_send: bool,
}
impl DatagramTransport for MockTransport {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:12345".parse().unwrap())
    }
    fn poll_recv_from(
        &self,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        self.recv_calls.fetch_add(1, Ordering::Relaxed);
        if self.read_error {
            Poll::Ready(Err(io::Error::other("SENSITIVE RAW MESSAGE")))
        } else {
            Poll::Pending
        }
    }
    fn poll_send_to(
        &self,
        _: &mut Context<'_>,
        buffer: &[u8],
        _: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.send_calls.fetch_add(1, Ordering::Relaxed);
        if self.partial_send {
            Poll::Ready(Ok(buffer.len().saturating_sub(1)))
        } else {
            Poll::Pending
        }
    }
}
fn mock(
    read_error: bool,
    partial_send: bool,
) -> (MockTransport, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let r = Arc::new(AtomicUsize::new(0));
    let s = Arc::new(AtomicUsize::new(0));
    (
        MockTransport {
            recv_calls: r.clone(),
            send_calls: s.clone(),
            read_error,
            partial_send,
        },
        r,
        s,
    )
}

#[tokio::test(start_paused = true)]
async fn udp_timeout_and_cancellation_reclaim_receive_buffers() {
    let (budget, scope) = setup(64);
    let metrics = Metrics::default();
    let (socket, _, _) = mock(false, false);
    let endpoint = DatagramEndpoint::new(socket, scope, 8, metrics.clone()).unwrap();
    let timed = OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(1)).unwrap()),
    );
    assert_eq!(
        endpoint.recv(&timed).await.unwrap_err(),
        Error::Stopped(StopReason::DeadlineExceeded)
    );
    assert_eq!(budget.snapshot().used().bytes(), 0);
    let cancelled = OperationContext::new(CancellationToken::new(), None);
    let mut recv = Box::pin(endpoint.recv(&cancelled));
    assert!(poll_once(recv.as_mut()).is_pending());
    assert_eq!(budget.snapshot().resident().bytes(), 9);
    cancelled.cancellation().cancel();
    assert_eq!(
        recv.await.unwrap_err(),
        Error::Stopped(StopReason::Cancelled)
    );
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(metrics.snapshot().counter(Counter::OperationTimeouts), 1);
    assert_eq!(metrics.snapshot().counter(Counter::OperationCancelled), 1);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveUdpReceives), 0);
}

#[tokio::test(start_paused = true)]
async fn shared_udp_receive_gate_prevents_overlapping_poll_owners() {
    let (budget, scope) = setup(64);
    let (socket, calls, _) = mock(false, false);
    let endpoint = DatagramEndpoint::new(socket, scope, 8, Metrics::default()).unwrap();
    let other = endpoint.clone();
    let context = OperationContext::new(CancellationToken::new(), None);
    let mut first = Box::pin(endpoint.recv(&context));
    let mut second = Box::pin(other.recv(&context));
    assert!(poll_once(first.as_mut()).is_pending());
    assert!(poll_once(second.as_mut()).is_pending());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(budget.snapshot().resident().allocations(), 1);
    drop(first);
    assert!(poll_once(second.as_mut()).is_pending());
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert_eq!(budget.snapshot().resident().allocations(), 1);
    drop(second);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[tokio::test]
async fn partial_udp_send_is_not_retried_or_counted_as_a_successful_packet() {
    let (_, scope) = setup(64);
    let metrics = Metrics::default();
    let (socket, _, calls) = mock(false, true);
    let endpoint = DatagramEndpoint::new(socket, scope, 8, metrics.clone()).unwrap();
    assert_eq!(
        endpoint
            .send_to("127.0.0.1:9".parse().unwrap(), b"data", &control())
            .await
            .unwrap_err(),
        Error::PartialDatagram {
            expected: 4,
            written: 3
        }
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.snapshot().counter(Counter::UdpSentPackets), 0);
    assert_eq!(metrics.snapshot().counter(Counter::UdpSentBytes), 0);
    assert!(
        endpoint
            .send_to("127.0.0.1:9".parse().unwrap(), &[1; 9], &control())
            .await
            .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveUdpSends), 0);
}

#[tokio::test]
async fn transport_errors_do_not_retain_original_messages_or_receive_capacity() {
    let (budget, scope) = setup(64);
    let (socket, _, _) = mock(true, false);
    let endpoint = DatagramEndpoint::new(socket, scope, 8, Metrics::default()).unwrap();
    let error = endpoint.recv(&control()).await.unwrap_err();
    assert!(!format!("{error} {error:?}").contains("SENSITIVE"));
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn maximum_and_guard_byte_must_fit_configuration() {
    let (_, scope) = setup(8);
    for max in [8, usize::MAX, 65536] {
        let (socket, _, _) = mock(false, false);
        assert!(matches!(
            DatagramEndpoint::new(socket, scope.clone(), max, Metrics::default()),
            Err(Error::InvalidDatagramLimit)
        ));
    }
    let native: SocketAddr = "[::1]:9".parse().unwrap();
    assert_eq!(canonical_socket(native), native);
}

#[tokio::test]
async fn maximum_receive_boundary_is_checked_independently_of_host_udp_send_limits() {
    struct FilledTransport(Vec<u8>);
    impl DatagramTransport for FilledTransport {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:9999".parse().unwrap())
        }
        fn poll_recv_from(
            &self,
            _: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<SocketAddr>> {
            let count = buffer.remaining().min(self.0.len());
            buffer.put_slice(&self.0[..count]);
            Poll::Ready(Ok("127.0.0.1:8888".parse().unwrap()))
        }
        fn poll_send_to(
            &self,
            _: &mut Context<'_>,
            _: &[u8],
            _: SocketAddr,
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }
    }
    for length in [65535, 65536, 65552] {
        let (budget, scope) = setup(65536);
        let endpoint = DatagramEndpoint::new(
            FilledTransport(vec![7; length]),
            scope,
            65535,
            Metrics::default(),
        )
        .unwrap();
        let result = endpoint.recv(&control()).await;
        if length == 65535 {
            let packet = result.unwrap();
            assert_eq!(packet.payload.len(), 65535);
            assert!(packet.payload.as_slice().iter().all(|&n| n == 7));
            assert_eq!(budget.snapshot().resident().bytes(), 65536);
            drop(packet);
        } else {
            assert_eq!(
                result.unwrap_err(),
                Error::DatagramTooLarge {
                    limit: 65535,
                    observed_at_least: 65536
                }
            );
        }
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn udp_send_gate_waits_are_deadlined_and_cancellable_without_extra_polls() {
    let (_, scope) = setup(64);
    let metrics = Metrics::default();
    let (socket, _, calls) = mock(false, false);
    let endpoint = DatagramEndpoint::new(socket, scope, 8, metrics.clone()).unwrap();
    let target = "127.0.0.1:9".parse().unwrap();
    let first_context = OperationContext::new(CancellationToken::new(), None);
    let mut first = Box::pin(endpoint.send_to(target, b"data", &first_context));
    assert!(poll_once(first.as_mut()).is_pending());
    let second_context = OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(1)).unwrap()),
    );
    let mut second = Box::pin(endpoint.send_to(target, b"next", &second_context));
    assert!(poll_once(second.as_mut()).is_pending());
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(
        second.await.unwrap_err(),
        Error::Stopped(StopReason::DeadlineExceeded)
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    first_context.cancellation().cancel();
    assert_eq!(
        first.await.unwrap_err(),
        Error::Stopped(StopReason::Cancelled)
    );
    assert_eq!(metrics.snapshot().gauge(Gauge::ActiveUdpSends), 0);
    assert_eq!(metrics.snapshot().counter(Counter::UdpSentPackets), 0);
}
