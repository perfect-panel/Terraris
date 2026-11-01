// SPDX-License-Identifier: GPL-3.0-only

use super::{AddressError, canonical_socket};
use crate::{
    buffer::{self, BufferLayout, BufferScope, QueueItem, SharedBuffer},
    telemetry::{Counter, Gauge, Metrics},
    time::{OperationContext, StopReason},
};
use std::{
    fmt,
    future::poll_fn,
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::ReadBuf,
    net::{TcpStream, UdpSocket},
    sync::Mutex,
};

/// Configuration ceiling, not a promise that every IP family accepts a packet
/// this large. The OS may impose a smaller send limit. UDP jumbograms are not
/// enabled by this adapter.
pub const MAX_DATAGRAM_LIMIT: usize = 65_535;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOperation {
    TcpConnect,
    UdpBind,
    LocalAddress,
    Receive,
    Send,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Address(AddressError),
    InvalidDatagramLimit,
    Buffer(buffer::Error),
    Stopped(StopReason),
    Io {
        operation: IoOperation,
        kind: io::ErrorKind,
    },
    DatagramTooLarge {
        limit: usize,
        observed_at_least: usize,
    },
    PartialDatagram {
        expected: usize,
        written: usize,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(e) => e.fmt(f),
            Self::InvalidDatagramLimit => {
                f.write_str("datagram limit and guard byte must fit the buffer scope")
            }
            Self::Buffer(e) => e.fmt(f),
            Self::Stopped(e) => e.fmt(f),
            Self::Io { operation, kind } => write!(f, "network {operation:?} failed: {kind:?}"),
            Self::DatagramTooLarge {
                limit,
                observed_at_least,
            } => write!(
                f,
                "datagram exceeds {limit} bytes (observed at least {observed_at_least})"
            ),
            Self::PartialDatagram { expected, written } => {
                write!(f, "datagram write accepted {written} of {expected} bytes")
            }
        }
    }
}
impl std::error::Error for Error {}

fn record_failure(metrics: &Metrics, error: Error) {
    metrics.increment(match error {
        Error::Stopped(StopReason::Cancelled) => Counter::OperationCancelled,
        Error::Stopped(StopReason::DeadlineExceeded) => Counter::OperationTimeouts,
        Error::Buffer(_) => Counter::BufferRejected,
        Error::DatagramTooLarge { .. } => Counter::UdpOversized,
        Error::Address(_) | Error::InvalidDatagramLimit => Counter::InvalidInputs,
        _ => Counter::IoErrors,
    });
}
fn io_error(operation: IoOperation, error: io::Error) -> Error {
    Error::Io {
        operation,
        kind: error.kind(),
    }
}

pub async fn connect_tcp(
    address: SocketAddr,
    context: &OperationContext,
    metrics: &Metrics,
) -> Result<TcpStream, Error> {
    let _active = metrics.guard(Gauge::ActiveTcpConnects);
    metrics.increment(Counter::TcpConnectAttempts);
    let result = async {
        if address.port() == 0 {
            return Err(Error::Address(AddressError::ZeroPort));
        }
        context
            .run(TcpStream::connect(canonical_socket(address)))
            .await
            .map_err(Error::Stopped)?
            .map_err(|e| io_error(IoOperation::TcpConnect, e))
    }
    .await;
    match &result {
        Ok(_) => metrics.increment(Counter::TcpConnectSucceeded),
        Err(error) => record_failure(metrics, *error),
    }
    result
}

/// The packet's bound local endpoint, not IP_PKTINFO's concrete destination.
/// local_addr may contain a wildcard address. Payload Debug remains redacted.
#[derive(Clone, Debug)]
pub struct Datagram {
    pub source: SocketAddr,
    pub local_addr: SocketAddr,
    pub payload: SharedBuffer,
}
impl QueueItem for Datagram {
    fn queue_bytes(&self) -> usize {
        self.payload.len()
    }
}

/// One endpoint owns receive/send polling for a transport. Implementations
/// must obey the poll contract: Pending cannot consume data, and writes report
/// the number of bytes accepted. A port must not have another independent
/// polling owner, since some socket APIs retain only the most recent waker.
pub trait DatagramTransport: Send + Sync + 'static {
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>>;
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>>;
}
impl DatagramTransport for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }
    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        UdpSocket::poll_recv_from(self, cx, buffer)
    }
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buffer: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send_to(self, cx, buffer, target)
    }
}

pub struct DatagramEndpoint<T: DatagramTransport = UdpSocket> {
    inner: Arc<DatagramInner<T>>,
}
struct DatagramInner<T> {
    transport: T,
    scope: BufferScope,
    maximum: usize,
    local: SocketAddr,
    metrics: Metrics,
    receive: Mutex<()>,
    send: Mutex<()>,
}
impl<T: DatagramTransport> Clone for DatagramEndpoint<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T: DatagramTransport> DatagramEndpoint<T> {
    pub fn new(
        transport: T,
        scope: BufferScope,
        maximum: usize,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        validate_limit(&scope, maximum)?;
        let local = transport
            .local_addr()
            .map_err(|e| io_error(IoOperation::LocalAddress, e))?;
        Ok(Self {
            inner: Arc::new(DatagramInner {
                transport,
                scope,
                maximum,
                local,
                metrics,
                receive: Mutex::new(()),
                send: Mutex::new(()),
            }),
        })
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local
    }
    pub fn max_payload(&self) -> usize {
        self.inner.maximum
    }

    /// Reserves max_payload + 1, so any oversized/truncated datagram is rejected
    /// rather than published as a valid shorter packet. Zero-byte packets work.
    pub async fn recv(&self, context: &OperationContext) -> Result<Datagram, Error> {
        let _active = self.inner.metrics.guard(Gauge::ActiveUdpReceives);
        let result = async {
            let _receive = context
                .run(self.inner.receive.lock())
                .await
                .map_err(Error::Stopped)?;
            let layout = BufferLayout::new(0, self.inner.maximum + 1, 0).map_err(Error::Buffer)?;
            let mut lease = self.inner.scope.try_lease(layout).map_err(Error::Buffer)?;
            let (source, count) = context
                .run(poll_fn(|cx| {
                    lease.poll_payload(cx, |cx, buffer| {
                        self.inner.transport.poll_recv_from(cx, buffer)
                    })
                }))
                .await
                .map_err(Error::Stopped)?
                .map_err(|e| io_error(IoOperation::Receive, e))?;
            if count > self.inner.maximum {
                return Err(Error::DatagramTooLarge {
                    limit: self.inner.maximum,
                    observed_at_least: count,
                });
            }
            self.inner.metrics.increment(Counter::UdpReceivedPackets);
            self.inner
                .metrics
                .add(Counter::UdpReceivedBytes, count as u64);
            Ok(Datagram {
                source: canonical_socket(source),
                local_addr: self.inner.local,
                payload: lease.freeze(),
            })
        }
        .await;
        if let Err(error) = result.as_ref() {
            record_failure(&self.inner.metrics, *error);
        }
        result
    }

    pub async fn send_to(
        &self,
        target: SocketAddr,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), Error> {
        let _active = self.inner.metrics.guard(Gauge::ActiveUdpSends);
        let result = async {
            context.check().map_err(Error::Stopped)?;
            if target.port() == 0 {
                return Err(Error::Address(AddressError::ZeroPort));
            }
            if payload.len() > self.inner.maximum {
                return Err(Error::DatagramTooLarge {
                    limit: self.inner.maximum,
                    observed_at_least: payload.len(),
                });
            }
            let _send = context
                .run(self.inner.send.lock())
                .await
                .map_err(Error::Stopped)?;
            let count = context
                .run(poll_fn(|cx| {
                    self.inner
                        .transport
                        .poll_send_to(cx, payload, canonical_socket(target))
                }))
                .await
                .map_err(Error::Stopped)?
                .map_err(|e| io_error(IoOperation::Send, e))?;
            if count != payload.len() {
                return Err(Error::PartialDatagram {
                    expected: payload.len(),
                    written: count,
                });
            }
            self.inner.metrics.increment(Counter::UdpSentPackets);
            self.inner.metrics.add(Counter::UdpSentBytes, count as u64);
            Ok(())
        }
        .await;
        if let Err(error) = result.as_ref() {
            record_failure(&self.inner.metrics, *error);
        }
        result
    }
}

impl DatagramEndpoint<UdpSocket> {
    pub async fn bind(
        address: SocketAddr,
        scope: BufferScope,
        maximum: usize,
        metrics: Metrics,
        context: &OperationContext,
    ) -> Result<Self, Error> {
        let result = async {
            validate_limit(&scope, maximum)?;
            let socket = context
                .run(UdpSocket::bind(address))
                .await
                .map_err(Error::Stopped)?
                .map_err(|e| io_error(IoOperation::UdpBind, e))?;
            Self::new(socket, scope, maximum, metrics.clone())
        }
        .await;
        if let Err(error) = result.as_ref() {
            record_failure(&metrics, *error);
        }
        result
    }
}

fn validate_limit(scope: &BufferScope, maximum: usize) -> Result<(), Error> {
    if maximum > MAX_DATAGRAM_LIMIT
        || maximum + 1 > scope.max_allocation()
        || maximum + 1 > scope.snapshot().limits().bytes()
    {
        return Err(Error::InvalidDatagramLimit);
    }
    Ok(())
}
