// SPDX-License-Identifier: GPL-3.0-only
//! Xray-compatible gRPC Hunk streams over HTTP/2. Connection drivers are owned
//! and polled by the carrier task or returned outbound stream, never detached.
use super::{Error, Multiplexed, web::Options};
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope, SharedBuffer},
    network::Stream,
};
use bytes::{Buf, Bytes};
use std::{
    collections::VecDeque,
    future::Future,
    io,
    ops::Range,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
const MAX_MESSAGE: usize = 1 << 20;

fn failure(_: impl std::fmt::Debug) -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn content_type(value: Option<&http::HeaderValue>) -> bool {
    value
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| matches!(v, "application/grpc" | "application/grpc+proto"))
}
pub(super) async fn server(
    stream: Stream,
    scope: BufferScope,
    options: &Options,
) -> Result<Box<dyn Multiplexed>, Error> {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(65535)
        .initial_connection_window_size(1 << 20)
        .max_frame_size(16384)
        .max_header_list_size(16384)
        .max_concurrent_streams(super::MAX_MULTIPLEX_STREAMS as u32)
        .max_send_buffer_size(65536)
        .max_pending_accept_reset_streams(32)
        .max_local_error_reset_streams(Some(64));
    let connection = builder
        .handshake(stream)
        .await
        .map_err(|_| Error::Configuration("HTTP/2 server handshake"))?;
    Ok(Box::new(Server {
        connection,
        scope,
        options: options.clone(),
        draining: false,
    }))
}
struct Server {
    connection: h2::server::Connection<Stream, Bytes>,
    scope: BufferScope,
    options: Options,
    draining: bool,
}
impl Multiplexed for Server {
    fn drain(&mut self) {
        if !self.draining {
            self.draining = true;
            self.connection.graceful_shutdown();
        }
    }
    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Stream>, Error>> {
        for _ in 0..32 {
            let Some(accepted) = ready!(self.connection.poll_accept(cx)) else {
                return Poll::Ready(Ok(None));
            };
            let (request, mut response) =
                accepted.map_err(|_| Error::Io(io::ErrorKind::ConnectionAborted))?;
            if self.draining {
                response.send_reset(h2::Reason::REFUSED_STREAM);
                continue;
            }
            let path = request.uri().path();
            let multi = path == self.options.grpc_path(true);
            let host = request.uri().authority().map(|v| v.as_str()).unwrap_or("");
            let host_ok = self.options.host.is_empty() || {
                let mut options = self.options.clone();
                options.path = path.to_owned();
                options.matches(host, path)
            };
            let valid = request.method() == http::Method::POST
                && request.uri().query().is_none()
                && (multi || path == self.options.grpc_path(false))
                && host_ok
                && content_type(request.headers().get("content-type"))
                && request.headers().get("te").is_some_and(|v| v == "trailers")
                && request
                    .headers()
                    .get("grpc-encoding")
                    .is_none_or(|v| v == "identity");
            if !valid {
                let reply = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "12")
                    .body(())
                    .expect("static response");
                let _ = response.send_response(reply, true);
                continue;
            }
            let reply = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .expect("static response");
            let send = match response.send_response(reply, false) {
                Ok(send) => send,
                Err(_) => continue,
            };
            return Poll::Ready(Ok(Some(Box::new(GrpcStream::new(
                Receive::Ready(request.into_body()),
                send,
                self.scope.clone(),
                true,
                multi,
                false,
            )))));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
pub(super) async fn client(
    pool: &std::sync::Arc<super::h2_pool::Pool>,
    addresses: &[std::net::SocketAddr],
    scope: BufferScope,
    options: &Options,
    secure: bool,
    context: &crate::time::OperationContext,
) -> Result<(Stream, std::net::SocketAddr), Error> {
    let uri = format!(
        "{}://{}{}",
        if secure { "https" } else { "http" },
        options.host,
        options.grpc_path(false)
    );
    let request = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .header("user-agent", "terraris/0.1")
        .body(())
        .map_err(|_| Error::Configuration("gRPC request"))?;
    let opened = pool.open(addresses, &scope, context, request).await?;
    let io = GrpcStream::new(
        Receive::Response(opened.response),
        opened.send,
        scope,
        false,
        false,
        false,
    );
    Ok((
        Box::new(Pooled {
            io,
            lease: opened.lease,
        }),
        opened.peer,
    ))
}
struct Pooled {
    io: GrpcStream,
    lease: super::h2_pool::Lease,
}
impl AsyncRead for Pooled {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.lease.stopped() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.io).poll_read(cx, out)
    }
}
impl AsyncWrite for Pooled {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.lease.stopped() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.io).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.lease.stopped() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.lease.stopped() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}
struct Pending {
    data: SharedBuffer,
    offset: usize,
    payload: usize,
    header: usize,
}
enum Receive {
    Ready(h2::RecvStream),
    Response(h2::client::ResponseFuture),
}
struct GrpcStream {
    recv: Receive,
    send: h2::SendStream<Bytes>,
    scope: BufferScope,
    server: bool,
    multi: bool,
    raw: Bytes,
    eof: bool,
    status: bool,
    header: [u8; 5],
    header_have: usize,
    body: Option<BufferLease>,
    body_have: usize,
    payloads: VecDeque<SharedBuffer>,
    offset: usize,
    pending: Option<Pending>,
    closed: bool,
    failed: bool,
}
impl GrpcStream {
    fn new(
        recv: Receive,
        send: h2::SendStream<Bytes>,
        scope: BufferScope,
        server: bool,
        multi: bool,
        status: bool,
    ) -> Self {
        Self {
            recv,
            send,
            scope,
            server,
            multi,
            raw: Bytes::new(),
            eof: false,
            status,
            header: [0; 5],
            header_have: 0,
            body: None,
            body_have: 0,
            payloads: VecDeque::new(),
            offset: 0,
            pending: None,
            closed: false,
            failed: false,
        }
    }
    fn wire(&mut self, cx: &mut Context<'_>, out: &mut [u8]) -> Poll<io::Result<usize>> {
        if let Receive::Response(response) = &mut self.recv {
            let response = ready!(Pin::new(response).poll(cx)).map_err(failure)?;
            if response.status() != 200
                || !content_type(response.headers().get("content-type"))
                || response
                    .headers()
                    .get("grpc-encoding")
                    .is_some_and(|v| v != "identity")
                || response
                    .headers()
                    .get("grpc-status")
                    .is_some_and(|v| v != "0")
                || (response.headers().contains_key("grpc-status")
                    && !response.body().is_end_stream())
            {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            self.status = response.headers().contains_key("grpc-status");
            self.recv = Receive::Ready(response.into_body());
        }
        let Receive::Ready(recv) = &mut self.recv else {
            unreachable!("response completed");
        };
        for _ in 0..32 {
            if !self.raw.is_empty() {
                let n = self.raw.len().min(out.len());
                out[..n].copy_from_slice(&self.raw[..n]);
                self.raw.advance(n);
                recv.flow_control().release_capacity(n).map_err(failure)?;
                return Poll::Ready(Ok(n));
            }
            if self.eof {
                return Poll::Ready(Ok(0));
            }
            match ready!(recv.poll_data(cx)) {
                Some(Ok(bytes)) => self.raw = bytes,
                Some(Err(error)) => return Poll::Ready(Err(failure(error))),
                None => {
                    let trailers = ready!(recv.poll_trailers(cx)).map_err(failure)?;
                    if !self.server
                        && !self.status
                        && trailers
                            .as_ref()
                            .and_then(|v| v.get("grpc-status"))
                            .is_none_or(|v| v != "0")
                    {
                        return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                    }
                    self.eof = true;
                    return Poll::Ready(Ok(0));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
    fn frame(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        while self.header_have < 5 {
            let mut temporary = [0; 5];
            let have = self.header_have;
            let n = ready!(self.wire(cx, &mut temporary[..5 - have]))?;
            if n == 0 {
                return if have == 0 {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            self.header[have..have + n].copy_from_slice(&temporary[..n]);
            self.header_have += n;
        }
        let length = u32::from_be_bytes(self.header[1..].try_into().expect("length")) as usize;
        if self.header[0] != 0 || length > MAX_MESSAGE {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        if self.body.is_none() {
            let mut body = self
                .scope
                .try_lease(BufferLayout::new(0, length, 0).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            body.append_zeroed(length).map_err(io::Error::other)?;
            self.body = Some(body);
        }
        while self.body_have < length {
            // Temporarily remove the lease to keep disjoint ownership during polling.
            let mut body = self.body.take().expect("body");
            let result = self.wire(cx, &mut body.as_mut_slice()[self.body_have..]);
            self.body = Some(body);
            let n = ready!(result)?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            self.body_have += n;
        }
        let data = self.body.take().expect("body").freeze();
        let ranges = fields(data.as_slice(), self.multi)?;
        for range in ranges {
            if !range.is_empty() {
                self.payloads
                    .push_back(data.slice(range).map_err(io::Error::other)?);
            }
        }
        self.header_have = 0;
        self.body_have = 0;
        Poll::Ready(Ok(true))
    }
    fn write_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let pending = self.pending.as_mut().expect("pending");
        while pending.offset < pending.data.len() {
            let remaining = pending.data.len() - pending.offset;
            self.send.reserve_capacity(remaining.min(16384));
            let capacity = if self.send.capacity() > 0 {
                self.send.capacity()
            } else {
                ready!(self.send.poll_capacity(cx))
                    .ok_or(io::ErrorKind::BrokenPipe)?
                    .map_err(failure)?
            };
            if capacity == 0 {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            let n = capacity.min(remaining);
            self.send
                .send_data(
                    pending
                        .data
                        .slice(pending.offset..pending.offset + n)
                        .map_err(io::Error::other)?
                        .into_bytes(),
                    false,
                )
                .map_err(failure)?;
            pending.offset += n;
        }
        let n = pending.payload;
        self.pending = None;
        Poll::Ready(Ok(n))
    }
}
impl AsyncRead for GrpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
        }
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if let Some(data) = this.payloads.front() {
                let n = (data.len() - this.offset).min(out.remaining());
                out.put_slice(&data.as_slice()[this.offset..this.offset + n]);
                this.offset += n;
                if this.offset == data.len() {
                    this.payloads.pop_front();
                    this.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }
            match ready!(this.frame(cx)) {
                Ok(false) => return Poll::Ready(Ok(())),
                Ok(true) => {}
                Err(error) => {
                    this.failed = true;
                    this.send.send_reset(h2::Reason::CANCEL);
                    return Poll::Ready(Err(error));
                }
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.pending.is_none() {
            let n = input.len().min(16384);
            let mut encoded = Vec::with_capacity(12);
            encoded.extend([0; 5]);
            encoded.push(10);
            encode_varint(n as u64, &mut encoded);
            let length = (encoded.len() - 5 + n) as u32;
            encoded[1..5].copy_from_slice(&length.to_be_bytes());
            let header = encoded.len();
            let mut data = this
                .scope
                .try_lease(BufferLayout::new(0, header + n, 0).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            data.append_payload(&encoded).map_err(io::Error::other)?;
            data.append_payload(&input[..n]).map_err(io::Error::other)?;
            this.pending = Some(Pending {
                data: data.freeze(),
                offset: 0,
                payload: n,
                header,
            });
        }
        let pending = this.pending.as_ref().expect("pending");
        if input.len() < pending.payload
            || input[..pending.payload] != pending.data.as_slice()[pending.header..]
        {
            this.send.send_reset(h2::Reason::CANCEL);
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        this.write_pending(cx)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_some() {
            ready!(this.write_pending(cx))?;
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_some() {
            ready!(this.write_pending(cx))?;
        }
        if !this.closed {
            if this.server {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                this.send.send_trailers(trailers).map_err(failure)?;
            } else {
                this.send.send_data(Bytes::new(), true).map_err(failure)?;
            }
            this.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl Drop for GrpcStream {
    fn drop(&mut self) {
        if !self.closed || !self.eof {
            self.send.send_reset(h2::Reason::CANCEL);
        }
    }
}
fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 128 {
        out.push((value as u8) | 128);
        value >>= 7;
    }
    out.push(value as u8);
}
fn varint(data: &[u8], at: &mut usize) -> io::Result<u64> {
    let mut value = 0;
    for shift in (0..70).step_by(7) {
        let byte = *data.get(*at).ok_or(io::ErrorKind::InvalidData)?;
        *at += 1;
        if shift == 63 && byte > 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        value |= ((byte & 127) as u64) << shift;
        if byte < 128 {
            return Ok(value);
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}
fn fields(data: &[u8], multi: bool) -> io::Result<Vec<Range<usize>>> {
    let mut at = 0;
    let mut ranges = Vec::new();
    let mut count = 0;
    while at < data.len() {
        count += 1;
        if count > 1024 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let key = varint(data, &mut at)?;
        let field = key >> 3;
        if field == 0 || field > (1 << 29) - 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let start = at;
        let length = match key & 7 {
            0 => {
                varint(data, &mut at)?;
                0
            }
            1 => 8,
            2 => usize::try_from(varint(data, &mut at)?).map_err(|_| io::ErrorKind::InvalidData)?,
            5 => 4,
            _ => return Err(io::ErrorKind::InvalidData.into()),
        };
        if field == 1 {
            if key & 7 != 2 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            if !multi {
                ranges.clear();
            }
            ranges.push(at..at.checked_add(length).ok_or(io::ErrorKind::InvalidData)?);
        }
        if key & 7 != 0 {
            at = at.checked_add(length).ok_or(io::ErrorKind::InvalidData)?;
        }
        if at > data.len() || at < start {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(ranges)
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    use crate::{
        resource::{Budget, Limits},
        task::CancellationToken,
        time::{Deadline, OperationContext},
    };
    use async_trait::async_trait;
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Dial(Arc<AtomicUsize>);
    #[async_trait]
    impl crate::transport::Outbound for Dial {
        async fn connect(
            &self,
            addresses: &[SocketAddr],
            _: &BufferScope,
            context: &OperationContext,
        ) -> Result<(Stream, SocketAddr), Error> {
            self.0.fetch_add(1, Ordering::SeqCst);
            let io = context
                .run(tokio::net::TcpStream::connect(addresses[0]))
                .await
                .map_err(Error::Stopped)??;
            Ok((Box::new(io), addresses[0]))
        }
    }
    fn ctx() -> OperationContext {
        OperationContext::new(
            CancellationToken::new(),
            Some(Deadline::after(Duration::from_secs(5)).unwrap()),
        )
    }
    #[tokio::test]
    async fn pooled_rpcs_reuse_connections_survive_sibling_drop_and_reconnect_after_goaway() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (goaway, _) = tokio::sync::broadcast::channel::<()>(4);
        let commands = goaway.clone();
        let closed = Arc::new(AtomicUsize::new(0));
        let ends = closed.clone();
        let server = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>{let(socket,_)=accepted.unwrap();let mut command=commands.subscribe();let ends=ends.clone();
                        connections.spawn(async move{
                            let mut connection=h2::server::handshake(socket).await.unwrap();let mut jobs=tokio::task::JoinSet::new();
                            loop {tokio::select! {
                                _=command.recv()=>connection.graceful_shutdown(),
                                _=jobs.join_next(),if !jobs.is_empty()=>{},
                                request=connection.accept()=>{
                                    let Some(Ok((request,mut response)))=request else {break;};assert_eq!(request.uri().path(),"/test/Tun");
                                    let Ok(mut send)=response.send_response(http::Response::builder().header("content-type","application/grpc").body(()).unwrap(),false) else { continue; };
                                    jobs.spawn(async move{let mut recv=request.into_body();while let Some(result)=recv.data().await{let Ok(data)=result else{return;};let n=data.len();if send.send_data(data,false).is_err(){return;}recv.flow_control().release_capacity(n).unwrap();}let mut trailers=http::HeaderMap::new();trailers.insert("grpc-status",http::HeaderValue::from_static("0"));let _=send.send_trailers(trailers);});
                                }
                            }}ends.fetch_add(1,Ordering::SeqCst);
                        });
                    }
                    _=connections.join_next(),if !connections.is_empty()=>{},
                }
            }
        });
        let dials = Arc::new(AtomicUsize::new(0));
        let pool = super::super::h2_pool::Pool::new(Arc::new(Dial(dials.clone()))).unwrap();
        let budget = Budget::new(Limits::new(4 << 20, 256).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        let options = Options {
            kind: super::super::web::Kind::Grpc,
            host: "localhost".into(),
            path: "/".into(),
            service: "test".into(),
            early_data: 0,
        };
        for _ in 0..3 {
            let (mut stream, _) = client(&pool, &[address], scope.clone(), &options, false, &ctx())
                .await
                .unwrap();
            stream.write_all(b"sequential").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            ctx()
                .run(stream.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, b"sequential");
        }
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        let (mut first, _) = client(&pool, &[address], scope.clone(), &options, false, &ctx())
            .await
            .unwrap();
        let (mut second, _) = client(&pool, &[address], scope.clone(), &options, false, &ctx())
            .await
            .unwrap();
        first.write_all(b"cancelled stream").await.unwrap();
        drop(first);
        second.write_all(b"survivor").await.unwrap();
        second.shutdown().await.unwrap();
        let mut reply = Vec::new();
        ctx()
            .run(second.read_to_end(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"survivor");
        drop(second);
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        goaway.send(()).unwrap();
        ctx()
            .run(async {
                while closed.load(Ordering::SeqCst) == 0 {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        let (mut retained, _) = client(&pool, &[address], scope.clone(), &options, false, &ctx())
            .await
            .unwrap();
        retained.write_all(b"new connection").await.unwrap();
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        pool.close().await;
        assert!(pool.idle());
        assert!(retained.write_all(b"closed").await.is_err());
        drop(retained);
        assert!(
            client(&pool, &[address], scope, &options, false, &ctx())
                .await
                .is_err()
        );
        assert_eq!(budget.snapshot().used().bytes(), 0);
        server.abort();
        server.await.ok();
    }
}
