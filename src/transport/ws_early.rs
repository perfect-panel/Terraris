// SPDX-License-Identifier: GPL-3.0-only
//! Defer HTTP Upgrade until the first write can carry a bounded early payload.
use super::{Error, web::Options};
use crate::{
    buffer::{BufferLayout, BufferScope, SharedBuffer},
    network::Stream,
    time::{Deadline, OperationContext},
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
type Opening = Pin<Box<dyn Future<Output = Result<Stream, Error>> + Send>>;
pub(super) fn deferred(
    stream: Stream,
    scope: BufferScope,
    options: Options,
    context: OperationContext,
) -> Result<Stream, Error> {
    let context = context.child_with_deadline(
        Deadline::after(Duration::from_secs(10))
            .map_err(|_| Error::Configuration("early data timeout"))?,
    );
    Ok(Box::new(Lazy {
        socket: Some(stream),
        io: None,
        opening: None,
        scope,
        options,
        context,
        first: None,
        failed: false,
    }))
}
struct Lazy {
    socket: Option<Stream>,
    io: Option<Stream>,
    opening: Option<Opening>,
    scope: BufferScope,
    options: Options,
    context: OperationContext,
    first: Option<SharedBuffer>,
    failed: bool,
}
impl Lazy {
    fn begin(&mut self, input: Option<&[u8]>) -> io::Result<()> {
        if self.socket.is_none() {
            return Ok(());
        }
        if let Some(input) = input {
            let n = input.len().min(self.options.early_data);
            let mut data = self
                .scope
                .try_lease(BufferLayout::new(0, n, 0).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            data.append_payload(&input[..n]).map_err(io::Error::other)?;
            self.first = Some(data.freeze());
        }
        let socket = self.socket.take().expect("fresh socket");
        let scope = self.scope.clone();
        let options = self.options.clone();
        let context = self.context.clone();
        let first = self.first.clone();
        self.opening = Some(Box::pin(async move {
            context
                .run(super::http1::client_early(
                    socket,
                    scope,
                    &options,
                    first.as_ref().map(SharedBuffer::as_slice),
                ))
                .await
                .map_err(Error::Stopped)?
        }));
        Ok(())
    }
    fn open(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.failed {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        if let Some(opening) = &mut self.opening {
            match ready!(opening.as_mut().poll(cx)) {
                Ok(io) => {
                    self.io = Some(io);
                    self.opening = None;
                }
                Err(_) => {
                    self.failed = true;
                    self.opening = None;
                    self.first = None;
                    return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncRead for Lazy {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        this.begin(None)?;
        ready!(this.open(cx))?;
        Pin::new(this.io.as_mut().expect("open")).poll_read(cx, out)
    }
}
impl AsyncWrite for Lazy {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.begin(Some(input))?;
        if let Some(first) = &this.first
            && (input.len() < first.len() || input[..first.len()] != *first.as_slice())
        {
            this.failed = true;
            this.opening = None;
            this.io = None;
            this.first = None;
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        ready!(this.open(cx))?;
        if let Some(first) = this.first.take() {
            return Poll::Ready(Ok(first.len()));
        }
        Pin::new(this.io.as_mut().expect("open")).poll_write(cx, input)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.begin(None)?;
        ready!(this.open(cx))?;
        Pin::new(this.io.as_mut().expect("open")).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.begin(None)?;
        ready!(this.open(cx))?;
        Pin::new(this.io.as_mut().expect("open")).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn setup() -> (
        crate::resource::Budget,
        BufferScope,
        Options,
        OperationContext,
    ) {
        let budget =
            crate::resource::Budget::new(crate::resource::Limits::new(1 << 20, 64).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        let options = Options {
            kind: super::super::web::Kind::WebSocket,
            host: "localhost".into(),
            path: "/relay?token=a%2Fb".into(),
            service: String::new(),
            early_data: 4,
        };
        let ctx = OperationContext::new(
            crate::task::CancellationToken::new(),
            Some(Deadline::after(Duration::from_secs(2)).unwrap()),
        );
        (budget, scope, options, ctx)
    }
    async fn header(io: &mut tokio::io::DuplexStream) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(io.read_u8().await.unwrap());
            assert!(bytes.len() < 16384);
        }
        String::from_utf8(bytes).unwrap()
    }
    async fn reply(io: &mut tokio::io::DuplexStream, header: &str) {
        let key = header
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap();
        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        io.write_all(format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").as_bytes()).await.unwrap();
    }
    #[tokio::test]
    async fn first_write_uses_early_header_and_remainder_is_sent_once() {
        let (budget, scope, options, ctx) = setup();
        let (socket, mut remote) = tokio::io::duplex(32768);
        let mut client = deferred(Box::new(socket), scope, options, ctx).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), remote.read_u8())
                .await
                .is_err()
        );
        let server = tokio::spawn(async move {
            let head = header(&mut remote).await;
            assert!(head.starts_with("GET /relay?token=a%2Fb HTTP/1.1\r\n"));
            let early = head
                .lines()
                .find_map(|l| l.strip_prefix("Sec-WebSocket-Protocol: "))
                .unwrap();
            let mut received = URL_SAFE_NO_PAD.decode(early).unwrap();
            assert_eq!(received, b"firs");
            reply(&mut remote, &head).await; // Accept a peer which does not echo the optional subprotocol.
            let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                remote,
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            while received.len() < 13 {
                received.extend(ws.next().await.unwrap().unwrap().into_data());
            }
            assert_eq!(received, b"first payload");
            ws.send(tokio_tungstenite::tungstenite::Message::Binary(
                received.into(),
            ))
            .await
            .unwrap();
        });
        client.write_all(b"first payload").await.unwrap();
        client.flush().await.unwrap();
        let mut received = [0; 13];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"first payload");
        drop(client);
        server.await.unwrap();
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn read_first_opens_without_early_data_and_cancelled_write_cannot_change_payload() {
        let (budget, scope, options, ctx) = setup();
        let (socket, mut remote) = tokio::io::duplex(32768);
        let mut client = deferred(Box::new(socket), scope, options, ctx).unwrap();
        let server = tokio::spawn(async move {
            let head = header(&mut remote).await;
            assert!(!head.contains("Sec-WebSocket-Protocol:"));
            reply(&mut remote, &head).await;
            let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                remote,
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            ws.send(tokio_tungstenite::tungstenite::Message::Binary(
                b"greeting".as_slice().into(),
            ))
            .await
            .unwrap();
        });
        let mut received = [0; 8];
        client.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"greeting");
        drop(client);
        server.await.unwrap();
        assert_eq!(budget.snapshot().used().bytes(), 0);
        let (budget, scope, options, ctx) = setup();
        let (socket, mut remote) = tokio::io::duplex(32768);
        let mut client = deferred(Box::new(socket), scope, options, ctx).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), client.write(b"first"))
                .await
                .is_err()
        );
        let head = header(&mut remote).await;
        assert!(head.contains("Sec-WebSocket-Protocol:"));
        assert_eq!(
            client.write(b"other").await.unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        drop(client);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}
