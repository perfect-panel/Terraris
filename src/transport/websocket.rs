// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    buffer::{BufferLayout, BufferScope, SharedBuffer},
    network::Stream,
};
use futures_util::{Sink, Stream as FuturesStream};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message,
        protocol::{Role, WebSocketConfig},
    },
};
const MAX_MESSAGE: usize = 1 << 20;
pub(super) async fn wrap(stream: Stream, scope: BufferScope, client: bool) -> Stream {
    let max_message = MAX_MESSAGE.min(scope.max_allocation());
    let config = WebSocketConfig::default()
        .read_buffer_size(16384)
        .write_buffer_size(0)
        .max_write_buffer_size(65536)
        .max_message_size(Some(max_message))
        .max_frame_size(Some(max_message));
    let io = WebSocketStream::from_raw_socket(
        stream,
        if client { Role::Client } else { Role::Server },
        Some(config),
    )
    .await;
    Box::new(Socket {
        io,
        scope,
        current: None,
        offset: 0,
        closing: false,
    })
}
struct Socket {
    io: WebSocketStream<Stream>,
    scope: BufferScope,
    current: Option<SharedBuffer>,
    offset: usize,
    closing: bool,
}
fn error(_: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::ErrorKind::InvalidData.into()
}
impl AsyncRead for Socket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        for _ in 0..32 {
            if let Some(data) = &this.current {
                let n = (data.len() - this.offset).min(out.remaining());
                out.put_slice(&data.as_slice()[this.offset..this.offset + n]);
                this.offset += n;
                if this.offset == data.len() {
                    this.current = None;
                    this.offset = 0;
                }
                if n > 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            if this.closing {
                match ready!(Pin::new(&mut this.io).poll_flush(cx)) {
                    Ok(())
                    | Err(
                        tokio_tungstenite::tungstenite::Error::ConnectionClosed
                        | tokio_tungstenite::tungstenite::Error::AlreadyClosed,
                    ) => return Poll::Ready(Ok(())),
                    Err(e) => return Poll::Ready(Err(error(e))),
                }
            }
            match ready!(Pin::new(&mut this.io).poll_next(cx)) {
                Some(Ok(Message::Binary(bytes))) => {
                    let mut data = this
                        .scope
                        .try_lease(BufferLayout::new(0, bytes.len(), 0).map_err(io::Error::other)?)
                        .map_err(io::Error::other)?;
                    data.append_payload(&bytes).map_err(io::Error::other)?;
                    this.current = Some(data.freeze());
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) => this.closing = true,
                None => return Poll::Ready(Ok(())),
                Some(Err(e)) => return Poll::Ready(Err(error(e))),
                _ => return Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
impl AsyncWrite for Socket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut this.io).poll_ready(cx)).map_err(error)?;
        let n = input.len().min(16384);
        let mut data = this
            .scope
            .try_lease(BufferLayout::new(0, n, 0).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
        data.append_payload(&input[..n]).map_err(io::Error::other)?;
        Pin::new(&mut this.io)
            .start_send(Message::Binary(data.freeze().into_bytes()))
            .map_err(error)?;
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io)
            .poll_flush(cx)
            .map_err(error)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io)
            .poll_close(cx)
            .map_err(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn resources() -> (crate::resource::Budget, BufferScope) {
        let budget =
            crate::resource::Budget::new(crate::resource::Limits::new(1 << 20, 64).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        (budget, scope)
    }
    fn masked(opcode: u8, bytes: &[u8]) -> Vec<u8> {
        assert!(bytes.len() < 126);
        let mask = [2, 3, 4, 5];
        let mut out = vec![opcode, 0x80 | bytes.len() as u8];
        out.extend(mask);
        out.extend(bytes.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        out
    }
    #[tokio::test]
    async fn close_handshake_is_clean_eof_and_sends_the_close_reply() {
        let (budget, scope) = resources();
        let (mut client, remote) = tokio::io::duplex(4096);
        let mut server = wrap(Box::new(remote), scope, false).await;
        client
            .write_all(&masked(0x88, &1000u16.to_be_bytes()))
            .await
            .unwrap();
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        let mut close = [0; 4];
        client.read_exact(&mut close).await.unwrap();
        assert_eq!(close, [0x88, 2, 3, 232]);
        drop(server);
        drop(client);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn fragmented_binary_frames_allow_ping_between_fragments() {
        let (budget, scope) = resources();
        let (mut client, remote) = tokio::io::duplex(4096);
        let mut server = wrap(Box::new(remote), scope, false).await;
        client.write_all(&masked(0x02, b"he")).await.unwrap();
        let mut output = [0; 5];
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                server.read_exact(&mut output)
            )
            .await
            .is_err()
        );
        client.write_all(&masked(0x89, b"p")).await.unwrap();
        client.write_all(&masked(0x80, b"llo")).await.unwrap();
        server.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"hello");
        server.flush().await.unwrap();
        let mut pong = [0; 3];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"\x8a\x01p");
        drop(server);
        drop(client);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn unmasked_clients_and_oversized_frame_claims_are_rejected() {
        for input in [
            &b"\x82\x01x"[..],
            &b"\x82\xff\x00\x00\x00\x00\x00\x20\x00\x00\x01\x02\x03\x04"[..],
        ] {
            let (budget, scope) = resources();
            let (mut client, remote) = tokio::io::duplex(4096);
            let mut server = wrap(Box::new(remote), scope, false).await;
            client.write_all(input).await.unwrap();
            let mut byte = [0];
            assert!(server.read(&mut byte).await.is_err());
            drop(server);
            drop(client);
            assert_eq!(budget.snapshot().used().bytes(), 0);
        }
    }
}
