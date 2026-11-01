// SPDX-License-Identifier: MPL-2.0
// XHTTP body adapters. Payload ownership stays with Terraris buffer leases.
use crate::{
    buffer::BufferScope,
    network::{Stream, pipe::Pipe},
};
use bytes::{Buf, Bytes};
use http_body::{Body as HttpBody, Frame};
use http_body_util::{BodyExt, combinators::UnsyncBoxBody};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub type Body = UnsyncBoxBody<Bytes, io::Error>;
pub fn empty() -> Body {
    http_body_util::Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}
pub fn incoming(body: hyper::body::Incoming) -> Body {
    body.map_err(io::Error::other).boxed_unsync()
}
pub struct Reader {
    body: Body,
    current: Bytes,
    eof: bool,
}
impl Reader {
    pub fn new(body: Body) -> Self {
        Self {
            body,
            current: Bytes::new(),
            eof: false,
        }
    }
}
impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.current.is_empty() {
                let n = out.remaining().min(self.current.len());
                out.put_slice(&self.current[..n]);
                self.current.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.body).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.current = data;
                    }
                }
                Some(Err(e)) => return Poll::Ready(Err(e)),
                None => self.eof = true,
            }
        }
    }
}
/// HTTP takes the queued Pipe lease directly. QUIC may retain these bytes
/// until acknowledgement, so forwarding must wait for capacity, not copy into
/// another allocation and fail when the shared scope is temporarily full.
pub struct PipeBody {
    reader: Pipe,
    done: bool,
}
impl PipeBody {
    pub fn boxed(reader: Pipe) -> Body {
        Self {
            reader,
            done: false,
        }
        .boxed_unsync()
    }
}
impl HttpBody for PipeBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match ready!(self.reader.poll_read_chunk(cx)) {
            Some(buffer) => Poll::Ready(Some(Ok(Frame::data(Bytes::from_owner(buffer))))),
            None => {
                self.done = true;
                Poll::Ready(None)
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.done
    }
}
pub struct Joined<R, W> {
    pub reader: R,
    pub writer: W,
}
impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for Joined<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, out)
    }
}
impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for Joined<R, W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, b)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}
// A response-body guard is also the lifetime of its logical session/request.
pub struct Guarded<G: Send + Unpin + 'static> {
    body: Body,
    _guard: G,
}
impl<G: Send + Unpin + 'static> Guarded<G> {
    pub fn boxed(body: Body, guard: G) -> Body {
        Self {
            body,
            _guard: guard,
        }
        .boxed_unsync()
    }
}
impl<G: Send + Unpin + 'static> HttpBody for Guarded<G> {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        Pin::new(&mut self.get_mut().body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}
pub fn response_pipe(scope: &BufferScope) -> io::Result<(Pipe, Body)> {
    let (a, b) = crate::network::pipe::pair(scope.clone(), 4)?;
    Ok((a, PipeBody::boxed(b)))
}
pub struct OwnedStream<G: Send + Unpin> {
    pub io: Stream,
    pub _guard: G,
}
impl<G: Send + Unpin> AsyncRead for OwnedStream<G> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, out)
    }
}
impl<G: Send + Unpin> AsyncWrite for OwnedStream<G> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, b)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Signals when the HTTP driver has consumed the final upload DATA frame.
/// A client may pipeline responses, but must not queue arbitrarily many later
/// packet bodies ahead of an earlier packet on the same HTTP connection.
pub fn submitted(body: Body, bytes: usize) -> (Body, tokio::sync::oneshot::Receiver<()>) {
    let (send, receive) = tokio::sync::oneshot::channel();
    (
        Submitted {
            body,
            remaining: bytes,
            send: Some(send),
        }
        .boxed_unsync(),
        receive,
    )
}
struct Submitted {
    body: Body,
    remaining: usize,
    send: Option<tokio::sync::oneshot::Sender<()>>,
}
impl HttpBody for Submitted {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let frame = ready!(Pin::new(&mut self.body).poll_frame(cx));
        match &frame {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    self.remaining = self.remaining.saturating_sub(data.len());
                }
                if self.remaining == 0
                    && let Some(send) = self.send.take()
                {
                    let _ = send.send(());
                }
            }
            None => {
                if self.remaining == 0
                    && let Some(send) = self.send.take()
                {
                    let _ = send.send(());
                } else {
                    self.send = None;
                }
            }
            Some(Err(_)) => self.send = None,
        }
        Poll::Ready(frame)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn http_body_transfers_the_only_buffer_without_a_second_allocation() {
        use crate::resource::{Budget, Limits};
        use tokio::io::AsyncWriteExt;
        let memory = Budget::new(Limits::new(16384, 1).unwrap());
        let scope = BufferScope::new(memory.root_scope(), 16384).unwrap();
        let (mut writer, reader) = crate::network::pipe::pair(scope, 1).unwrap();
        let mut body = PipeBody::boxed(reader);
        writer.write_all(b"direct ownership").await.unwrap();
        let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(frame.as_ref(), b"direct ownership");
        assert_eq!(memory.snapshot().used().allocations(), 1);
        assert_eq!(memory.snapshot().used().bytes(), 16);
        drop(frame);
        writer.shutdown().await.unwrap();
        assert!(body.frame().await.is_none());
        assert_eq!(memory.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn submission_tracks_the_last_frame_and_does_not_ack_truncation_or_drop() {
        fn frames() -> Body {
            http_body_util::StreamBody::new(futures_util::stream::iter([
                Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"one!"))),
                Ok(Frame::data(Bytes::from_static(b"two!"))),
            ]))
            .boxed_unsync()
        }
        let (mut body, mut done) = submitted(frames(), 8);
        body.frame().await.unwrap().unwrap();
        assert!(matches!(
            done.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        body.frame().await.unwrap().unwrap();
        assert_eq!(done.await, Ok(()));
        let (mut body, done) = submitted(frames(), 9);
        while body.frame().await.is_some() {}
        assert!(done.await.is_err());
        let (mut body, done) = submitted(frames(), 8);
        body.frame().await.unwrap().unwrap();
        drop(body);
        assert!(done.await.is_err());
    }
}
