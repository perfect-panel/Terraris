// SPDX-License-Identifier: MPL-2.0
// XHTTP body adapters. Payload ownership stays with Terraris buffer leases.
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope},
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
pub fn copy(scope: &BufferScope, data: &[u8]) -> io::Result<Bytes> {
    let mut lease = scope
        .try_lease(BufferLayout::new(0, data.len(), 0).map_err(io::Error::other)?)
        .map_err(io::Error::other)?;
    lease.append_payload(data).map_err(io::Error::other)?;
    Ok(Bytes::from_owner(lease))
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
pub struct ReadBody<R> {
    reader: R,
    scope: BufferScope,
    buffer: Option<BufferLease>,
    done: bool,
}
impl<R: AsyncRead + Unpin + Send + 'static> ReadBody<R> {
    pub fn boxed(reader: R, scope: BufferScope) -> Body {
        Self {
            reader,
            scope,
            buffer: None,
            done: false,
        }
        .boxed_unsync()
    }
}
impl<R: AsyncRead + Unpin> HttpBody for ReadBody<R> {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = &mut *self;
        if this.done {
            return Poll::Ready(None);
        }
        if this.buffer.is_none() {
            this.buffer = Some(
                this.scope
                    .try_lease(BufferLayout::new(0, 16384, 0).map_err(io::Error::other)?)
                    .map_err(io::Error::other)?,
            );
        }
        let (_, n) = match ready!(
            this.buffer
                .as_mut()
                .expect("allocated buffer")
                .poll_payload(cx, |cx, out| Pin::new(&mut this.reader).poll_read(cx, out))
        ) {
            Ok(v) => v,
            Err(e) => {
                this.done = true;
                this.buffer = None;
                return Poll::Ready(Some(Err(e)));
            }
        };
        let buffer = this.buffer.take().expect("allocated buffer");
        if n == 0 {
            this.done = true;
            Poll::Ready(None)
        } else {
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_owner(buffer)))))
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
    Ok((a, ReadBody::boxed(b, scope.clone())))
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
