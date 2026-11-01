// SPDX-License-Identifier: GPL-3.0-only
//! A duplex byte stream whose queued payload is owned by BufferLease. It is
//! used by local services instead of introducing unaccounted relay buffers.
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope},
    task::CancellationToken,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
const CHUNK: usize = 16384;
type Reservation = Pin<
    Box<
        dyn Future<Output = Result<mpsc::OwnedPermit<BufferLease>, mpsc::error::SendError<()>>>
            + Send,
    >,
>;
pub struct Pipe {
    read: mpsc::Receiver<BufferLease>,
    write: Option<mpsc::Sender<BufferLease>>,
    current: Option<BufferLease>,
    pending: Option<Reservation>,
    scope: BufferScope,
    cancel_on_drop: Option<CancellationToken>,
}
pub fn pair(scope: BufferScope, messages: usize) -> io::Result<(Pipe, Pipe)> {
    if messages == 0 || messages > 1024 || scope.max_allocation() < CHUNK {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let (a_tx, a_rx) = mpsc::channel(messages);
    let (b_tx, b_rx) = mpsc::channel(messages);
    Ok((
        Pipe {
            read: a_rx,
            write: Some(b_tx),
            current: None,
            pending: None,
            scope: scope.clone(),
            cancel_on_drop: None,
        },
        Pipe {
            read: b_rx,
            write: Some(a_tx),
            current: None,
            pending: None,
            scope,
            cancel_on_drop: None,
        },
    ))
}
impl Pipe {
    pub fn cancel_on_drop(mut self, token: CancellationToken) -> Self {
        self.cancel_on_drop = Some(token);
        self
    }
}
impl Drop for Pipe {
    fn drop(&mut self) {
        if let Some(token) = &self.cancel_on_drop {
            token.cancel();
        }
    }
}
impl AsyncRead for Pipe {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(buffer) = &mut this.current {
                let n = buffer.len().min(output.remaining());
                output.put_slice(&buffer.as_slice()[..n]);
                buffer.consume(n).map_err(io::Error::other)?;
                if buffer.is_empty() {
                    this.current = None;
                }
                return Poll::Ready(Ok(()));
            }
            match ready!(this.read.poll_recv(cx)) {
                Some(buffer) => this.current = Some(buffer),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}
impl AsyncWrite for Pipe {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.pending.is_none() {
            let sender = this
                .write
                .as_ref()
                .ok_or(io::ErrorKind::BrokenPipe)?
                .clone();
            this.pending = Some(Box::pin(sender.reserve_owned()));
        }
        let result = ready!(
            this.pending
                .as_mut()
                .expect("reservation")
                .as_mut()
                .poll(cx)
        );
        this.pending = None;
        let permit = result.map_err(|_| io::ErrorKind::BrokenPipe)?;
        let n = input.len().min(CHUNK);
        let mut buffer = this
            .scope
            .try_lease(BufferLayout::new(0, n, 0).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
        buffer
            .append_payload(&input[..n])
            .map_err(io::Error::other)?;
        permit.send(buffer);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.pending = None;
        this.write = None;
        Poll::Ready(Ok(()))
    }
}
