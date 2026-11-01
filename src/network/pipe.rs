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
type Reservation =
    Pin<Box<dyn Future<Output = io::Result<(mpsc::OwnedPermit<BufferLease>, BufferLease)>> + Send>>;
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
    /// Transfer ownership of an already budgeted block to a framed transport.
    /// This avoids allocating a second block while the first fills the budget.
    pub(crate) fn poll_read_chunk(&mut self, cx: &mut Context<'_>) -> Poll<Option<BufferLease>> {
        if let Some(buffer) = self.current.take() {
            Poll::Ready(Some(buffer))
        } else {
            self.read.poll_recv(cx)
        }
    }
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
            let scope = this.scope.clone();
            let layout =
                BufferLayout::new(0, input.len().min(CHUNK), 0).map_err(io::Error::other)?;
            this.pending = Some(Box::pin(async move {
                let permit = sender
                    .clone()
                    .reserve_owned()
                    .await
                    .map_err(|_| io::ErrorKind::BrokenPipe)?;
                // A peer closing the pipe must wake a writer even when all
                // buffer capacity is held by an unrelated HTTP/QUIC sender.
                let buffer = tokio::select! {
                    biased;
                    _ = sender.closed() => return Err(io::ErrorKind::BrokenPipe.into()),
                    result = scope.lease_when_available(layout) => result.map_err(io::Error::other)?,
                };
                Ok((permit, buffer))
            }));
        }
        let result = ready!(
            this.pending
                .as_mut()
                .expect("reservation")
                .as_mut()
                .poll(cx)
        );
        this.pending = None;
        let (permit, mut buffer) = result?;
        // A cancelled poll_write may be followed by different input. The
        // allocation owns capacity only; no previous payload was captured.
        let n = input.len().min(buffer.remaining_payload());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{Budget, Limits};
    use std::{future::poll_fn, time::Duration};
    use tokio::io::AsyncWriteExt;
    fn pipes() -> (Budget, Pipe, Pipe) {
        let memory = Budget::new(Limits::new(CHUNK, 1).unwrap());
        let scope = BufferScope::new(memory.root_scope(), CHUNK).unwrap();
        let (a, b) = pair(scope, 2).unwrap();
        (memory, a, b)
    }
    #[tokio::test]
    async fn retained_http_chunk_backpressures_writer_and_cancelled_input_is_not_replayed() {
        let (memory, mut writer, mut reader) = pipes();
        writer.write_all(b"first").await.unwrap();
        let held = poll_fn(|cx| reader.poll_read_chunk(cx)).await.unwrap();
        let mut pending = Box::pin(writer.write_all(b"obsolete payload"));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        assert_eq!(memory.snapshot().used().allocations(), 1);
        drop(pending);
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), writer.write_all(b"new"))
            .await
            .unwrap()
            .unwrap();
        let chunk = poll_fn(|cx| reader.poll_read_chunk(cx)).await.unwrap();
        assert_eq!(chunk.as_slice(), b"new");
        drop(chunk);
        writer.shutdown().await.unwrap();
        assert!(poll_fn(|cx| reader.poll_read_chunk(cx)).await.is_none());
        assert_eq!(memory.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn receiver_close_interrupts_budget_wait_without_waiting_for_retained_bytes() {
        let (memory, mut writer, mut reader) = pipes();
        writer.write_all(b"held").await.unwrap();
        let held = poll_fn(|cx| reader.poll_read_chunk(cx)).await.unwrap();
        let mut pending = Box::pin(writer.write_all(b"waiting"));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        drop(reader);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), &mut pending)
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        drop(pending);
        drop(writer);
        drop(held);
        assert_eq!(memory.snapshot().used().bytes(), 0);
    }
}
