// SPDX-License-Identifier: GPL-3.0-only
//! Each write is driven by its owning stream future; successful payload writes
//! reach Metered in the same poll that completes the TLS frame (no detached queue).
use super::wire::{self, Writer};
use crate::{
    buffer::{BufferLayout, SharedBuffer},
    task::CancellationToken,
};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};
pub struct State {
    pub cancel: CancellationToken,
    pub remote_closed: AtomicBool,
    pub fin_sent: AtomicBool,
}
impl State {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancel: CancellationToken::new(),
            remote_closed: AtomicBool::new(false),
            fin_sent: AtomicBool::new(false),
        })
    }
}
type Write = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
pub struct MuxStream {
    pub id: u32,
    writer: Arc<Writer>,
    incoming: mpsc::Receiver<SharedBuffer>,
    current: Option<SharedBuffer>,
    offset: usize,
    pending: Option<Write>,
    pending_data: Option<SharedBuffer>,
    shutdown: Option<Write>,
    state: Arc<State>,
}
impl MuxStream {
    pub fn new(
        id: u32,
        writer: Arc<Writer>,
        incoming: mpsc::Receiver<SharedBuffer>,
        state: Arc<State>,
    ) -> Self {
        Self {
            id,
            writer,
            incoming,
            current: None,
            offset: 0,
            pending: None,
            pending_data: None,
            shutdown: None,
            state,
        }
    }
}
impl AsyncRead for MuxStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 || this.state.cancel.is_cancelled() {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some(data) = &this.current {
                let n = (data.len() - this.offset).min(output.remaining());
                output.put_slice(&data.as_slice()[this.offset..this.offset + n]);
                this.offset += n;
                if this.offset == data.len() {
                    this.current = None;
                    this.offset = 0;
                }
                if n != 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            match ready!(this.incoming.poll_recv(cx)) {
                Some(data) => this.current = Some(data),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}
impl AsyncWrite for MuxStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.state.cancel.is_cancelled() || this.state.fin_sent.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.pending.is_none() {
            let n = input.len().min(16384);
            let mut buffer = this
                .writer
                .scope
                .try_lease(BufferLayout::new(0, n, 0).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            buffer
                .append_payload(&input[..n])
                .map_err(io::Error::other)?;
            let data = buffer.freeze();
            let writer = this.writer.clone();
            let id = this.id;
            let owned = data.clone();
            this.pending_data = Some(data);
            this.pending = Some(Box::pin(
                async move { writer.frame(wire::PSH, id, owned).await },
            ));
        }
        let data = this.pending_data.as_ref().expect("write data");
        if input.len() < data.len() || input[..data.len()] != *data.as_slice() {
            this.writer.cancel.cancel();
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        let n = data.len();
        let result = ready!(this.pending.as_mut().expect("write").as_mut().poll(cx));
        this.pending = None;
        this.pending_data = None;
        Poll::Ready(result.map(|_| n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(pending) = &mut this.pending {
            ready!(pending.as_mut().poll(cx))?;
            this.pending = None;
            this.pending_data = None;
        }
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pending.is_some() {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        }
        if this.shutdown.is_none() {
            if this.state.remote_closed.load(Ordering::Acquire)
                || this.state.fin_sent.swap(true, Ordering::AcqRel)
            {
                return Poll::Ready(Ok(()));
            }
            let writer = this.writer.clone();
            let id = this.id;
            let state = this.state.clone();
            this.shutdown = Some(Box::pin(async move {
                let result = writer.bytes(wire::FIN, id, &[]).await;
                state.cancel.cancel();
                result
            }));
        }
        let result = ready!(this.shutdown.as_mut().expect("shutdown").as_mut().poll(cx));
        this.shutdown = None;
        Poll::Ready(result)
    }
}
