// SPDX-License-Identifier: GPL-3.0-only
use super::{Error, Session};
use crate::reports::TrafficReservation;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Mutex as AsyncMutex,
    time::Instant,
};
struct State {
    rate: u64,
    tokens: f64,
    last: Instant,
}
pub(crate) struct Limiter {
    state: Mutex<State>,
    gate: AsyncMutex<()>,
}
impl Limiter {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                rate: 0,
                tokens: 0.0,
                last: Instant::now(),
            }),
            gate: AsyncMutex::new(()),
        }
    }
    pub(crate) async fn reserve(
        self: Arc<Self>,
        session: Arc<Session>,
        bytes: usize,
    ) -> Result<Permit, Error> {
        let _gate = session.run(self.gate.lock()).await?;
        loop {
            let rate = session.rate()?;
            if rate == 0 {
                return Ok(Permit {
                    limiter: self.clone(),
                    remaining: 0,
                });
            }
            let delay = {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                if state.rate != rate {
                    state.tokens = state.tokens.min(rate as f64);
                    state.rate = rate;
                }
                state.tokens = (state.tokens
                    + now.duration_since(state.last).as_secs_f64() * rate as f64)
                    .min(rate as f64);
                state.last = now;
                if state.tokens >= bytes as f64 {
                    state.tokens -= bytes as f64;
                    None
                } else {
                    Some(Duration::from_secs_f64(
                        ((bytes as f64 - state.tokens) / rate as f64).clamp(0.000001, 1.0),
                    ))
                }
            };
            if let Some(delay) = delay {
                session.run(tokio::time::sleep(delay)).await?;
            } else {
                return Ok(Permit {
                    limiter: self.clone(),
                    remaining: bytes,
                });
            }
        }
    }
}
pub struct Permit {
    limiter: Arc<Limiter>,
    remaining: usize,
}
impl Permit {
    pub fn commit(&mut self, bytes: usize) {
        if self.remaining != 0 {
            assert!(bytes <= self.remaining);
            self.remaining -= bytes;
        }
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        let mut state = self.limiter.state.lock().unwrap_or_else(|e| e.into_inner());
        state.tokens = (state.tokens + self.remaining as f64).min(state.rate as f64);
    }
}
type Pending = Pin<Box<dyn Future<Output = Result<Permit, Error>> + Send>>;
/// Wraps only successful payload writes in the common rate/counter policy.
pub struct Metered<S> {
    io: S,
    session: Arc<Session>,
    upload: bool,
    pending: Option<Pending>,
    quota: Option<Permit>,
    accounting: Option<TrafficReservation>,
    length: usize,
}
impl<S> Metered<S> {
    pub fn new(io: S, session: Arc<Session>, upload: bool) -> Self {
        Self {
            io,
            session,
            upload,
            pending: None,
            quota: None,
            accounting: None,
            length: 0,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for Metered<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.session.check()?;
        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Metered<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.session.check()?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.pending.is_none() && this.quota.is_none() {
            this.length = data.len().min(8192);
            let session = this.session.clone();
            let n = this.length;
            this.pending = Some(Box::pin(async move { session.quota(n).await }));
        }
        if let Some(pending) = &mut this.pending {
            let permit = ready!(pending.as_mut().poll(cx))?;
            this.pending = None;
            this.quota = Some(permit);
        }
        let n = this.length.min(data.len());
        if this.accounting.is_none() {
            this.accounting = Some(this.session.reserve(this.upload, this.length)?);
        }
        match Pin::new(&mut this.io).poll_write(cx, &data[..n]) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                if let Ok(written) = result {
                    this.quota.as_mut().expect("quota").commit(written);
                    this.accounting
                        .as_mut()
                        .expect("counter")
                        .commit(written as u64);
                }
                this.quota.take();
                this.accounting.take();
                Poll::Ready(result)
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
