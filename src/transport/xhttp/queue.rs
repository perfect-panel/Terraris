// SPDX-License-Identifier: MPL-2.0
// Ported from Polaris 56d52fb44958 XHTTP upload_queue.go (Xray b17a88f9b46d).
use super::{body, config::Config};
use crate::task::CancellationToken;
use bytes::{Buf, Bytes};
use futures_util::task::AtomicWaker;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::Notify,
};
pub struct Budget {
    lock: Mutex<usize>,
    limit: usize,
    headroom: usize,
    pub changed: Notify,
}
impl Budget {
    pub fn new(c: &Config) -> Arc<Self> {
        Arc::new(Self {
            lock: Mutex::new(0),
            limit: c.sc_max_total_buffered_bytes,
            headroom: c.sc_max_each_post_bytes.to,
            changed: Notify::new(),
        })
    }
}
struct Quota {
    used: AtomicUsize,
    next: std::sync::atomic::AtomicU64,
}
pub struct Reservation {
    budget: Arc<Budget>,
    quota: Arc<Quota>,
    size: usize,
}
impl Reservation {
    pub fn shrink(&mut self, size: usize) {
        assert!(size <= self.size);
        let difference = self.size - size;
        {
            let mut total = self.budget.lock.lock().unwrap_or_else(|e| e.into_inner());
            *total -= difference;
            self.quota.used.fetch_sub(difference, Ordering::AcqRel);
        }
        self.size = size;
        self.budget.changed.notify_waiters();
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        self.shrink(0);
    }
}
pub struct Packet {
    pub chunks: VecDeque<Bytes>,
    pub _reservation: Reservation,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    None,
    Packets,
    Stream,
}
struct State {
    mode: Mode,
    packets: BTreeMap<u64, Packet>,
    stream: Option<body::Reader>,
    attached: bool,
}
pub struct Session {
    state: Mutex<State>,
    quota: Arc<Quota>,
    budget: Arc<Budget>,
    max_bytes: usize,
    max_post: usize,
    max_posts: usize,
    pub closed: CancellationToken,
    pub upload_done: CancellationToken,
    wake: AtomicWaker,
    pub created: tokio::time::Instant,
}
impl Session {
    pub fn new(config: &Config, budget: Arc<Budget>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                mode: Mode::None,
                packets: BTreeMap::new(),
                stream: None,
                attached: false,
            }),
            quota: Arc::new(Quota {
                used: AtomicUsize::new(0),
                next: std::sync::atomic::AtomicU64::new(0),
            }),
            budget,
            max_bytes: config.sc_max_buffered_bytes,
            max_post: config.sc_max_each_post_bytes.to,
            max_posts: config.sc_max_buffered_posts,
            closed: CancellationToken::new(),
            upload_done: CancellationToken::new(),
            wake: AtomicWaker::new(),
            created: tokio::time::Instant::now(),
        })
    }
    pub fn attach(&self) -> bool {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.attached || self.closed.is_cancelled() {
            false
        } else {
            s.attached = true;
            true
        }
    }
    pub fn orphaned(&self) -> bool {
        !self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .attached
    }
    pub fn close(&self) {
        self.closed.cancel();
        self.upload_done.cancel();
        {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.packets.clear();
            s.stream = None;
        }
        self.wake.wake();
        self.budget.changed.notify_waiters();
    }
    pub async fn reserve(&self, seq: u64, size: usize) -> Result<Reservation, u16> {
        if size > self.max_post {
            return Err(413);
        }
        let wait = async {
            loop {
                let notified = self.budget.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.closed.is_cancelled() {
                    return Err(409);
                }
                let next = self.quota.next.load(Ordering::Acquire);
                if seq.saturating_sub(next) >= self.max_posts as u64 {
                    return Err(400);
                }
                {
                    let mut total = self.budget.lock.lock().unwrap_or_else(|e| e.into_inner());
                    let used = self.quota.used.load(Ordering::Acquire);
                    let head = seq <= next;
                    let local_limit = if head {
                        self.max_bytes
                    } else {
                        self.max_bytes - self.max_post
                    };
                    let global_limit = if head {
                        self.budget.limit
                    } else {
                        self.budget.limit - self.budget.headroom
                    };
                    if used.saturating_add(size) <= local_limit
                        && total.saturating_add(size) <= global_limit
                    {
                        *total += size;
                        self.quota.used.fetch_add(size, Ordering::AcqRel);
                        return Ok(Reservation {
                            budget: self.budget.clone(),
                            quota: self.quota.clone(),
                            size,
                        });
                    }
                }
                tokio::select! {_=self.closed.cancelled()=>return Err(409),_=notified=>{}}
            }
        };
        tokio::time::timeout(Duration::from_secs(30), wait)
            .await
            .map_err(|_| 503u16)?
    }
    pub fn push(&self, seq: u64, packet: Packet) -> Result<(), u16> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.is_cancelled() || s.mode == Mode::Stream {
            return Err(409);
        }
        s.mode = Mode::Packets;
        let next = self.quota.next.load(Ordering::Acquire);
        if seq < next || s.packets.contains_key(&seq) {
            return Ok(());
        }
        if seq - next >= self.max_posts as u64 || s.packets.len() >= self.max_posts {
            return Err(400);
        }
        s.packets.insert(seq, packet);
        drop(s);
        self.wake.wake();
        Ok(())
    }
    pub fn upload(&self, body: body::Body) -> Result<(), u16> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.is_cancelled() || s.mode != Mode::None {
            return Err(409);
        }
        s.mode = Mode::Stream;
        s.stream = Some(body::Reader::new(body));
        drop(s);
        self.wake.wake();
        Ok(())
    }
    pub fn reader(self: &Arc<Self>) -> Reader {
        Reader {
            session: self.clone(),
            current: None,
            stream: None,
        }
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.closed.cancel();
        self.upload_done.cancel();
    }
}
pub struct Reader {
    session: Arc<Session>,
    current: Option<Packet>,
    stream: Option<body::Reader>,
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
        self.session.wake.register(cx.waker());
        if self.session.closed.is_cancelled() {
            return Poll::Ready(Err(io::ErrorKind::ConnectionAborted.into()));
        }
        for _ in 0..64 {
            if let Some(reader) = &mut self.stream {
                let before = out.filled().len();
                let result = Pin::new(reader).poll_read(cx, out);
                if matches!(result, Poll::Ready(Ok(()))) && out.filled().len() == before {
                    self.session.upload_done.cancel();
                }
                return result;
            }
            if let Some(packet) = &mut self.current {
                if let Some(chunk) = packet.chunks.front_mut() {
                    let n = out.remaining().min(chunk.len());
                    out.put_slice(&chunk[..n]);
                    chunk.advance(n);
                    if chunk.is_empty() {
                        packet.chunks.pop_front();
                    }
                    return Poll::Ready(Ok(()));
                }
                self.current = None;
                self.session.quota.next.fetch_add(1, Ordering::AcqRel);
                self.session.budget.changed.notify_waiters();
            }
            let (stream, packet) = {
                let mut s = self.session.state.lock().unwrap_or_else(|e| e.into_inner());
                let next = self.session.quota.next.load(Ordering::Acquire);
                (s.stream.take(), s.packets.remove(&next))
            };
            if let Some(stream) = stream {
                self.stream = Some(stream);
            } else if let Some(packet) = packet {
                self.current = Some(packet);
            } else {
                return Poll::Pending;
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        buffer::BufferScope,
        resource::{Budget as Memory, Limits},
    };
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn out_of_order_headroom_duplicates_and_close_release_all_bytes() {
        let c=Config::parse("localhost","/relay","packet-up",r#"{"scMaxEachPostBytes":8,"scMaxBufferedBytes":16,"scMaxTotalBufferedBytes":16,"scMaxBufferedPosts":3}"#).unwrap();
        let budget = Budget::new(&c);
        let session = Session::new(&c, budget.clone());
        let memory = Memory::new(Limits::new(1024, 32).unwrap());
        let scope = BufferScope::new(memory.root_scope(), 64).unwrap();
        let later = session.reserve(1, 8).await.unwrap();
        session
            .push(
                1,
                Packet {
                    chunks: VecDeque::from([body::copy(&scope, b"second!!").unwrap()]),
                    _reservation: later,
                },
            )
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), session.reserve(2, 8))
                .await
                .is_err()
        );
        let head = session.reserve(0, 8).await.unwrap();
        session
            .push(
                0,
                Packet {
                    chunks: VecDeque::from([body::copy(&scope, b"first!!!").unwrap()]),
                    _reservation: head,
                },
            )
            .unwrap();
        let mut reader = session.reader();
        let mut data = [0; 16];
        reader.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"first!!!second!!");
        drop(reader);
        let next = session.reserve(2, 8).await.unwrap();
        session
            .push(
                2,
                Packet {
                    chunks: VecDeque::from([body::copy(&scope, b"third!!!").unwrap()]),
                    _reservation: next,
                },
            )
            .unwrap();
        session.close();
        assert_eq!(*budget.lock.lock().unwrap(), 0);
        assert_eq!(memory.snapshot().used().bytes(), 0);
        assert!(session.reserve(3, 8).await.is_err());
    }
}
