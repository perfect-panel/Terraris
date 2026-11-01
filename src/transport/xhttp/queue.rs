// SPDX-License-Identifier: MPL-2.0
// Ported from Polaris 56d52fb44958 XHTTP upload_queue.go (Xray b17a88f9b46d).
// Packet bodies stream into bounded, coalesced blocks. The expected packet can
// be consumed before HTTP EOF; later packets cannot use its reserved headroom.
use super::{body, config::Config};
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope},
    task::CancellationToken,
};
use futures_util::task::AtomicWaker;
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
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
/// At most half the physical connection's buffer bytes/slots are upload
/// blocks; the other half stays available to protocol forwarding/downloads.
/// This state is shared by every HTTP request on the same carrier.
pub struct Storage {
    scope: BufferScope,
    pub block_size: usize,
    blocks: Mutex<usize>,
    limit: usize,
    changed: Notify,
}
impl Storage {
    pub fn new(scope: BufferScope) -> Arc<Self> {
        let limits = scope.snapshot().limits();
        let size = 65536usize
            .min(scope.max_allocation())
            .min((limits.bytes() / 4).max(1));
        let block_size = 1usize << (usize::BITS - 1 - size.leading_zeros());
        let limit = (limits.bytes() / 2 / block_size).min(limits.allocations() / 2);
        Arc::new(Self {
            scope,
            block_size,
            blocks: Mutex::new(0),
            limit,
            changed: Notify::new(),
        })
    }
}
struct Quota {
    used: AtomicUsize,
    next: AtomicU64,
}
struct Reservation {
    budget: Arc<Budget>,
    quota: Arc<Quota>,
    storage: Arc<Storage>,
    size: usize,
}
impl Reservation {
    fn shrink(&mut self, size: usize) {
        assert!(size <= self.size);
        if size == self.size {
            return;
        }
        {
            let mut total = self.budget.lock.lock().unwrap_or_else(|e| e.into_inner());
            let difference = self.size - size;
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
        *self
            .storage
            .blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner()) -= 1;
        self.storage.changed.notify_waiters();
    }
}
/// Drop the actual allocation before waking producers waiting on its quota.
pub struct Chunk {
    pub buffer: BufferLease,
    reservation: Reservation,
}
impl Chunk {
    fn ready(mut self) -> Self {
        self.reservation.shrink(self.buffer.len());
        self
    }
}
struct Packet {
    chunks: VecDeque<Chunk>,
    complete: bool,
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
    pub fn new(c: &Config, budget: Arc<Budget>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                mode: Mode::None,
                packets: BTreeMap::new(),
                stream: None,
                attached: false,
            }),
            quota: Arc::new(Quota {
                used: AtomicUsize::new(0),
                next: AtomicU64::new(0),
            }),
            budget,
            max_bytes: c.sc_max_buffered_bytes,
            max_post: c.sc_max_each_post_bytes.to,
            max_posts: c.sc_max_buffered_posts,
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
    /// None acknowledges a duplicate without ever forwarding its bytes twice.
    pub fn begin(self: &Arc<Self>, seq: u64) -> Result<Option<Writer>, u16> {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.is_cancelled() || s.mode == Mode::Stream {
            return Err(409);
        }
        let next = self.quota.next.load(Ordering::Acquire);
        if seq < next || s.packets.contains_key(&seq) {
            return Ok(None);
        }
        if seq - next >= self.max_posts as u64 || s.packets.len() >= self.max_posts {
            return Err(400);
        }
        s.mode = Mode::Packets;
        s.packets.insert(
            seq,
            Packet {
                chunks: VecDeque::new(),
                complete: false,
            },
        );
        Ok(Some(Writer {
            session: self.clone(),
            seq,
            finished: false,
        }))
    }
    async fn allocate(&self, seq: u64, storage: &Arc<Storage>, size: usize) -> Result<Chunk, u16> {
        if size == 0 || size > self.max_post || size > storage.block_size {
            return Err(413);
        }
        loop {
            let quota_changed = self.budget.changed.notified();
            tokio::pin!(quota_changed);
            quota_changed.as_mut().enable();
            let blocks_changed = storage.changed.notified();
            tokio::pin!(blocks_changed);
            blocks_changed.as_mut().enable();
            let memory_changed = storage.scope.capacity_changed().notified();
            tokio::pin!(memory_changed);
            memory_changed.as_mut().enable();
            if self.closed.is_cancelled() {
                return Err(409);
            }
            let head = seq <= self.quota.next.load(Ordering::Acquire);
            {
                // Check both logical budgets before touching the backing allocator.
                // Failed attempts leave no provisional charge or self-notification.
                let mut total = self.budget.lock.lock().unwrap_or_else(|e| e.into_inner());
                let mut blocks = storage.blocks.lock().unwrap_or_else(|e| e.into_inner());
                let used = self.quota.used.load(Ordering::Acquire);
                let local = if head {
                    self.max_bytes
                } else {
                    self.max_bytes - self.max_post
                };
                let global = if head {
                    self.budget.limit
                } else {
                    self.budget.limit - self.budget.headroom
                };
                let slots = if head {
                    storage.limit
                } else {
                    storage.limit.saturating_sub(1)
                };
                if storage.limit == 0 {
                    return Err(503);
                }
                if used.saturating_add(size) <= local
                    && total.saturating_add(size) <= global
                    && *blocks < slots
                {
                    // Use a consistent block size regardless of HTTP DATA/QUIC
                    // fragment boundaries, including short final payloads.
                    let layout = BufferLayout::new(0, storage.block_size, 0).map_err(|_| 503u16)?;
                    match storage.scope.try_lease(layout) {
                        Ok(buffer) => {
                            *blocks += 1;
                            *total += size;
                            self.quota.used.fetch_add(size, Ordering::AcqRel);
                            return Ok(Chunk {
                                buffer,
                                reservation: Reservation {
                                    budget: self.budget.clone(),
                                    quota: self.quota.clone(),
                                    storage: storage.clone(),
                                    size,
                                },
                            });
                        }
                        Err(crate::buffer::Error::Resource(
                            crate::resource::Error::Exhausted {
                                requested, limit, ..
                            },
                        )) if requested <= limit => {}
                        Err(_) => return Err(503),
                    }
                }
            }
            tokio::select! {_=self.closed.cancelled()=>return Err(409),_=quota_changed=>{},_=blocks_changed=>{},_=memory_changed=>{}}
        }
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
/// An interrupted/truncated request must terminate the session: its streamed
/// prefix cannot be rolled back or silently joined to the next packet.
pub struct Writer {
    session: Arc<Session>,
    seq: u64,
    finished: bool,
}
impl Writer {
    pub async fn allocate(&self, storage: &Arc<Storage>, size: usize) -> Result<Chunk, u16> {
        self.session.allocate(self.seq, storage, size).await
    }
    pub fn push(&self, chunk: Chunk) -> Result<(), u16> {
        if chunk.buffer.is_empty() {
            return Ok(());
        }
        let mut s = self.session.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.session.closed.is_cancelled() {
            return Err(409);
        }
        let packet = s.packets.get_mut(&self.seq).ok_or(409u16)?;
        packet.chunks.push_back(chunk.ready());
        drop(s);
        self.session.wake.wake();
        Ok(())
    }
    pub fn finish(mut self) -> Result<(), u16> {
        let mut s = self.session.state.lock().unwrap_or_else(|e| e.into_inner());
        let packet = s.packets.get_mut(&self.seq).ok_or(409u16)?;
        packet.complete = true;
        self.finished = true;
        drop(s);
        self.session.wake.wake();
        Ok(())
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        if !self.finished {
            self.session.close();
        }
    }
}
pub struct Reader {
    session: Arc<Session>,
    current: Option<Chunk>,
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
            self.current = None;
            self.stream = None;
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
            if let Some(chunk) = &mut self.current {
                let n = out.remaining().min(chunk.buffer.len());
                out.put_slice(&chunk.buffer.as_slice()[..n]);
                chunk.buffer.consume(n).map_err(io::Error::other)?;
                if chunk.buffer.is_empty() {
                    self.current = None;
                }
                return Poll::Ready(Ok(()));
            }
            let mut advanced = false;
            let (stream, chunk) = {
                let mut s = self.session.state.lock().unwrap_or_else(|e| e.into_inner());
                let next = self.session.quota.next.load(Ordering::Acquire);
                let chunk = s.packets.get_mut(&next).and_then(|p| p.chunks.pop_front());
                if chunk.is_none() && s.packets.get(&next).is_some_and(|p| p.complete) {
                    s.packets.remove(&next);
                    self.session.quota.next.fetch_add(1, Ordering::AcqRel);
                    advanced = true;
                }
                (s.stream.take(), chunk)
            };
            if advanced {
                self.session.budget.changed.notify_waiters();
                continue;
            }
            if let Some(stream) = stream {
                self.stream = Some(stream);
            } else if let Some(chunk) = chunk {
                self.current = Some(chunk);
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
        buffer::{BufferPool, PoolConfig},
        resource::{Budget as Memory, Limits},
    };
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    fn config() -> Config {
        Config::parse("localhost", "/relay", "packet-up", "{}").unwrap()
    }
    fn bounded_storage(bytes: usize) -> (Memory, BufferPool, Arc<Storage>) {
        let memory = Memory::new(Limits::new(64 << 20, 16384).unwrap());
        let pool =
            BufferPool::new(memory.clone(), PoolConfig::standard(16 << 20, 4096, 64)).unwrap();
        let scope = pool
            .scope(
                memory.scope(Limits::new(bytes, 256).unwrap()).unwrap(),
                128 << 10,
            )
            .unwrap();
        (memory, pool, Storage::new(scope))
    }
    async fn push(writer: &Writer, storage: &Arc<Storage>, value: u8) {
        let mut chunk = writer.allocate(storage, storage.block_size).await.unwrap();
        chunk
            .buffer
            .append_zeroed(storage.block_size)
            .unwrap()
            .fill(value);
        writer.push(chunk).unwrap();
    }
    #[tokio::test]
    async fn reorder_headroom_streaming_duplicates_empty_packets_and_abort() {
        let c = config();
        let budget = Budget::new(&c);
        let s = Session::new(&c, budget.clone());
        let (memory, pool, storage) = bounded_storage(256 << 10);
        assert_eq!(storage.limit, 2);
        let later = s.begin(1).unwrap().unwrap();
        push(&later, &storage, 2).await;
        let mut blocked = Box::pin(later.allocate(&storage, storage.block_size));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut blocked)
                .await
                .is_err()
        );
        let first = s.begin(0).unwrap().unwrap();
        push(&first, &storage, 1).await;
        assert!(s.begin(1).unwrap().is_none());
        let mut reader = s.reader();
        let mut data = vec![0; storage.block_size];
        // Consume the first block even though the HTTP upload has not ended.
        reader.read_exact(&mut data).await.unwrap();
        assert!(data.iter().all(|b| *b == 1));
        first.finish().unwrap();
        reader.read_exact(&mut data).await.unwrap();
        assert!(data.iter().all(|b| *b == 2));
        let mut chunk = tokio::time::timeout(Duration::from_secs(1), &mut blocked)
            .await
            .unwrap()
            .unwrap();
        chunk.buffer.append_payload(b"end").unwrap();
        drop(blocked);
        later.push(chunk).unwrap();
        later.finish().unwrap();
        let mut end = [0; 3];
        reader.read_exact(&mut end).await.unwrap();
        assert_eq!(&end, b"end");
        s.begin(2).unwrap().unwrap().finish().unwrap();
        let third = s.begin(3).unwrap().unwrap();
        push(&third, &storage, 3).await;
        reader.read_exact(&mut data).await.unwrap();
        assert!(data.iter().all(|b| *b == 3));
        drop(third);
        assert!(reader.read_u8().await.is_err());
        drop(reader);
        assert_eq!(*storage.blocks.lock().unwrap(), 0);
        assert_eq!(*budget.lock.lock().unwrap(), 0);
        assert_eq!(storage.scope.snapshot().used().bytes(), 0);
        pool.close();
        assert_eq!(memory.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn process_pressure_release_cancel_and_scope_close_wake_waiters() {
        let c = config();
        let s = Session::new(&c, Budget::new(&c));
        let (memory, pool, storage) = bounded_storage(4 << 20);
        let writer = s.begin(0).unwrap().unwrap();
        let blocker = memory.root_scope().try_reserve(64 << 20).unwrap();
        let mut pending = Box::pin(writer.allocate(&storage, 65536));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        drop(blocker);
        let chunk = tokio::time::timeout(Duration::from_secs(1), &mut pending)
            .await
            .unwrap()
            .unwrap();
        drop(pending);
        drop(chunk);
        pool.trim().unwrap();
        let blocker = memory.root_scope().try_reserve(64 << 20).unwrap();
        let mut pending = Box::pin(writer.allocate(&storage, 65536));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        storage.scope.close();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), &mut pending)
                .await
                .unwrap(),
            Err(503)
        ));
        drop(pending);
        drop(blocker);
        drop(writer);
        assert_eq!(*storage.blocks.lock().unwrap(), 0);
        pool.close();
        assert_eq!(memory.snapshot().used().bytes(), 0);
        let s = Session::new(&c, Budget::new(&c));
        let (memory, pool, storage) = bounded_storage(256 << 10);
        let writer = s.begin(0).unwrap().unwrap();
        push(&writer, &storage, 1).await;
        push(&writer, &storage, 2).await;
        let mut pending = Box::pin(writer.allocate(&storage, 65536));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        s.close();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), &mut pending)
                .await
                .unwrap(),
            Err(409)
        ));
        assert_eq!(*storage.blocks.lock().unwrap(), 0);
        pool.close();
        assert_eq!(memory.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn sixteen_streaming_sessions_share_default_connection_budget() {
        let c = config();
        let budget = Budget::new(&c);
        let (memory, pool, storage) = bounded_storage(4 << 20);
        let mut jobs = tokio::task::JoinSet::new();
        for identity in 0..16u8 {
            let s = Session::new(&c, budget.clone());
            let store = storage.clone();
            jobs.spawn(async move {
                let read = s.clone();
                let producer = async {
                    for seq in 0..8 {
                        let writer = s.begin(seq).unwrap().unwrap();
                        for _ in 0..16 {
                            push(&writer, &store, identity).await;
                        }
                        writer.finish().unwrap();
                    }
                };
                let consumer = async {
                    let mut reader = read.reader();
                    let mut b = vec![0; 65536];
                    for n in 0..128 {
                        reader.read_exact(&mut b).await.unwrap();
                        assert!(b.iter().all(|v| *v == identity));
                        if n % 8 == 0 {
                            tokio::task::yield_now().await;
                        }
                    }
                };
                tokio::join!(producer, consumer);
                s.close();
            });
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(r) = jobs.join_next().await {
                r.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(*storage.blocks.lock().unwrap(), 0);
        assert_eq!(*budget.lock.lock().unwrap(), 0);
        assert_eq!(storage.scope.snapshot().used().bytes(), 0);
        pool.close();
        assert_eq!(memory.snapshot().used().bytes(), 0);
    }
}
