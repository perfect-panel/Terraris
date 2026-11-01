// SPDX-License-Identifier: GPL-3.0-only

//! MPSC queue with atomic byte AND message reservations, bounded FIFO waiters
//! and cancellation-safe grants. It budgets logical queue contents; owning
//! buffer handles independently retain their physical allocation budgets.

use std::{
    collections::VecDeque,
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU8, Ordering},
    },
};

use tokio::{sync::Notify, time::Instant};

use super::{BufferLease, SharedBuffer};

pub trait QueueItem: Send {
    /// Must remain constant while the item is queued. Interior mutation that
    /// changes this cost violates the queue item's contract.
    fn queue_bytes(&self) -> usize;
}
impl QueueItem for SharedBuffer {
    fn queue_bytes(&self) -> usize {
        self.len()
    }
}
impl QueueItem for BufferLease {
    fn queue_bytes(&self) -> usize {
        self.len()
    }
}
impl QueueItem for bytes::Bytes {
    fn queue_bytes(&self) -> usize {
        self.len()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct QueueLimits {
    bytes: usize,
    messages: usize,
    waiters: usize,
}
impl QueueLimits {
    /// A zero byte budget allows only empty messages; zero waiters disables
    /// waiting when full. Message capacity must always be positive.
    pub fn new(bytes: usize, messages: usize, waiters: usize) -> Result<Self, QueueError> {
        if messages == 0 {
            return Err(QueueError::InvalidLimits);
        }
        Ok(Self {
            bytes,
            messages,
            waiters,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    InvalidLimits,
    AllocationFailed,
    TooLarge,
    Full,
    WaiterLimit,
    Closed,
    Timeout,
    SizeMismatch,
    Empty,
}
impl fmt::Display for QueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimits => "queue must have positive message capacity",
            Self::AllocationFailed => "queue metadata allocation failed",
            Self::TooLarge => "item exceeds queue byte limit",
            Self::Full => "queue capacity unavailable or earlier waiters have priority",
            Self::WaiterLimit => "queue waiter limit reached",
            Self::Closed => "queue is closed",
            Self::Timeout => "queue reservation deadline exceeded",
            Self::SizeMismatch => "item size differs from reserved byte count",
            Self::Empty => "queue has no message available",
        })
    }
}
impl std::error::Error for QueueError {}

/// Returns the caller's item on any unsuccessful synchronous send. Debug and
/// Display never include the item's payload.
pub struct SendError<T> {
    pub error: QueueError,
    pub item: T,
}
impl<T> fmt::Debug for SendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SendError").field(&self.error).finish()
    }
}
impl<T> fmt::Display for SendError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}
impl<T> std::error::Error for SendError<T> {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueSnapshot {
    pub queued_bytes: usize,
    pub queued_messages: usize,
    pub reserved_bytes: usize,
    pub reserved_messages: usize,
    pub waiting: usize,
    pub senders: usize,
    pub closed: bool,
}

struct Entry<T> {
    item: T,
    bytes: usize,
}
struct State<T> {
    items: VecDeque<Entry<T>>,
    waiters: VecDeque<Arc<Waiter>>,
    queued_bytes: usize,
    reserved_bytes: usize,
    reserved_messages: usize,
    senders: usize,
    closed: bool,
}
struct Inner<T> {
    limits: QueueLimits,
    state: Mutex<State<T>>,
    readable: Notify,
}

/// The unique receiver. Dropping it discards queued items and rejects all
/// future sends. close() instead allows already queued items to be drained.
pub struct BufferQueue<T: QueueItem> {
    inner: Arc<Inner<T>>,
}
pub struct BufferSender<T: QueueItem> {
    inner: Arc<Inner<T>>,
}

/// Construct the queue before accepting traffic; message and waiter slot
/// storage is allocated up front. These metadata bytes are not payload bytes.
///
/// ```
/// use bytes::Bytes;
/// use terraris::buffer::{bounded_queue, QueueLimits};
/// use tokio::time::{Instant, Duration};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let (sender, mut queue) = bounded_queue::<Bytes>(QueueLimits::new(1024, 16, 8)?)?;
/// let permit = sender.reserve(3, Instant::now() + Duration::from_secs(1)).await?;
/// permit.send(Bytes::from_static(b"abc"))?;
/// drop(sender);
/// assert_eq!(queue.recv().await.unwrap().as_ref(), b"abc");
/// assert!(queue.recv().await.is_none());
/// # Ok(())
/// # }
/// ```
pub fn bounded_queue<T: QueueItem>(
    limits: QueueLimits,
) -> Result<(BufferSender<T>, BufferQueue<T>), QueueError> {
    let mut items = VecDeque::new();
    items
        .try_reserve_exact(limits.messages)
        .map_err(|_| QueueError::AllocationFailed)?;
    let mut waiters = VecDeque::new();
    waiters
        .try_reserve_exact(limits.waiters)
        .map_err(|_| QueueError::AllocationFailed)?;
    let inner = Arc::new(Inner {
        limits,
        state: Mutex::new(State {
            items,
            waiters,
            queued_bytes: 0,
            reserved_bytes: 0,
            reserved_messages: 0,
            senders: 1,
            closed: false,
        }),
        readable: Notify::new(),
    });
    Ok((
        BufferSender {
            inner: inner.clone(),
        },
        BufferQueue { inner },
    ))
}

const WAITING: u8 = 0;
const GRANTED: u8 = 1;
const CONSUMED: u8 = 2;
const REJECTED: u8 = 3;
const CANCELLED: u8 = 4;
struct Waiter {
    bytes: usize,
    phase: AtomicU8,
    notify: Notify,
}

impl<T> Inner<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn snapshot(&self) -> QueueSnapshot {
        let s = self.lock();
        QueueSnapshot {
            queued_bytes: s.queued_bytes,
            queued_messages: s.items.len(),
            reserved_bytes: s.reserved_bytes,
            reserved_messages: s.reserved_messages,
            waiting: s.waiters.len(),
            senders: s.senders,
            closed: s.closed || (s.senders == 0 && s.reserved_messages == 0),
        }
    }
    fn fits(&self, s: &State<T>, bytes: usize) -> bool {
        s.items.len() + s.reserved_messages < self.limits.messages
            && bytes <= self.limits.bytes - s.queued_bytes - s.reserved_bytes
    }
    fn reserve(&self, s: &mut State<T>, bytes: usize) {
        s.reserved_bytes += bytes;
        s.reserved_messages += 1;
    }
    fn release(&self, s: &mut State<T>, bytes: usize) {
        s.reserved_bytes -= bytes;
        s.reserved_messages -= 1;
    }

    // Grants only the FIFO head, atomically in both dimensions. No channels
    // containing RAII permits are sent under this lock (avoids drop recursion).
    fn dispatch(&self, s: &mut State<T>) -> Vec<Arc<Waiter>> {
        let mut wakes = Vec::new();
        if s.closed {
            return wakes;
        }
        while let Some(waiter) = s.waiters.front() {
            if !self.fits(s, waiter.bytes) {
                break;
            }
            let waiter = s.waiters.pop_front().expect("FIFO head");
            self.reserve(s, waiter.bytes);
            waiter.phase.store(GRANTED, Ordering::Relaxed);
            wakes.push(waiter);
        }
        wakes
    }

    fn close(&self, discard: bool) {
        let (waiters, discarded) = {
            let mut s = self.lock();
            s.closed = true;
            let waiters = std::mem::take(&mut s.waiters);
            for waiter in &waiters {
                waiter.phase.store(REJECTED, Ordering::Relaxed);
            }
            let discarded = if discard {
                s.queued_bytes = 0;
                std::mem::take(&mut s.items)
            } else {
                VecDeque::new()
            };
            (waiters, discarded)
        };
        // Destructors and wakers are invoked outside the mutex.
        drop(discarded);
        for waiter in waiters {
            waiter.notify.notify_one();
        }
        self.readable.notify_one();
    }
}

fn wake(waiters: Vec<Arc<Waiter>>) {
    for waiter in waiters {
        waiter.notify.notify_one();
    }
}

impl<T: QueueItem> BufferSender<T> {
    pub fn snapshot(&self) -> QueueSnapshot {
        self.inner.snapshot()
    }
    pub fn close(&self) {
        self.inner.close(false);
    }

    pub fn try_reserve(&self, bytes: usize) -> Result<QueuePermit<T>, QueueError> {
        let mut s = self.inner.lock();
        if s.closed {
            return Err(QueueError::Closed);
        }
        if bytes > self.inner.limits.bytes {
            return Err(QueueError::TooLarge);
        }
        if !s.waiters.is_empty() || !self.inner.fits(&s, bytes) {
            return Err(QueueError::Full);
        }
        self.inner.reserve(&mut s, bytes);
        Ok(QueuePermit {
            inner: self.inner.clone(),
            bytes,
            active: true,
        })
    }

    pub fn try_send(&self, item: T) -> Result<(), SendError<T>> {
        match self.try_reserve(item.queue_bytes()) {
            Ok(permit) => permit.send(item),
            Err(error) => Err(SendError { error, item }),
        }
    }

    /// FIFO byte/message reservation. Dropping this future removes its waiter
    /// or refunds an already-granted reservation exactly once. Deadlines are
    /// checked again before a grant is consumed, so expired waiters cannot send.
    pub async fn reserve(
        &self,
        bytes: usize,
        deadline: Instant,
    ) -> Result<QueuePermit<T>, QueueError> {
        if Instant::now() >= deadline {
            return Err(QueueError::Timeout);
        }
        let waiter = {
            let mut s = self.inner.lock();
            if s.closed {
                return Err(QueueError::Closed);
            }
            if Instant::now() >= deadline {
                return Err(QueueError::Timeout);
            }
            if bytes > self.inner.limits.bytes {
                return Err(QueueError::TooLarge);
            }
            if s.waiters.is_empty() && self.inner.fits(&s, bytes) {
                self.inner.reserve(&mut s, bytes);
                return Ok(QueuePermit {
                    inner: self.inner.clone(),
                    bytes,
                    active: true,
                });
            }
            if s.waiters.len() >= self.inner.limits.waiters {
                return Err(QueueError::WaiterLimit);
            }
            let waiter = Arc::new(Waiter {
                bytes,
                phase: AtomicU8::new(WAITING),
                notify: Notify::new(),
            });
            s.waiters.push_back(waiter.clone());
            waiter
        };
        let guard = WaiterGuard {
            inner: self.inner.clone(),
            waiter,
        };
        loop {
            // Each cell has one waiter, so Notify's stored permit prevents a
            // grant between the state check and awaiting from being lost.
            let notified = guard.waiter.notify.notified();
            {
                let s = self.inner.lock();
                if s.closed {
                    return Err(QueueError::Closed);
                }
                if Instant::now() >= deadline {
                    return Err(QueueError::Timeout);
                }
                if guard.waiter.phase.load(Ordering::Relaxed) == GRANTED {
                    let permit = QueuePermit {
                        inner: self.inner.clone(),
                        bytes,
                        active: true,
                    };
                    guard.waiter.phase.store(CONSUMED, Ordering::Relaxed);
                    return Ok(permit);
                }
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => return Err(QueueError::Timeout),
                _ = notified => {}
            }
        }
    }

    /// On an ordinary error the original item is returned. Dropping the future
    /// cancels the reservation AND drops its item; use reserve() first when the
    /// caller needs to retain ownership during cancellation.
    pub async fn send(&self, item: T, deadline: Instant) -> Result<(), SendError<T>> {
        match self.reserve(item.queue_bytes(), deadline).await {
            Ok(permit) => permit.send(item),
            Err(error) => Err(SendError { error, item }),
        }
    }
}

impl<T: QueueItem> Clone for BufferSender<T> {
    fn clone(&self) -> Self {
        self.inner.lock().senders += 1;
        Self {
            inner: self.inner.clone(),
        }
    }
}
impl<T: QueueItem> Drop for BufferSender<T> {
    fn drop(&mut self) {
        let last = {
            let mut s = self.inner.lock();
            s.senders -= 1;
            s.senders == 0
        };
        if last {
            self.inner.readable.notify_one();
        }
    }
}
impl<T: QueueItem> fmt::Debug for BufferSender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot().fmt(f)
    }
}

struct WaiterGuard<T> {
    inner: Arc<Inner<T>>,
    waiter: Arc<Waiter>,
}
impl<T> Drop for WaiterGuard<T> {
    fn drop(&mut self) {
        let wakes = {
            let mut s = self.inner.lock();
            match self.waiter.phase.load(Ordering::Relaxed) {
                WAITING => {
                    if let Some(index) = s.waiters.iter().position(|w| Arc::ptr_eq(w, &self.waiter))
                    {
                        s.waiters.remove(index);
                    }
                    self.waiter.phase.store(CANCELLED, Ordering::Relaxed);
                }
                GRANTED => {
                    self.inner.release(&mut s, self.waiter.bytes);
                    self.waiter.phase.store(CANCELLED, Ordering::Relaxed);
                }
                _ => {}
            }
            self.inner.dispatch(&mut s)
        };
        wake(wakes);
        self.inner.readable.notify_one();
    }
}

/// Non-cloneable reservation. Successful send transfers the reservation to an
/// entry. Size mismatch or closure returns the item and refunds the reservation.
///
/// ```compile_fail
/// use terraris::buffer::QueuePermit;
/// fn duplicate(permit: QueuePermit<bytes::Bytes>) { let _ = permit.clone(); }
/// ```
#[must_use = "dropping a queue permit returns its byte and message capacity"]
pub struct QueuePermit<T: QueueItem> {
    inner: Arc<Inner<T>>,
    bytes: usize,
    active: bool,
}
impl<T: QueueItem> QueuePermit<T> {
    pub fn bytes(&self) -> usize {
        self.bytes
    }
    pub fn send(mut self, item: T) -> Result<(), SendError<T>> {
        if item.queue_bytes() != self.bytes {
            return Err(SendError {
                error: QueueError::SizeMismatch,
                item,
            });
        }
        {
            let mut s = self.inner.lock();
            if s.closed {
                return Err(SendError {
                    error: QueueError::Closed,
                    item,
                });
            }
            self.inner.release(&mut s, self.bytes);
            s.queued_bytes += self.bytes;
            s.items.push_back(Entry {
                item,
                bytes: self.bytes,
            });
            self.active = false;
        }
        self.inner.readable.notify_one();
        Ok(())
    }
}
impl<T: QueueItem> Drop for QueuePermit<T> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let wakes = {
            let mut s = self.inner.lock();
            self.inner.release(&mut s, self.bytes);
            self.inner.dispatch(&mut s)
        };
        self.active = false;
        wake(wakes);
        self.inner.readable.notify_one();
    }
}
impl<T: QueueItem> fmt::Debug for QueuePermit<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuePermit")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl<T: QueueItem> BufferQueue<T> {
    pub fn snapshot(&self) -> QueueSnapshot {
        self.inner.snapshot()
    }
    pub fn close(&mut self) {
        self.inner.close(false);
    }
    pub fn try_recv(&mut self) -> Result<T, QueueError> {
        let (entry, wakes) = {
            let mut s = self.inner.lock();
            if let Some(entry) = s.items.pop_front() {
                s.queued_bytes -= entry.bytes;
                let wakes = self.inner.dispatch(&mut s);
                (entry, wakes)
            } else if s.closed || (s.senders == 0 && s.reserved_messages == 0) {
                return Err(QueueError::Closed);
            } else {
                return Err(QueueError::Empty);
            }
        };
        wake(wakes);
        Ok(entry.item)
    }
    pub async fn recv(&mut self) -> Option<T> {
        loop {
            let inner = self.inner.clone();
            let notified = inner.readable.notified();
            match self.try_recv() {
                Ok(item) => return Some(item),
                Err(QueueError::Closed) => return None,
                Err(QueueError::Empty) => notified.await,
                Err(_) => unreachable!("receive only returns Empty or Closed"),
            }
        }
    }
}
impl<T: QueueItem> Drop for BufferQueue<T> {
    fn drop(&mut self) {
        self.inner.close(true);
    }
}
impl<T: QueueItem> fmt::Debug for BufferQueue<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot().fmt(f)
    }
}
