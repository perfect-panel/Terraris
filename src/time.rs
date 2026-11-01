// SPDX-License-Identifier: GPL-3.0-only

//! Monotonic operation deadlines and separately typed wall-clock timestamps.

use std::{
    fmt,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Notify;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    DeadlineOverflow,
    BeforeUnixEpoch,
    TimestampOverflow,
    AlreadyConstrained,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DeadlineOverflow => "deadline overflows monotonic clock",
            Self::BeforeUnixEpoch => "wall clock precedes Unix epoch",
            Self::TimestampOverflow => "Unix millisecond timestamp overflows i64",
            Self::AlreadyConstrained => "operation already has another revocation constraint",
        })
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline(Instant);
impl Deadline {
    pub fn at(instant: Instant) -> Self {
        Self(instant)
    }
    pub fn after(duration: Duration) -> Result<Self, Error> {
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(Error::DeadlineOverflow)
    }
    pub fn instant(self) -> Instant {
        self.0
    }
    pub fn is_elapsed(self) -> bool {
        Instant::now() >= self.0
    }
    pub async fn wait(self) {
        tokio::time::sleep_until(self.0).await;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct UnixMillis(i64);
impl UnixMillis {
    pub fn now() -> Result<Self, Error> {
        Self::from_system_time(SystemTime::now())
    }
    pub fn from_system_time(time: SystemTime) -> Result<Self, Error> {
        let millis = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::BeforeUnixEpoch)?
            .as_millis();
        Ok(Self(
            i64::try_from(millis).map_err(|_| Error::TimestampOverflow)?,
        ))
    }
    pub fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    Cancelled,
    DeadlineExceeded,
}
impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cancelled => "operation cancelled",
            Self::DeadlineExceeded => "operation deadline exceeded",
        })
    }
}
impl std::error::Error for StopReason {}

#[derive(Clone, Debug)]
/// ```
/// use terraris::{task::CancellationToken, time::{Deadline, OperationContext}};
/// use std::time::Duration;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let operation = OperationContext::new(CancellationToken::new(), Some(Deadline::after(Duration::from_secs(1))?));
/// assert_eq!(operation.run(async { 42 }).await?, 42);
/// let child = operation.child();
/// child.cancellation().cancel();
/// assert!(child.check().is_err());
/// assert!(operation.check().is_ok());
/// # Ok(())
/// # }
/// ```
pub struct OperationContext {
    cancellation: CancellationToken,
    deadline: Option<Deadline>,
    revocation: Option<Revocation>,
}
impl OperationContext {
    pub fn new(cancellation: CancellationToken, deadline: Option<Deadline>) -> Self {
        Self {
            cancellation,
            deadline,
            revocation: None,
        }
    }
    pub fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
    pub fn deadline(&self) -> Option<Deadline> {
        self.deadline
    }
    pub fn child(&self) -> Self {
        Self {
            cancellation: self.cancellation.child_token(),
            deadline: self.deadline,
            revocation: self.revocation.clone(),
        }
    }
    /// A child may shorten, but never extend, its parent's deadline.
    pub fn child_with_deadline(&self, deadline: Deadline) -> Self {
        Self {
            cancellation: self.cancellation.child_token(),
            deadline: Some(
                self.deadline
                    .map_or(deadline, |parent| parent.min(deadline)),
            ),
            revocation: self.revocation.clone(),
        }
    }
    pub fn with_revocation(mut self, revocation: Revocation) -> Result<Self, Error> {
        if self
            .revocation
            .as_ref()
            .is_some_and(|old| !Arc::ptr_eq(&old.inner, &revocation.inner))
        {
            return Err(Error::AlreadyConstrained);
        }
        self.revocation = Some(revocation);
        Ok(self)
    }
    pub fn check(&self) -> Result<(), StopReason> {
        if self.cancellation.is_cancelled()
            || self.revocation.as_ref().is_some_and(Revocation::is_revoked)
        {
            Err(StopReason::Cancelled)
        } else if self.deadline.is_some_and(Deadline::is_elapsed) {
            Err(StopReason::DeadlineExceeded)
        } else {
            Ok(())
        }
    }
    /// Cancellation/expiry already observed before polling wins over ready work.
    /// After a future completes, its result is not discarded by a second check:
    /// an accepted I/O write must remain observable and countable.
    pub async fn run<F: Future>(&self, future: F) -> Result<F::Output, StopReason> {
        self.check()?;
        tokio::select! {
            biased;
            _=self.cancellation.cancelled()=>Err(StopReason::Cancelled),
            _=self.wait_revocation()=>Err(StopReason::Cancelled),
            _=self.wait_deadline()=>Err(StopReason::DeadlineExceeded),
            value=future=>Ok(value),
        }
    }
    async fn wait_deadline(&self) {
        if let Some(deadline) = self.deadline {
            deadline.wait().await;
        } else {
            std::future::pending::<()>().await;
        }
    }
    async fn wait_revocation(&self) {
        if let Some(signal) = &self.revocation {
            signal.revoked().await;
        } else {
            std::future::pending::<()>().await;
        }
    }
}

/// A monotonic revocation flag whose publication and wakeup can be separated.
/// Committers mark under their publication lock, then wake after unlocking.
#[derive(Clone, Default)]
pub struct Revocation {
    inner: Arc<RevocationInner>,
}
#[derive(Default)]
struct RevocationInner {
    revoked: AtomicBool,
    notify: Notify,
}
impl Revocation {
    pub fn is_revoked(&self) -> bool {
        self.inner.revoked.load(Ordering::Acquire)
    }
    pub fn revoke(&self) {
        self.mark();
        self.notify();
    }
    pub(crate) fn mark(&self) {
        self.inner.revoked.store(true, Ordering::Release);
    }
    pub(crate) fn notify(&self) {
        self.inner.notify.notify_waiters();
    }
    pub async fn revoked(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_revoked() {
                return;
            }
            notified.await;
        }
    }
}
impl fmt::Debug for Revocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Revocation")
            .field("revoked", &self.is_revoked())
            .finish()
    }
}
