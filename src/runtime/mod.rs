// SPDX-License-Identifier: GPL-3.0-only

//! Protocol-independent lifecycle ports. Implementations must be rollback-safe
//! during preparation. Connection work belongs to Core; shared services own
//! bounded task groups that are joined by their explicit close lifecycle.

mod publication;
pub use publication::{Publication, ReadPermit, WritePermit};

use crate::{
    panel::{CertificateFingerprint, ProtocolConfig, ProtocolName, ServerConfig},
    protocol::runtimekit::Core,
    time::{OperationContext, StopReason},
    users,
};
use async_trait::async_trait;
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct GenerationId(u64);
impl GenerationId {
    pub fn new(value: u64) -> Result<Self, Error> {
        if value == 0 {
            return Err(Error::InvalidState);
        }
        Ok(Self(value))
    }
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidState,
    Closed,
    NotReady,
    WrongPublication,
    Unsupported,
    Preparation(&'static str),
    Commit(&'static str),
    Stopped(StopReason),
    Users(users::Error),
    Resource(crate::resource::Error),
    Task(crate::task::SpawnError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "runtime: {self:?}")
    }
}
impl std::error::Error for Error {}

pub struct AdmissionGate {
    publication: Publication,
    open: AtomicBool,
}
impl AdmissionGate {
    pub fn new(publication: Publication) -> Self {
        Self {
            publication,
            open: AtomicBool::new(false),
        }
    }
    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }
    pub(crate) fn set(&self, permit: &WritePermit<'_>, open: bool) {
        assert!(self.publication.owns_write(permit));
        self.open.store(open, Ordering::Release);
    }
    pub fn publication(&self) -> &Publication {
        &self.publication
    }
    pub fn close(&self) {
        let guard = self.publication.write(0);
        self.set(&guard, false);
    }
}

pub trait PreparedListener: Send + Sync {
    /// Local, bounded handoff only. Generation admission is still closed.
    /// Must not perform I/O, panic, or reenter Core/publication APIs.
    /// Failure may discard the private candidate, but must leave live listeners intact.
    fn commit(&mut self) -> Result<(), Error>;
    fn stop_accepting(&mut self) -> Result<(), Error>;
    /// Synchronous cancellation/close fallback; must be idempotent.
    fn abort(&mut self);
}

#[async_trait]
pub trait ProtocolDriver: users::AuthUpdater + Send + Sync {
    async fn prepare_listener(
        &self,
        context: &OperationContext,
    ) -> Result<Box<dyn PreparedListener>, Error>;
    fn certificate(&self) -> Option<CertificateFingerprint> {
        None
    }
    /// Both abort and close must be idempotent; close may be retried after cancellation.
    fn abort(&self);
    async fn close(&self, context: &OperationContext) -> Result<(), Error>;
}

#[async_trait]
pub trait SharedServices: Send + Sync + 'static {
    /// Both abort and close must be idempotent; close may be retried after cancellation.
    fn abort(&self);
    async fn close(&self, context: &OperationContext) -> Result<(), Error>;
}

#[async_trait]
/// Preparation futures must own and release partial resources on cancellation.
/// Connection work belongs to Core. Shared ingress/resolver work must retain
/// bounded owning task groups and join them in its explicit close lifecycle.
/// Check Core admission for every connection, UDP association and multiplexed
/// substream before proxy traffic.
pub trait RuntimeFactory: Send + Sync + 'static {
    type Shared: SharedServices;
    /// Process-owned services outlive individual generations. One factory belongs
    /// to one Supervisor lifecycle. Factories without such services need no
    /// shutdown work. Both methods must be idempotent.
    fn abort(&self) {}
    async fn close(&self, _context: &OperationContext) -> Result<(), Error> {
        Ok(())
    }

    fn supports(&self, protocol: &ProtocolName) -> bool;
    /// Validate and compile all non-default shared DNS/routing/outbound fields.
    /// Returning success while silently ignoring unsupported policy is invalid.
    async fn prepare_shared(
        &self,
        config: Arc<ServerConfig>,
        buffers: crate::buffer::BufferScope,
        context: &OperationContext,
    ) -> Result<Self::Shared, Error>;
    /// A new private protocol/auth state for this candidate, never the currently
    /// active driver. Validate protocol-specific security/transport options here.
    async fn prepare_protocol(
        &self,
        config: ProtocolConfig,
        shared: Arc<Self::Shared>,
        core: Core,
        context: &OperationContext,
    ) -> Result<Arc<dyn ProtocolDriver>, Error>;
}
