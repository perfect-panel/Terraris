// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    buffer::BufferScope,
    controller::Controller,
    panel::{CertificateFingerprint, ProtocolName},
    reports::Reports,
    runtime::{AdmissionGate, Error, GenerationId, PreparedListener, ProtocolDriver},
    task::{CancellationToken, TaskFailure, TaskGroup, TaskReport},
    telemetry::Metrics,
    time::{Deadline, OperationContext},
    users::{self, Identity, PreparedUpdate, SessionLease, Store},
};
use std::{
    future::{Future, poll_fn},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Mutex as AsyncMutex, Notify};

struct Inner {
    protocol: ProtocolName,
    generation: GenerationId,
    store: Store,
    reports: Reports,
    buffers: BufferScope,
    gate: Arc<AdmissionGate>,
    cancel: CancellationToken,
    tasks: Mutex<TaskGroup>,
    active: AtomicUsize,
    changed: Notify,
    metrics: Metrics,
}
#[derive(Clone)]
pub struct Core {
    inner: Arc<Inner>,
}
/// One owning lifecycle guard; clones handed to protocol tasks are only handles.
/// Dropping the owner aborts tasks even if a task captured a Core clone.
pub struct CoreOwner {
    core: Core,
}
impl CoreOwner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: ProtocolName,
        generation: GenerationId,
        store: Store,
        reports: Reports,
        buffers: BufferScope,
        gate: Arc<AdmissionGate>,
        parent: &CancellationToken,
        task_limit: usize,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        if !store.publication().same_domain(gate.publication()) {
            return Err(Error::WrongPublication);
        }
        let cancel = parent.child_token();
        let tasks = TaskGroup::new(&cancel, task_limit, metrics.clone()).map_err(Error::Task)?;
        Ok(Self {
            core: Core {
                inner: Arc::new(Inner {
                    protocol,
                    generation,
                    store,
                    reports,
                    buffers,
                    gate,
                    cancel,
                    tasks: Mutex::new(tasks),
                    active: AtomicUsize::new(0),
                    changed: Notify::new(),
                    metrics,
                }),
            },
        })
    }
    pub fn handle(&self) -> Core {
        self.core.clone()
    }
}
impl Drop for CoreOwner {
    fn drop(&mut self) {
        self.core.abort();
    }
}
impl Core {
    pub fn protocol(&self) -> &ProtocolName {
        &self.inner.protocol
    }
    pub fn generation(&self) -> GenerationId {
        self.inner.generation
    }
    pub fn users(&self) -> &Store {
        &self.inner.store
    }
    pub fn reports(&self) -> &Reports {
        &self.inner.reports
    }
    pub fn buffers(&self) -> &BufferScope {
        &self.inner.buffers
    }
    pub fn metrics(&self) -> &Metrics {
        &self.inner.metrics
    }
    pub fn gate(&self) -> &Arc<AdmissionGate> {
        &self.inner.gate
    }
    pub fn cancellation(&self) -> &CancellationToken {
        &self.inner.cancel
    }
    pub fn is_closed(&self) -> bool {
        self.inner.cancel.is_cancelled()
    }
    pub fn is_current(&self) -> bool {
        !self.is_closed()
            && self.inner.gate.is_open()
            && self.inner.store.is_owner(self.inner.generation)
    }
    pub fn active_sessions(&self) -> usize {
        self.inner.active.load(Ordering::Acquire)
    }
    pub fn admit(&self, identity: &Identity) -> Result<AdmissionLease, Error> {
        let permit = self.inner.store.publication().read();
        if self.is_closed() {
            return Err(Error::Closed);
        }
        if !self.inner.gate.is_open() {
            return Err(Error::NotReady);
        }
        let session = self
            .inner
            .store
            .acquire(&permit, self.inner.generation, identity, &self.inner.cancel)
            .map_err(Error::Users)?;
        self.inner.active.fetch_add(1, Ordering::AcqRel);
        Ok(AdmissionLease {
            session,
            active: ActiveLease(self.inner.clone()),
        })
    }
    pub fn spawn<F, Fut>(&self, name: &'static str, factory: F) -> Result<tokio::task::Id, Error>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskFailure>> + Send + 'static,
    {
        if self.is_closed() {
            return Err(Error::Closed);
        }
        let mut tasks = self.inner.tasks.lock().unwrap_or_else(|e| e.into_inner());
        // Completed outcomes are reflected in Metrics; no unbounded result queue.
        while tasks.try_join_next().is_some() {}
        tasks.spawn(name, factory).map_err(Error::Task)
    }
    pub fn reap_tasks(&self) -> Vec<TaskReport> {
        let mut tasks = self.inner.tasks.lock().unwrap_or_else(|e| e.into_inner());
        let mut reports = Vec::new();
        while let Some(report) = tasks.try_join_next() {
            reports.push(report);
        }
        reports
    }
    pub fn abort(&self) {
        self.inner.cancel.cancel();
        self.inner
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .abort_all();
    }
    pub async fn drain(&self, context: &OperationContext) -> Result<(), Error> {
        context
            .run(async {
                loop {
                    let changed = self.inner.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if self.active_sessions() == 0 {
                        return;
                    }
                    changed.await;
                }
            })
            .await
            .map_err(Error::Stopped)
    }
    /// JoinSet remains inside Core if this future is cancelled. A later close
    /// can continue joining; taking/dropping a local JoinSet would detach cleanup.
    pub async fn shutdown(&self, deadline: Deadline) {
        self.inner.cancel.cancel();
        self.inner
            .tasks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancel();
        loop {
            tokio::select! {biased;
                _=deadline.wait()=>{self.inner.tasks.lock().unwrap_or_else(|e|e.into_inner()).abort_all();break;}
                result=poll_fn(|cx|self.inner.tasks.lock().unwrap_or_else(|e|e.into_inner()).poll_join_next(cx))=>{if result.is_none(){return;}}
            }
        }
        while poll_fn(|cx| {
            self.inner
                .tasks
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .poll_join_next(cx)
        })
        .await
        .is_some()
        {}
    }
}
pub struct AdmissionLease {
    session: SessionLease,
    active: ActiveLease,
}
impl AdmissionLease {
    pub fn context(&self, deadline: Option<Deadline>) -> OperationContext {
        self.session.context(deadline)
    }
    pub fn current_user(&self) -> Result<crate::panel::User, users::Error> {
        self.session.current_user()
    }
    pub fn identity(&self) -> &Identity {
        self.session.identity()
    }
    pub fn generation(&self) -> GenerationId {
        self.active.0.generation
    }
}
struct ActiveLease(Arc<Inner>);
impl Drop for ActiveLease {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}

struct Listener {
    value: Box<dyn PreparedListener>,
    committed: bool,
    stopped: bool,
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.value.abort();
    }
}
pub struct Runtime {
    owner: CoreOwner,
    driver: Arc<dyn ProtocolDriver>,
    pub controller: Arc<Controller>,
    listener: Mutex<Option<Listener>>,
    users: Mutex<Option<PreparedUpdate>>,
    close_gate: AsyncMutex<()>,
    closed: std::sync::atomic::AtomicBool,
}
impl Runtime {
    pub(crate) fn new(
        owner: CoreOwner,
        driver: Arc<dyn ProtocolDriver>,
        controller: Arc<Controller>,
    ) -> Self {
        Self {
            owner,
            driver,
            controller,
            listener: Mutex::new(None),
            users: Mutex::new(None),
            close_gate: AsyncMutex::new(()),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub fn core(&self) -> Core {
        self.owner.handle()
    }
    pub fn certificate(&self) -> Option<CertificateFingerprint> {
        self.driver.certificate()
    }
    pub(crate) async fn prepare_control(&self, context: &OperationContext) -> Result<(), Error> {
        if self.core().is_closed()
            || self.core().gate().is_open()
            || self
                .users
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        {
            return Err(Error::InvalidState);
        }
        let prepared = self
            .controller
            .prepare(context)
            .await
            .map_err(|_| Error::Preparation("users"))?;
        *self.users.lock().unwrap_or_else(|e| e.into_inner()) = Some(prepared);
        Ok(())
    }
    pub(crate) async fn prepare_listener(&self, context: &OperationContext) -> Result<(), Error> {
        if self.core().is_closed()
            || self.core().gate().is_open()
            || self
                .listener
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
        {
            return Err(Error::InvalidState);
        }
        let listener = context
            .run(self.driver.prepare_listener(context))
            .await
            .map_err(Error::Stopped)??;
        *self.listener.lock().unwrap_or_else(|e| e.into_inner()) = Some(Listener {
            value: listener,
            committed: false,
            stopped: false,
        });
        Ok(())
    }
    pub(crate) fn validate(&self, permit: &crate::runtime::WritePermit<'_>) -> Result<(), Error> {
        self.users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .ok_or(Error::InvalidState)?
            .validate(self.core().users(), permit)
            .map_err(Error::Users)
    }
    pub(crate) fn publish_private_users(
        &self,
        permit: &crate::runtime::WritePermit<'_>,
    ) -> Result<(), Error> {
        self.users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_mut()
            .ok_or(Error::InvalidState)?
            .commit_auth(permit)
            .map_err(Error::Users)
    }
    pub(crate) fn commit_listener(&self) -> Result<(), Error> {
        let mut guard = self.listener.lock().unwrap_or_else(|e| e.into_inner());
        let listener = guard.as_mut().ok_or(Error::InvalidState)?;
        if !listener.committed {
            listener.value.commit()?;
            listener.committed = true;
        }
        Ok(())
    }
    pub(crate) fn publish_store(&self, permit: &mut crate::runtime::WritePermit<'_>) {
        let mut prepared = self
            .users
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("prepared users");
        prepared.publish(self.core().users(), permit, Some(self.core().generation()));
    }
    /// Synchronous fallback for an abandoned generation, including when callers
    /// still hold runtime handles. Explicit close remains responsible for join.
    pub fn abort(&self) {
        self.driver.abort();
        self.core().abort();
        self.listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }
    pub fn stop_accepting(&self) -> Result<(), Error> {
        let mut listener = self.listener.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(listener) = listener.as_mut()
            && !listener.stopped
        {
            listener.value.stop_accepting()?;
            listener.stopped = true;
        }
        Ok(())
    }
    pub async fn drain(&self, context: &OperationContext) -> Result<(), Error> {
        self.core().drain(context).await
    }
    pub async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        let _guard = self.close_gate.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Ok(());
        }
        let stop = self.stop_accepting();
        self.driver.abort();
        self.core().abort();
        self.core()
            .shutdown(
                context
                    .deadline()
                    .unwrap_or_else(|| Deadline::at(tokio::time::Instant::now())),
            )
            .await;
        let driver = context
            .run(self.driver.close(context))
            .await
            .map_err(Error::Stopped)?;
        self.listener
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.users.lock().unwrap_or_else(|e| e.into_inner()).take();
        driver?;
        stop?;
        self.closed.store(true, Ordering::Release);
        Ok(())
    }
}
impl Drop for Runtime {
    fn drop(&mut self) {
        self.driver.abort();
        self.owner.core.abort();
    }
}
