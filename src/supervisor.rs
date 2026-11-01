// SPDX-License-Identifier: GPL-3.0-only

//! Transactional generation coordinator. Runtime factories supply actual wire
//! engines; this module never installs a placeholder proxy listener.

use crate::{
    buffer::BufferScope,
    controller::{self, Controller},
    panel::{
        self, Connection, Fetch, NodeStatus, ProtocolClient, ProtocolName, ServerConfig, Validator,
    },
    protocol::runtimekit::{CoreOwner, Runtime},
    reports::Reports,
    runtime::{self, AdmissionGate, GenerationId, Publication, RuntimeFactory, SharedServices},
    scheduler::{self, JobSpec, Lane, Schedule, Scheduler},
    task::{CancellationToken, TaskGroup},
    telemetry::Metrics,
    time::{Deadline, OperationContext, StopReason},
    users::{self, Store},
};
use async_trait::async_trait;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidOptions,
    Closed,
    Capacity,
    MissingConfig,
    RequiredProtocol,
    DuplicateProtocol,
    PortConflict,
    Panel(panel::Error),
    Runtime(runtime::Error),
    Users(users::Error),
    Controller(controller::Error),
    Scheduler(scheduler::Error),
    Stopped(StopReason),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "supervisor: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone)]
pub struct Options {
    pub max_protocols: usize,
    pub max_scopes: usize,
    pub max_retired: usize,
    pub runtime_tasks: usize,
    pub report_entries: usize,
    pub users: users::Limits,
    pub scheduler: scheduler::Limits,
    pub config_interval: Duration,
    pub operation_timeout: Duration,
    pub drain_timeout: Duration,
    pub close_timeout: Duration,
    pub required_protocols: BTreeSet<ProtocolName>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            max_protocols: 16,
            max_scopes: 32,
            max_retired: 2,
            runtime_tasks: 4096,
            report_entries: 100_000,
            users: users::Limits {
                max_users: 100_000,
                max_sessions: 100_000,
                max_age: Duration::from_secs(900),
            },
            scheduler: scheduler::Limits {
                max_jobs: 128,
                concurrency: 8,
                critical_reserve: 2,
            },
            config_interval: Duration::from_secs(30),
            operation_timeout: Duration::from_secs(15),
            drain_timeout: Duration::from_secs(30),
            close_timeout: Duration::from_secs(5),
            required_protocols: BTreeSet::new(),
        }
    }
}
#[async_trait]
pub trait StatusSampler: Send + Sync {
    async fn sample(&self, context: &OperationContext) -> Result<NodeStatus, runtime::Error>;
}
/// A complete map is prepared before publication. Replacing it must be local,
/// infallible and non-reentrant; implementations must not perform I/O.
pub trait FingerprintSink: Send + Sync {
    fn replace(&self, values: BTreeMap<ProtocolName, panel::CertificateFingerprint>);
}

#[derive(Clone)]
struct Scope {
    users: Store,
    reports: Reports,
    client: Arc<dyn ProtocolClient>,
}
struct SharedOwner<S: SharedServices>(Arc<S>);
impl<S: SharedServices> Drop for SharedOwner<S> {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Completion(CancellationToken);
impl Drop for Completion {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
struct Maintenance {
    cancel: CancellationToken,
    start: CancellationToken,
    done: CancellationToken,
    tasks: AsyncMutex<TaskGroup>,
}
impl Maintenance {
    fn prepare(
        scheduler: Scheduler,
        parent: &CancellationToken,
        previous: CancellationToken,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        let cancel = parent.child_token();
        let start = CancellationToken::new();
        let done = CancellationToken::new();
        let completion = Completion(done.clone());
        let mut tasks = TaskGroup::new(&cancel, 1, metrics)
            .map_err(|e| Error::Runtime(runtime::Error::Task(e)))?;
        let begin = start.clone();
        tasks
            .spawn("maintenance", move |cancel| async move {
                let _completion = completion;
                let context = OperationContext::new(cancel, None);
                if context.run(begin.cancelled()).await.is_err() {
                    return Ok(());
                }
                if context.run(previous.cancelled()).await.is_err() {
                    return Ok(());
                }
                scheduler
                    .run(&context)
                    .await
                    .map_err(|_| crate::task::TaskFailure::Failed("scheduler"))
            })
            .map_err(|e| Error::Runtime(runtime::Error::Task(e)))?;
        Ok(Self {
            cancel,
            start,
            done,
            tasks: AsyncMutex::new(tasks),
        })
    }
    async fn close(&self, deadline: Deadline) {
        self.cancel.cancel();
        self.tasks.lock().await.shutdown(deadline).await;
    }
}
impl Drop for Maintenance {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.get_mut().abort_all();
    }
}
struct Generation<S: SharedServices> {
    id: GenerationId,
    gate: Arc<AdmissionGate>,
    runtimes: BTreeMap<ProtocolName, Arc<Runtime>>,
    shared: SharedOwner<S>,
    maintenance: Option<Maintenance>,
    drain_deadline: Mutex<Option<Deadline>>,
}
impl<S: SharedServices> Generation<S> {
    fn retire(&self, drain: Duration) {
        self.drain_deadline
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert_with(|| Deadline::after(drain).expect("validated duration"));
        if let Some(m) = &self.maintenance {
            m.cancel.cancel();
        }
        for runtime in self.runtimes.values() {
            if runtime.stop_accepting().is_err() {
                runtime.abort();
            }
        }
    }
    async fn close(&self, drain: Duration, close: Duration) -> Result<(), Error> {
        self.retire(drain);
        let context = OperationContext::new(
            CancellationToken::new(),
            *self
                .drain_deadline
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        );
        for runtime in self.runtimes.values() {
            let _ = runtime.drain(&context).await;
        }
        let context = OperationContext::new(
            CancellationToken::new(),
            Some(Deadline::after(close).expect("validated duration")),
        );
        if let Some(m) = &self.maintenance {
            m.close(context.deadline().expect("close deadline")).await;
        }
        let mut result = Ok(());
        for runtime in self.runtimes.values() {
            if let Err(e) = runtime.close(&context).await {
                result = Err(Error::Runtime(e));
            }
        }
        self.shared.0.abort();
        match context.run(self.shared.0.close(&context)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => result = Err(Error::Runtime(e)),
            Err(e) => result = Err(Error::Stopped(e)),
        }
        result
    }
}
impl<S: SharedServices> Drop for Generation<S> {
    fn drop(&mut self) {
        if let Some(m) = &self.maintenance {
            m.cancel.cancel();
        }
        for runtime in self.runtimes.values() {
            runtime.abort();
        }
    }
}
struct State<S: SharedServices> {
    active: Option<Arc<Generation<S>>>,
    retired: Vec<Arc<Generation<S>>>,
    scopes: BTreeMap<ProtocolName, Scope>,
    config: Option<Arc<ServerConfig>>,
    validator: Option<Validator>,
    next: u64,
    last_error: Option<Error>,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub generation: Option<GenerationId>,
    pub protocols: Vec<ProtocolName>,
    pub ready: bool,
    pub retired: usize,
    pub scopes: usize,
    pub last_error: Option<Error>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncOutcome {
    Unchanged,
    Published(GenerationId),
}
pub struct Supervisor<F: RuntimeFactory> {
    connection: Arc<dyn Connection>,
    factory: Arc<F>,
    buffers: BufferScope,
    options: Options,
    metrics: Metrics,
    publication: Publication,
    cancel: CancellationToken,
    closed: AtomicBool,
    running: AtomicBool,
    transition: AsyncMutex<()>,
    cleanup: AsyncMutex<()>,
    state: Mutex<State<F::Shared>>,
    sampler: Option<Arc<dyn StatusSampler>>,
    fingerprints: Arc<dyn FingerprintSink>,
}
impl<F: RuntimeFactory> Supervisor<F> {
    pub fn new(
        connection: Arc<dyn Connection>,
        factory: Arc<F>,
        buffers: BufferScope,
        options: Options,
        metrics: Metrics,
        fingerprints: Arc<dyn FingerprintSink>,
        sampler: Option<Arc<dyn StatusSampler>>,
    ) -> Result<Self, Error> {
        if options.max_protocols == 0
            || options.max_scopes < options.max_protocols
            || options.max_retired == 0
            || options.runtime_tasks == 0
            || options.report_entries == 0
            || options.users.validate().is_err()
            || options.scheduler.critical_reserve == 0
            || options.scheduler.concurrency < 2
            || options.scheduler.max_jobs
                < options.max_protocols.saturating_mul(5).saturating_add(1)
        {
            return Err(Error::InvalidOptions);
        }
        for duration in [
            options.config_interval,
            options.operation_timeout,
            options.drain_timeout,
            options.close_timeout,
        ] {
            if duration.is_zero() || Deadline::after(duration).is_err() {
                return Err(Error::InvalidOptions);
            }
        }
        Scheduler::new(options.scheduler, vec![]).map_err(Error::Scheduler)?;
        Ok(Self {
            connection,
            factory,
            buffers,
            options,
            metrics,
            publication: Publication::default(),
            cancel: CancellationToken::new(),
            closed: AtomicBool::new(false),
            running: AtomicBool::new(false),
            transition: AsyncMutex::new(()),
            cleanup: AsyncMutex::new(()),
            state: Mutex::new(State {
                active: None,
                retired: Vec::new(),
                scopes: BTreeMap::new(),
                config: None,
                validator: None,
                next: 1,
                last_error: None,
            }),
            sampler,
            fingerprints,
        })
    }
    pub fn snapshot(&self) -> Snapshot {
        let _permit = self.publication.read();
        let s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let protocols = s
            .active
            .as_ref()
            .map(|g| g.runtimes.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        Snapshot {
            generation: s.active.as_ref().map(|g| g.id),
            ready: !self.closed.load(Ordering::Acquire)
                && !protocols.is_empty()
                && s.active.as_ref().is_some_and(|g| {
                    g.gate.is_open()
                        && g.runtimes.values().all(|runtime| {
                            !runtime.core().is_closed()
                                && runtime.core().users().fresh_with(&_permit)
                        })
                }),
            protocols,
            retired: s.retired.len(),
            scopes: s.scopes.len(),
            last_error: s.last_error.clone(),
        }
    }
    pub fn runtime(&self, name: &ProtocolName) -> Option<Arc<Runtime>> {
        let _permit = self.publication.read();
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active
            .as_ref()?
            .runtimes
            .get(name)
            .cloned()
    }
    pub fn reports(&self, name: &ProtocolName) -> Option<Reports> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scopes
            .get(name)
            .map(|s| s.reports.clone())
    }
    pub async fn sync_config(&self, context: &OperationContext) -> Result<SyncOutcome, Error> {
        let _transition = context
            .run(self.transition.lock())
            .await
            .map_err(Error::Stopped)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let result = self.sync_inner(context).await;
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_error = result.as_ref().err().cloned();
        result
    }
    async fn sync_inner(&self, context: &OperationContext) -> Result<SyncOutcome, Error> {
        let validator = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .validator
            .clone();
        let response = context
            .run(self.connection.server().get_config(validator.as_ref()))
            .await
            .map_err(Error::Stopped)?
            .map_err(Error::Panel)?;
        context.check().map_err(Error::Stopped)?;
        let active = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active
            .clone();
        // A replacement configuration may intentionally remove an unavailable asset.
        let replaces = matches!(&response, Fetch::Changed{value,..} if self.state.lock().unwrap_or_else(|e|e.into_inner()).config.as_ref().is_none_or(|current|**current != *value));
        let refresh = active
            .as_ref()
            .filter(|_| !replaces)
            .map(|active| {
                let mut refresh = active.shared.0.reload_required()?;
                for runtime in active.runtimes.values() {
                    refresh |= runtime.reload_required()?;
                }
                Ok::<_, runtime::Error>(refresh)
            })
            .transpose()
            .map_err(Error::Runtime)?
            .unwrap_or(false);
        let (config, validator) = match response {
            Fetch::Unchanged { validator } => {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let config = state.config.clone().ok_or(Error::MissingConfig)?;
                if !refresh {
                    state.validator = Some(validator);
                    return Ok(SyncOutcome::Unchanged);
                }
                (config, validator)
            }
            Fetch::Changed { value, validator } => (Arc::new(value), validator),
        };
        let (id, mut scopes, previous) = {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !refresh
                && s.config
                    .as_ref()
                    .is_some_and(|current| **current == *config)
            {
                s.validator = Some(validator);
                return Ok(SyncOutcome::Unchanged);
            }
            if s.retired.len() >= self.options.max_retired {
                return Err(Error::Capacity);
            }
            let id = GenerationId::new(s.next).map_err(Error::Runtime)?;
            s.next = s.next.checked_add(1).ok_or(Error::Capacity)?;
            let previous = s
                .active
                .as_ref()
                .and_then(|g| g.maintenance.as_ref())
                .map(|m| m.done.clone())
                .unwrap_or_else(|| {
                    let token = CancellationToken::new();
                    token.cancel();
                    token
                });
            (id, s.scopes.clone(), previous)
        };
        let selected = self.select(&config)?;
        for p in &selected {
            if !scopes.contains_key(&p.protocol) {
                if scopes.len() >= self.options.max_scopes {
                    return Err(Error::Capacity);
                }
                let scope = Scope {
                    users: Store::new(self.publication.clone(), self.options.users)
                        .map_err(Error::Users)?,
                    reports: Reports::new(self.options.report_entries)
                        .map_err(|_| Error::InvalidOptions)?,
                    client: self
                        .connection
                        .protocol(p.protocol.as_str())
                        .map_err(Error::Panel)?,
                };
                scopes.insert(p.protocol.clone(), scope);
            }
        }
        let shared = context
            .run(
                self.factory
                    .prepare_shared(config.clone(), self.buffers.clone(), context),
            )
            .await
            .map_err(Error::Stopped)?
            .map_err(Error::Runtime)?;
        let mut candidate = Generation {
            id,
            gate: Arc::new(AdmissionGate::new(self.publication.clone())),
            runtimes: BTreeMap::new(),
            shared: SharedOwner(Arc::new(shared)),
            maintenance: None,
            drain_deadline: Mutex::new(None),
        };
        let prepared = self
            .prepare(
                &mut candidate,
                selected,
                &scopes,
                config.clone(),
                previous,
                context,
            )
            .await;
        if let Err(error) = prepared {
            let _ = candidate
                .close(Duration::ZERO, self.options.close_timeout)
                .await;
            return Err(error);
        }
        let active_names: BTreeSet<_> = candidate.runtimes.keys().cloned().collect();
        let removed: Vec<_> = scopes
            .iter()
            .filter(|(name, scope)| {
                !active_names.contains(*name) && scope.users.view().writer.is_some()
            })
            .map(|(_, scope)| {
                scope
                    .users
                    .candidate(scope.users.view(), vec![], None)
                    .map(|candidate| (scope.users.clone(), candidate))
            })
            .collect::<Result<_, _>>()
            .map_err(Error::Users)?;
        let fingerprints = candidate
            .runtimes
            .iter()
            .filter_map(|(name, runtime)| runtime.certificate().map(|value| (name.clone(), value)))
            .collect();
        let candidate = Arc::new(candidate);
        let publication = (|| {
            let mut permit = self
                .publication
                .write(candidate.runtimes.len() + removed.len());
            context.check().map_err(Error::Stopped)?;
            if self.closed.load(Ordering::Acquire) {
                return Err(Error::Closed);
            }
            for runtime in candidate.runtimes.values() {
                runtime.validate(&permit).map_err(Error::Runtime)?;
            }
            for (store, update) in &removed {
                store
                    .validate_candidate(&permit, update)
                    .map_err(Error::Users)?;
            }
            for runtime in candidate.runtimes.values() {
                runtime
                    .publish_private_users(&permit)
                    .map_err(Error::Runtime)?;
            }
            for runtime in candidate.runtimes.values() {
                runtime.commit_listener().map_err(Error::Runtime)?;
            }
            // Nothing fallible after this point; never check late cancellation.
            for runtime in candidate.runtimes.values() {
                runtime.publish_store(&mut permit);
            }
            for (store, update) in removed {
                store.publish(&mut permit, update, None);
            }
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(old) = s.active.take() {
                old.gate.set(&permit, false);
                s.retired.push(old);
            }
            self.fingerprints.replace(fingerprints);
            s.scopes = scopes;
            s.config = Some(config);
            s.validator = Some(validator);
            s.active = Some(candidate.clone());
            candidate.gate.set(&permit, true);
            Ok(())
        })();
        if let Err(error) = publication {
            let _ = candidate
                .close(Duration::ZERO, self.options.close_timeout)
                .await;
            return Err(error);
        }
        self.factory.published(candidate.shared.0.as_ref());
        // Wakes and listener stop happen outside the publication lock. The new
        // maintenance task waits until its predecessor's futures are dropped.
        let retired = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retired
            .clone();
        for old in &retired {
            if old.shared.0.invalidates(candidate.shared.0.as_ref()) {
                for runtime in old.runtimes.values() {
                    runtime.core().abort();
                }
            }
        }
        if let Some(old) = retired.last() {
            old.retire(self.options.drain_timeout);
        }
        if let Some(m) = &candidate.maintenance {
            m.start.cancel();
        }
        Ok(SyncOutcome::Published(id))
    }
    fn select(&self, config: &ServerConfig) -> Result<Vec<panel::ProtocolConfig>, Error> {
        if config.protocols.len() > self.options.max_protocols {
            return Err(Error::Capacity);
        }
        let mut names = BTreeSet::new();
        let mut ports = BTreeSet::new();
        let mut selected = Vec::new();
        for protocol in &config.protocols {
            if !names.insert(protocol.protocol.clone()) {
                return Err(Error::DuplicateProtocol);
            }
            if !protocol.enabled {
                continue;
            }
            if !self.factory.supports(&protocol.protocol) {
                continue;
            }
            if protocol.port == 0 || !ports.insert(protocol.port) {
                return Err(Error::PortConflict);
            }
            selected.push(protocol.clone());
        }
        if config.protocols.iter().any(|protocol| protocol.enabled)
            && self
                .options
                .required_protocols
                .iter()
                .any(|required| !selected.iter().any(|p| &p.protocol == required))
        {
            return Err(Error::RequiredProtocol);
        }
        Ok(selected)
    }
    async fn prepare(
        &self,
        candidate: &mut Generation<F::Shared>,
        selected: Vec<panel::ProtocolConfig>,
        scopes: &BTreeMap<ProtocolName, Scope>,
        config: Arc<ServerConfig>,
        previous: CancellationToken,
        context: &OperationContext,
    ) -> Result<(), Error> {
        for protocol in selected {
            let scope = &scopes[&protocol.protocol];
            let owner = CoreOwner::new(
                protocol.protocol.clone(),
                candidate.id,
                scope.users.clone(),
                scope.reports.clone(),
                self.buffers.clone(),
                candidate.gate.clone(),
                &self.cancel,
                self.options.runtime_tasks,
                self.metrics.clone(),
            )
            .map_err(Error::Runtime)?;
            let driver = context
                .run(self.factory.prepare_protocol(
                    protocol,
                    candidate.shared.0.clone(),
                    owner.handle(),
                    context,
                ))
                .await
                .map_err(Error::Stopped)?
                .map_err(Error::Runtime)?;
            let controller = Arc::new(
                Controller::new(
                    owner.handle(),
                    scope.client.clone(),
                    driver.clone(),
                    controller::Options {
                        pull_interval: config.pull_interval,
                        push_interval: config.push_interval,
                        timeout: self.options.operation_timeout,
                        traffic_threshold: config.traffic_report_threshold,
                    },
                )
                .map_err(|error| {
                    driver.abort();
                    Error::Controller(error)
                })?,
            );
            let runtime = Arc::new(Runtime::new(owner, driver, controller));
            candidate
                .runtimes
                .insert(runtime.core().protocol().clone(), runtime.clone());
            runtime
                .prepare_control(context)
                .await
                .map_err(Error::Runtime)?;
        }
        for runtime in candidate.runtimes.values() {
            runtime
                .prepare_listener(context)
                .await
                .map_err(Error::Runtime)?;
        }
        let mut jobs = Vec::new();
        for runtime in candidate.runtimes.values() {
            jobs.extend(runtime.controller.jobs().map_err(Error::Scheduler)?);
        }
        if let Some(sampler) = &self.sampler {
            let clients = candidate
                .runtimes
                .keys()
                .map(|name| self.connection.status(name.as_str()))
                .collect::<panel::Result<Vec<_>>>()
                .map_err(Error::Panel)?;
            let sampler = sampler.clone();
            let schedule = Schedule::new(
                config.push_interval,
                self.options.operation_timeout,
                config.push_interval.saturating_mul(8),
            )
            .map_err(Error::Scheduler)?;
            jobs.push(JobSpec::new(
                "node.status",
                Lane::Normal,
                schedule,
                scheduler::job(move |context| {
                    let sampler = sampler.clone();
                    let clients = clients.clone();
                    async move {
                        let status = sampler
                            .sample(&context)
                            .await
                            .map_err(|_| scheduler::JobFailure::Failed("sample"))?;
                        for client in clients {
                            client
                                .report_status(status)
                                .await
                                .map_err(|_| scheduler::JobFailure::Failed("status"))?;
                        }
                        Ok(())
                    }
                }),
            ));
        }
        candidate.maintenance = Some(Maintenance::prepare(
            Scheduler::new(self.options.scheduler, jobs).map_err(Error::Scheduler)?,
            &self.cancel,
            previous,
            self.metrics.clone(),
        )?);
        Ok(())
    }
    pub async fn reap_retired(&self, context: &OperationContext) -> Result<(), Error> {
        let _cleanup = context
            .run(self.cleanup.lock())
            .await
            .map_err(Error::Stopped)?;
        let generations = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retired
            .clone();
        for generation in generations {
            context.check().map_err(Error::Stopped)?;
            generation
                .close(self.options.drain_timeout, self.options.close_timeout)
                .await?;
            self.state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retired
                .retain(|g| g.id != generation.id);
        }
        Ok(())
    }
    /// Removed protocols retain their counters here until successful ACKs. The
    /// buffer itself serializes batches with any retiring controller.
    pub async fn flush_reports(&self, context: &OperationContext) -> Result<(), Error> {
        let scopes: Vec<_> = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .scopes
            .values()
            .cloned()
            .collect();
        for scope in scopes {
            while scope.reports.snapshot().pending_bytes > 0 {
                context.check().map_err(Error::Stopped)?;
                controller::flush_reports(&scope.reports, scope.client.as_ref(), 0, context)
                    .await
                    .map_err(Error::Controller)?;
            }
            controller::flush_online(&scope.reports, scope.client.as_ref(), context)
                .await
                .map_err(Error::Controller)?;
        }
        Ok(())
    }
    pub async fn run(self: &Arc<Self>, context: &OperationContext) -> Result<(), Error> {
        if self
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::InvalidOptions);
        }
        let _guard = RunGuard(self.as_ref());
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let schedule = Schedule::new(
            self.options.config_interval,
            self.options.operation_timeout,
            self.options.config_interval.saturating_mul(8),
        )
        .map_err(Error::Scheduler)?;
        let config_schedule = if self.snapshot().generation.is_some() {
            schedule
                .initial_delay(self.options.config_interval)
                .map_err(Error::Scheduler)?
        } else {
            schedule
        };
        let owned = self.clone();
        let config = JobSpec::new(
            "config",
            Lane::Critical,
            config_schedule,
            scheduler::job(move |ctx| {
                let owned = owned.clone();
                async move {
                    owned
                        .sync_config(&ctx)
                        .await
                        .map(|_| ())
                        .map_err(|_| scheduler::JobFailure::Failed("config"))
                }
            }),
        );
        let owned = self.clone();
        let cleanup = JobSpec::new(
            "retirement",
            Lane::Normal,
            Schedule::new(
                self.options.config_interval,
                self.options
                    .drain_timeout
                    .saturating_add(self.options.close_timeout)
                    .saturating_mul(self.options.max_retired.min(u32::MAX as usize) as u32),
                self.options.config_interval.saturating_mul(8),
            )
            .map_err(Error::Scheduler)?,
            scheduler::job(move |ctx| {
                let owned = owned.clone();
                async move {
                    owned
                        .reap_retired(&ctx)
                        .await
                        .map_err(|_| scheduler::JobFailure::Failed("retirement"))
                }
            }),
        );
        let owned = self.clone();
        let reports = JobSpec::new(
            "retired-reports",
            Lane::Normal,
            schedule,
            scheduler::job(move |ctx| {
                let owned = owned.clone();
                async move {
                    let scopes: Vec<_> = owned
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .scopes
                        .values()
                        .cloned()
                        .collect();
                    for scope in scopes {
                        if scope.users.view().writer.is_some() {
                            continue;
                        }
                        controller::flush_reports(&scope.reports, scope.client.as_ref(), 0, &ctx)
                            .await
                            .map_err(|_| scheduler::JobFailure::Failed("retired reports"))?;
                        controller::flush_online(&scope.reports, scope.client.as_ref(), &ctx)
                            .await
                            .map_err(|_| scheduler::JobFailure::Failed("retired online"))?;
                    }
                    Ok(())
                }
            }),
        );
        let scheduler = Scheduler::new(
            scheduler::Limits {
                max_jobs: 3,
                concurrency: 3,
                critical_reserve: 1,
            },
            vec![config, cleanup, reports],
        )
        .map_err(Error::Scheduler)?;
        let result = tokio::select! {result=scheduler.run(context)=>result.map_err(Error::Scheduler),_=self.cancel.cancelled()=>Ok(())};
        // Shutdown gets its own deadline; the run context is already cancelled.
        let duration = self
            .options
            .drain_timeout
            .saturating_add(self.options.close_timeout)
            .saturating_mul(
                self.options
                    .max_retired
                    .saturating_add(1)
                    .min(u32::MAX as usize) as u32,
            )
            .saturating_add(self.options.operation_timeout);
        let closing = OperationContext::new(
            CancellationToken::new(),
            Some(Deadline::after(duration).map_err(|_| Error::InvalidOptions)?),
        );
        let closed = self.close(&closing).await;
        result.and(closed)
    }
    pub async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        let _transition = context
            .run(self.transition.lock())
            .await
            .map_err(Error::Stopped)?;
        self.closed.store(true, Ordering::Release);
        {
            let permit = self.publication.write(0);
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(active) = s.active.take() {
                active.gate.set(&permit, false);
                s.retired.push(active);
            }
            self.fingerprints.replace(BTreeMap::new());
        }
        // Drain before cancelling runtime session tokens.
        if let Err(error) = self.reap_retired(context).await {
            self.factory.abort();
            return Err(error);
        }
        self.cancel.cancel();
        self.factory.close(context).await.map_err(Error::Runtime)?;
        self.flush_reports(context).await
    }
}
/// Synchronous fallback when the run future itself is dropped or aborted.
struct RunGuard<'a, F: RuntimeFactory>(&'a Supervisor<F>);
impl<F: RuntimeFactory> Drop for RunGuard<'_, F> {
    fn drop(&mut self) {
        self.0.halt();
        self.0.running.store(false, Ordering::Release);
    }
}
impl<F: RuntimeFactory> Supervisor<F> {
    fn halt(&self) {
        self.closed.store(true, Ordering::Release);
        let generations = {
            let permit = self.publication.write(0);
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let generations: Vec<_> = state
                .active
                .iter()
                .chain(state.retired.iter())
                .cloned()
                .collect();
            for generation in &generations {
                generation.gate.set(&permit, false);
            }
            self.fingerprints.replace(BTreeMap::new());
            generations
        };
        self.cancel.cancel();
        self.factory.abort();
        for generation in generations {
            for runtime in generation.runtimes.values() {
                runtime.abort();
            }
        }
    }
}
impl<F: RuntimeFactory> Drop for Supervisor<F> {
    fn drop(&mut self) {
        self.halt();
    }
}
