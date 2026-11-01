// SPDX-License-Identifier: GPL-3.0-only
//! Common authenticated stream-protocol runtime; engines own only wire semantics.
pub mod relay;
use crate::{
    buffer::BufferScope,
    egress,
    network::Stream,
    panel::{Connection, ProtocolClient, ProtocolConfig},
    protocol::{
        flow::{self, Policies, Session},
        ingress::{self, Acceptor},
        runtimekit::Core,
    },
    resource,
    runtime::{self, PreparedListener, ProtocolDriver},
    time::{Deadline, OperationContext},
    users::{self, AuthUpdater, Identity, PreparedAuth, Snapshot},
};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Semaphore;
#[derive(Clone, Debug)]
pub struct Options {
    pub listen: IpAddr,
    pub max_connections: usize,
    pub max_handshakes: usize,
    pub connection_buffers: resource::Limits,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub udp_idle_timeout: Duration,
    pub max_streams: usize,
    pub queue_packets: usize,
    pub max_udp_ports: usize,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            listen: Ipv4Addr::UNSPECIFIED.into(),
            max_connections: 4096,
            max_handshakes: 128,
            connection_buffers: resource::Limits::new(4 << 20, 256).expect("fixed limits"),
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            udp_idle_timeout: Duration::from_secs(60),
            max_streams: 32,
            queue_packets: 32,
            max_udp_ports: 32,
        }
    }
}
impl Options {
    pub fn validate(&self) -> Result<(), runtime::Error> {
        if self.max_connections == 0
            || self.max_connections > 1_000_000
            || self.max_handshakes == 0
            || self.max_handshakes > self.max_connections
            || self.max_streams == 0
            || self.max_streams > 1024
            || self.queue_packets == 0
            || self.queue_packets > 1024
            || self.max_udp_ports == 0
            || self.max_udp_ports > 256
            || self.connection_buffers.bytes() < 262144
            || self.connection_buffers.allocations() < 8
        {
            return Err(runtime::Error::Preparation("stream limits"));
        }
        for timeout in [
            self.handshake_timeout,
            self.idle_timeout,
            self.udp_idle_timeout,
        ] {
            if timeout.is_zero() || Deadline::after(timeout).is_err() {
                return Err(runtime::Error::Preparation("stream timeout"));
            }
        }
        Ok(())
    }
}
impl From<&super::vless::Options> for Options {
    fn from(value: &super::vless::Options) -> Self {
        Self {
            listen: value.listen,
            max_connections: value.max_connections,
            max_handshakes: value.max_handshakes,
            connection_buffers: value.connection_buffers,
            handshake_timeout: value.handshake_timeout,
            idle_timeout: value.idle_timeout,
            udp_idle_timeout: value.udp_idle_timeout,
            queue_packets: value.queue_packets,
            ..Default::default()
        }
    }
}
pub trait EngineFactory: Send + Sync {
    fn prepare(&self, config: &ProtocolConfig) -> Result<Arc<dyn Engine>, runtime::Error>;
}
#[async_trait]
pub trait Engine: Send + Sync {
    fn credential(&self, password: &str) -> Result<Vec<u8>, users::Error>;
    async fn handshake(
        &self,
        stream: Stream,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Handshake, std::io::Error>;
}
pub struct Handshake {
    pub key: Vec<u8>,
    pub connection: Box<dyn Authenticated>,
}
#[async_trait]
pub trait Authenticated: Send {
    async fn serve(self: Box<Self>, context: Arc<Context>) -> Result<(), flow::Error>;
}
pub struct Context {
    pub core: Core,
    pub egress: Arc<egress::Handle>,
    pub options: Options,
    pub buffers: BufferScope,
    pub session: Arc<Session>,
    pub identity: Identity,
    pub source: IpAddr,
    policies: Arc<Policies>,
    client: Arc<dyn ProtocolClient>,
}
impl Context {
    pub fn operation(&self) -> Result<OperationContext, flow::Error> {
        Ok(self.session.context().child_with_deadline(
            Deadline::after(self.options.handshake_timeout)
                .map_err(|_| flow::Error::InvalidOptions)?,
        ))
    }
    pub async fn admit(&self) -> Result<Arc<Session>, flow::Error> {
        let operation = self.operation()?;
        operation
            .run(
                self.policies
                    .admit(&self.core, &self.identity, self.source, self.client.clone()),
            )
            .await
            .map_err(|_| flow::Error::Stopped)?
    }
}
pub struct Factory {
    connection: Arc<dyn Connection>,
    engine: Arc<dyn EngineFactory>,
    transports: Arc<crate::transport::Registry>,
    options: Options,
    policies: Arc<Policies>,
    ingress: Arc<ingress::Registry>,
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}
impl Factory {
    pub fn new(
        connection: Arc<dyn Connection>,
        engine: Arc<dyn EngineFactory>,
        transports: Arc<crate::transport::Registry>,
        options: Options,
        policy: flow::Options,
    ) -> Result<Self, runtime::Error> {
        options.validate()?;
        Ok(Self {
            connection,
            engine,
            transports,
            policies: Arc::new(
                Policies::new(policy).map_err(|_| runtime::Error::Preparation("flow limits"))?,
            ),
            ingress: Arc::new(ingress::Registry::default()),
            connections: Arc::new(Semaphore::new(options.max_connections)),
            handshakes: Arc::new(Semaphore::new(options.max_handshakes)),
            options,
        })
    }
}
#[async_trait]
impl super::InboundFactory for Factory {
    async fn prepare(
        &self,
        config: ProtocolConfig,
        egress: Arc<egress::Handle>,
        core: Core,
        context: &OperationContext,
    ) -> Result<Arc<dyn ProtocolDriver>, runtime::Error> {
        context.check().map_err(runtime::Error::Stopped)?;
        core.buffers()
            .child(self.options.connection_buffers)
            .map_err(|_| runtime::Error::Preparation("connection buffers"))?;
        if config.port == 0 {
            return Err(runtime::Error::Unsupported);
        }
        let engine = self.engine.prepare(&config)?;
        let transport = self
            .transports
            .inbound(&config)
            .map_err(|_| runtime::Error::Preparation("inbound transport"))?;
        if !transport.is_encrypted() {
            return Err(runtime::Error::Preparation("protocol requires TLS"));
        }
        let client = self
            .connection
            .protocol(config.protocol.as_str())
            .map_err(|_| runtime::Error::Preparation("panel scope"))?;
        Ok(Arc::new_cyclic(|weak| Driver {
            weak: weak.clone(),
            core,
            egress,
            engine,
            transport,
            client,
            options: self.options.clone(),
            policies: self.policies.clone(),
            address: SocketAddr::new(self.options.listen, config.port),
            ingress: self.ingress.clone(),
            binding: Mutex::new(None),
            auth: Arc::new(RwLock::new(None)),
            connections: self.connections.clone(),
            handshakes: self.handshakes.clone(),
            committed: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }))
    }
}
struct Auth {
    _snapshot: Arc<Snapshot>,
    keys: BTreeMap<Vec<u8>, Identity>,
}
struct Driver {
    weak: Weak<Self>,
    core: Core,
    egress: Arc<egress::Handle>,
    engine: Arc<dyn Engine>,
    transport: Arc<dyn crate::transport::Inbound>,
    client: Arc<dyn ProtocolClient>,
    options: Options,
    policies: Arc<Policies>,
    address: SocketAddr,
    ingress: Arc<ingress::Registry>,
    binding: Mutex<Option<Arc<ingress::Ingress>>>,
    auth: Arc<RwLock<Option<Arc<Auth>>>>,
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    committed: AtomicBool,
    stopped: AtomicBool,
    closed: AtomicBool,
}
impl Driver {
    async fn serve(
        self: Arc<Self>,
        stream: Stream,
        source: SocketAddr,
        cancel: crate::task::CancellationToken,
        handshake: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), crate::task::TaskFailure> {
        use crate::task::TaskFailure;
        let operation = OperationContext::new(
            cancel,
            Some(
                Deadline::after(self.options.handshake_timeout)
                    .map_err(|_| TaskFailure::Failed("timeout"))?,
            ),
        );
        let buffers = self
            .core
            .buffers()
            .child(self.options.connection_buffers)
            .map_err(|_| TaskFailure::Failed("buffers"))?;
        let stream = self
            .transport
            .handshake(stream, &buffers, &operation)
            .await
            .map_err(|_| TaskFailure::Failed("TLS handshake"))?;
        let ready = operation
            .run(self.engine.handshake(stream, &buffers, &operation))
            .await
            .map_err(TaskFailure::from)?
            .map_err(|_| TaskFailure::Failed("protocol handshake"))?;
        let identity = {
            let _permit = self.core.users().publication().read();
            self.auth
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .and_then(|auth| auth.keys.get(&ready.key))
                .cloned()
        }
        .ok_or(TaskFailure::Failed("authentication"))?;
        let session = operation
            .run(
                self.policies
                    .admit(&self.core, &identity, source.ip(), self.client.clone()),
            )
            .await
            .map_err(TaskFailure::from)?
            .map_err(|_| TaskFailure::Failed("admission"))?;
        drop(handshake);
        let context = Arc::new(Context {
            core: self.core.clone(),
            egress: self.egress.clone(),
            options: self.options.clone(),
            buffers,
            session: session.clone(),
            identity,
            source: source.ip(),
            policies: self.policies.clone(),
            client: self.client.clone(),
        });
        tokio::select! {
            result=session.run(ready.connection.serve(context))=>result.and_then(|value|value).map_err(|_|TaskFailure::Failed("forwarding")),
            result=session.maintain()=>result.map_err(|_|TaskFailure::Failed("device lease")),
        }
    }
}
impl Acceptor for Driver {
    fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    fn accepting(&self) -> bool {
        self.committed.load(Ordering::Acquire)
            && !self.stopped.load(Ordering::Acquire)
            && !self.closed()
            && self.core.is_current()
    }
    fn accept(self: Arc<Self>, stream: Stream, source: SocketAddr) {
        let Ok(connection) = self.connections.clone().try_acquire_owned() else {
            return;
        };
        let Ok(handshake) = self.handshakes.clone().try_acquire_owned() else {
            return;
        };
        let core = self.core.clone();
        let _ = core.spawn("protocol.connection", move |cancel| async move {
            let _connection = connection;
            self.serve(stream, source, cancel, handshake).await
        });
    }
}
struct AuthUpdate {
    target: Arc<RwLock<Option<Arc<Auth>>>>,
    next: Option<Arc<Auth>>,
    publication: runtime::Publication,
}
impl PreparedAuth for AuthUpdate {
    fn commit(&mut self, permit: &runtime::WritePermit<'_>) -> Result<(), users::Error> {
        if !self.publication.owns_write(permit) {
            return Err(users::Error::ForeignSnapshot);
        }
        *self.target.write().unwrap_or_else(|e| e.into_inner()) =
            Some(self.next.take().ok_or(users::Error::StaleCandidate)?);
        Ok(())
    }
    fn abort(&mut self) {
        self.next.take();
    }
}
#[async_trait]
impl AuthUpdater for Driver {
    async fn prepare_users(
        &self,
        snapshot: Arc<Snapshot>,
        context: &OperationContext,
    ) -> Result<Box<dyn PreparedAuth>, users::Error> {
        context.check().map_err(users::Error::Stopped)?;
        let mut keys = BTreeMap::new();
        for user in snapshot.users() {
            let key = self.engine.credential(user.credential.expose())?;
            if keys
                .insert(
                    key,
                    snapshot.identity(user.id).ok_or(users::Error::Revoked)?,
                )
                .is_some()
            {
                return Err(users::Error::DuplicateCredential);
            }
        }
        Ok(Box::new(AuthUpdate {
            target: self.auth.clone(),
            next: Some(Arc::new(Auth {
                _snapshot: snapshot,
                keys,
            })),
            publication: self.core.users().publication().clone(),
        }))
    }
}
struct Listener(Weak<Driver>);
impl PreparedListener for Listener {
    fn commit(&mut self) -> Result<(), runtime::Error> {
        let driver = self.0.upgrade().ok_or(runtime::Error::Closed)?;
        if driver.closed() {
            return Err(runtime::Error::Closed);
        }
        driver.committed.store(true, Ordering::Release);
        Ok(())
    }
    fn stop_accepting(&mut self) -> Result<(), runtime::Error> {
        if let Some(driver) = self.0.upgrade() {
            driver.stopped.store(true, Ordering::Release);
        }
        Ok(())
    }
    fn abort(&mut self) {
        let _ = self.stop_accepting();
    }
}
#[async_trait]
impl ProtocolDriver for Driver {
    fn reload_required(&self) -> Result<bool, runtime::Error> {
        self.transport
            .reload_required()
            .map_err(|_| runtime::Error::Preparation("TLS identity reload"))
    }
    fn certificate(&self) -> Option<crate::panel::CertificateFingerprint> {
        self.transport.certificate()
    }
    async fn prepare_listener(
        &self,
        context: &OperationContext,
    ) -> Result<Box<dyn PreparedListener>, runtime::Error> {
        let binding = self
            .ingress
            .bind(
                self.address,
                self.transport.clone(),
                self.core.metrics().clone(),
                context,
            )
            .await?;
        let driver: Arc<dyn Acceptor> = self.weak.upgrade().ok_or(runtime::Error::Closed)?;
        binding.register(Arc::downgrade(&driver))?;
        *self.binding.lock().unwrap_or_else(|e| e.into_inner()) = Some(binding);
        Ok(Box::new(Listener(self.weak.clone())))
    }
    fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        self.stopped.store(true, Ordering::Release);
        if let Some(binding) = self
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            binding.stop_if_unused();
        }
    }
    async fn close(&self, context: &OperationContext) -> Result<(), runtime::Error> {
        self.abort();
        let binding = self
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(binding) = binding {
            binding
                .close_if_unused(
                    context
                        .deadline()
                        .unwrap_or_else(|| Deadline::at(tokio::time::Instant::now())),
                )
                .await;
        }
        self.binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        Ok(())
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Protocol engines and stream transports validate disjoint field sets.
pub fn validate_fields(config: &ProtocolConfig, padding: bool) -> Result<(), runtime::Error> {
    if config.version != 0
        || !config.mode.is_empty()
        || !config.cipher.is_empty()
        || !config.server_key.expose().is_empty()
        || !config.plugin.is_empty()
        || config.plugin_options != crate::panel::ConfigValue::Null
        || !config.flow.is_empty()
        || !config.hop_ports.is_empty()
        || config.hop_interval != 0
        || !config.obfs_password.expose().is_empty()
        || config.reduce_rtt
        || config.heartbeat != 0
        || !config.udp_relay_mode.is_empty()
        || !config.congestion_controller.is_empty()
        || !config.quic_congestion_control.is_empty()
        || !config.multiplex.is_empty()
        || (!padding && !config.padding_scheme.is_empty())
        || !config.traffic_pattern.is_empty()
        || config.user_hint_is_mandatory
        || config.up_mbps != 0
        || config.down_mbps != 0
        || !config.obfs.is_empty()
        || !config.ssr_protocol.is_empty()
        || !config.protocol_param.is_empty()
        || !config.obfs_param.is_empty()
        || !config.obfs_host.is_empty()
        || !config.obfs_path.is_empty()
        || !matches!(config.encryption.as_str(), "" | "none")
        || !config.encryption_mode.is_empty()
        || !config.encryption_rtt.is_empty()
        || !config.encryption_ticket.expose().is_empty()
        || !config.encryption_server_padding.is_empty()
        || !config.encryption_private_key.expose().is_empty()
        || !config.encryption_client_padding.is_empty()
        || !config.encryption_password.expose().is_empty()
        || !config.extensions.is_empty()
        || config.uot_version > 2
    {
        return Err(runtime::Error::Unsupported);
    }
    Ok(())
}
