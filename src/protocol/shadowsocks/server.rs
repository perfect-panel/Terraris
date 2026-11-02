// SPDX-License-Identifier: GPL-3.0-only
//! Shared-policy Shadowsocks runtime. Candidates publish credentials and both
//! listeners atomically through the existing runtime transaction.
use super::{
    method::{Key, Method},
    replay::Protection,
    stream, udp,
};
use crate::{
    buffer::BufferScope,
    egress,
    network::{Datagram, DatagramEndpoint, Stream},
    panel::{Connection, ProtocolClient, ProtocolConfig},
    protocol::{
        flow::{self, Policies},
        ingress::{self, Acceptor},
        runtimekit::Core,
        stream::{Options, relay},
        uot,
    },
    runtime::{self, PreparedListener, ProtocolDriver},
    task::{CancellationToken, TaskFailure},
    telemetry::Metrics,
    time::{Deadline, OperationContext},
    users::{self, AuthUpdater, Identity, PreparedAuth, Snapshot},
};
use async_trait::async_trait;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Semaphore;

pub(super) struct Config {
    pub method: Method,
    pub server: Option<Arc<Key>>,
    pub tcp: bool,
    pub udp: bool,
    pub uot: bool,
}
fn configure(config: &ProtocolConfig) -> Result<(Config, ProtocolConfig), runtime::Error> {
    let method = Method::parse(&config.cipher)
        .map_err(|_| runtime::Error::Preparation("Shadowsocks cipher"))?;
    let server = if config.server_key.expose().is_empty() {
        None
    } else {
        if !method.identity() {
            return Err(runtime::Error::Preparation("server_key requires AES-2022"));
        }
        Some(
            Key::new(method, config.server_key.expose().as_bytes())
                .map_err(|_| runtime::Error::Preparation("Shadowsocks server_key size"))?,
        )
    };
    let mut base = config.clone();
    base.network = base.network.trim().to_ascii_lowercase();
    base.transport = base.transport.trim().to_ascii_lowercase();
    base.cipher.clear();
    base.server_key = crate::panel::Secret::new("");
    crate::protocol::stream::validate_fields(&base, false)?;
    if !config.uot && config.uot_version != 0 {
        return Err(runtime::Error::Unsupported);
    }
    let (tcp, udp) = match config.network.trim().to_ascii_lowercase().as_str() {
        "" | "tcp,udp" | "udp,tcp" => (true, true),
        "tcp" | "raw" => (true, false),
        "udp" => (false, true),
        _ => (true, false),
    };
    if !base.transport.is_empty() {
        base.network = base.transport.clone();
    } else if matches!(
        base.network.as_str(),
        "" | "tcp,udp" | "udp,tcp" | "tcp" | "raw" | "udp"
    ) {
        base.network = "tcp".into();
    }
    if !tcp
        && (!matches!(base.network.as_str(), "tcp" | "raw")
            || !matches!(base.security.as_str(), "" | "none"))
    {
        return Err(runtime::Error::Unsupported);
    }
    if udp && base.alpn == ["h3"] {
        return Err(runtime::Error::Preparation(
            "native UDP conflicts with HTTP/3 on the same port",
        ));
    }
    Ok((
        Config {
            method,
            server,
            tcp,
            udp,
            uot: config.uot,
        },
        base,
    ))
}
pub struct Factory {
    connection: Arc<dyn Connection>,
    transports: Arc<crate::transport::Registry>,
    options: Options,
    policies: Arc<Policies>,
    ingress: Arc<ingress::Registry>,
    udp: Arc<udp::Service>,
    protection: Arc<Protection>,
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}
impl Factory {
    pub fn new(
        connection: Arc<dyn Connection>,
        transports: Arc<crate::transport::Registry>,
        options: Options,
        policy: flow::Options,
        metrics: Metrics,
    ) -> Result<Self, runtime::Error> {
        options.validate()?;
        let protection = Protection::new();
        Ok(Self {
            connection,
            transports,
            policies: Arc::new(
                Policies::new(policy).map_err(|_| runtime::Error::Preparation("flow options"))?,
            ),
            ingress: Arc::new(ingress::Registry::default()),
            udp: udp::Service::new(options.clone(), metrics)?,
            protection,
            connections: Arc::new(Semaphore::new(options.max_connections)),
            handshakes: Arc::new(Semaphore::new(options.max_handshakes)),
            options,
        })
    }
}
#[async_trait]
impl crate::protocol::InboundFactory for Factory {
    fn abort(&self) {
        self.udp.abort();
    }
    async fn close(&self, context: &OperationContext) -> Result<(), runtime::Error> {
        self.udp.close(context).await
    }
    fn published(&self, shared: &egress::Handle) {
        self.udp.retain_policy(shared.migration_scope());
    }
    async fn prepare(
        &self,
        config: ProtocolConfig,
        egress: Arc<egress::Handle>,
        core: Core,
        context: &OperationContext,
    ) -> Result<Arc<dyn ProtocolDriver>, runtime::Error> {
        context.check().map_err(runtime::Error::Stopped)?;
        if config.port == 0 {
            return Err(runtime::Error::Unsupported);
        }
        core.buffers()
            .child(self.options.connection_buffers)
            .map_err(|_| runtime::Error::Preparation("SS connection buffers"))?;
        let (settings, base) = configure(&config)?;
        if settings.method.modern()
            && settings.udp
            && self.options.udp_idle_timeout < std::time::Duration::from_secs(60)
        {
            return Err(runtime::Error::Preparation(
                "SS2022 UDP requires at least 60 seconds of session retention",
            ));
        }
        let transport = self
            .transports
            .inbound(&base)
            .map_err(|_| runtime::Error::Preparation("SS transport"))?;
        let client = self
            .connection
            .protocol(config.protocol.as_str())
            .map_err(|_| runtime::Error::Preparation("panel scope"))?;
        Ok(Arc::new_cyclic(|weak| Driver {
            weak: weak.clone(),
            config: settings,
            core,
            egress,
            transport,
            client,
            options: self.options.clone(),
            policies: self.policies.clone(),
            protection: self.protection.clone(),
            ingress: self.ingress.clone(),
            udp: self.udp.clone(),
            address: SocketAddr::new(self.options.listen, config.port),
            binding: Mutex::new(None),
            udp_binding: Mutex::new(None),
            auth: Arc::new(RwLock::new(None)),
            connections: self.connections.clone(),
            handshakes: self.handshakes.clone(),
            committed: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }))
    }
}
pub(super) struct Auth {
    pub keys: stream::Keys,
    pub identities: HashMap<[u8; 32], Identity>,
    _snapshot: Arc<Snapshot>,
}
pub(super) struct Driver {
    weak: Weak<Driver>,
    pub config: Config,
    pub core: Core,
    pub egress: Arc<egress::Handle>,
    transport: Arc<dyn crate::transport::Inbound>,
    pub client: Arc<dyn ProtocolClient>,
    pub options: Options,
    pub policies: Arc<Policies>,
    pub protection: Arc<Protection>,
    ingress: Arc<ingress::Registry>,
    pub udp: Arc<udp::Service>,
    address: SocketAddr,
    binding: Mutex<Option<Arc<ingress::Ingress>>>,
    udp_binding: Mutex<Option<Arc<udp::Binding>>>,
    auth: Arc<RwLock<Option<Arc<Auth>>>>,
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    committed: AtomicBool,
    stopped: AtomicBool,
    closed: AtomicBool,
}
impl Driver {
    pub fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.core.is_closed()
    }
    pub fn accepting(&self) -> bool {
        self.committed.load(Ordering::Acquire)
            && !self.stopped.load(Ordering::Acquire)
            && !self.closed()
            && self.core.is_current()
    }
    fn auth(&self) -> Option<Arc<Auth>> {
        let _permit = self.core.users().publication().read();
        self.auth.read().unwrap_or_else(|e| e.into_inner()).clone()
    }
    async fn serve(
        self: Arc<Self>,
        carrier: crate::transport::Accepted,
        source: SocketAddr,
        cancel: CancellationToken,
        handshake: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), TaskFailure> {
        let context = OperationContext::new(
            cancel.clone(),
            Some(
                Deadline::after(self.options.handshake_timeout)
                    .map_err(|_| TaskFailure::Failed("timeout"))?,
            ),
        );
        let scope = self
            .core
            .buffers()
            .child(self.options.connection_buffers)
            .map_err(|_| TaskFailure::Failed("buffers"))?;
        match self
            .transport
            .open_carrier(carrier, &scope, &context)
            .await
            .map_err(|_| TaskFailure::Failed("transport"))?
        {
            crate::transport::Incoming::Single(stream) => {
                self.serve_stream(stream, source, scope, context, handshake)
                    .await
            }
            crate::transport::Incoming::Multiplexed(carrier) => {
                drop(handshake);
                let core = self.core.clone();
                let timeout = self.options.handshake_timeout;
                let idle = self.options.idle_timeout;
                ingress::multiplex(
                    carrier,
                    core,
                    cancel,
                    timeout,
                    idle,
                    move |stream, cancel| {
                        let this = self.clone();
                        let scope = scope.clone();
                        Box::pin(async move {
                            let Ok(handshake) = this.handshakes.clone().try_acquire_owned() else {
                                return;
                            };
                            let Ok(deadline) = Deadline::after(timeout) else {
                                return;
                            };
                            let context = OperationContext::new(cancel, Some(deadline));
                            let _ = this
                                .serve_stream(stream, source, scope, context, handshake)
                                .await;
                        })
                    },
                )
                .await
            }
        }
    }
    async fn serve_stream(
        self: Arc<Self>,
        raw: Stream,
        source: SocketAddr,
        scope: BufferScope,
        context: OperationContext,
        handshake: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), TaskFailure> {
        let auth = self
            .auth()
            .ok_or(TaskFailure::Failed("users unavailable"))?;
        let mut accepted = context
            .run(stream::accept(
                raw,
                self.config.method,
                self.config.server.as_deref(),
                &auth.keys,
                self.protection.clone(),
                &scope,
                &context,
            ))
            .await
            .map_err(TaskFailure::from)?
            .map_err(|_| TaskFailure::Failed("Shadowsocks handshake"))?;
        let identity = auth
            .identities
            .get(&accepted.key)
            .ok_or(TaskFailure::Failed("authentication"))?;
        let session = context
            .run(
                self.policies
                    .admit(&self.core, identity, source.ip(), self.client.clone()),
            )
            .await
            .map_err(TaskFailure::from)?
            .map_err(|_| TaskFailure::Failed("admission"))?;
        drop(handshake);
        drop(auth);
        let work = async {
            let target = accepted
                .target
                .target()
                .map_err(|e| flow::Error::Io(e.kind()))?;
            let operation = session.context().child_with_deadline(
                Deadline::after(self.options.handshake_timeout)
                    .map_err(|_| flow::Error::InvalidOptions)?,
            );
            if let Some(version) = uot::Version::for_target(&target) {
                if !self.config.uot {
                    return Err(flow::Error::Unsupported);
                }
                let codec = operation
                    .run(version.read(&mut accepted.stream))
                    .await
                    .map_err(|_| flow::Error::Stopped)?
                    .map_err(|e| flow::Error::Io(e.kind()))?;
                relay::udp(
                    accepted.stream,
                    codec,
                    self.egress.clone(),
                    session.clone(),
                    scope,
                    relay::UdpOptions {
                        idle: self.options.udp_idle_timeout,
                        operation_timeout: self.options.handshake_timeout,
                        max_ports: self.options.max_udp_ports,
                    },
                )
                .await
            } else {
                let upstream = session
                    .run(self.egress.connect(&target, &operation, scope.clone()))
                    .await?
                    .map_err(|_| flow::Error::Resolve)?;
                relay::tcp(
                    accepted.stream,
                    upstream,
                    session.clone(),
                    scope,
                    self.options.idle_timeout,
                    self.core.metrics().clone(),
                )
                .await
            }
        };
        tokio::select! {result=session.run(work)=>result.and_then(|v|v).map_err(|_|TaskFailure::Failed("forwarding")),result=session.maintain()=>result.map_err(|_|TaskFailure::Failed("device lease"))}
    }
    pub fn accept_packet(
        self: Arc<Self>,
        packet: Datagram,
        endpoint: Arc<DatagramEndpoint>,
        arrival: u64,
    ) {
        if !self.accepting() {
            return;
        }
        let Ok(permit) = self.handshakes.clone().try_acquire_owned() else {
            return;
        };
        let core = self.core.clone();
        let _ = core.spawn("ss.udp.auth", move |cancel| async move {
            let _permit = permit;
            let context = OperationContext::new(
                cancel,
                Some(
                    Deadline::after(self.options.handshake_timeout)
                        .map_err(|_| TaskFailure::Failed("timeout"))?,
                ),
            );
            let work = async {
                let auth = self.auth().ok_or_else(super::method::bad)?;
                let decoded = super::packet::decode_request(
                    packet.payload.as_slice(),
                    self.config.method,
                    self.config.server.as_deref(),
                    &auth.keys,
                    self.udp.hint(packet.source),
                    &self.protection,
                    self.core.buffers(),
                    &context,
                )
                .await?;
                let identity = auth
                    .identities
                    .get(&decoded.key.id)
                    .cloned()
                    .ok_or_else(super::method::bad)?;
                self.udp
                    .dispatch(
                        &self,
                        identity,
                        decoded,
                        packet.source,
                        endpoint,
                        arrival,
                        &context,
                    )
                    .await
                    .map_err(std::io::Error::from)
            };
            context
                .run(work)
                .await
                .map_err(TaskFailure::from)?
                .map_err(|_| TaskFailure::Failed("SS UDP packet"))
        });
    }
}
impl Acceptor for Driver {
    fn closed(&self) -> bool {
        self.closed()
    }
    fn accepting(&self) -> bool {
        self.accepting()
    }
    fn accept(self: Arc<Self>, stream: crate::transport::Accepted, source: SocketAddr) {
        let Ok(connection) = self.connections.clone().try_acquire_owned() else {
            return;
        };
        let Ok(handshake) = self.handshakes.clone().try_acquire_owned() else {
            return;
        };
        let core = self.core.clone();
        let _ = core.spawn("ss.tcp", move |cancel| async move {
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
        if self.config.server.is_none() && snapshot.len() > 1024 {
            return Err(users::Error::TooManyUsers);
        }
        let mut keys = Vec::new();
        let mut identities = HashMap::new();
        for (index, user) in snapshot.users().enumerate() {
            if index % 128 == 0 {
                context.check().map_err(users::Error::Stopped)?;
                tokio::task::yield_now().await;
            }
            let key = self
                .config
                .method
                .user_key(user.credential.expose())
                .map_err(|_| users::Error::InvalidUser)?;
            if identities
                .insert(
                    key.id,
                    snapshot.identity(user.id).ok_or(users::Error::Revoked)?,
                )
                .is_some()
            {
                return Err(users::Error::DuplicateCredential);
            }
            keys.push(key);
        }
        let keys = stream::Keys::new(keys, self.config.server.is_some())
            .map_err(|_| users::Error::DuplicateCredential)?;
        Ok(Box::new(AuthUpdate {
            target: self.auth.clone(),
            next: Some(Arc::new(Auth {
                keys,
                identities,
                _snapshot: snapshot,
            })),
            publication: self.core.users().publication().clone(),
        }))
    }
}
struct Listener(Weak<Driver>);
impl PreparedListener for Listener {
    fn commit(&mut self) -> Result<(), runtime::Error> {
        let d = self.0.upgrade().ok_or(runtime::Error::Closed)?;
        if d.closed() {
            return Err(runtime::Error::Closed);
        }
        d.committed.store(true, Ordering::Release);
        Ok(())
    }
    fn stop_accepting(&mut self) -> Result<(), runtime::Error> {
        if let Some(d) = self.0.upgrade() {
            d.stopped.store(true, Ordering::Release);
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
            .map_err(|_| runtime::Error::Preparation("SS TLS identity"))
    }
    fn certificate(&self) -> Option<crate::panel::CertificateFingerprint> {
        self.transport.certificate()
    }
    async fn prepare_listener(
        &self,
        context: &OperationContext,
    ) -> Result<Box<dyn PreparedListener>, runtime::Error> {
        let this = self.weak.upgrade().ok_or(runtime::Error::Closed)?;
        if self.config.tcp {
            let binding = self
                .ingress
                .bind(
                    self.address,
                    self.transport.clone(),
                    self.core.metrics().clone(),
                    context,
                )
                .await?;
            let acceptor: Arc<dyn Acceptor> = this.clone();
            binding.register(Arc::downgrade(&acceptor))?;
            *self.binding.lock().unwrap_or_else(|e| e.into_inner()) = Some(binding);
        }
        if self.config.udp {
            let binding = self
                .udp
                .bind(
                    self.address,
                    Arc::downgrade(&this),
                    self.core.buffers().clone(),
                    context,
                )
                .await?;
            *self.udp_binding.lock().unwrap_or_else(|e| e.into_inner()) = Some(binding);
        }
        Ok(Box::new(Listener(self.weak.clone())))
    }
    fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        self.stopped.store(true, Ordering::Release);
        self.transport.abort();
        self.udp.cancel_generation(self.core.generation());
        if let Some(b) = self
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            b.stop_if_unused();
        }
        if let Some(b) = self
            .udp_binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            b.stop_if_unused();
        }
    }
    async fn close(&self, context: &OperationContext) -> Result<(), runtime::Error> {
        self.abort();
        let deadline = context
            .deadline()
            .unwrap_or_else(|| Deadline::at(tokio::time::Instant::now()));
        let binding = self
            .binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(b) = binding {
            b.close_if_unused(deadline).await;
        }
        let binding = self
            .udp_binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some(b) = binding {
            b.close_if_unused(deadline).await;
        }
        self.binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.udp_binding
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.udp
            .close_generation(self.core.generation(), context)
            .await?;
        self.transport
            .close(context)
            .await
            .map_err(|_| runtime::Error::Closed)
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        self.abort();
    }
}
