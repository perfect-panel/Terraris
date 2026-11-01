// SPDX-License-Identifier: GPL-3.0-only
use super::{
    egress::Egress,
    encryption,
    ingress::{Ingress, Registry},
    options::{self, Options},
    wire,
};
use crate::{
    buffer::BufferScope,
    dataplane::{DataPlane, TransferConfig},
    panel::{Connection, ProtocolClient, ProtocolConfig, ProtocolName, ServerConfig},
    protocol::{
        flow::{self, Metered, Policies, Session},
        runtimekit::Core,
    },
    runtime::{self, PreparedListener, ProtocolDriver, RuntimeFactory},
    task::TaskFailure,
    time::{Deadline, OperationContext},
    users::{self, AuthUpdater, Identity, PreparedAuth, Snapshot},
};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, RwLock, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::Semaphore,
};

pub(super) trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}
pub(super) type Stream = Box<dyn Io>;
pub struct Factory {
    connection: Arc<dyn Connection>,
    options: Options,
    ingress: Arc<Registry>,
    policies: Arc<Policies>,
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
    encryption_cache: Mutex<BTreeMap<[u8; 32], Weak<encryption::Server>>>,
}
impl Factory {
    pub fn new(
        connection: Arc<dyn Connection>,
        options: Options,
        policy_options: flow::Options,
    ) -> Result<Self, runtime::Error> {
        options.validate()?;
        let policies = Arc::new(
            Policies::new(policy_options)
                .map_err(|_| runtime::Error::Preparation("flow policy limits"))?,
        );
        Ok(Self {
            connection,
            ingress: Arc::new(Registry::default()),
            policies,
            connections: Arc::new(Semaphore::new(options.max_connections)),
            handshakes: Arc::new(Semaphore::new(options.max_handshakes)),
            options,
            encryption_cache: Mutex::new(BTreeMap::new()),
        })
    }
}
#[async_trait]
impl RuntimeFactory for Factory {
    type Shared = Egress;
    fn supports(&self, protocol: &ProtocolName) -> bool {
        protocol.as_str() == "vless"
    }
    async fn prepare_shared(
        &self,
        config: Arc<ServerConfig>,
        buffers: BufferScope,
        context: &OperationContext,
    ) -> Result<Egress, runtime::Error> {
        context.check().map_err(runtime::Error::Stopped)?;
        buffers
            .child(self.options.connection_buffers)
            .map_err(|_| runtime::Error::Preparation("connection buffer limits"))?;
        Egress::new(&config)
    }
    async fn prepare_protocol(
        &self,
        config: ProtocolConfig,
        egress: Arc<Egress>,
        core: Core,
        context: &OperationContext,
    ) -> Result<Arc<dyn ProtocolDriver>, runtime::Error> {
        context.check().map_err(runtime::Error::Stopped)?;
        let encrypted = if let Some(config) = options::validate(&config, &self.options)? {
            let key = config.cache_key();
            let mut cache = self
                .encryption_cache
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(server) = cache.get(&key).and_then(Weak::upgrade) {
                Some(server)
            } else {
                cache.retain(|_, server| server.strong_count() > 0);
                if cache.len() >= 64 {
                    return Err(runtime::Error::Preparation("encryption instance capacity"));
                }
                let server = Arc::new(
                    encryption::Server::new(config, self.options.encryption_limits)
                        .map_err(|_| runtime::Error::Preparation("VLESS encryption"))?,
                );
                cache.insert(key, Arc::downgrade(&server));
                Some(server)
            }
        } else {
            None
        };
        let client = self
            .connection
            .protocol("vless")
            .map_err(|_| runtime::Error::Preparation("VLESS panel scope"))?;
        let driver = Arc::new_cyclic(|weak| Driver {
            weak: weak.clone(),
            core,
            egress,
            options: self.options.clone(),
            address: SocketAddr::new(self.options.listen, config.port),
            encryption: Mutex::new(encrypted),
            client,
            policies: self.policies.clone(),
            registry: self.ingress.clone(),
            binding: Mutex::new(None),
            auth: Arc::new(RwLock::new(None)),
            committed: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            connections: self.connections.clone(),
            handshakes: self.handshakes.clone(),
        });
        Ok(driver)
    }
}
struct Auth {
    _snapshot: Arc<Snapshot>,
    identities: BTreeMap<[u8; 16], Identity>,
}
pub(super) struct Driver {
    weak: Weak<Self>,
    pub(super) core: Core,
    pub(super) egress: Arc<Egress>,
    pub(super) options: Options,
    address: SocketAddr,
    encryption: Mutex<Option<Arc<encryption::Server>>>,
    pub(super) client: Arc<dyn ProtocolClient>,
    pub(super) policies: Arc<Policies>,
    registry: Arc<Registry>,
    binding: Mutex<Option<Arc<Ingress>>>,
    auth: Arc<RwLock<Option<Arc<Auth>>>>,
    committed: AtomicBool,
    stopped: AtomicBool,
    closed: AtomicBool,
    connections: Arc<Semaphore>,
    handshakes: Arc<Semaphore>,
}
impl Driver {
    pub(super) fn closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub(super) fn accepting(&self) -> bool {
        self.committed.load(Ordering::Acquire)
            && !self.stopped.load(Ordering::Acquire)
            && !self.closed()
            && self.core.is_current()
    }
    fn authenticate(&self, uuid: &[u8; 16]) -> Option<Identity> {
        let _permit = self.core.users().publication().read();
        self.auth
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()?
            .identities
            .get(uuid)
            .cloned()
    }
    pub(super) fn accept(self: &Arc<Self>, socket: TcpStream, source: SocketAddr) {
        let Ok(connection) = self.connections.clone().try_acquire_owned() else {
            return;
        };
        let Ok(handshake) = self.handshakes.clone().try_acquire_owned() else {
            return;
        };
        let owned = self.clone();
        let _ = self
            .core
            .spawn("vless.connection", move |cancel| async move {
                let _connection = connection;
                owned.serve(socket, source, cancel, handshake).await
            });
    }
    async fn serve(
        self: Arc<Self>,
        socket: TcpStream,
        source: SocketAddr,
        cancel: crate::task::CancellationToken,
        handshake: tokio::sync::OwnedSemaphorePermit,
    ) -> Result<(), TaskFailure> {
        let context = OperationContext::new(
            cancel,
            Some(
                Deadline::after(self.options.handshake_timeout)
                    .map_err(|_| TaskFailure::Failed("handshake timeout"))?,
            ),
        );
        let buffers = self
            .core
            .buffers()
            .child(self.options.connection_buffers)
            .map_err(|_| TaskFailure::Failed("connection budget"))?;
        let encryption = self
            .encryption
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if self.closed() {
            return Err(TaskFailure::Cancelled);
        }
        let mut stream: Stream = if let Some(encryption) = encryption {
            Box::new(
                encryption
                    .handshake(socket, &buffers, &context)
                    .await
                    .map_err(|_| TaskFailure::Failed("encrypted handshake"))?,
            )
        } else {
            Box::new(socket)
        };
        let request = context
            .run(wire::Request::read(&mut stream))
            .await
            .map_err(TaskFailure::from)?
            .map_err(|_| TaskFailure::Failed("VLESS header"))?;
        let identity = self
            .authenticate(&request.uuid)
            .ok_or(TaskFailure::Failed("authentication"))?;
        let session = context
            .run(
                self.policies
                    .admit(&self.core, &identity, source.ip(), self.client.clone()),
            )
            .await
            .map_err(TaskFailure::from)?
            .map_err(|_| TaskFailure::Failed("admission"))?;
        drop(handshake);
        let forwarding = async {
            match request.command {
                wire::Command::Tcp => {
                    self.tcp(
                        stream,
                        request.target.as_ref().expect("TCP target"),
                        session.clone(),
                        buffers,
                    )
                    .await
                }
                wire::Command::Udp => {
                    super::udp::standard(
                        &self,
                        stream,
                        request.target.expect("UDP target"),
                        session.clone(),
                        buffers,
                    )
                    .await
                }
                wire::Command::Xudp => {
                    super::udp::multiplex(
                        &self,
                        stream,
                        &identity,
                        source.ip(),
                        session.clone(),
                        buffers,
                    )
                    .await
                }
            }
        };
        tokio::select! {
            result=session.run(forwarding)=>result.and_then(|result|result).map_err(|_|TaskFailure::Failed("forwarding")),
            result=session.maintain()=>result.map_err(|_|TaskFailure::Failed("device lease"))
        }
    }
    async fn tcp(
        &self,
        mut stream: Stream,
        target: &crate::network::Address,
        session: Arc<Session>,
        buffers: BufferScope,
    ) -> Result<(), flow::Error> {
        let context = session.context().child_with_deadline(
            Deadline::after(self.options.handshake_timeout)
                .map_err(|_| flow::Error::InvalidOptions)?,
        );
        let upstream = session
            .run(self.egress.connect(target, &context, self.core.metrics()))
            .await?
            .map_err(|_| flow::Error::Resolve)?;
        session.check()?;
        session
            .run(wire::write_response(&mut stream))
            .await?
            .map_err(|_| flow::Error::Io(std::io::ErrorKind::BrokenPipe))?;
        let client = Metered::new(stream, session.clone(), false);
        let upstream = Metered::new(upstream, session.clone(), true);
        let plane = DataPlane::new(
            buffers,
            TransferConfig::new(16384, Some(self.options.idle_timeout))
                .map_err(|_| flow::Error::InvalidOptions)?,
            self.core.metrics().clone(),
        )
        .map_err(|_| flow::Error::InvalidOptions)?;
        plane
            .relay_tcp(client, upstream, &session.context())
            .await
            .map_err(|_| flow::Error::Io(std::io::ErrorKind::ConnectionAborted))?;
        Ok(())
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
        let next = self.next.take().ok_or(users::Error::StaleCandidate)?;
        *self.target.write().unwrap_or_else(|e| e.into_inner()) = Some(next);
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
        let mut identities = BTreeMap::new();
        for user in snapshot.users() {
            let uuid = uuid::Uuid::parse_str(user.credential.expose())
                .map_err(|_| users::Error::InvalidUser)?;
            let id = snapshot.identity(user.id).ok_or(users::Error::Revoked)?;
            if identities.insert(*uuid.as_bytes(), id).is_some() {
                return Err(users::Error::DuplicateCredential);
            }
        }
        Ok(Box::new(AuthUpdate {
            target: self.auth.clone(),
            next: Some(Arc::new(Auth {
                _snapshot: snapshot,
                identities,
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
    async fn prepare_listener(
        &self,
        context: &OperationContext,
    ) -> Result<Box<dyn PreparedListener>, runtime::Error> {
        let binding = self
            .registry
            .bind(self.address, self.core.metrics().clone(), context)
            .await?;
        binding.register(self.weak.clone())?;
        *self.binding.lock().unwrap_or_else(|e| e.into_inner()) = Some(binding);
        Ok(Box::new(Listener(self.weak.clone())))
    }
    fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        self.stopped.store(true, Ordering::Release);
        self.encryption
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
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
