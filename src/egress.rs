// SPDX-License-Identifier: GPL-3.0-only
//! Generation policy and process-owned compatible transport services.
use crate::{
    buffer::{
        BufferLayout, BufferQueue, BufferScope, BufferSender, QueueItem, QueueLimits, SharedBuffer,
        bounded_queue,
    },
    dns::{self, Resolver, Strategy},
    network::{self, Address, Network, Stream},
    outbound::{self, Connector, Packet, PacketPort},
    panel::{Outbound, ServerConfig},
    route::{
        self, Decision, Table, Target,
        geodata::{Catalog, Stamp},
    },
    runtime::{self, SharedServices},
    task::{CancellationToken, TaskGroup},
    telemetry::Metrics,
    time::{Deadline, OperationContext},
};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::{
    future::poll_fn,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex as AsyncMutex,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration(&'static str),
    Blocked,
    Closed,
    Capacity,
    Dns(dns::Error),
    Outbound(outbound::Error),
    Stopped(crate::time::StopReason),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "egress: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortKey {
    target: Target,
    family: bool,
}
pub struct Plan {
    pub decision: Decision,
    pub address: Address,
    addresses: Vec<SocketAddr>,
    pub port_key: PortKey,
    engine: Arc<Engine>,
}
pub struct Registry {
    engines: Mutex<Vec<Arc<Engine>>>,
    prepare: AsyncMutex<()>,
    closed: AtomicBool,
    dns: dns::Settings,
    routing: route::Settings,
    task_limit: usize,
    outbounds: Arc<outbound::Registry>,
    transports: Arc<crate::transport::Registry>,
}
impl Registry {
    pub fn new(
        dns: dns::Settings,
        routing: route::Settings,
        task_limit: usize,
    ) -> Result<Arc<Self>, Error> {
        Self::with_providers(
            dns,
            routing,
            task_limit,
            Arc::new(outbound::Registry::builtin()),
            Arc::new(crate::transport::Registry::builtin()),
        )
    }
    pub fn with_providers(
        dns: dns::Settings,
        routing: route::Settings,
        task_limit: usize,
        outbounds: Arc<outbound::Registry>,
        transports: Arc<crate::transport::Registry>,
    ) -> Result<Arc<Self>, Error> {
        dns.validate().map_err(Error::Dns)?;
        routing
            .limits
            .validate()
            .map_err(|_| Error::Configuration("route limits"))?;
        if task_limit == 0 {
            return Err(Error::Configuration("service tasks"));
        }
        Ok(Arc::new(Self {
            engines: Mutex::new(Vec::new()),
            prepare: AsyncMutex::new(()),
            closed: AtomicBool::new(false),
            dns,
            routing,
            task_limit,
            outbounds,
            transports,
        }))
    }
    pub async fn open(
        self: &Arc<Self>,
        config: &ServerConfig,
        buffers: BufferScope,
        metrics: Metrics,
        context: &OperationContext,
    ) -> Result<Handle, Error> {
        let _guard = context
            .run(self.prepare.lock())
            .await
            .map_err(Error::Stopped)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        self.reap();
        let candidate = Arc::new(Engine::compile(config, self, buffers, metrics)?);
        context.check().map_err(Error::Stopped)?;
        let mut engines = self.engines.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(current) = engines
            .iter()
            .find(|engine| engine.hash == candidate.hash && !engine.closed.load(Ordering::Acquire))
        {
            *current.stamps.lock().unwrap_or_else(|e| e.into_inner()) = candidate
                .stamps
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            return Ok(Handle {
                engine: Mutex::new(Some(current.clone())),
                hash: current.hash,
                registry: Arc::downgrade(self),
            });
        }
        if engines.len() >= 8 {
            return Err(Error::Capacity);
        }
        engines.push(candidate.clone());
        Ok(Handle {
            hash: candidate.hash,
            engine: Mutex::new(Some(candidate)),
            registry: Arc::downgrade(self),
        })
    }
    fn reap(&self) {
        let mut engines = self.engines.lock().unwrap_or_else(|e| e.into_inner());
        engines.retain(|engine| {
            if Arc::strong_count(engine) == 1 {
                engine.abort();
                !engine.idle()
            } else {
                true
            }
        });
    }
    pub fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        let engines = self
            .engines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for engine in engines {
            engine.abort();
        }
    }
    pub async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        self.abort();
        let engines = self
            .engines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        for engine in engines {
            engine.close(context).await?;
        }
        self.engines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        Ok(())
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        self.abort();
    }
}
pub struct Handle {
    engine: Mutex<Option<Arc<Engine>>>,
    hash: [u8; 32],
    registry: std::sync::Weak<Registry>,
}
impl Handle {
    fn engine(&self) -> Result<Arc<Engine>, Error> {
        self.engine
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(Error::Closed)
    }
    pub fn migration_scope(&self) -> [u8; 32] {
        self.hash
    }
    pub async fn plan(
        &self,
        target: &Address,
        network: Network,
        context: &OperationContext,
    ) -> Result<Plan, Error> {
        self.engine()?.plan(target, network, context).await
    }
    pub async fn connect(
        &self,
        target: &Address,
        context: &OperationContext,
        scope: BufferScope,
    ) -> Result<Stream, Error> {
        let engine = self.engine()?;
        let plan = engine.plan(target, Network::Tcp, context).await?;
        engine.connect(plan, scope, context).await
    }
    pub async fn packet(
        &self,
        plan: &Plan,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Arc<dyn PacketPort>, Error> {
        if plan.engine.hash != self.hash {
            return Err(Error::Closed);
        }
        plan.engine.packet(plan, scope, context).await
    }
    pub fn dns_snapshot(&self) -> Result<dns::Snapshot, Error> {
        Ok(self.engine()?.dns.snapshot())
    }
}
#[async_trait]
impl SharedServices for Handle {
    fn abort(&self) {
        self.engine.lock().unwrap_or_else(|e| e.into_inner()).take();
    }
    async fn close(&self, _: &OperationContext) -> Result<(), runtime::Error> {
        self.abort();
        if let Some(registry) = self.registry.upgrade() {
            registry.reap();
        }
        Ok(())
    }
    fn reload_required(&self) -> Result<bool, runtime::Error> {
        let engine = self.engine().map_err(|_| runtime::Error::Closed)?;
        for stamp in engine
            .stamps
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            if stamp
                .changed()
                .map_err(|_| runtime::Error::Preparation("policy asset unavailable"))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn invalidates(&self, next: &Self) -> bool {
        self.hash != next.hash
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.abort();
    }
}
struct Engine {
    hash: [u8; 32],
    table: Arc<Table>,
    strategy: Strategy,
    dns: Arc<Resolver>,
    proxies: Vec<Option<Arc<dyn Connector>>>,
    stamps: Mutex<Vec<Stamp>>,
    metrics: Metrics,
    cancel: CancellationToken,
    jobs: Mutex<TaskGroup>,
    closed: AtomicBool,
}
impl Engine {
    fn compile(
        config: &ServerConfig,
        services: &Registry,
        scope: BufferScope,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        let dns_settings = &services.dns;
        let routing = &services.routing;
        let outbounds = &services.outbounds;
        let active = config.protocols.iter().any(|p| p.enabled);
        let mut normalized = config.clone();
        if !active {
            normalized.dns.clear();
            normalized.block.clear();
            normalized.outbounds.clear();
            normalized.extensions.clear();
            normalized.ip_strategy.clear();
        }
        if !normalized.extensions.is_empty() {
            return Err(Error::Configuration("server extension"));
        }
        let strategy = Strategy::parse(&normalized.ip_strategy).map_err(Error::Dns)?;
        let mut catalog = Catalog::new(routing.assets());
        let table = Arc::new(
            Table::compile_with_registry(&normalized, &mut catalog, &routing.limits, outbounds)
                .map_err(|_| Error::Configuration("route rules"))?,
        );
        let effective_dns = if active {
            dns_settings.clone()
        } else {
            dns::Settings::default()
        };
        let dns = Arc::new(
            Resolver::new(
                &normalized.dns,
                &mut catalog,
                &routing.limits,
                effective_dns,
                scope.clone(),
                metrics.clone(),
            )
            .map_err(Error::Dns)?,
        );
        let tls = crate::dns::tls_config(
            &dns::Settings {
                ca_file: if active {
                    routing.outbound_ca_file.clone()
                } else {
                    None
                },
                ..Default::default()
            },
            &mut catalog,
        )
        .map_err(Error::Dns)?;
        let mut proxies = Vec::new();
        let outbound_context = outbound::registry::Context {
            tls,
            system: dns.system(),
            transports: services.transports.clone(),
        };
        for outbound in &normalized.outbounds {
            if outbounds
                .kind(outbound.protocol.as_str())
                .map_err(Error::Outbound)?
                == outbound::registry::Kind::Dns
                && !dns.available()
            {
                return Err(Error::Configuration("DNS outbound needs a resolver"));
            }
            proxies.push(
                outbounds
                    .compile(outbound, &outbound_context)
                    .map_err(Error::Outbound)?,
            );
        }
        let stamps = catalog.stamps();
        let hash = fingerprint(&normalized, &stamps, strategy);
        let cancel = CancellationToken::new();
        let jobs = TaskGroup::new(&cancel, services.task_limit, metrics.clone())
            .map_err(|_| Error::Configuration("service tasks"))?;
        Ok(Self {
            hash,
            table,
            strategy,
            dns,
            proxies,
            stamps: Mutex::new(stamps),
            metrics,
            cancel,
            jobs: Mutex::new(jobs),
            closed: AtomicBool::new(false),
        })
    }
    async fn plan(
        self: &Arc<Self>,
        target: &Address,
        network: Network,
        context: &OperationContext,
    ) -> Result<Plan, Error> {
        context.check().map_err(Error::Stopped)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let domain = target.domain_name().map(|value| value.as_str());
        let mut ips = target
            .socket_addr()
            .map(|address| vec![address.ip()])
            .unwrap_or_default();
        let preliminary = self.table.decide(domain, &ips);
        if preliminary.target == Target::Block && !self.table.ip_rules_before(preliminary) {
            return Err(Error::Blocked);
        }
        if ips.is_empty()
            && (preliminary.target == Target::Direct
                || self.table.has_ip_rules()
                || self.dns.configured())
        {
            ips = self
                .dns
                .lookup(
                    domain.ok_or(Error::Configuration("target"))?,
                    self.strategy,
                    context,
                )
                .await
                .map_err(Error::Dns)?;
        }
        ips = self.strategy.select(ips, self.dns.settings().max_answers);
        let mut decision = self.table.decide(domain, &ips);
        if decision.target == Target::Block {
            return Err(Error::Blocked);
        }
        if decision.rule.is_none() && target.port() == 53 && self.dns.intercept() {
            decision.target = Target::Dns;
        }
        if let Target::Proxy(index) = decision.target
            && !self.proxies[index]
                .as_ref()
                .is_some_and(|proxy| proxy.supports(network))
        {
            return Err(Error::Outbound(outbound::Error::Unsupported));
        }
        let addresses: Vec<_> = ips
            .into_iter()
            .filter(|ip| {
                decision.target == Target::Dns
                    || self.table.decide(domain, &[*ip]).target == decision.target
            })
            .map(|ip| SocketAddr::new(ip, target.port()))
            .collect();
        let address = if decision.target == Target::Dns {
            target.clone()
        } else if let Some(address) = addresses.first() {
            Address::from_socket(*address).map_err(|_| Error::Configuration("target"))?
        } else {
            target.clone()
        };
        let family =
            decision.target == Target::Direct && address.socket_addr().is_some_and(|v| v.is_ipv6());
        Ok(Plan {
            decision,
            address,
            addresses,
            port_key: PortKey {
                target: decision.target,
                family,
            },
            engine: self.clone(),
        })
    }
    async fn connect(
        self: &Arc<Self>,
        plan: Plan,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error> {
        match plan.decision.target {
            Target::Direct => {
                for address in plan.addresses {
                    if let Ok(stream) = network::connect_tcp(address, context, &self.metrics).await
                    {
                        return Ok(Box::new(stream));
                    }
                    context.check().map_err(Error::Stopped)?;
                }
                Err(Error::Outbound(outbound::Error::Io(
                    std::io::ErrorKind::ConnectionRefused,
                )))
            }
            Target::Proxy(index) => self.proxies[index]
                .as_ref()
                .ok_or(Error::Configuration("proxy"))?
                .connect(&plan.address, &scope, context)
                .await
                .map_err(Error::Outbound),
            Target::Block => Err(Error::Blocked),
            Target::Dns => self.dns_stream(scope),
        }
    }
    async fn packet(
        self: &Arc<Self>,
        plan: &Plan,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Arc<dyn PacketPort>, Error> {
        let port: Arc<dyn PacketPort> = match plan.decision.target {
            Target::Direct => {
                let address = if plan.port_key.family {
                    "[::]:0"
                } else {
                    "0.0.0.0:0"
                };
                Arc::new(
                    outbound::Direct::bind(
                        address.parse().expect("fixed bind"),
                        scope,
                        self.metrics.clone(),
                        context,
                    )
                    .await
                    .map_err(Error::Outbound)?,
                )
            }
            Target::Proxy(index) => self.proxies[index]
                .as_ref()
                .ok_or(Error::Configuration("proxy"))?
                .packet(scope, context)
                .await
                .map_err(Error::Outbound)?,
            Target::Block => return Err(Error::Blocked),
            Target::Dns => Arc::new(DnsPacket::new(self.clone(), scope)?),
        };
        Ok(Arc::new(OwnedPacket {
            port,
            _engine: self.clone(),
        }))
    }
    fn spawn<F>(&self, name: &'static str, future: F) -> Result<(), Error>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        while jobs.try_join_next().is_some() {}
        jobs.spawn(name, move |_| async move {
            future.await;
            Ok(())
        })
        .map_err(|_| Error::Capacity)?;
        Ok(())
    }
    async fn dns_answer(
        &self,
        query: &[u8],
        udp: bool,
        context: &OperationContext,
    ) -> Result<SharedBuffer, dns::Error> {
        let message = dns::wire::query(query)?;
        let name = message.queries[0].name.to_ascii();
        let preliminary = self.table.decide(Some(&name), &[]);
        if preliminary.target == Target::Block && !self.table.ip_rules_before(preliminary) {
            return self
                .dns
                .failure(query, hickory_proto::op::ResponseCode::Refused, udp);
        }
        match self.dns.exchange(query, udp, context).await {
            Ok(answer) => {
                let response = dns::wire::parse(answer.as_slice())?;
                let ips = response
                    .answers
                    .iter()
                    .filter_map(|r| match &r.data {
                        hickory_proto::rr::RData::A(ip) => Some(IpAddr::V4(ip.0)),
                        hickory_proto::rr::RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                if self.table.blocked(Some(&name), &ips)
                    || ips.iter().any(|ip| self.table.blocked(Some(&name), &[*ip]))
                {
                    self.dns
                        .failure(query, hickory_proto::op::ResponseCode::Refused, udp)
                } else {
                    Ok(answer)
                }
            }
            Err(dns::Error::Stopped(reason)) => Err(dns::Error::Stopped(reason)),
            Err(_) => self
                .dns
                .failure(query, hickory_proto::op::ResponseCode::ServFail, udp),
        }
    }
    fn dns_stream(self: &Arc<Self>, scope: BufferScope) -> Result<Stream, Error> {
        let (client, mut server) =
            network::pipe::pair(scope.clone(), 8).map_err(|_| Error::Capacity)?;
        let token = self.cancel.child_token();
        let returned = client.cancel_on_drop(token.clone());
        let engine = self.clone();
        self.spawn("egress.dns.tcp", async move {
            let context = OperationContext::new(token, None);
            let _ = context
                .run(async {
                    loop {
                        let n = match server.read_u16().await {
                            Ok(n) => n as usize,
                            Err(_) => return,
                        };
                        if n < 12 {
                            return;
                        }
                        let mut query = match scope
                            .try_lease(BufferLayout::new(0, n, 0).expect("bounded DNS length"))
                        {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        if query.append_zeroed(n).is_err()
                            || server.read_exact(query.as_mut_slice()).await.is_err()
                        {
                            return;
                        }
                        let reply = match engine.dns_answer(query.as_slice(), false, &context).await
                        {
                            Ok(value) => value,
                            Err(_) => return,
                        };
                        if server
                            .write_all(&(reply.len() as u16).to_be_bytes())
                            .await
                            .is_err()
                            || server.write_all(reply.as_slice()).await.is_err()
                        {
                            return;
                        }
                    }
                })
                .await;
        })?;
        Ok(Box::new(returned))
    }
    fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancel.cancel();
        self.dns.abort();
        for proxy in self.proxies.iter().flatten() {
            proxy.abort();
        }
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .abort_all();
    }
    fn idle(&self) -> bool {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        while jobs.try_join_next().is_some() {}
        jobs.is_empty()
            && self.dns.idle()
            && self.proxies.iter().flatten().all(|proxy| proxy.idle())
    }
    async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        self.abort();
        while poll_fn(|cx| {
            self.jobs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .poll_join_next(cx)
        })
        .await
        .is_some()
        {}
        let mut error = None;
        for proxy in self.proxies.iter().flatten() {
            if let Err(e) = proxy.close(context).await {
                error.get_or_insert(Error::Outbound(e));
            }
        }
        if let Err(e) = self.dns.close(context).await {
            error.get_or_insert(Error::Dns(e));
        }
        error.map_or(Ok(()), Err)
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        self.abort();
    }
}
struct OwnedPacket {
    port: Arc<dyn PacketPort>,
    _engine: Arc<Engine>,
}
#[async_trait]
impl PacketPort for OwnedPacket {
    async fn send(
        &self,
        target: &Address,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), outbound::Error> {
        tokio::select! {biased;_=self._engine.cancel.cancelled()=>Err(outbound::Error::Closed),result=self.port.send(target,payload,context)=>result}
    }
    async fn recv(&self, context: &OperationContext) -> Result<Packet, outbound::Error> {
        tokio::select! {biased;_=self._engine.cancel.cancelled()=>Err(outbound::Error::Closed),result=self.port.recv(context)=>result}
    }
    fn abort(&self) {
        self.port.abort();
    }
}
impl Drop for OwnedPacket {
    fn drop(&mut self) {
        self.port.abort();
    }
}
struct DnsPacket {
    engine: Arc<Engine>,
    scope: BufferScope,
    sender: BufferSender<Packet>,
    queue: AsyncMutex<BufferQueue<Packet>>,
    cancel: CancellationToken,
}
impl QueueItem for Packet {
    fn queue_bytes(&self) -> usize {
        self.payload.len()
    }
}
impl DnsPacket {
    fn new(engine: Arc<Engine>, scope: BufferScope) -> Result<Self, Error> {
        let (sender, queue) =
            bounded_queue(QueueLimits::new(32 * 65535, 32, 32).map_err(|_| Error::Capacity)?)
                .map_err(|_| Error::Capacity)?;
        let cancel = engine.cancel.child_token();
        Ok(Self {
            engine,
            scope,
            sender,
            queue: AsyncMutex::new(queue),
            cancel,
        })
    }
}
#[async_trait]
impl PacketPort for DnsPacket {
    async fn send(
        &self,
        target: &Address,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), outbound::Error> {
        dns::wire::query(payload).map_err(|_| outbound::Error::Protocol)?;
        let permit = self
            .sender
            .try_reserve(65535)
            .map_err(|_| outbound::Error::Capacity)?;
        let mut query = self
            .scope
            .try_lease(
                BufferLayout::new(0, payload.len(), 0).map_err(|_| outbound::Error::Capacity)?,
            )
            .map_err(|_| outbound::Error::Capacity)?;
        query
            .append_payload(payload)
            .map_err(|_| outbound::Error::Capacity)?;
        let engine = self.engine.clone();
        let source = target.clone();
        let token = self.cancel.child_token();
        let sender = self.sender.clone();
        let reply_scope = self.scope.clone();
        context.check().map_err(outbound::Error::Stopped)?;
        self.engine
            .spawn("egress.dns.udp", async move {
                let operation = OperationContext::new(
                    token,
                    Some(
                        Deadline::after(Duration::from_secs(engine.dns.settings().timeout_seconds))
                            .expect("validated timeout"),
                    ),
                );
                if let Ok(response) = engine.dns_answer(query.as_slice(), true, &operation).await {
                    // Cache storage belongs to the engine; queued per-client
                    // replies must also respect that association's byte budget.
                    let Ok(layout) = BufferLayout::new(0, response.len(), 0) else {
                        return;
                    };
                    let Ok(mut payload) = reply_scope.try_lease(layout) else {
                        return;
                    };
                    if payload.append_payload(response.as_slice()).is_err() {
                        return;
                    }
                    drop(permit);
                    let _ = sender.try_send(Packet {
                        source,
                        payload: payload.freeze(),
                    });
                }
            })
            .map_err(|_| outbound::Error::Capacity)?;
        Ok(())
    }
    async fn recv(&self, context: &OperationContext) -> Result<Packet, outbound::Error> {
        let mut queue = context
            .run(self.queue.lock())
            .await
            .map_err(outbound::Error::Stopped)?;
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(outbound::Error::Closed),value=context.run(queue.recv())=>value.map_err(outbound::Error::Stopped)?.ok_or(outbound::Error::Closed)}
    }
    fn abort(&self) {
        self.cancel.cancel();
        self.sender.close();
    }
}
impl Drop for DnsPacket {
    fn drop(&mut self) {
        self.abort();
    }
}
fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
fn fingerprint(config: &ServerConfig, stamps: &[Stamp], strategy: Strategy) -> [u8; 32] {
    let mut hash = Sha256::new();
    field(&mut hash, format!("{strategy:?}").as_bytes());
    field(&mut hash, b"terraris.egress.v1");
    field(&mut hash, &(config.dns.len() as u64).to_be_bytes());
    for server in &config.dns {
        for value in [&server.transport, &server.address, &server.server_name] {
            field(&mut hash, value.as_bytes());
        }
        field(&mut hash, &(server.domains.len() as u64).to_be_bytes());
        for domain in &server.domains {
            field(&mut hash, domain.as_bytes());
        }
    }
    field(&mut hash, &(config.block.len() as u64).to_be_bytes());
    for rule in &config.block {
        field(&mut hash, rule.as_bytes());
    }
    field(&mut hash, &(config.outbounds.len() as u64).to_be_bytes());
    for outbound in &config.outbounds {
        hash_outbound(&mut hash, outbound);
    }
    field(&mut hash, &(stamps.len() as u64).to_be_bytes());
    for stamp in stamps {
        field(&mut hash, &stamp.digest);
    }
    hash.finalize().into()
}
fn hash_outbound(hash: &mut Sha256, value: &Outbound) {
    field(hash, value.name.as_bytes());
    field(hash, value.protocol.as_str().as_bytes());
    field(hash, value.address.as_bytes());
    field(hash, &value.port.to_be_bytes());
    field(hash, value.user.as_bytes());
    field(hash, value.password.expose().as_bytes());
    field(hash, value.uuid.expose().as_bytes());
    field(hash, value.cipher.as_bytes());
    field(hash, value.plugin.as_bytes());
    field(hash, value.security.as_bytes());
    field(hash, value.sni.as_bytes());
    field(hash, &(value.alpn.len() as u64).to_be_bytes());
    for item in &value.alpn {
        field(hash, item.as_bytes());
    }
    field(hash, &[u8::from(value.allow_insecure)]);
    field(hash, value.fingerprint.as_bytes());
    field(hash, value.transport.as_bytes());
    field(hash, value.host.as_bytes());
    field(hash, value.path.as_bytes());
    field(hash, value.service_name.as_bytes());
    field(hash, value.xhttp_mode.as_bytes());
    field(hash, value.xhttp_extra.as_bytes());
    field(hash, value.flow.as_bytes());
    field(hash, value.encryption.as_bytes());
    field(hash, value.encryption_mode.as_bytes());
    field(hash, value.encryption_rtt.as_bytes());
    field(hash, value.encryption_ticket.expose().as_bytes());
    field(hash, value.encryption_client_padding.as_bytes());
    field(hash, value.encryption_password.expose().as_bytes());
    field(hash, value.multiplex.as_bytes());
    field(hash, &[u8::from(value.uot)]);
    field(hash, &value.uot_version.to_be_bytes());
    field(hash, value.congestion_controller.as_bytes());
    field(hash, &[u8::from(value.udp_stream)]);
    field(hash, &[u8::from(value.reduce_rtt)]);
    field(hash, &value.heartbeat.to_be_bytes());
    field(hash, value.reality_public_key.as_bytes());
    field(hash, value.reality_short_id.as_bytes());
    field(hash, value.spider_x.as_bytes());
    field(hash, value.settings.as_bytes());
    field(hash, value.stream_settings.as_bytes());
    field(hash, &(value.rules.len() as u64).to_be_bytes());
    for item in &value.rules {
        field(hash, item.as_bytes());
    }
}
