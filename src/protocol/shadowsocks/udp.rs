// SPDX-License-Identifier: GPL-3.0-only
//! UDP ingress has one polling owner. Authenticated associations own bounded
//! queues and relay ports and can move to a compatible published generation.
use super::{
    method::Key,
    packet::{self, Decoded},
    replay::{Protection, UdpState},
    server::Driver,
};
use crate::{
    buffer::{BufferScope, SharedBuffer},
    egress::{Handle, PortKey},
    network::{Address, DatagramEndpoint, Network},
    outbound::{Packet, PacketPort},
    protocol::{
        flow::{self, Session},
        stream::Options,
    },
    runtime::{self, GenerationId},
    task::{CancellationToken, TaskGroup},
    telemetry::Metrics,
    time::{Deadline, OperationContext},
    users::Identity,
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    collections::{HashMap, HashSet},
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};
type Endpoint = Arc<DatagramEndpoint>;
#[derive(Clone, PartialEq, Eq, Hash)]
enum Peer {
    Classic(SocketAddr),
    Session([u8; 8]),
}
#[derive(Clone, PartialEq, Eq, Hash)]
struct Index {
    identity: Identity,
    policy: [u8; 32],
    key: [u8; 32],
    peer: Peer,
}
struct Owner {
    session: Arc<Session>,
    generation: GenerationId,
    source: SocketAddr,
    endpoint: Endpoint,
    arrival: u64,
}
struct Message {
    target: Address,
    payload: SharedBuffer,
}
struct Association {
    owner: Mutex<Owner>,
    changed: Notify,
    send: mpsc::Sender<Message>,
    cancel: CancellationToken,
    scope: BufferScope,
    index: Index,
}
type Slot = AsyncMutex<Weak<Association>>;
type AuthHints = HashMap<SocketAddr, ([u8; 32], Weak<Association>)>;
struct Jobs {
    group: TaskGroup,
    tracked: HashMap<tokio::task::Id, Weak<Association>>,
}
pub(super) struct Service {
    options: Options,
    metrics: Metrics,
    cancel: CancellationToken,
    jobs: Mutex<Jobs>,
    changed: Notify,
    entries: Mutex<HashMap<Index, Weak<Slot>>>,
    hints: Mutex<AuthHints>,
    bindings: AsyncMutex<HashMap<SocketAddr, Weak<Binding>>>,
    arrival: Arc<AtomicU64>,
}
impl Service {
    pub fn new(options: Options, metrics: Metrics) -> Result<Arc<Self>, runtime::Error> {
        let cancel = CancellationToken::new();
        let group = TaskGroup::new(&cancel, options.max_connections, metrics.clone())
            .map_err(runtime::Error::Task)?;
        Ok(Arc::new(Self {
            options,
            metrics,
            cancel,
            jobs: Mutex::new(Jobs {
                group,
                tracked: HashMap::new(),
            }),
            changed: Notify::new(),
            entries: Mutex::new(HashMap::new()),
            hints: Mutex::new(HashMap::new()),
            bindings: AsyncMutex::new(HashMap::new()),
            arrival: Arc::new(AtomicU64::new(0)),
        }))
    }
    pub fn hint(&self, source: SocketAddr) -> Option<[u8; 32]> {
        self.hints
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&source)
            .filter(|(_, a)| a.strong_count() > 0)
            .map(|(key, _)| *key)
    }
    pub async fn bind(
        &self,
        address: SocketAddr,
        driver: Weak<Driver>,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Arc<Binding>, runtime::Error> {
        let mut bindings = context
            .run(self.bindings.lock())
            .await
            .map_err(runtime::Error::Stopped)?;
        if let Some(binding) = bindings
            .get(&address)
            .and_then(Weak::upgrade)
            .filter(|b| !b.cancel.is_cancelled())
        {
            binding.register(driver)?;
            return Ok(binding);
        }
        bindings.retain(|_, v| v.strong_count() > 0);
        if bindings.len() >= 64 {
            return Err(runtime::Error::Preparation("SS UDP listeners"));
        }
        let endpoint = Arc::new(
            DatagramEndpoint::bind(
                address,
                scope,
                packet::MAX_WIRE,
                self.metrics.clone(),
                context,
            )
            .await
            .map_err(|_| runtime::Error::Preparation("SS UDP bind"))?,
        );
        let cancel = CancellationToken::new();
        let binding = Arc::new(Binding {
            routes: Mutex::new(vec![driver]),
            cancel: cancel.clone(),
            tasks: AsyncMutex::new(
                TaskGroup::new(&cancel, 1, self.metrics.clone()).map_err(runtime::Error::Task)?,
            ),
        });
        let weak = Arc::downgrade(&binding);
        let arrivals = self.arrival.clone();
        binding.tasks.lock().await.spawn("ss.udp.receive",move|cancel|async move{
   let context=OperationContext::new(cancel.clone(),None);
   loop{
    let received=tokio::select!{biased;_=cancel.cancelled()=>break,packet=endpoint.recv(&context)=>packet};
    let packet=match received{Ok(packet)=>packet,Err(_)=>{tokio::time::sleep(Duration::from_millis(5)).await;continue;}};
    let Some(binding)=weak.upgrade()else{break;};let driver=binding.candidates().into_iter().find(|d|d.accepting());drop(binding);
    if let Some(driver)=driver{let Ok(arrival)=arrivals.fetch_update(Ordering::AcqRel,Ordering::Acquire,|n|n.checked_add(1))else{break;};driver.accept_packet(packet,endpoint.clone(),arrival);}
   }Ok(())
  }).map_err(runtime::Error::Task)?;
        bindings.insert(address, Arc::downgrade(&binding));
        Ok(binding)
    }
    fn reap(&self, jobs: &mut Jobs) {
        while let Some(report) = jobs.group.try_join_next() {
            jobs.tracked.remove(&report.id);
            self.changed.notify_waiters();
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch(
        self: &Arc<Self>,
        driver: &Driver,
        identity: Identity,
        decoded: Decoded,
        source: SocketAddr,
        endpoint: Endpoint,
        arrival: u64,
        context: &OperationContext,
    ) -> Result<(), flow::Error> {
        if self.cancel.is_cancelled() || !driver.accepting() || source.port() == 0 {
            return Err(flow::Error::Stopped);
        }
        let index = Index {
            identity: identity.clone(),
            policy: driver.egress.migration_scope(),
            key: decoded.key.id,
            peer: decoded
                .client_id
                .map_or(Peer::Classic(source), Peer::Session),
        };
        let slot = {
            let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(slot) = entries.get(&index).and_then(Weak::upgrade) {
                slot
            } else {
                entries.retain(|_, v| v.strong_count() > 0);
                if entries.len() >= self.options.max_connections {
                    return Err(flow::Error::Capacity);
                }
                let slot = Arc::new(AsyncMutex::new(Weak::new()));
                entries.insert(index.clone(), Arc::downgrade(&slot));
                slot
            }
        };
        let mut current = context
            .run(slot.lock())
            .await
            .map_err(|_| flow::Error::Stopped)?;
        let previous = current
            .upgrade()
            .filter(|a| !a.cancel.is_cancelled() && !a.send.is_closed());
        let renew = previous.as_ref().is_none_or(|a| {
            let (generation, ip, session) = {
                let owner = a.owner.lock().unwrap_or_else(|e| e.into_inner());
                (owner.generation, owner.source.ip(), owner.session.clone())
            };
            generation != driver.core.generation() || ip != source.ip() || session.check().is_err()
        });
        let session = if renew {
            Some(
                context
                    .run(driver.policies.admit(
                        &driver.core,
                        &identity,
                        source.ip(),
                        driver.client.clone(),
                    ))
                    .await
                    .map_err(|_| flow::Error::Stopped)??,
            )
        } else {
            None
        };
        let association = if let Some(a) =
            previous.filter(|a| !a.cancel.is_cancelled() && !a.send.is_closed())
        {
            let mut owner = a.owner.lock().unwrap_or_else(|e| e.into_inner());
            if arrival < owner.arrival {
                return Ok(());
            }
            if let Some(session) = session {
                owner.session = session;
                owner.generation = driver.core.generation();
            }
            owner.source = source;
            owner.endpoint = endpoint;
            owner.arrival = arrival;
            drop(owner);
            if renew {
                a.changed.notify_waiters();
            }
            a
        } else {
            let session = if let Some(session) = session {
                session
            } else {
                context
                    .run(driver.policies.admit(
                        &driver.core,
                        &identity,
                        source.ip(),
                        driver.client.clone(),
                    ))
                    .await
                    .map_err(|_| flow::Error::Stopped)??
            };
            let scope = driver
                .core
                .buffers()
                .child(driver.options.connection_buffers)
                .map_err(|_| flow::Error::Capacity)?;
            let (send, receive) = mpsc::channel(driver.options.queue_packets);
            let a = Arc::new(Association {
                owner: Mutex::new(Owner {
                    session,
                    generation: driver.core.generation(),
                    source,
                    endpoint,
                    arrival,
                }),
                changed: Notify::new(),
                send,
                cancel: CancellationToken::new(),
                scope,
                index: index.clone(),
            });
            let runner = a.clone();
            let retained = slot.clone();
            let egress = driver.egress.clone();
            let options = driver.options.clone();
            let method = driver.config.method;
            let key = decoded.key.clone();
            let state = decoded.state.clone();
            let client = decoded.client_id;
            let protection = driver.protection.clone();
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            self.reap(&mut jobs);
            let id=jobs.group.spawn("ss.udp.session",move|cancel|async move{
    let _slot=retained;
    tokio::select!{biased;_=cancel.cancelled()=>{},_=runner.cancel.cancelled()=>{},_=run(&runner,receive,egress,options,method,key,client,state,protection)=>{}}
    runner.cancel.cancel();Ok(())
   }).map_err(|_|flow::Error::Capacity)?;
            jobs.tracked.insert(id, Arc::downgrade(&a));
            *current = Arc::downgrade(&a);
            a
        };
        {
            let mut hints = self.hints.lock().unwrap_or_else(|e| e.into_inner());
            if hints.len() >= self.options.max_connections {
                hints.retain(|_, (_, a)| a.strong_count() > 0);
            }
            if hints.len() < self.options.max_connections || hints.contains_key(&source) {
                hints.insert(source, (decoded.key.id, Arc::downgrade(&association)));
            }
        }
        let payload = decoded
            .payload
            .freeze()
            .copy_to(&association.scope)
            .map_err(|_| flow::Error::Capacity)?
            .freeze();
        association
            .send
            .try_send(Message {
                target: decoded
                    .target
                    .address()
                    .map_err(|e| flow::Error::Io(e.kind()))?,
                payload,
            })
            .map_err(|_| flow::Error::Capacity)?;
        Ok(())
    }
    pub fn retain_policy(&self, policy: [u8; 32]) {
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        for a in jobs.tracked.values().filter_map(Weak::upgrade) {
            if a.index.policy != policy {
                a.cancel.cancel();
            }
        }
    }
    pub fn cancel_generation(&self, generation: GenerationId) {
        let jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        for a in jobs.tracked.values().filter_map(Weak::upgrade) {
            if a.owner.lock().unwrap_or_else(|e| e.into_inner()).generation == generation {
                a.cancel.cancel();
            }
        }
    }
    pub async fn close_generation(
        &self,
        generation: GenerationId,
        context: &OperationContext,
    ) -> Result<(), runtime::Error> {
        self.cancel_generation(generation);
        let selected = {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            self.reap(&mut jobs);
            jobs.tracked
                .iter()
                .filter(|(_, a)| {
                    a.upgrade().is_none_or(|a| {
                        a.owner.lock().unwrap_or_else(|e| e.into_inner()).generation == generation
                    })
                })
                .map(|(id, _)| *id)
                .collect::<HashSet<_>>()
        };
        context.run(async{loop{
   let changed=self.changed.notified();tokio::pin!(changed);changed.as_mut().enable();
   {let mut jobs=self.jobs.lock().unwrap_or_else(|e|e.into_inner());self.reap(&mut jobs);if selected.iter().all(|id|!jobs.tracked.contains_key(id)){return;}}
   tokio::select!{_=changed=>{},_=poll_fn(|cx|{let mut jobs=self.jobs.lock().unwrap_or_else(|e|e.into_inner());jobs.group.poll_join_next(cx).map(|report|{if let Some(report)=report{jobs.tracked.remove(&report.id);self.changed.notify_waiters();}})})=>{}}
  }}).await.map_err(runtime::Error::Stopped)
    }
    pub fn abort(&self) {
        self.cancel.cancel();
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .group
            .abort_all();
    }
    pub async fn close(&self, _context: &OperationContext) -> Result<(), runtime::Error> {
        self.abort();
        while poll_fn(|cx| {
            self.jobs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .group
                .poll_join_next(cx)
        })
        .await
        .is_some()
        {}
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .tracked
            .clear();
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.abort();
    }
}
pub(super) struct Binding {
    routes: Mutex<Vec<Weak<Driver>>>,
    cancel: CancellationToken,
    tasks: AsyncMutex<TaskGroup>,
}
impl Binding {
    fn register(&self, driver: Weak<Driver>) -> Result<(), runtime::Error> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        routes.retain(|v| v.strong_count() > 0);
        if self.cancel.is_cancelled() || routes.len() >= 64 {
            return Err(runtime::Error::Closed);
        }
        routes.push(driver);
        Ok(())
    }
    fn candidates(&self) -> Vec<Arc<Driver>> {
        self.routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
    pub fn stop_if_unused(&self) {
        let drivers: Vec<Arc<Driver>>;
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        drivers = routes.iter().filter_map(Weak::upgrade).collect();
        if drivers.iter().all(|d| d.closed()) {
            self.cancel.cancel();
        }
        drop(routes);
        drop(drivers);
    }
    pub async fn close_if_unused(&self, deadline: Deadline) {
        self.stop_if_unused();
        if self.cancel.is_cancelled() {
            self.tasks.lock().await.shutdown(deadline).await;
        }
    }
}
impl Drop for Binding {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.get_mut().abort_all();
    }
}
struct Port {
    socket: Arc<dyn PacketPort>,
    allowed: HashSet<Address>,
    domain: bool,
}
impl Drop for Port {
    fn drop(&mut self) {
        self.socket.abort();
    }
}
type Receive =
    Pin<Box<dyn Future<Output = (PortKey, Result<Packet, crate::outbound::Error>)> + Send>>;
fn receive(key: PortKey, socket: Arc<dyn PacketPort>, context: OperationContext) -> Receive {
    Box::pin(async move { (key, socket.recv(&context).await) })
}
#[allow(clippy::too_many_arguments)]
async fn run(
    a: &Arc<Association>,
    mut input: mpsc::Receiver<Message>,
    egress: Arc<Handle>,
    options: Options,
    method: super::Method,
    key: Arc<Key>,
    client: Option<[u8; 8]>,
    state: Option<Arc<Mutex<UdpState>>>,
    protection: Arc<Protection>,
) -> Result<(), flow::Error> {
    let mut ports = HashMap::<PortKey, Port>::new();
    let mut receives = FuturesUnordered::<Receive>::new();
    let mut last = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let actor_context = OperationContext::new(a.cancel.clone(), None);
    loop {
        let changed = a.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let session = a
            .owner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .session
            .clone();
        let session_context = session.context();
        if session.check().is_err() {
            tokio::select! {_=changed=>continue,_=tokio::time::sleep(Duration::from_secs(1))=>return Ok(())}
        }
        tokio::select! {
         biased;
         _=changed=>continue,
         _=session_context.cancellation().cancelled()=>continue,
         _=tokio::time::sleep_until(last+options.udp_idle_timeout)=>return Ok(()),
         _=tick.tick()=>{if session.refresh_device().await.is_err(){continue;}},
         message=input.recv()=>{
          let Some(message)=message else{return Ok(());};
          let op=session.context().child_with_deadline(Deadline::after(options.handshake_timeout).map_err(|_|flow::Error::InvalidOptions)?);
          let ports = &mut ports;
          let receives = &mut receives;
          let active = session.clone();
          let target_egress = egress.clone();
          let recv_context = actor_context.clone();
          let result=async move{
           let session = active;
           let egress = target_egress;
           let plan=match session.run(egress.plan(&message.target,Network::Udp,&op)).await?{Ok(v)=>v,Err(crate::egress::Error::Blocked)=>return Ok(()),Err(_)=>return Err(flow::Error::Resolve)};
           if !ports.contains_key(&plan.port_key){if ports.len()>=options.max_udp_ports{return Err(flow::Error::Capacity);}let socket=session.run(egress.packet(&plan,a.scope.clone(),&op)).await?.map_err(|_|flow::Error::Resolve)?;receives.push(receive(plan.port_key,socket.clone(),recv_context));ports.insert(plan.port_key,Port{socket,allowed:HashSet::new(),domain:false});}
           let port=ports.get_mut(&plan.port_key).unwrap();if port.allowed.len()>=256&&!port.allowed.contains(&plan.address){return Err(flow::Error::Capacity);}port.domain|=plan.address.domain_name().is_some();port.allowed.insert(plan.address.clone());
           let n=message.payload.len();let mut quota=session.quota(n).await?;let mut count=session.reserve(true,n)?;
           session.run(port.socket.send(&plan.address,message.payload.as_slice(),&op)).await?.map_err(|_|flow::Error::Resolve)?;quota.commit(n);count.commit(n as u64);Ok::<_,flow::Error>(())
          }.await;
          if result.is_err()&&session.check().is_ok(){return result;}last=tokio::time::Instant::now();
         },
         received=receives.next(),if !receives.is_empty()=>{
          let(port_key,packet)=received.unwrap();let packet=packet.map_err(|_|flow::Error::Resolve)?;let port=ports.get(&port_key).unwrap();receives.push(receive(port_key,port.socket.clone(),actor_context.clone()));
          if !port.allowed.contains(&packet.source)&&!port.domain{continue;}
          let n=packet.payload.len();let mut quota=session.quota(n).await?;let mut count=session.reserve(false,n)?;
          let target=crate::protocol::socksaddr::Endpoint::from_address(&packet.source).map_err(|e|flow::Error::Io(e.kind()))?;
          let wire=packet::response(method,key.clone(),client,state.as_ref(),&target,packet.payload.as_slice(),&a.scope).map_err(|e|flow::Error::Io(e.kind()))?;
          if !method.modern(){protection.udp_salt(key.id,&wire.as_slice()[..method.key_len()]).map_err(|e|flow::Error::Io(e.kind()))?;}
          let (endpoint,source)={let owner=a.owner.lock().unwrap_or_else(|e|e.into_inner());(owner.endpoint.clone(),owner.source)};
          session.run(endpoint.send_to(source,wire.as_slice(),&actor_context)).await?.map_err(|_|flow::Error::Resolve)?;quota.commit(n);count.commit(n as u64);last=tokio::time::Instant::now();
         }
        }
    }
}
