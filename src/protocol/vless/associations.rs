// SPDX-License-Identifier: GPL-3.0-only

//! Process-owned UDP associations. A carrier owns an attachment, not a socket.
//! A nonzero GlobalID can move only within the same authenticated store/epoch
//! and egress policy. Every takeover receives a fresh policy session.
use super::options::Options;
use crate::{
    buffer::{BufferScope, BufferSender, QueueItem},
    egress::{Handle as Egress, Plan, PortKey},
    outbound::{Packet as Datagram, PacketPort},
    protocol::{
        flow::{Error, Session},
        runtimekit::Core,
    },
    task::{CancellationToken, TaskGroup},
    telemetry::Metrics,
    time::{Deadline, OperationContext, Revocation},
    users::{Identity, Store},
};
use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Mutex as AsyncMutex, time::Instant};

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    identity: Identity,
    egress: [u8; 32],
    global: [u8; 8],
}
struct Index {
    entries: HashMap<u64, Arc<Entry>>,
    global: HashMap<Key, u64>,
    next: u64,
}
struct Jobs {
    group: Option<TaskGroup>,
    started: bool,
}
pub(super) struct Registry {
    index: Mutex<Index>,
    jobs: Mutex<Jobs>,
    close_gate: AsyncMutex<()>,
    cancel: CancellationToken,
    closed: AtomicBool,
    options: Options,
    reattachments: AtomicU64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub associations: usize,
    pub attached: usize,
    pub detached: usize,
    pub buffered_packets: usize,
    pub tracked_tasks: usize,
    pub reattachments: u64,
}

/// Per-carrier slot revisions keep delayed End frames from closing a reused ID.
pub(super) struct Carrier {
    slots: Mutex<HashMap<u16, u64>>,
    activity: Mutex<Instant>,
}
impl Carrier {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            slots: Mutex::new(HashMap::new()),
            activity: Mutex::new(Instant::now()),
        })
    }
    pub(super) fn install(&self, id: u16, serial: u64) {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, serial);
        self.touch();
    }
    pub(super) fn remove(&self, id: u16, serial: u64) {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        if slots.get(&id) == Some(&serial) {
            slots.remove(&id);
        }
    }
    pub(super) fn matches(&self, id: u16, serial: u64) -> bool {
        self.slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .is_none_or(|value| *value == serial)
    }
    pub(super) fn touch(&self) {
        *self.activity.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }
    pub(super) fn last(&self) -> Instant {
        *self.activity.lock().unwrap_or_else(|e| e.into_inner())
    }
}
pub(super) enum Output {
    Data {
        packet: Datagram,
        binding: Arc<Binding>,
        entry: Weak<Entry>,
    },
    End {
        id: u16,
        serial: u64,
        carrier: Arc<Carrier>,
        error: bool,
    },
}
impl QueueItem for Output {
    fn queue_bytes(&self) -> usize {
        match self {
            Self::Data { packet, .. } => packet.payload.len(),
            Self::End { .. } => 0,
        }
    }
}
pub(super) struct Binding {
    pub(super) id: u16,
    serial: u64,
    owner: u64,
    pub(super) session: Arc<Session>,
    pub(super) context: OperationContext,
    flag: Revocation,
    sender: BufferSender<Output>,
    carrier: Arc<Carrier>,
}
impl Binding {
    fn stop(&self) {
        self.flag.notify();
        self.context.cancellation().cancel();
    }
    fn end(&self) {
        let _ = self.sender.try_send(Output::End {
            id: self.id,
            serial: self.serial,
            carrier: self.carrier.clone(),
            error: false,
        });
    }
}
struct State {
    owner: u64,
    binding: Option<Arc<Binding>>,
    pending: VecDeque<Datagram>,
    last: Instant,
    expires: Option<Instant>,
}
pub(super) struct Entry {
    id: u64,
    key: Option<Key>,
    identity: Identity,
    store: Store,
    buffers: BufferScope,
    registry: Weak<Registry>,
    cancel: CancellationToken,
    closed: AtomicBool,
    state: Mutex<State>,
    sockets: Mutex<HashMap<PortKey, Arc<dyn PacketPort>>>,
    policy: [u8; 32],
    bind_gate: AsyncMutex<()>,
    idle: Duration,
    resume: Duration,
    pending_limit: usize,
}
pub(super) struct Lease {
    entry: Arc<Entry>,
    pub(super) binding: Arc<Binding>,
    pub(super) target: crate::network::Address,
    handshake_timeout: Duration,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.binding
            .carrier
            .remove(self.binding.id, self.binding.serial);
        self.entry.detach(self.binding.owner);
    }
}
impl Lease {
    pub(super) fn valid(&self) -> bool {
        !self.entry.closed.load(Ordering::Acquire)
            && self.binding.context.check().is_ok()
            && self.binding.session.check().is_ok()
    }
    pub(super) async fn send(
        &self,
        plan: &Plan,
        egress: &Egress,
        packet: &[u8],
    ) -> Result<(), Error> {
        self.binding
            .context
            .run(self.binding.session.run(async {
                let socket = self.entry.socket(self, plan, egress).await?;
                let mut quota = self.binding.session.quota(packet.len()).await?;
                let mut counter = self.binding.session.reserve(true, packet.len())?;
                self.binding.context.check().map_err(|_| Error::Stopped)?;
                socket
                    .send(&plan.address, packet, &self.binding.context)
                    .await
                    .map_err(|_| Error::Io(std::io::ErrorKind::ConnectionAborted))?;
                quota.commit(packet.len());
                counter.commit(packet.len() as u64);
                self.entry.touch(self.binding.owner);
                Ok(())
            }))
            .await
            .map_err(|_| Error::Stopped)??
    }
}
impl Registry {
    pub(super) fn new(options: Options) -> Arc<Self> {
        Arc::new(Self {
            index: Mutex::new(Index {
                entries: HashMap::new(),
                global: HashMap::new(),
                next: 1,
            }),
            jobs: Mutex::new(Jobs {
                group: None,
                started: false,
            }),
            close_gate: AsyncMutex::new(()),
            cancel: CancellationToken::new(),
            closed: AtomicBool::new(false),
            options,
            reattachments: AtomicU64::new(0),
        })
    }
    fn start(self: &Arc<Self>, metrics: Metrics) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        if jobs.group.is_none() {
            jobs.group = Some(
                TaskGroup::new(
                    &self.cancel,
                    self.options.max_xudp_associations * 2 + 1,
                    metrics,
                )
                .map_err(|_| Error::Capacity)?,
            );
        }
        if !jobs.started {
            let weak = Arc::downgrade(self);
            jobs.group.as_mut().expect("group").spawn("xudp.reaper",move|cancel|async move{loop{tokio::select!{biased;_=cancel.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}let Some(registry)=weak.upgrade()else{break;};registry.prune();registry.reap();}Ok(())}).map_err(|_|Error::Capacity)?;
            jobs.started = true;
        }
        Ok(())
    }
    fn reap(&self) {
        if let Some(group) = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .group
            .as_mut()
        {
            while group.try_join_next().is_some() {}
        }
    }
    fn entries(&self) -> Vec<Arc<Entry>> {
        self.index
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .values()
            .cloned()
            .collect()
    }
    fn prune(&self) {
        let entries = self.entries();
        for entry in &entries {
            entry.prune();
        }
        let mut removed = Vec::new();
        let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
        for entry in entries {
            if entry.closed.load(Ordering::Acquire)
                && index
                    .entries
                    .get(&entry.id)
                    .is_some_and(|current| Arc::ptr_eq(current, &entry))
            {
                if let Some(key) = &entry.key
                    && index.global.get(key) == Some(&entry.id)
                {
                    index.global.remove(key);
                }
                if let Some(entry) = index.entries.remove(&entry.id) {
                    removed.push(entry);
                }
            }
        }
        drop(index);
        drop(removed);
    }
    fn remove_closed(&self, id: u64, key: Option<&Key>) {
        let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(key) = key
            && index.global.get(key) == Some(&id)
        {
            index.global.remove(key);
        }
        let removed = index.entries.remove(&id);
        drop(index);
        drop(removed);
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) fn attach(
        self: &Arc<Self>,
        core: &Core,
        identity: &Identity,
        egress: [u8; 32],
        global: Option<[u8; 8]>,
        id: u16,
        serial: u64,
        target: crate::network::Address,
        session: Arc<Session>,
        sender: BufferSender<Output>,
        carrier: Arc<Carrier>,
    ) -> Result<Lease, Error> {
        session.check()?;
        self.start(core.metrics().clone())?;
        if self
            .index
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .len()
            >= self.options.max_xudp_associations
        {
            self.prune();
        }
        let key = global.filter(|id| *id != [0; 8]).map(|global| Key {
            identity: identity.clone(),
            egress,
            global,
        });
        // Retry once if expiry wins the race with this attachment.
        for _ in 0..2 {
            let entry = {
                let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
                if self.closed.load(Ordering::Acquire) {
                    return Err(Error::Stopped);
                }
                let existing = key
                    .as_ref()
                    .and_then(|key| index.global.get(key))
                    .and_then(|id| index.entries.get(id))
                    .cloned();
                if let Some(entry) = existing {
                    entry
                } else {
                    if index.entries.len() >= self.options.max_xudp_associations {
                        return Err(Error::Capacity);
                    }
                    let buffers = core
                        .buffers()
                        .child(self.options.connection_buffers)
                        .map_err(|_| Error::Capacity)?;
                    let number = index.next;
                    index.next = number.checked_add(1).ok_or(Error::Capacity)?;
                    let entry = Arc::new(Entry {
                        id: number,
                        key: key.clone(),
                        identity: identity.clone(),
                        store: core.users().clone(),
                        buffers,
                        registry: Arc::downgrade(self),
                        cancel: self.cancel.child_token(),
                        closed: AtomicBool::new(false),
                        state: Mutex::new(State {
                            owner: 0,
                            binding: None,
                            pending: VecDeque::new(),
                            last: Instant::now(),
                            expires: None,
                        }),
                        sockets: Mutex::new(HashMap::new()),
                        policy: egress,
                        bind_gate: AsyncMutex::new(()),
                        idle: self.options.udp_idle_timeout,
                        resume: self.options.xudp_resume_timeout,
                        pending_limit: self.options.xudp_detached_packets,
                    });
                    if let Some(key) = &key {
                        index.global.insert(key.clone(), number);
                    }
                    index.entries.insert(number, entry.clone());
                    entry
                }
            };
            match entry.attach(id, serial, session.clone(), sender.clone(), carrier.clone()) {
                Ok(binding) => {
                    if binding.owner > 1 {
                        let _ = self.reattachments.fetch_update(
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                            |value| Some(value.saturating_add(1)),
                        );
                    }
                    return Ok(Lease {
                        entry,
                        binding,
                        target,
                        handshake_timeout: self.options.handshake_timeout,
                    });
                }
                Err(Error::Stopped) => {
                    self.prune();
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::Stopped)
    }
    fn reader(
        self: &Arc<Self>,
        entry: Arc<Entry>,
        socket: Arc<dyn PacketPort>,
    ) -> Result<(), Error> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        let group = jobs.group.as_mut().ok_or(Error::Stopped)?;
        while group.try_join_next().is_some() {}
        group
            .spawn("xudp.receive", move |_| async move {
                let _guard = ReadGuard(Arc::downgrade(&entry));
                let context = OperationContext::new(entry.cancel.clone(), None);
                loop {
                    match socket.recv(&context).await {
                        Ok(packet) => entry.deliver(packet),
                        Err(crate::outbound::Error::Capacity) => {
                            if context
                                .run(tokio::time::sleep(Duration::from_millis(100)))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                    if context.check().is_err() {
                        break;
                    }
                }
                Ok(())
            })
            .map_err(|_| Error::Capacity)?;
        Ok(())
    }
    pub(super) fn retain_policy(&self, policy: [u8; 32]) {
        for entry in self.entries() {
            if entry.policy != policy {
                entry.close();
            }
        }
    }
    pub(super) fn snapshot(&self) -> Snapshot {
        self.prune();
        let entries = self.entries();
        let mut snapshot = Snapshot {
            reattachments: self.reattachments.load(Ordering::Relaxed),
            ..Snapshot::default()
        };
        for entry in entries {
            let state = entry.state.lock().unwrap_or_else(|e| e.into_inner());
            snapshot.associations += 1;
            if state.binding.is_some() {
                snapshot.attached += 1;
            } else {
                snapshot.detached += 1;
            }
            snapshot.buffered_packets += state.pending.len();
        }
        snapshot.tracked_tasks = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .group
            .as_ref()
            .map_or(0, TaskGroup::len);
        snapshot
    }
    pub(super) fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        self.cancel.cancel();
        let entries = {
            let mut index = self.index.lock().unwrap_or_else(|e| e.into_inner());
            index.global.clear();
            std::mem::take(&mut index.entries)
        };
        for entry in entries.into_values() {
            entry.close();
        }
        if let Some(group) = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .group
            .as_mut()
        {
            group.abort_all();
        }
    }
    pub(super) async fn close(&self, deadline: Deadline) {
        let _guard = self.close_gate.lock().await;
        self.abort();
        loop {
            let result = poll_fn(|cx| {
                let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
                match jobs.group.as_mut() {
                    Some(group) => group.poll_join_next(cx),
                    None => std::task::Poll::Ready(None),
                }
            });
            tokio::select! {biased;_=deadline.wait()=>{if let Some(group)=self.jobs.lock().unwrap_or_else(|e|e.into_inner()).group.as_mut(){group.abort_all();}break;},report=result=>if report.is_none(){return;}}
        }
        while poll_fn(|cx| {
            self.jobs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .group
                .as_mut()
                .map_or(std::task::Poll::Ready(None), |g| g.poll_join_next(cx))
        })
        .await
        .is_some()
        {}
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        self.abort();
    }
}
struct ReadGuard(Weak<Entry>);
impl Drop for ReadGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.0.upgrade() {
            entry.close();
        }
    }
}
impl Entry {
    fn attach(
        self: &Arc<Self>,
        id: u16,
        serial: u64,
        session: Arc<Session>,
        sender: BufferSender<Output>,
        carrier: Arc<Carrier>,
    ) -> Result<Arc<Binding>, Error> {
        session.check()?;
        if self.store.validate_identity(&self.identity).is_err() {
            self.close();
            return Err(Error::Revoked);
        }
        let (old, binding) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if self.closed.load(Ordering::Acquire)
                || state.expires.is_some_and(|at| at <= Instant::now())
                || state.expires.is_none() && state.last.elapsed() >= self.idle
            {
                drop(state);
                self.close();
                return Err(Error::Stopped);
            }
            state.owner = state.owner.checked_add(1).ok_or(Error::Capacity)?;
            let flag = Revocation::default();
            let context = OperationContext::new(self.cancel.child_token(), None)
                .with_revocation(flag.clone())
                .expect("fresh binding");
            let binding = Arc::new(Binding {
                id,
                serial,
                owner: state.owner,
                session,
                context,
                flag,
                sender,
                carrier,
            });
            let old = state.binding.replace(binding.clone());
            if let Some(old) = &old {
                old.flag.mark();
            }
            state.expires = None;
            state.last = Instant::now();
            binding.carrier.touch();
            while let Some(packet) = state.pending.pop_front() {
                let _ = binding.sender.try_send(Output::Data {
                    packet,
                    binding: binding.clone(),
                    entry: Arc::downgrade(self),
                });
            }
            (old, binding)
        };
        if let Some(old) = old {
            old.stop();
            old.end();
        }
        Ok(binding)
    }
    fn detach(&self, owner: u64) {
        let old = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state
                .binding
                .as_ref()
                .is_none_or(|binding| binding.owner != owner)
            {
                return;
            }
            let old = state.binding.take().expect("owner");
            old.flag.mark();
            state.expires = Some(Instant::now() + self.resume);
            old
        };
        old.stop();
        if self.key.is_none()
            || self
                .sockets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty()
        {
            self.close();
        }
    }
    fn touch(&self, owner: u64) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(binding) = &state.binding
            && binding.owner == owner
        {
            binding.carrier.touch();
            state.last = Instant::now();
        }
    }
    fn prune(&self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if self.store.validate_identity(&self.identity).is_err() {
            self.close();
            return;
        }
        let binding = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .binding
            .clone();
        if let Some(binding) = binding
            && binding.session.check().is_err()
        {
            self.detach(binding.owner);
        }
        self.close_if(|state| {
            if let Some(at) = state.expires {
                at <= Instant::now()
            } else {
                state.last.elapsed() >= self.idle
            }
        });
    }
    pub(super) fn deliver(self: &Arc<Self>, packet: Datagram) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if self.store.validate_identity(&self.identity).is_err() {
            self.close();
            return;
        }
        let binding = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .binding
            .clone();
        if let Some(binding) = binding
            && binding.session.check().is_err()
        {
            self.detach(binding.owner);
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        if let Some(binding) = &state.binding {
            binding.carrier.touch();
            let binding = binding.clone();
            state.last = Instant::now();
            let _ = binding.sender.try_send(Output::Data {
                packet,
                binding: binding.clone(),
                entry: Arc::downgrade(self),
            });
        } else if state.expires.is_some_and(|at| at > Instant::now())
            && state.pending.len() < self.pending_limit
        {
            state.pending.push_back(packet);
        }
    }
    async fn socket(
        self: &Arc<Self>,
        lease: &Lease,
        plan: &Plan,
        egress: &Egress,
    ) -> Result<Arc<dyn PacketPort>, Error> {
        let context = lease.binding.context.child_with_deadline(
            Deadline::after(lease.handshake_timeout).map_err(|_| Error::InvalidOptions)?,
        );
        let _gate = context
            .run(self.bind_gate.lock())
            .await
            .map_err(|_| Error::Stopped)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }
        if let Some(socket) = self
            .sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&plan.port_key)
        {
            return Ok(socket.clone());
        }
        if self.sockets.lock().unwrap_or_else(|e| e.into_inner()).len() >= 64 {
            return Err(Error::Capacity);
        }
        let socket = egress
            .packet(plan, self.buffers.clone(), &context)
            .await
            .map_err(|_| Error::Capacity)?;
        {
            let mut sockets = self.sockets.lock().unwrap_or_else(|e| e.into_inner());
            context.check().map_err(|_| Error::Stopped)?;
            if self.closed.load(Ordering::Acquire) {
                socket.abort();
                return Err(Error::Stopped);
            }
            sockets.insert(plan.port_key, socket.clone());
        }
        if let Err(error) = self
            .registry
            .upgrade()
            .ok_or(Error::Stopped)?
            .reader(self.clone(), socket.clone())
        {
            self.close();
            return Err(error);
        }
        Ok(socket)
    }
    fn close(&self) {
        self.close_if(|_| true);
    }
    fn close_if(&self, predicate: impl FnOnce(&State) -> bool) {
        let (old, pending) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if self.closed.load(Ordering::Acquire) || !predicate(&state) {
                return;
            }
            self.closed.store(true, Ordering::Release);
            let old = state.binding.take();
            if let Some(binding) = &old {
                binding.flag.mark();
            }
            (old, std::mem::take(&mut state.pending))
        };
        self.cancel.cancel();
        if let Some(binding) = old {
            binding.stop();
            binding.end();
        }
        let sockets = std::mem::take(&mut *self.sockets.lock().unwrap_or_else(|e| e.into_inner()));
        for socket in sockets.into_values() {
            socket.abort();
        }
        drop(pending);
        if let Some(registry) = self.registry.upgrade() {
            registry.remove_closed(self.id, self.key.as_ref());
        }
    }
}
impl Drop for Entry {
    fn drop(&mut self) {
        self.close();
    }
}
