// SPDX-License-Identifier: GPL-3.0-only
use super::{
    Error, Settings, Strategy,
    system::System,
    transport::{Server, tls_config},
    wire,
};
use crate::{
    buffer::{BufferLayout, BufferScope, SharedBuffer},
    panel::DnsResolver,
    route::{self, geodata::Catalog},
    task::{CancellationToken, TaskGroup},
    telemetry::Metrics,
    time::{Deadline, OperationContext},
};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::RecordType,
};
use std::{
    collections::{HashMap, HashSet},
    future::poll_fn,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
struct Answer {
    wire: SharedBuffer,
    at: Instant,
    ttl: u32,
}
struct Cached {
    answer: Arc<Answer>,
    used: u64,
}
struct Flight {
    result: Mutex<Option<Result<Arc<Answer>, Error>>>,
    changed: Notify,
    cancel: CancellationToken,
    waiters: AtomicUsize,
}
struct Completion {
    inner: Arc<Inner>,
    key: Vec<u8>,
    flight: Arc<Flight>,
    done: bool,
}
impl Drop for Completion {
    fn drop(&mut self) {
        if !self.done {
            finish(&self.inner, &self.key, &self.flight, Err(Error::Transport));
        }
    }
}
struct Waiter {
    flight: Arc<Flight>,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Waiter {
    fn drop(&mut self) {
        if self.flight.waiters.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.flight.cancel.cancel();
        }
    }
}
struct Cache {
    entries: HashMap<Vec<u8>, Cached>,
    bytes: usize,
    tick: u64,
    pending: HashMap<Vec<u8>, Arc<Flight>>,
}
struct Inner {
    servers: Vec<Arc<Server>>,
    custom: bool,
    system: Arc<System>,
    settings: Settings,
    scope: BufferScope,
    cache: Mutex<Cache>,
    jobs: Mutex<TaskGroup>,
    waiters: Arc<Semaphore>,
    cancel: CancellationToken,
    closed: AtomicBool,
    hits: AtomicU64,
    misses: AtomicU64,
    coalesced: AtomicU64,
}
/// The owning guard cancels workers even when a pending query holds Inner.
pub struct Resolver {
    inner: Arc<Inner>,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Snapshot {
    pub entries: usize,
    pub bytes: usize,
    pub in_flight: usize,
    pub hits: u64,
    pub misses: u64,
    pub coalesced: u64,
}
impl Resolver {
    pub fn new(
        servers: &[DnsResolver],
        catalog: &mut Catalog,
        limits: &route::Limits,
        mut settings: Settings,
        scope: BufferScope,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        settings.validate()?;
        if servers.len() > 64 {
            return Err(Error::Configuration("resolver count"));
        }
        let mut bootstrap = std::collections::BTreeMap::new();
        for (host, ips) in std::mem::take(&mut settings.bootstrap) {
            let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
            if host.is_empty() || host.len() > 253 || bootstrap.insert(host, ips).is_some() {
                return Err(Error::Configuration("bootstrap name"));
            }
        }
        settings.bootstrap = bootstrap;
        let custom = !servers.is_empty();
        let system_servers = if custom {
            Vec::new()
        } else {
            system_servers(catalog)
        };
        let servers = if custom {
            servers
        } else {
            system_servers.as_slice()
        };
        let system = System::new(settings.concurrency);
        let tls = tls_config(&settings, catalog)?;
        let servers = servers
            .iter()
            .map(|item| {
                Server::compile(
                    item,
                    catalog,
                    limits,
                    &settings,
                    system.clone(),
                    tls.clone(),
                )
                .map(Arc::new)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cancel = CancellationToken::new();
        let jobs = TaskGroup::new(&cancel, settings.concurrency, metrics)
            .map_err(|_| Error::Configuration("query limit"))?;
        Ok(Self {
            inner: Arc::new(Inner {
                servers,
                custom,
                system,
                scope,
                waiters: Arc::new(Semaphore::new(settings.max_waiters)),
                settings,
                cache: Mutex::new(Cache {
                    entries: HashMap::new(),
                    bytes: 0,
                    tick: 0,
                    pending: HashMap::new(),
                }),
                jobs: Mutex::new(jobs),
                cancel,
                closed: AtomicBool::new(false),
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                coalesced: AtomicU64::new(0),
            }),
        })
    }
    pub fn configured(&self) -> bool {
        self.inner.custom
    }
    pub fn available(&self) -> bool {
        !self.inner.servers.is_empty()
    }
    pub fn intercept(&self) -> bool {
        self.configured() && self.inner.settings.intercept
    }
    pub fn system(&self) -> Arc<System> {
        self.inner.system.clone()
    }
    pub fn settings(&self) -> &Settings {
        &self.inner.settings
    }
    pub fn snapshot(&self) -> Snapshot {
        let cache = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            entries: cache.entries.len(),
            bytes: cache.bytes,
            in_flight: cache.pending.len(),
            hits: self.inner.hits.load(Ordering::Relaxed),
            misses: self.inner.misses.load(Ordering::Relaxed),
            coalesced: self.inner.coalesced.load(Ordering::Relaxed),
        }
    }
    pub async fn lookup(
        &self,
        name: &str,
        strategy: Strategy,
        context: &OperationContext,
    ) -> Result<Vec<IpAddr>, Error> {
        context.check().map_err(Error::Stopped)?;
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if let Ok(ip) = name.parse::<IpAddr>() {
            let ips = strategy.select([ip], self.inner.settings.max_answers);
            return if ips.is_empty() {
                Err(Error::NoRecords)
            } else {
                Ok(ips)
            };
        }
        if !self.configured() {
            let ips = self.inner.system.lookup(name, context).await?;
            let ips = strategy.select(ips, self.inner.settings.max_answers);
            return if ips.is_empty() {
                Err(Error::NoRecords)
            } else {
                Ok(ips)
            };
        }
        let v4 = async {
            if strategy.ipv4() {
                self.lookup_kind(name, RecordType::A, context).await
            } else {
                Ok(vec![])
            }
        };
        let v6 = async {
            if strategy.ipv6() {
                self.lookup_kind(name, RecordType::AAAA, context).await
            } else {
                Ok(vec![])
            }
        };
        let (a, b) = tokio::join!(v4, v6);
        let mut ips = Vec::new();
        let mut error = Error::NoRecords;
        for result in [a, b] {
            match result {
                Ok(values) => ips.extend(values),
                Err(value) => error = value,
            }
        }
        let ips = strategy.select(ips, self.inner.settings.max_answers);
        if ips.is_empty() { Err(error) } else { Ok(ips) }
    }
    async fn lookup_kind(
        &self,
        name: &str,
        kind: RecordType,
        context: &OperationContext,
    ) -> Result<Vec<IpAddr>, Error> {
        let mut name = name.to_owned();
        let mut visited = HashSet::new();
        for _ in 0..16 {
            if !visited.insert(name.to_ascii_lowercase()) {
                return Err(Error::InvalidResponse);
            }
            let query = wire::address_query(&name, kind)?;
            let answer = self.answer(query, context).await?;
            let message = wire::parse(answer.wire.as_slice())?;
            let (ips, next) = wire::addresses(&message)?;
            if !ips.is_empty() {
                return Ok(ips);
            }
            let Some(next) = next else {
                return Err(Error::NoRecords);
            };
            name = next;
        }
        Err(Error::InvalidResponse)
    }
    pub async fn exchange(
        &self,
        bytes: &[u8],
        udp: bool,
        context: &OperationContext,
    ) -> Result<SharedBuffer, Error> {
        let request = wire::query(bytes)?;
        let answer = self.answer(request.clone(), context).await?;
        let mut response = wire::parse(answer.wire.as_slice())?;
        wire::age(
            &mut response,
            answer.at.elapsed().as_secs().min(u32::MAX as u64) as u32,
        );
        let bytes = wire::for_client(response, &request, udp)?;
        self.copy(&bytes)
    }
    pub fn failure(
        &self,
        bytes: &[u8],
        code: ResponseCode,
        udp: bool,
    ) -> Result<SharedBuffer, Error> {
        let query = wire::query(bytes)?;
        let bytes = wire::for_client(wire::error_response(&query, code), &query, udp)?;
        self.copy(&bytes)
    }
    fn copy(&self, bytes: &[u8]) -> Result<SharedBuffer, Error> {
        copy(&self.inner.scope, bytes)
    }
    async fn answer(
        &self,
        request: Message,
        context: &OperationContext,
    ) -> Result<Arc<Answer>, Error> {
        context.check().map_err(Error::Stopped)?;
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let name = request.queries[0].name.to_ascii();
        let server = self.select(&name)?;
        let (request, mut key) = wire::canonical(request)?;
        key.extend_from_slice(&(server as u64).to_be_bytes());
        let permit = self
            .inner
            .waiters
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Capacity)?;
        let (flight, leader) = {
            let mut cache = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.tick = cache.tick.saturating_add(1);
            let tick = cache.tick;
            if let Some(entry) = cache.entries.get_mut(&key)
                && entry.answer.at.elapsed() < Duration::from_secs(u64::from(entry.answer.ttl))
            {
                entry.used = tick;
                self.inner.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(entry.answer.clone());
            }
            if let Some(entry) = cache.entries.remove(&key) {
                cache.bytes -= entry.answer.wire.len();
            }
            if let Some(flight) = cache.pending.get(&key).filter(|f| !f.cancel.is_cancelled()) {
                flight.waiters.fetch_add(1, Ordering::Relaxed);
                self.inner.coalesced.fetch_add(1, Ordering::Relaxed);
                (flight.clone(), false)
            } else {
                if cache.pending.len() >= self.inner.settings.concurrency {
                    return Err(Error::Capacity);
                }
                let flight = Arc::new(Flight {
                    result: Mutex::new(None),
                    changed: Notify::new(),
                    cancel: self.inner.cancel.child_token(),
                    waiters: AtomicUsize::new(1),
                });
                cache.pending.insert(key.clone(), flight.clone());
                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                (flight, true)
            }
        };
        let _waiter = Waiter {
            flight: flight.clone(),
            _permit: permit,
        };
        if leader {
            let inner = self.inner.clone();
            let task_flight = flight.clone();
            let task_key = key.clone();
            let mut jobs = self.inner.jobs.lock().unwrap_or_else(|e| e.into_inner());
            while jobs.try_join_next().is_some() {}
            let started = jobs.spawn("dns.query", move |_| async move {
                let mut completion = Completion {
                    inner: inner.clone(),
                    key: task_key.clone(),
                    flight: task_flight.clone(),
                    done: false,
                };
                let operation = OperationContext::new(
                    task_flight.cancel.clone(),
                    Some(
                        Deadline::after(Duration::from_secs(inner.settings.timeout_seconds))
                            .expect("validated timeout"),
                    ),
                );
                let result = async {
                    let (message, _) = inner.servers[server]
                        .exchange(&request, &inner.scope, &operation)
                        .await?;
                    let ttl = wire::ttl(
                        &message,
                        inner.settings.max_ttl_seconds,
                        inner.settings.negative_ttl_seconds,
                    );
                    if !matches!(
                        message.metadata.response_code,
                        ResponseCode::NoError | ResponseCode::NXDomain
                    ) {
                        return Err(Error::ServerFailure);
                    }
                    let bytes = message.to_vec().map_err(|_| Error::InvalidResponse)?;
                    Ok(Arc::new(Answer {
                        wire: copy(&inner.scope, &bytes)?,
                        at: Instant::now(),
                        ttl,
                    }))
                }
                .await;
                completion.done = true;
                finish(&inner, &task_key, &task_flight, result);
                Ok(())
            });
            drop(jobs);
            if started.is_err() {
                finish(&self.inner, &key, &flight, Err(Error::Capacity));
            }
        }
        context
            .run(async {
                loop {
                    let changed = flight.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if let Some(result) = flight
                        .result
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone()
                    {
                        return result;
                    }
                    changed.await;
                }
            })
            .await
            .map_err(Error::Stopped)?
    }
    fn select(&self, name: &str) -> Result<usize, Error> {
        let mut fallback = None;
        for (index, server) in self.inner.servers.iter().enumerate() {
            if server.default {
                fallback = Some(index);
            } else if server.selector.domain(name) {
                return Ok(index);
            }
        }
        fallback.ok_or(Error::NoResolver)
    }
    pub(crate) fn idle(&self) -> bool {
        let mut jobs = self.inner.jobs.lock().unwrap_or_else(|e| e.into_inner());
        while jobs.try_join_next().is_some() {}
        jobs.is_empty() && self.inner.system.idle()
    }
    pub fn abort(&self) {
        self.inner.closed.store(true, Ordering::Release);
        self.inner.cancel.cancel();
        self.inner.system.abort();
        self.inner.waiters.close();
        let flights = {
            let mut cache = self.inner.cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.entries.clear();
            cache.bytes = 0;
            std::mem::take(&mut cache.pending)
        };
        for flight in flights.into_values() {
            *flight.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(Err(Error::Closed));
            flight.changed.notify_waiters();
        }
        self.inner
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .abort_all();
    }
    pub async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        self.abort();
        while poll_fn(|cx| {
            self.inner
                .jobs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .poll_join_next(cx)
        })
        .await
        .is_some()
        {}
        self.inner.system.close(context).await
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        self.abort();
    }
}
fn copy(scope: &BufferScope, bytes: &[u8]) -> Result<SharedBuffer, Error> {
    let mut buffer = scope
        .try_lease(BufferLayout::new(0, bytes.len(), 0).map_err(|_| Error::Capacity)?)
        .map_err(|_| Error::Capacity)?;
    buffer.append_payload(bytes).map_err(|_| Error::Capacity)?;
    Ok(buffer.freeze())
}
fn finish(inner: &Inner, key: &[u8], flight: &Arc<Flight>, result: Result<Arc<Answer>, Error>) {
    let result = if inner.closed.load(Ordering::Acquire) {
        Err(Error::Closed)
    } else {
        result
    };
    {
        let mut cache = inner.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache
            .pending
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            cache.pending.remove(key);
            if let Ok(answer) = &result
                && answer.ttl > 0
                && !inner.closed.load(Ordering::Acquire)
                && inner.settings.cache_entries > 0
                && answer.wire.len() <= inner.settings.cache_bytes
            {
                let expired: Vec<_> = cache
                    .entries
                    .iter()
                    .filter(|(_, entry)| {
                        entry.answer.at.elapsed()
                            >= Duration::from_secs(u64::from(entry.answer.ttl))
                    })
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in expired {
                    if let Some(entry) = cache.entries.remove(&key) {
                        cache.bytes -= entry.answer.wire.len();
                    }
                }
                while cache.entries.len() >= inner.settings.cache_entries
                    || cache.bytes.saturating_add(answer.wire.len()) > inner.settings.cache_bytes
                {
                    let Some(oldest) = cache
                        .entries
                        .iter()
                        .min_by_key(|(_, entry)| entry.used)
                        .map(|(key, _)| key.clone())
                    else {
                        break;
                    };
                    let removed = cache.entries.remove(&oldest).expect("LRU entry");
                    cache.bytes -= removed.answer.wire.len();
                }
                cache.tick = cache.tick.saturating_add(1);
                let used = cache.tick;
                cache.bytes += answer.wire.len();
                cache.entries.insert(
                    key.to_vec(),
                    Cached {
                        answer: answer.clone(),
                        used,
                    },
                );
            }
        }
    }
    let mut slot = flight.result.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_none() {
        *slot = Some(if inner.closed.load(Ordering::Acquire) {
            Err(Error::Closed)
        } else {
            result
        });
    }
    drop(slot);
    flight.changed.notify_waiters();
}

fn system_servers(catalog: &mut Catalog) -> Vec<DnsResolver> {
    let Ok((bytes, stamp)) =
        crate::route::geodata::read(std::path::Path::new("/etc/resolv.conf"), 65536)
    else {
        return Vec::new();
    };
    let Ok(body) = String::from_utf8(bytes) else {
        return Vec::new();
    };
    if catalog.record(stamp).is_err() {
        return Vec::new();
    }
    let mut servers = Vec::new();
    for line in body.lines() {
        let mut parts = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(address) = parts.next().and_then(|s| s.parse::<IpAddr>().ok()) else {
            continue;
        };
        servers.push(DnsResolver {
            transport: "udp".into(),
            address: std::net::SocketAddr::new(address, 53).to_string(),
            server_name: String::new(),
            domains: vec![],
            extensions: std::collections::BTreeMap::new(),
        });
        if servers.len() == 16 {
            break;
        }
    }
    // The selector's final default is authoritative; retain OS priority.
    servers.reverse();
    servers
}
