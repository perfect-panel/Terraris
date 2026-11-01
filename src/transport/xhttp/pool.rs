// SPDX-License-Identifier: MPL-2.0
// Bounded XMUX request/connection ownership, adapted from Polaris 56d52fb44958.
use super::{
    Error,
    body::{self, Body},
    config::Config,
    h3 as quic,
    server::Executor,
};
use crate::{
    buffer::BufferScope,
    time::OperationContext,
    transport::{Outbound, jobs::Jobs},
};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::BodyExt;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;
pub type ResponseFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, Error>> + Send>>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    H1,
    H2,
    H3,
}
pub struct Endpoint {
    pub version: Version,
    pub dial: Arc<dyn Outbound>,
    pub tls: Option<Arc<rustls::ClientConfig>>,
    pub name: String,
}
pub struct Manager {
    pub config: Arc<Config>,
    pub endpoint: Endpoint,
    pub jobs: Arc<Jobs>,
    groups: Mutex<Vec<Arc<Group>>>,
    all: Mutex<Vec<std::sync::Weak<Group>>>,
    max_connections: usize,
    max_concurrency: usize,
}
pub struct Group {
    physical: AsyncMutex<Vec<Arc<Physical>>>,
    sessions: AtomicUsize,
    uses: AtomicUsize,
    requests: AtomicUsize,
    expires: Option<tokio::time::Instant>,
    retired: AtomicBool,
}
struct Physical {
    sender: Sender,
    peer: SocketAddr,
    active: AtomicUsize,
    done: AtomicBool,
    last: Mutex<tokio::time::Instant>,
    connection: Option<quinn::Connection>,
    endpoint: Option<quinn::Endpoint>,
}
enum Sender {
    H1(Mutex<hyper::client::conn::http1::SendRequest<Body>>),
    H2(hyper::client::conn::http2::SendRequest<Body>),
    H3(h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>),
}
#[derive(Clone)]
pub struct Lease {
    pub group: Arc<Group>,
    pub _manager: Arc<Manager>,
    _use: Arc<SessionUse>,
}
struct SessionUse(Arc<Group>);
impl Drop for SessionUse {
    fn drop(&mut self) {
        self.0.sessions.fetch_sub(1, Ordering::AcqRel);
    }
}
struct RequestLease {
    physical: Arc<Physical>,
    _group: Arc<Group>,
}
impl Drop for RequestLease {
    fn drop(&mut self) {
        self.physical.active.fetch_sub(1, Ordering::AcqRel);
        *self.physical.last.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
    }
}
struct DriverDone(Arc<Physical>);
impl Drop for DriverDone {
    fn drop(&mut self) {
        self.0.done.store(true, Ordering::Release);
        if let Some(c) = &self.0.connection {
            c.close(0u32.into(), b"closed");
        }
        if let Some(e) = &self.0.endpoint {
            e.close(0u32.into(), b"closed");
        }
    }
}
pub struct Open {
    pub response: ResponseFuture,
    pub peer: SocketAddr,
}
impl Manager {
    pub fn new(config: Arc<Config>, endpoint: Endpoint) -> Result<Arc<Self>, Error> {
        let max_connections = config.xmux.max_connections.random();
        let max_concurrency = config.xmux.max_concurrency.random();
        Ok(Arc::new(Self {
            config,
            endpoint,
            jobs: Arc::new(Jobs::new(4096)?),
            groups: Mutex::new(Vec::new()),
            all: Mutex::new(Vec::new()),
            max_connections,
            max_concurrency,
        }))
    }
    pub fn acquire(self: &Arc<Self>) -> Result<Lease, Error> {
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        self.acquire_locked(&mut groups)
    }
    fn acquire_locked(self: &Arc<Self>, groups: &mut Vec<Arc<Group>>) -> Result<Lease, Error> {
        if self.jobs.cancel.is_cancelled() {
            return Err(closed());
        }
        groups.retain(|g| {
            if !g.available() {
                g.retired.store(true, Ordering::Release);
                false
            } else {
                true
            }
        });
        let candidate = if self.max_connections > 0 && groups.len() < self.max_connections {
            None
        } else {
            groups
                .iter()
                .filter(|g| {
                    self.max_concurrency == 0
                        || g.sessions.load(Ordering::Acquire) < self.max_concurrency
                })
                .min_by_key(|g| g.sessions.load(Ordering::Acquire))
                .cloned()
        };
        let group = if let Some(g) = candidate {
            g
        } else {
            let mut all = self.all.lock().unwrap_or_else(|e| e.into_inner());
            all.retain(|v| v.strong_count() > 0);
            if all.len() >= 128 {
                return Err(Error::Io(io::ErrorKind::WouldBlock));
            }
            let reuse = self.config.xmux.c_max_reuse_times.random();
            let requests = self.config.xmux.h_max_request_times.random();
            let age = self.config.xmux.h_max_reusable_secs.random();
            let g = Arc::new(Group {
                physical: AsyncMutex::new(Vec::new()),
                sessions: AtomicUsize::new(0),
                uses: AtomicUsize::new(if reuse == 0 { usize::MAX } else { reuse }),
                requests: AtomicUsize::new(if requests == 0 { usize::MAX } else { requests }),
                expires: if age == 0 {
                    None
                } else {
                    Some(tokio::time::Instant::now() + Duration::from_secs(age as u64))
                },
                retired: AtomicBool::new(false),
            });
            all.push(Arc::downgrade(&g));
            groups.push(g.clone());
            g
        };
        group.uses.fetch_sub(1, Ordering::AcqRel);
        group.sessions.fetch_add(1, Ordering::AcqRel);
        Ok(Lease {
            _use: Arc::new(SessionUse(group.clone())),
            group,
            _manager: self.clone(),
        })
    }
    pub fn abort(&self) {
        self.jobs.abort();
        for g in self
            .all
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(std::sync::Weak::upgrade)
        {
            g.retired.store(true, Ordering::Release);
            if let Ok(physical) = g.physical.try_lock() {
                for p in physical.iter() {
                    if let Some(c) = &p.connection {
                        c.close(0u32.into(), b"shutdown");
                    }
                    if let Some(e) = &p.endpoint {
                        e.close(0u32.into(), b"shutdown");
                    }
                }
            }
        }
    }
    pub fn idle(&self) -> bool {
        self.jobs.idle()
    }
    pub async fn close(&self) {
        self.abort();
        self.jobs.close().await;
        let groups = self
            .all
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .collect::<Vec<_>>();
        for g in groups {
            let physical = std::mem::take(&mut *g.physical.lock().await);
            for p in physical {
                if let Some(e) = &p.endpoint {
                    e.wait_idle().await;
                }
            }
        }
        self.groups
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
    pub async fn open(
        self: &Arc<Self>,
        lease: &mut Lease,
        addresses: &[SocketAddr],
        scope: &BufferScope,
        context: &OperationContext,
        request: Request<Body>,
    ) -> Result<Open, Error> {
        self.reserve_request(lease, context)?;
        let physical = self
            .connection(&lease.group, addresses, scope, context)
            .await?;
        let guard = Arc::new(RequestLease {
            physical: physical.clone(),
            _group: lease.group.clone(),
        });
        let peer = physical.peer;
        let future: ResponseFuture = match &physical.sender {
            Sender::H1(sender) => {
                let response = sender
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .send_request(request);
                Box::pin(async move {
                    response
                        .await
                        .map(|r| r.map(body::incoming))
                        .map_err(|_| closed())
                })
            }
            Sender::H2(sender) => {
                let mut sender = sender.clone();
                context
                    .run(sender.ready())
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| closed())?;
                let response = sender.send_request(request);
                Box::pin(async move {
                    response
                        .await
                        .map(|r| r.map(body::incoming))
                        .map_err(|_| closed())
                })
            }
            Sender::H3(sender) => {
                let mut sender = sender.clone();
                let (parts, mut body) = request.into_parts();
                let stream = context
                    .run(sender.send_request(Request::from_parts(parts, ())))
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| closed())?;
                let (mut send, mut recv) = stream.split();
                let upload_guard = guard.clone();
                self.jobs
                    .spawn("xhttp.h3-upload", move |cancel| async move {
                        let _guard = upload_guard;
                        let send = async {
                            while let Some(frame) = body.frame().await {
                                if let Ok(data) = frame?.into_data() {
                                    send.send_data(data).await.map_err(io::Error::other)?;
                                }
                            }
                            send.finish().await.map_err(io::Error::other)
                        };
                        tokio::select! {_=cancel.cancelled()=>{},_=send=>{}}
                        Ok(())
                    })?;
                Box::pin(async move {
                    let response = recv.recv_response().await.map_err(|_| closed())?;
                    Ok(response.map(|_| quic::ClientBody(recv).boxed_unsync()))
                })
            }
        };
        Ok(Open {
            peer,
            response: Box::pin(async move {
                let response = future.await?;
                Ok(response.map(|b| body::Guarded::boxed(b, guard)))
            }),
        })
    }
    fn reserve_request(
        self: &Arc<Self>,
        lease: &mut Lease,
        context: &OperationContext,
    ) -> Result<(), Error> {
        // Selection and ticket consumption share one lock. With concurrent
        // uploads, a replacement must not lose its last request between
        // acquire() and take_request() and spuriously abort a healthy session.
        let mut groups = self.groups.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            context.check().map_err(Error::Stopped)?;
            if lease.group.take_request() {
                return Ok(());
            }
            lease.group.retired.store(true, Ordering::Release);
            *lease = self.acquire_locked(&mut groups)?;
        }
    }
    async fn connection(
        self: &Arc<Self>,
        group: &Arc<Group>,
        addresses: &[SocketAddr],
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Arc<Physical>, Error> {
        let mut connections = context
            .run(group.physical.lock())
            .await
            .map_err(Error::Stopped)?;
        if self.jobs.cancel.is_cancelled() {
            return Err(closed());
        }
        connections.retain(|c| !c.done.load(Ordering::Acquire));
        for c in connections.iter() {
            let cap = if self.endpoint.version == Version::H1 {
                1
            } else {
                64
            };
            let ready = match &c.sender {
                Sender::H1(s) => s.lock().unwrap_or_else(|e| e.into_inner()).is_ready(),
                Sender::H2(s) => !s.is_closed(),
                Sender::H3(_) => c
                    .connection
                    .as_ref()
                    .is_some_and(|c| c.close_reason().is_none()),
            };
            if ready && addresses.contains(&c.peer) && c.active.load(Ordering::Acquire) < cap {
                c.active.fetch_add(1, Ordering::AcqRel);
                return Ok(c.clone());
            }
        }
        if connections.len() >= 64 {
            return Err(Error::Io(io::ErrorKind::WouldBlock));
        }
        let executor = Executor(Arc::downgrade(&self.jobs));
        let (sender, peer, driver, connection, endpoint): ConnectionParts =
            if self.endpoint.version == Version::H3 {
                let tls = self.endpoint.tls.as_ref().ok_or(Error::Tls)?;
                let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((**tls).clone())
                    .map_err(|_| Error::Tls)?;
                let mut config = quinn::ClientConfig::new(Arc::new(crypto));
                config.transport_config(quic::transport(&self.config, false));
                let (endpoint, connection, peer) =
                    quic::dial(addresses, &self.endpoint.name, config, context).await?;
                let (mut driver, sender) = context
                    .run(h3::client::new(h3_quinn::Connection::new(
                        connection.clone(),
                    )))
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| closed())?;
                (
                    Sender::H3(sender),
                    peer,
                    Box::pin(async move {
                        let _ = driver.wait_idle().await;
                    }),
                    Some(connection),
                    Some(endpoint),
                )
            } else {
                let (socket, peer) = self
                    .endpoint
                    .dial
                    .connect(addresses, scope, context)
                    .await?;
                let socket = hyper_util::rt::TokioIo::new(socket);
                if self.endpoint.version == Version::H2 {
                    let mut builder = hyper::client::conn::http2::Builder::new(executor);
                    builder
                        .initial_stream_window_size(65536)
                        .initial_connection_window_size(1 << 20)
                        .max_send_buf_size(65536)
                        .max_header_list_size(self.config.server_max_header_bytes as u32);
                    if self.config.xmux.h_keep_alive_period > 0 {
                        builder
                            .timer(hyper_util::rt::TokioTimer::new())
                            .keep_alive_interval(Some(Duration::from_secs(
                                self.config.xmux.h_keep_alive_period as u64,
                            )))
                            .keep_alive_while_idle(true);
                    }
                    let (sender, connection) = context
                        .run(builder.handshake(socket))
                        .await
                        .map_err(Error::Stopped)?
                        .map_err(|_| closed())?;
                    (
                        Sender::H2(sender),
                        peer,
                        Box::pin(async move {
                            let _ = connection.await;
                        }),
                        None,
                        None,
                    )
                } else {
                    let mut builder = hyper::client::conn::http1::Builder::new();
                    builder.max_buf_size(self.config.server_max_header_bytes.max(8192));
                    let (sender, connection) = context
                        .run(builder.handshake(socket))
                        .await
                        .map_err(Error::Stopped)?
                        .map_err(|_| closed())?;
                    (
                        Sender::H1(Mutex::new(sender)),
                        peer,
                        Box::pin(async move {
                            let _ = connection.await;
                        }),
                        None,
                        None,
                    )
                }
            };
        let physical = Arc::new(Physical {
            sender,
            peer,
            active: AtomicUsize::new(1),
            done: AtomicBool::new(false),
            last: Mutex::new(tokio::time::Instant::now()),
            connection,
            endpoint,
        });
        let tracked = physical.clone();
        let group = Arc::downgrade(group);
        self.jobs.spawn("xhttp.connection",move|cancel|async move{
            let _done=DriverDone(tracked.clone());let mut driver=driver;let mut tick=tokio::time::interval(Duration::from_secs(1));
            loop{tokio::select!{_=cancel.cancelled()=>break,_=&mut driver=>break,_=tick.tick()=>{
                let retired=group.upgrade().is_none_or(|g|g.retired.load(Ordering::Acquire)&&g.sessions.load(Ordering::Acquire)==0);
                if tracked.active.load(Ordering::Acquire)==0&&(retired||tracked.last.lock().unwrap_or_else(|e|e.into_inner()).elapsed()>=Duration::from_secs(300)){break;}
            }}}
            if let Some(c)=&tracked.connection{c.close(0u32.into(),b"closed");}
            if let Some(e)=&tracked.endpoint{e.close(0u32.into(),b"closed");e.wait_idle().await;}Ok(())
        })?;
        connections.push(physical.clone());
        Ok(physical)
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        self.abort();
    }
}
impl Group {
    fn available(&self) -> bool {
        !self.retired.load(Ordering::Acquire)
            && self.uses.load(Ordering::Acquire) > 0
            && self.requests.load(Ordering::Acquire) > 0
            && self.expires.is_none_or(|t| tokio::time::Instant::now() < t)
    }
    fn take_request(&self) -> bool {
        if self
            .expires
            .is_some_and(|t| tokio::time::Instant::now() >= t)
        {
            return false;
        }
        self.requests
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1))
            .is_ok()
    }
}
fn closed() -> Error {
    Error::Io(io::ErrorKind::ConnectionAborted)
}

type ConnectionParts = (
    Sender,
    SocketAddr,
    Pin<Box<dyn Future<Output = ()> + Send>>,
    Option<quinn::Connection>,
    Option<quinn::Endpoint>,
);
