// SPDX-License-Identifier: MPL-2.0
// Ported from Polaris 56d52fb44958 XHTTP server.go/server_upload.go/server_download.go.
use super::{
    Error,
    body::{self, Body, Guarded},
    config::Config,
    queue::{self, Session},
};
use crate::{buffer::BufferScope, network::Stream, task::CancellationToken, transport::jobs::Jobs};
use http::{Request, Response};
use http_body_util::BodyExt;
use std::{
    collections::{BTreeMap, VecDeque},
    convert::Infallible,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{Semaphore, mpsc};
#[derive(Clone)]
pub struct Executor(pub Weak<Jobs>);
impl<F> hyper::rt::Executor<F> for Executor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    fn execute(&self, f: F) {
        if let Some(jobs) = self.0.upgrade() {
            let _ = jobs.spawn("xhttp.http", |cancel| async move {
                tokio::select! {_=cancel.cancelled()=>{},_=f=>{}}
                Ok(())
            });
        }
    }
}
pub struct Shared {
    pub config: Arc<Config>,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    budget: Arc<queue::Budget>,
    requests: Arc<Semaphore>,
    owners: AtomicUsize,
    started: AtomicBool,
    jobs: Jobs,
}
impl Shared {
    pub fn new(config: Config) -> Result<Arc<Self>, Error> {
        let budget = queue::Budget::new(&config);
        let requests = Arc::new(Semaphore::new(config.sc_max_concurrent_requests));
        Ok(Arc::new(Self {
            config: Arc::new(config),
            sessions: Mutex::new(BTreeMap::new()),
            budget,
            requests,
            owners: AtomicUsize::new(0),
            started: AtomicBool::new(false),
            jobs: Jobs::new(1)?,
        }))
    }
    pub fn retain(&self) {
        self.owners.fetch_add(1, Ordering::AcqRel);
    }
    pub fn live(&self) -> bool {
        !self.jobs.cancel.is_cancelled()
    }
    pub fn release(&self) {
        if self.owners.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.jobs.abort();
            let sessions =
                std::mem::take(&mut *self.sessions.lock().unwrap_or_else(|e| e.into_inner()));
            for s in sessions.values() {
                s.close();
            }
        }
    }
    pub async fn close_if_unused(&self) {
        if self.owners.load(Ordering::Acquire) == 0 {
            self.jobs.close().await;
        }
    }
    pub fn start(self: &Arc<Self>) -> Result<(), Error> {
        if !self.started.swap(true, Ordering::AcqRel) {
            let weak = Arc::downgrade(self);
            self.jobs.spawn("xhttp.sessions",|cancel|async move{let mut tick=tokio::time::interval(Duration::from_secs(1));loop{tokio::select!{_=cancel.cancelled()=>break,_=tick.tick()=>{let Some(shared)=weak.upgrade()else{break;};let mut sessions=shared.sessions.lock().unwrap_or_else(|e|e.into_inner());sessions.retain(|_,s|{if s.closed.is_cancelled() || (s.orphaned()&&s.created.elapsed()>=Duration::from_secs(30)){s.close();false}else{true}});}}}Ok(())})?;
        }
        Ok(())
    }
    fn session(&self, id: &str, allow_new: bool) -> Result<Arc<Session>, u16> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = sessions.get(id) {
            if !s.closed.is_cancelled() {
                return Ok(s.clone());
            }
            sessions.remove(id);
        }
        if !allow_new || !self.live() || sessions.len() >= self.config.sc_max_active_sessions {
            return Err(503);
        }
        let s = Session::new(&self.config, self.budget.clone());
        sessions.insert(id.to_owned(), s.clone());
        Ok(s)
    }
}
pub struct Activity {
    active: AtomicUsize,
    last: Mutex<tokio::time::Instant>,
    pub draining: AtomicBool,
}
impl Activity {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            last: Mutex::new(tokio::time::Instant::now()),
            draining: AtomicBool::new(false),
        })
    }
    fn guard(self: &Arc<Self>) -> Active {
        self.active.fetch_add(1, Ordering::AcqRel);
        self.touch();
        Active(self.clone())
    }
    fn touch(&self) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
    }
    pub fn busy(&self) -> bool {
        self.active.load(Ordering::Acquire) > 0
    }
    pub fn last(&self) -> tokio::time::Instant {
        *self.last.lock().unwrap_or_else(|e| e.into_inner())
    }
}
struct Active(Arc<Activity>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.touch();
    }
}
pub struct SessionGuard {
    shared: Weak<Shared>,
    session: Arc<Session>,
    id: String,
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.session.close();
        if let Some(shared) = self.shared.upgrade() {
            let mut sessions = shared.sessions.lock().unwrap_or_else(|e| e.into_inner());
            if sessions
                .get(&self.id)
                .is_some_and(|s| Arc::ptr_eq(s, &self.session))
            {
                sessions.remove(&self.id);
            }
        }
    }
}
struct CancelSession(Arc<Session>);
impl Drop for CancelSession {
    fn drop(&mut self) {
        self.0.close();
    }
}
#[derive(Clone)]
pub struct Service {
    pub shared: Arc<Shared>,
    pub scope: BufferScope,
    pub streams: mpsc::Sender<Stream>,
    pub activity: Arc<Activity>,
}
impl Service {
    pub async fn handle(&self, request: Request<Body>) -> Response<Body> {
        let active = self.activity.guard();
        let (parts, body) = request.into_parts();
        let req = Request::from_parts(parts, ());
        let c = &self.shared.config;
        if !c.matches(&req) {
            return response(404, body::empty());
        }
        let headers = match c.response_headers(&req) {
            Ok(v) => v,
            Err(_) => return response(400, body::empty()),
        };
        let result = if req.method() == http::Method::OPTIONS {
            Ok(body::empty())
        } else {
            self.serve(&req, body).await
        };
        let (status, body) = match result {
            Ok(body) => (200, body),
            Err(status) => (status, body::empty()),
        };
        let mut r = response(status, Guarded::boxed(body, active));
        *r.headers_mut() = headers;
        if status == 503 {
            r.headers_mut()
                .insert("retry-after", http::HeaderValue::from_static("1"));
        }
        if status == 200 && req.method() != http::Method::OPTIONS {
            r.headers_mut()
                .insert("cache-control", http::HeaderValue::from_static("no-store"));
            r.headers_mut()
                .insert("x-accel-buffering", http::HeaderValue::from_static("no"));
            let (id, seq) = c.extract(&req);
            if ((req.method() == http::Method::GET && seq.is_empty()) || id.is_empty())
                && !c.no_sse_header
            {
                r.headers_mut().insert(
                    "content-type",
                    http::HeaderValue::from_static("text/event-stream"),
                );
            }
        }
        r
    }
    async fn serve(&self, req: &Request<()>, mut body: Body) -> Result<Body, u16> {
        let c = &self.shared.config;
        if req
            .headers()
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 4)
            .sum::<usize>()
            + req.uri().to_string().len()
            > c.server_max_header_bytes
        {
            return Err(431);
        }
        if !c.valid_padding(req) {
            return Err(400);
        }
        let (id, seq) = c.extract(req);
        if id.len() > 4096 || seq.len() > 20 {
            return Err(400);
        }
        let sequence = if seq.is_empty() {
            None
        } else {
            Some(seq.parse::<u64>().map_err(|_| 400u16)?)
        };
        if id.is_empty() && !matches!(c.mode.as_str(), "auto" | "stream-one" | "stream-up") {
            return Err(400);
        }
        let upload = req.method() != http::Method::GET || sequence.is_some();
        if upload
            && !id.is_empty()
            && ((sequence.is_none() && !matches!(c.mode.as_str(), "auto" | "stream-up"))
                || (sequence.is_some() && !matches!(c.mode.as_str(), "auto" | "packet-up")))
        {
            return Err(400);
        }
        let request_permit = if upload || id.is_empty() {
            Some(
                self.shared
                    .requests
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| 503u16)?,
            )
        } else {
            None
        };
        let session = if !id.is_empty() {
            Some(
                self.shared
                    .session(&id, !self.activity.draining.load(Ordering::Acquire))?,
            )
        } else {
            None
        };
        if upload && let Some(s) = &session {
            if let Some(sequence) = sequence {
                let encoded = c.encoded_payload(req.headers()).map_err(|_| 400u16)?;
                let has_body = matches!(c.uplink_data_placement.as_str(), "auto" | "body");
                let content_length = req
                    .headers()
                    .get(http::header::CONTENT_LENGTH)
                    .map(|v| {
                        v.to_str()
                            .ok()
                            .and_then(|v| v.parse::<usize>().ok())
                            .ok_or(400u16)
                    })
                    .transpose()?;
                let capacity = if has_body {
                    content_length
                        .map(|n| n.checked_add(encoded.len()).ok_or(413u16))
                        .transpose()?
                        .unwrap_or(c.sc_max_each_post_bytes.to)
                } else {
                    encoded.len()
                };
                let mut reservation = s.reserve(sequence, capacity).await?;
                let mut chunks = VecDeque::new();
                let mut size = encoded.len();
                for chunk in encoded.chunks(16384) {
                    chunks.push_back(body::copy(&self.scope, chunk).map_err(|_| 503u16)?);
                }
                if has_body {
                    let read = async {
                        while let Some(frame) = body.frame().await {
                            let frame = frame.map_err(|_| 400u16)?;
                            if let Ok(data) = frame.into_data() {
                                size = size.checked_add(data.len()).ok_or(413u16)?;
                                if size > capacity {
                                    return Err(413u16);
                                }
                                for chunk in data.chunks(16384) {
                                    chunks.push_back(
                                        body::copy(&self.scope, chunk).map_err(|_| 503u16)?,
                                    );
                                }
                            }
                        }
                        Ok::<_, u16>(())
                    };
                    tokio::select! {_=s.closed.cancelled()=>return Err(409),r=tokio::time::timeout(Duration::from_secs(30),read)=>r.map_err(|_|408u16)??};
                }
                reservation.shrink(size);
                s.push(
                    sequence,
                    queue::Packet {
                        chunks,
                        _reservation: reservation,
                    },
                )?;
                return Ok(body::empty());
            }
            s.upload(body)?;
            let s = s.clone();
            let interval = c.sc_stream_up_server_secs;
            let padding = c.clone();
            let keepalive = req.headers().contains_key("referer") || c.xpadding_obfs_mode;
            let stream = futures_util::stream::unfold(
                (s, interval, padding),
                move |(s, interval, c)| async move {
                    tokio::select! {_=s.closed.cancelled()=>None,_=s.upload_done.cancelled()=>None,_=tokio::time::sleep(Duration::from_secs(interval.random() as u64)),if keepalive=>{Some((Ok::<_,std::io::Error>(http_body::Frame::data(bytes::Bytes::from("X".repeat(c.xpadding_bytes.random())))),(s,interval,c)))}}
                },
            );
            return Ok(Guarded::boxed(
                http_body_util::StreamBody::new(Box::pin(stream)).boxed_unsync(),
                request_permit,
            ));
        }
        if self.activity.draining.load(Ordering::Acquire) {
            return Err(503);
        }
        if let Some(s) = &session
            && !s.attach()
        {
            return Err(409);
        }
        let (writer, output) = body::response_pipe(&self.scope).map_err(|_| 503u16)?;
        let (reader, guard): (
            Box<dyn tokio::io::AsyncRead + Unpin + Send>,
            Option<SessionGuard>,
        ) = if let Some(s) = &session {
            (
                Box::new(s.reader()),
                Some(SessionGuard {
                    shared: Arc::downgrade(&self.shared),
                    session: s.clone(),
                    id,
                }),
            )
        } else {
            (Box::new(body::Reader::new(body)), None)
        };
        let stream: Stream = Box::new(body::OwnedStream {
            io: Box::new(body::Joined { reader, writer }),
            _guard: session.as_ref().map(|s| CancelSession(s.clone())),
        });
        self.streams.try_send(stream).map_err(|_| 503u16)?;
        Ok(Guarded::boxed(output, (guard, request_permit)))
    }
}
fn response(status: u16, body: Body) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(body)
        .expect("valid HTTP status")
}
pub struct Carrier {
    pub drive: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>,
    pub streams: mpsc::Receiver<Stream>,
    pub activity: Arc<Activity>,
    pub drain: CancellationToken,
    pub jobs: Arc<Jobs>,
    finished: bool,
}
impl Carrier {
    pub fn new(
        drive: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>,
        streams: mpsc::Receiver<Stream>,
        activity: Arc<Activity>,
        drain: CancellationToken,
        jobs: Arc<Jobs>,
    ) -> Self {
        Self {
            drive,
            streams,
            activity,
            drain,
            jobs,
            finished: false,
        }
    }
}
impl crate::transport::Multiplexed for Carrier {
    fn close(&mut self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.jobs.abort();
        self.finished = true;
        self.drive = Box::pin(async { Ok(()) });
        self.streams.close();
        while self.streams.try_recv().is_ok() {}
        Box::pin(async { self.jobs.close().await })
    }

    fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Stream>, Error>> {
        if !self.finished
            && let Poll::Ready(result) = self.drive.as_mut().poll(cx)
        {
            self.finished = true;
            result?;
        }
        match self.streams.poll_recv(cx) {
            Poll::Ready(Some(s)) => Poll::Ready(Ok(Some(s))),
            _ if self.finished => Poll::Ready(Ok(None)),
            _ => Poll::Pending,
        }
    }
    fn drain(&mut self) {
        self.activity.draining.store(true, Ordering::Release);
        self.drain.cancel();
    }
    fn busy(&self) -> bool {
        self.activity.busy()
    }
    fn last_activity(&self) -> Option<tokio::time::Instant> {
        Some(self.activity.last())
    }
}
impl Drop for Carrier {
    fn drop(&mut self) {
        self.jobs.abort();
    }
}
pub fn tcp(
    stream: Stream,
    scope: BufferScope,
    shared: Arc<Shared>,
) -> Result<Box<dyn crate::transport::Multiplexed>, Error> {
    shared.start()?;
    let jobs = Arc::new(Jobs::new(128)?);
    let executor = Executor(Arc::downgrade(&jobs));
    let activity = Activity::new();
    let drain = CancellationToken::new();
    let (send, recv) = mpsc::channel(crate::transport::MAX_MULTIPLEX_STREAMS);
    let service = Service {
        shared: shared.clone(),
        scope,
        streams: send,
        activity: activity.clone(),
    };
    let drain_signal = drain.clone();
    let owned_jobs = jobs.clone();
    let drive = Box::pin(async move {
        let service = hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
            let service = service.clone();
            async move { Ok::<_, Infallible>(service.handle(request.map(body::incoming)).await) }
        });
        let mut builder = hyper_util::server::conn::auto::Builder::new(executor);
        builder
            .http1()
            .half_close(false)
            .max_buf_size(shared.config.server_max_header_bytes.max(8192))
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(Duration::from_secs(4));
        builder
            .http2()
            .max_concurrent_streams(64)
            .max_header_list_size(shared.config.server_max_header_bytes as u32)
            .initial_stream_window_size(65536)
            .initial_connection_window_size(1 << 20)
            .max_send_buf_size(65536);
        let connection = builder.serve_connection(hyper_util::rt::TokioIo::new(stream), service);
        tokio::pin!(connection);
        let result = tokio::select! {r=&mut connection=>r,_=drain_signal.cancelled()=>{connection.as_mut().graceful_shutdown();connection.await}};
        owned_jobs.close().await;
        result.map_err(|_| Error::Io(std::io::ErrorKind::ConnectionAborted))
    });
    Ok(Box::new(Carrier::new(drive, recv, activity, drain, jobs)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{Budget, Limits};
    #[tokio::test(start_paused = true)]
    async fn malformed_requests_caps_and_orphan_expiry_release_buffers() {
        let config=Config::parse("localhost","/relay","packet-up",r#"{"scMaxEachPostBytes":8,"scMaxBufferedBytes":16,"scMaxTotalBufferedBytes":16,"scMaxActiveSessions":1,"scMaxConcurrentRequests":1}"#).unwrap();
        let shared = Shared::new(config).unwrap();
        shared.retain();
        shared.start().unwrap();
        let memory = Budget::new(Limits::new(65536, 64).unwrap());
        let scope = BufferScope::new(memory.root_scope(), 16384).unwrap();
        let (send, mut streams) = mpsc::channel(2);
        let service = Service {
            shared: shared.clone(),
            scope,
            streams: send,
            activity: Activity::new(),
        };
        let packet = |id: &str, bytes: &'static [u8]| {
            let mut request = shared
                .config
                .request("localhost", false, id, Some(0), true, None)
                .unwrap();
            request
                .headers_mut()
                .insert("content-length", bytes.len().to_string().parse().unwrap());
            request.map(|_| {
                http_body_util::Full::new(bytes::Bytes::from_static(bytes))
                    .map_err(|never| match never {})
                    .boxed_unsync()
            })
        };
        let mut bad = packet("bad", b"a");
        bad.headers_mut().remove("referer");
        assert_eq!(service.handle(bad).await.status(), 400);
        assert!(shared.sessions.lock().unwrap().is_empty());
        assert_eq!(
            service.handle(packet("large", b"oversized")).await.status(),
            413
        );
        // Failed upload IDs remain bounded and expire without a download.
        assert_eq!(service.handle(packet("second", b"a")).await.status(), 503);
        tokio::time::advance(Duration::from_secs(31)).await;
        tokio::task::yield_now().await;
        assert!(shared.sessions.lock().unwrap().is_empty());
        let permit = shared.requests.clone().acquire_owned().await.unwrap();
        assert_eq!(service.handle(packet("one", b"a")).await.status(), 503);
        drop(permit);
        assert_eq!(
            service.handle(packet("one", b"payload!")).await.status(),
            200
        );
        assert!(memory.snapshot().used().bytes() > 0);
        let request = || {
            shared
                .config
                .request("localhost", false, "one", None, false, None)
                .unwrap()
                .map(|_| body::empty())
        };
        let response = service.handle(request()).await;
        assert_eq!(response.status(), 200);
        let stream = streams.recv().await.unwrap();
        assert_eq!(service.handle(request()).await.status(), 409);
        drop(stream);
        drop(response);
        assert_eq!(memory.snapshot().used().bytes(), 0);
        assert!(shared.sessions.lock().unwrap().is_empty());
        shared.release();
        shared.close_if_unused().await;
        assert!(shared.jobs.idle());
    }
}
