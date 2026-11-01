// SPDX-License-Identifier: GPL-3.0-only
//! HTTP/2 connection reuse scoped to one immutable outbound configuration.
use super::{Error, Outbound, jobs::Jobs};
use crate::{buffer::BufferScope, time::OperationContext};
use bytes::Bytes;
use std::{
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;
const MAX_CONNECTIONS: usize = 4;
const MAX_STREAMS: usize = 32;
const IDLE: Duration = Duration::from_secs(60);
const MAX_AGE: Duration = Duration::from_secs(1800);
pub(super) struct Pool {
    base: Arc<dyn Outbound>,
    sessions: AsyncMutex<Vec<Arc<Session>>>,
    jobs: Jobs,
}
struct Session {
    sender: h2::client::SendRequest<Bytes>,
    peer: SocketAddr,
    active: AtomicUsize,
    accepting: AtomicBool,
    done: AtomicBool,
    last: Mutex<tokio::time::Instant>,
    created: tokio::time::Instant,
}
pub(super) struct Lease {
    session: Arc<Session>,
    pool: Arc<Pool>,
}
impl Lease {
    pub fn stopped(&self) -> bool {
        self.pool.jobs.cancel.is_cancelled()
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.session.active.fetch_sub(1, Ordering::AcqRel);
        *self.session.last.lock().unwrap_or_else(|e| e.into_inner()) = tokio::time::Instant::now();
    }
}
struct Finished(Arc<Session>);
impl Drop for Finished {
    fn drop(&mut self) {
        self.0.accepting.store(false, Ordering::Release);
        self.0.done.store(true, Ordering::Release);
    }
}
pub(super) struct Open {
    pub response: h2::client::ResponseFuture,
    pub send: h2::SendStream<Bytes>,
    pub lease: Lease,
    pub peer: SocketAddr,
}
impl Pool {
    pub fn new(base: Arc<dyn Outbound>) -> Result<Arc<Self>, Error> {
        Ok(Arc::new(Self {
            base,
            sessions: AsyncMutex::new(Vec::new()),
            jobs: Jobs::new(MAX_CONNECTIONS)?,
        }))
    }
    async fn session(
        self: &Arc<Self>,
        addresses: &[SocketAddr],
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Lease, Error> {
        let mut sessions = context
            .run(self.sessions.lock())
            .await
            .map_err(Error::Stopped)?;
        if self.jobs.cancel.is_cancelled() {
            return Err(Error::Io(std::io::ErrorKind::ConnectionAborted));
        }
        sessions.retain(|s| !s.done.load(Ordering::Acquire));
        for session in sessions.iter() {
            if session.created.elapsed() >= MAX_AGE {
                session.accepting.store(false, Ordering::Release);
            }
            if session.accepting.load(Ordering::Acquire)
                && addresses.contains(&session.peer)
                && session.active.load(Ordering::Acquire) < MAX_STREAMS
            {
                session.active.fetch_add(1, Ordering::AcqRel);
                return Ok(Lease {
                    session: session.clone(),
                    pool: self.clone(),
                });
            }
        }
        if sessions.len() >= MAX_CONNECTIONS {
            return Err(Error::Io(std::io::ErrorKind::WouldBlock));
        }
        let (stream, peer) = self.base.connect(addresses, scope, context).await?;
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(65535)
            .initial_connection_window_size(1 << 20)
            .max_frame_size(16384)
            .max_header_list_size(16384)
            .max_send_buffer_size(65536);
        let (sender, connection) = context
            .run(builder.handshake(stream))
            .await
            .map_err(Error::Stopped)?
            .map_err(|_| Error::Io(std::io::ErrorKind::ConnectionAborted))?;
        context.check().map_err(Error::Stopped)?;
        let session = Arc::new(Session {
            sender,
            peer,
            active: AtomicUsize::new(1),
            accepting: AtomicBool::new(true),
            done: AtomicBool::new(false),
            last: Mutex::new(tokio::time::Instant::now()),
            created: tokio::time::Instant::now(),
        });
        let tracked = session.clone();
        self.jobs.spawn("transport.h2",move|cancel|async move{
            let _finished=Finished(tracked.clone());let mut connection=Box::pin(connection);let mut timer=tokio::time::interval(Duration::from_secs(1));
            loop {tokio::select! {
                biased;
                _=cancel.cancelled()=>return Ok(()),
                result=&mut connection=>return result.map_err(|_|crate::task::TaskFailure::Failed("HTTP/2 connection")),
                _=timer.tick()=>{
                    if tracked.created.elapsed()>=MAX_AGE{tracked.accepting.store(false,Ordering::Release);}
                    if tracked.active.load(Ordering::Acquire)==0 && (!tracked.accepting.load(Ordering::Acquire)||tracked.last.lock().unwrap_or_else(|e|e.into_inner()).elapsed()>=IDLE){return Ok(());}
                }
            }}
        })?;
        sessions.push(session.clone());
        Ok(Lease {
            session,
            pool: self.clone(),
        })
    }
    pub async fn open(
        self: &Arc<Self>,
        addresses: &[SocketAddr],
        scope: &BufferScope,
        context: &OperationContext,
        request: http::Request<()>,
    ) -> Result<Open, Error> {
        // Retry only before an HTTP stream exists. Payload is never replayed.
        for attempt in 0..2 {
            let lease = self.session(addresses, scope, context).await?;
            let ready = context
                .run(lease.session.sender.clone().ready())
                .await
                .map_err(Error::Stopped)?;
            let result = ready.and_then(|mut sender| sender.send_request(request.clone(), false));
            match result {
                Ok((response, send)) => {
                    let peer = lease.session.peer;
                    return Ok(Open {
                        response,
                        send,
                        lease,
                        peer,
                    });
                }
                Err(_) => {
                    lease.session.accepting.store(false, Ordering::Release);
                    if attempt == 1 {
                        return Err(Error::Io(std::io::ErrorKind::ConnectionAborted));
                    }
                }
            }
        }
        unreachable!("bounded attempts")
    }
    pub fn abort(&self) {
        self.jobs.abort();
    }
    pub fn idle(&self) -> bool {
        self.jobs.idle()
    }
    pub async fn close(&self) {
        self.jobs.close().await;
        self.sessions.lock().await.clear();
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.jobs.abort();
    }
}
