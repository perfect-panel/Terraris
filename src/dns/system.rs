// SPDX-License-Identifier: GPL-3.0-only
//! Bounded system bootstrap. Permits remain with getaddrinfo even if a caller
//! cancels; explicit close retains and joins every blocking handle.
use super::Error;
use crate::{task::CancellationToken, time::OperationContext};
use std::{
    future::poll_fn,
    net::{IpAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    task::Poll,
};
use tokio::{
    sync::{Semaphore, oneshot},
    task::JoinSet,
};
pub struct System {
    permits: Arc<Semaphore>,
    jobs: Mutex<JoinSet<()>>,
    cancel: CancellationToken,
    limit: usize,
}
impl System {
    pub fn new(concurrency: usize) -> Arc<Self> {
        Arc::new(Self {
            permits: Arc::new(Semaphore::new(concurrency)),
            jobs: Mutex::new(JoinSet::new()),
            cancel: CancellationToken::new(),
            limit: concurrency,
        })
    }
    pub async fn lookup(
        &self,
        name: &str,
        context: &OperationContext,
    ) -> Result<Vec<IpAddr>, Error> {
        context.check().map_err(Error::Stopped)?;
        if self.cancel.is_cancelled() {
            return Err(Error::Closed);
        }
        if let Ok(ip) = name.parse() {
            return Ok(vec![ip]);
        }
        if name.len() > 253 {
            return Err(Error::InvalidQuery);
        }
        let permit = context
            .run(self.permits.clone().acquire_owned())
            .await
            .map_err(Error::Stopped)?
            .map_err(|_| Error::Closed)?;
        let name = name.to_owned();
        let (sender, receiver) = oneshot::channel();
        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            while jobs.try_join_next().is_some() {}
            if self.cancel.is_cancelled() {
                return Err(Error::Closed);
            }
            if jobs.len() >= self.limit {
                return Err(Error::Capacity);
            }
            jobs.spawn_blocking(move || {
                let _permit = permit;
                let result = (name.as_str(), 0)
                    .to_socket_addrs()
                    .map(|values| {
                        let mut ips = Vec::new();
                        for address in values {
                            if !ips.contains(&address.ip()) {
                                ips.push(address.ip());
                            }
                            if ips.len() == 64 {
                                break;
                            }
                        }
                        ips
                    })
                    .map_err(|_| Error::Transport);
                let _ = sender.send(result);
            });
        }
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Closed),result=context.run(receiver)=>result.map_err(Error::Stopped)?.map_err(|_|Error::Closed)?}
    }
    pub(crate) fn idle(&self) -> bool {
        let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
        while jobs.try_join_next().is_some() {}
        jobs.is_empty()
    }
    pub fn abort(&self) {
        self.cancel.cancel();
        self.permits.close();
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .abort_all();
    }
    pub async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        self.abort();
        context
            .run(poll_fn(|cx| {
                let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    match jobs.poll_join_next(cx) {
                        Poll::Ready(Some(_)) => {}
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }))
            .await
            .map_err(Error::Stopped)
    }
}
impl Drop for System {
    fn drop(&mut self) {
        self.abort();
    }
}
