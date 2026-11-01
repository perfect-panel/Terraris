// SPDX-License-Identifier: GPL-3.0-only
//! One accept loop per address, shared across configuration candidates. Preparing
//! a candidate never redirects an established listener away from the live driver.
use crate::{
    runtime::Error,
    task::{CancellationToken, TaskGroup},
    telemetry::Metrics,
    time::{Deadline, OperationContext},
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::Mutex as AsyncMutex;

pub(crate) trait Acceptor: Send + Sync {
    fn closed(&self) -> bool;
    fn accepting(&self) -> bool;
    fn accept(self: Arc<Self>, stream: crate::transport::Accepted, source: SocketAddr);
}
#[derive(Default)]
pub(crate) struct Registry {
    bindings: AsyncMutex<BTreeMap<SocketAddr, Weak<Ingress>>>,
}
impl Registry {
    pub(crate) async fn bind(
        &self,
        address: SocketAddr,
        transport: Arc<dyn crate::transport::Inbound>,
        metrics: Metrics,
        context: &OperationContext,
    ) -> Result<Arc<Ingress>, Error> {
        let mut bindings = context
            .run(self.bindings.lock())
            .await
            .map_err(Error::Stopped)?;
        if let Some(binding) = bindings.get(&address).and_then(Weak::upgrade)
            && !binding.cancel.is_cancelled()
        {
            if binding.key != transport.binding_key() {
                return Err(Error::Preparation("incompatible listener transport"));
            }
            return Ok(binding);
        }
        bindings.retain(|_, v| v.strong_count() > 0);
        if !bindings.contains_key(&address) && bindings.len() >= 64 {
            return Err(Error::Preparation("listener capacity"));
        }
        let listener = transport
            .bind(address, context)
            .await
            .map_err(|_| Error::Preparation("transport bind"))?;
        let cancel = CancellationToken::new();
        let binding = Arc::new(Ingress {
            key: transport.binding_key().to_owned(),
            routes: Mutex::new(Vec::new()),
            tasks: AsyncMutex::new(TaskGroup::new(&cancel, 1, metrics).map_err(Error::Task)?),
            cancel,
        });
        let weak = Arc::downgrade(&binding);
        binding.tasks.lock().await.spawn("protocol.accept",move|cancel|async move{
            let context = OperationContext::new(cancel.clone(), None);
            loop{let accepted=tokio::select!{biased;_=cancel.cancelled()=>break,result=listener.accept_carrier(&context)=>result};let(socket,source)=match accepted{Ok(v)=>v,Err(_)=>{tokio::time::sleep(std::time::Duration::from_millis(10)).await;continue;}};
                let Some(binding)=weak.upgrade()else{break;};let driver=binding.candidates().into_iter().find(|driver|driver.accepting());drop(binding);
                if let Some(driver)=driver{driver.accept(socket,source);} // Otherwise the unready socket is dropped.
            }listener.close().await;Ok(())
        }).map_err(Error::Task)?;
        bindings.insert(address, Arc::downgrade(&binding));
        Ok(binding)
    }
}
pub(crate) struct Ingress {
    key: String,
    routes: Mutex<Vec<Weak<dyn Acceptor>>>,
    tasks: AsyncMutex<TaskGroup>,
    cancel: CancellationToken,
}
impl Ingress {
    pub(crate) fn register(&self, driver: Weak<dyn Acceptor>) -> Result<(), Error> {
        let mut routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        if self.cancel.is_cancelled() {
            return Err(Error::Closed);
        }
        // Dropping a last Driver Arc can call back into this ingress. Keep
        // pruning free of strong-reference destructors while holding routes.
        routes.retain(|w| w.strong_count() > 0);
        if routes.len() >= 64 {
            return Err(Error::Preparation("candidate listener capacity"));
        }
        routes.push(driver);
        Ok(())
    }
    fn candidates(&self) -> Vec<Arc<dyn Acceptor>> {
        self.routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
    pub(crate) fn stop_if_unused(&self) {
        // Declare strong owners first so even unwinding releases routes before
        // their destructors. Registration and the final stop decision serialize.
        let drivers: Vec<Arc<dyn Acceptor>>;
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        drivers = routes.iter().filter_map(Weak::upgrade).collect();
        if drivers.iter().all(|driver| driver.closed()) {
            self.cancel.cancel();
        }
        drop(routes);
        drop(drivers);
    }
    pub(crate) async fn close_if_unused(&self, deadline: Deadline) {
        self.stop_if_unused();
        if self.cancel.is_cancelled() {
            self.tasks.lock().await.shutdown(deadline).await;
        }
    }
}
impl Drop for Ingress {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.tasks.get_mut().abort_all();
    }
}

/// Own all logical-stream futures alongside the multiplexed transport driver.
/// Dropping this future drops HTTP/2, every stream and all their buffer leases.
pub(crate) async fn multiplex<F>(
    mut carrier: Box<dyn crate::transport::Multiplexed>,
    core: crate::protocol::runtimekit::Core,
    cancel: CancellationToken,
    handshake_timeout: std::time::Duration,
    idle_timeout: std::time::Duration,
    mut handle: F,
) -> Result<(), crate::task::TaskFailure>
where
    F: FnMut(
            crate::network::Stream,
            CancellationToken,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send,
{
    use futures_util::{StreamExt, stream::FuturesUnordered};
    let mut jobs = FuturesUnordered::new();
    let mut retirement = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut draining = false;
    let mut had_stream = false;
    let mut last = tokio::time::Instant::now();
    let result = async {
    loop {
        if draining && jobs.is_empty() && !carrier.busy() {
            // Give GOAWAY a chance to flush before releasing an empty carrier.
            std::future::poll_fn(|cx| {
                let _ = carrier.poll_accept(cx);
                std::task::Poll::Ready(())
            })
            .await;
            return Ok(());
        }
        tokio::select! {
            biased;
            _=cancel.cancelled()=>return Err(crate::task::TaskFailure::Cancelled),
            _=retirement.tick()=>{
                if !core.is_current() && !draining {draining=true;carrier.drain();}
            }
            _=tokio::time::sleep_until(last+if had_stream{idle_timeout}else{handshake_timeout}),if jobs.is_empty() && !carrier.busy()=>{
                if carrier.last_activity().is_some_and(|activity|activity>last){last=carrier.last_activity().unwrap();}else{return Ok(());}
            },
            _=jobs.next(),if !jobs.is_empty()=>{last=tokio::time::Instant::now();}
            stream=std::future::poll_fn(|cx|carrier.poll_accept(cx))=>{
                let Some(stream)=stream.map_err(|_|crate::task::TaskFailure::Failed("multiplexed transport"))? else{return Ok(());};
                if draining || !core.is_current() || jobs.len()>=crate::transport::MAX_MULTIPLEX_STREAMS {drop(stream);continue;}
                had_stream=true;last=tokio::time::Instant::now();
                jobs.push(handle(stream,cancel.child_token()));
            }
        }
    }
    }.await;
    drop(jobs);
    carrier.close().await;
    result
}
