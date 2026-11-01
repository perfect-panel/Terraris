// SPDX-License-Identifier: GPL-3.0-only
//! One accept loop per address, shared across configuration candidates. Preparing
//! a candidate never redirects an established listener away from the live driver.
use super::server::Driver;
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
#[derive(Default)]
pub(super) struct Registry {
    bindings: AsyncMutex<BTreeMap<SocketAddr, Weak<Ingress>>>,
}
impl Registry {
    pub(super) async fn bind(
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
        binding.tasks.lock().await.spawn("vless.accept",move|cancel|async move{
            let context = OperationContext::new(cancel.clone(), None);
            loop{let accepted=tokio::select!{biased;_=cancel.cancelled()=>break,result=listener.accept(&context)=>result};let(socket,source)=match accepted{Ok(v)=>v,Err(_)=>{tokio::time::sleep(std::time::Duration::from_millis(10)).await;continue;}};
                let Some(binding)=weak.upgrade()else{break;};let driver=binding.candidates().into_iter().find(|driver|driver.accepting());drop(binding);
                if let Some(driver)=driver{driver.accept(socket,source);} // Otherwise the unready socket is dropped.
            }Ok(())
        }).map_err(Error::Task)?;
        bindings.insert(address, Arc::downgrade(&binding));
        Ok(binding)
    }
}
pub(super) struct Ingress {
    key: String,
    routes: Mutex<Vec<Weak<Driver>>>,
    tasks: AsyncMutex<TaskGroup>,
    cancel: CancellationToken,
}
impl Ingress {
    pub(super) fn register(&self, driver: Weak<Driver>) -> Result<(), Error> {
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
    fn candidates(&self) -> Vec<Arc<Driver>> {
        self.routes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(Weak::upgrade)
            .collect()
    }
    pub(super) fn stop_if_unused(&self) {
        // Declare strong owners first so even unwinding releases routes before
        // their destructors. Registration and the final stop decision serialize.
        let drivers: Vec<Arc<Driver>>;
        let routes = self.routes.lock().unwrap_or_else(|e| e.into_inner());
        drivers = routes.iter().filter_map(Weak::upgrade).collect();
        if drivers.iter().all(|driver| driver.closed()) {
            self.cancel.cancel();
        }
        drop(routes);
        drop(drivers);
    }
    pub(super) async fn close_if_unused(&self, deadline: Deadline) {
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
