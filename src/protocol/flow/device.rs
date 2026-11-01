// SPDX-License-Identifier: GPL-3.0-only
use super::Error;
use crate::{
    panel::{ProtocolClient, SubscriptionId},
    task::CancellationToken,
    time::OperationContext,
};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify, Semaphore},
    time::Instant,
};

pub(super) struct Devices {
    entries: Mutex<BTreeMap<(SubscriptionId, IpAddr), Weak<Device>>>,
    limit: usize,
    requests: Arc<Semaphore>,
}
impl Devices {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            limit,
            requests: Arc::new(Semaphore::new(32)),
        }
    }
    pub(super) fn get(&self, id: SubscriptionId, ip: IpAddr) -> Result<Arc<Device>, Error> {
        let ip = match ip {
            IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(Error::InvalidOptions);
        }
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let key = (id, ip);
        if let Some(entry) = entries.get(&key).and_then(Weak::upgrade)
            && !entry.cancelled()
        {
            return Ok(entry);
        }
        if entries.len() >= self.limit {
            entries.retain(|_, entry| entry.strong_count() > 0);
        }
        if !entries.contains_key(&key) && entries.len() >= self.limit {
            return Err(Error::Capacity);
        }
        let entry = Arc::new(Device {
            id,
            ip,
            gate: AsyncMutex::new(()),
            state: Mutex::new(State {
                renew: None,
                expires: None,
                limit: 0,
            }),
            cancel: CancellationToken::new(),
            changed: Notify::new(),
            requests: self.requests.clone(),
        });
        entries.insert(key, Arc::downgrade(&entry));
        Ok(entry)
    }
}
struct State {
    renew: Option<Instant>,
    expires: Option<Instant>,
    limit: u64,
}
pub(super) struct Device {
    id: SubscriptionId,
    ip: IpAddr,
    gate: AsyncMutex<()>,
    state: Mutex<State>,
    cancel: CancellationToken,
    changed: Notify,
    requests: Arc<Semaphore>,
}
impl Device {
    pub(super) fn cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
    pub(super) fn admitted(&self, limit: u64) -> bool {
        if limit == 0 {
            return !self.cancelled();
        }
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .expires
            .is_some_and(|at| at > Instant::now())
            && !self.cancelled()
    }
    pub(super) async fn closed(&self) {
        self.cancel.cancelled().await;
    }
    pub(super) async fn expired(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let expires = self.state.lock().unwrap_or_else(|e| e.into_inner()).expires;
            let Some(expires) = expires else {
                return;
            };
            if expires <= Instant::now() || self.cancelled() {
                return;
            }
            tokio::select! {_=self.cancel.cancelled()=>return,_=&mut changed=>{},_=tokio::time::sleep_until(expires)=>{}}
        }
    }
    pub(super) async fn ensure(
        &self,
        client: &dyn ProtocolClient,
        limit: u64,
        context: &OperationContext,
    ) -> Result<(), Error> {
        if limit == 0 {
            return Ok(());
        }
        if self.cancelled() {
            return Err(Error::DeviceExpired);
        }
        let _gate = context
            .run(self.gate.lock())
            .await
            .map_err(|_| Error::Stopped)?;
        let previous = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.limit == limit && state.renew.is_some_and(|at| at > Instant::now()) {
                return Ok(());
            }
            state.expires
        };
        let result = context
            .run(async {
                let _permit = self.requests.acquire().await.map_err(|_| ())?;
                client.claim_device(self.id, self.ip).await.map_err(|_| ())
            })
            .await;
        match result {
            Ok(Ok(claim)) if claim.allowed => {
                if claim.ttl.is_zero() {
                    self.cancel.cancel();
                    return Err(Error::DeviceExpired);
                }
                let now = Instant::now();
                let expires = now.checked_add(claim.ttl).ok_or(Error::InvalidOptions)?;
                let renew = now + claim.ttl.div_f64(3.0).min(Duration::from_secs(30));
                *self.state.lock().unwrap_or_else(|e| e.into_inner()) = State {
                    renew: Some(renew),
                    expires: Some(expires),
                    limit,
                };
                self.changed.notify_waiters();
                Ok(())
            }
            Ok(Ok(_)) => {
                self.cancel.cancel();
                Err(Error::DeviceDenied)
            }
            _ => {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if previous.is_some_and(|at| at > Instant::now()) {
                    state.renew = Some(
                        (Instant::now() + Duration::from_secs(1))
                            .min(previous.expect("live lease")),
                    );
                    Ok(())
                } else {
                    self.cancel.cancel();
                    Err(Error::DeviceUnavailable)
                }
            }
        }
    }
}
