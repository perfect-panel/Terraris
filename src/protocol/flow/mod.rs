// SPDX-License-Identifier: GPL-3.0-only

//! Protocol-neutral policy leases. Admission precedes every blocking device,
//! DNS, dial and forwarding operation; counters are reserved before writes.
mod device;
mod rate;
pub use rate::Metered;

use crate::{
    panel::{ProtocolClient, ProtocolName, SubscriptionId},
    protocol::runtimekit::{AdmissionLease, Core},
    reports::{OnlineLease, TrafficLease, TrafficReservation},
    time::{Deadline, OperationContext},
    users::Identity,
};
use device::{Device, Devices};
use rate::Limiter;
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    net::IpAddr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidOptions,
    Capacity,
    Admission,
    Revoked,
    DeviceDenied,
    DeviceUnavailable,
    DeviceExpired,
    Counter,
    Stopped,
    Io(io::ErrorKind),
    Resolve,
    Unsupported,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "flow policy: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        io::Error::new(io::ErrorKind::PermissionDenied, error)
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub max_entries: usize,
    pub device_timeout: Duration,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            device_timeout: Duration::from_secs(10),
        }
    }
}
pub struct Policies {
    devices: Devices,
    limiters: Mutex<BTreeMap<(ProtocolName, SubscriptionId), Weak<Limiter>>>,
    options: Options,
}
impl Policies {
    pub fn new(options: Options) -> Result<Self, Error> {
        if options.max_entries == 0
            || options.device_timeout.is_zero()
            || Deadline::after(options.device_timeout).is_err()
        {
            return Err(Error::InvalidOptions);
        }
        Ok(Self {
            devices: Devices::new(options.max_entries),
            limiters: Mutex::new(BTreeMap::new()),
            options,
        })
    }
    pub async fn admit(
        &self,
        core: &Core,
        identity: &Identity,
        source: IpAddr,
        client: Arc<dyn ProtocolClient>,
    ) -> Result<Arc<Session>, Error> {
        let admission = core.admit(identity).map_err(|_| Error::Admission)?;
        let context = admission.context(None).child();
        let traffic = core
            .reports()
            .traffic_lease(identity.id())
            .map_err(|_| Error::Counter)?;
        let device = self.devices.get(identity.id(), source)?;
        let limiter = {
            let mut limits = self.limiters.lock().unwrap_or_else(|e| e.into_inner());
            let key = (core.protocol().clone(), identity.id());
            if let Some(value) = limits.get(&key).and_then(Weak::upgrade) {
                value
            } else {
                if limits.len() >= self.options.max_entries {
                    limits.retain(|_, v| v.strong_count() > 0);
                }
                if limits.len() >= self.options.max_entries {
                    return Err(Error::Capacity);
                }
                let value = Arc::new(Limiter::new());
                limits.insert(key, Arc::downgrade(&value));
                value
            }
        };
        // Do not register online activity until device admission succeeds.
        let mut session = Session {
            admission,
            context,
            device,
            client,
            limiter,
            traffic,
            online: None,
            device_timeout: self.options.device_timeout,
        };
        session.refresh_device().await?;
        session.online = Some(
            core.reports()
                .online(identity.id(), source)
                .map_err(|_| Error::Capacity)?,
        );
        Ok(Arc::new(session))
    }
}
pub struct Session {
    admission: AdmissionLease,
    context: OperationContext,
    device: Arc<Device>,
    client: Arc<dyn ProtocolClient>,
    pub(crate) limiter: Arc<Limiter>,
    traffic: TrafficLease,
    online: Option<OnlineLease>,
    device_timeout: Duration,
}
impl Session {
    pub fn context(&self) -> OperationContext {
        self.context.clone()
    }
    pub fn id(&self) -> SubscriptionId {
        self.admission.identity().id()
    }
    pub fn check(&self) -> Result<(), Error> {
        self.context.check().map_err(|_| Error::Revoked)?;
        let user = self.admission.current_user().map_err(|_| Error::Revoked)?;
        if !self.device.admitted(user.device_limit) {
            return Err(Error::DeviceExpired);
        }
        Ok(())
    }
    pub(crate) fn rate(&self) -> Result<u64, Error> {
        self.check()?;
        self.admission
            .current_user()
            .map_err(|_| Error::Revoked)?
            .speed_limit_mbps
            .checked_mul(125_000)
            .ok_or(Error::InvalidOptions)
    }
    pub fn reserve(&self, upload: bool, bytes: usize) -> Result<TrafficReservation, Error> {
        self.check()?;
        self.traffic
            .reserve(upload, bytes as u64)
            .map_err(|_| Error::Counter)
    }
    pub async fn run<F: Future>(&self, future: F) -> Result<F::Output, Error> {
        self.check()?;
        let limited = self
            .admission
            .current_user()
            .map_err(|_| Error::Revoked)?
            .device_limit
            > 0;
        tokio::pin!(future);
        let checked = std::future::poll_fn(|cx| {
            if let Err(error) = self.check() {
                return std::task::Poll::Ready(Err(error));
            }
            future.as_mut().poll(cx).map(Ok)
        });
        tokio::select! {biased;
            _=self.device.closed()=>Err(Error::DeviceExpired),
            _=self.device.expired(),if limited=>Err(Error::DeviceExpired),
            result=self.context.run(checked)=>result.map_err(|_|Error::Stopped)?,
        }
    }
    pub async fn refresh_device(&self) -> Result<(), Error> {
        let user = self.admission.current_user().map_err(|_| Error::Revoked)?;
        let context = self.context.child_with_deadline(
            Deadline::after(self.device_timeout).map_err(|_| Error::InvalidOptions)?,
        );
        let result = self
            .device
            .ensure(self.client.as_ref(), user.device_limit, &context)
            .await;
        self.check()?;
        result
    }
    /// The connection owns this future alongside forwarding; no detached timer.
    pub async fn maintain(&self) -> Result<(), Error> {
        loop {
            self.run(tokio::time::sleep(Duration::from_secs(1))).await?;
            self.refresh_device().await?;
        }
    }
    pub async fn quota(self: &Arc<Self>, bytes: usize) -> Result<rate::Permit, Error> {
        self.limiter.clone().reserve(self.clone(), bytes).await
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.context.cancellation().cancel();
    }
}
