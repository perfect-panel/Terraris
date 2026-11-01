// SPDX-License-Identifier: GPL-3.0-only

//! Bounded in-memory report state, independent of any runtime generation.
//! An ACK subtracts only its immutable batch. Unconfirmed traffic stays counted;
//! the legacy panel API can still bill ambiguous retries more than once.

use crate::panel::{OnlineUser, SubscriptionId, Traffic};
use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
    sync::{Arc, Mutex},
};
const MAX_TRAFFIC: u64 = 10 << 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLimit,
    Full,
    Overflow,
    Busy,
    InvalidAddress,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "report buffer: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Default)]
struct Counts {
    upload: u64,
    download: u64,
    reserved_upload: u64,
    reserved_download: u64,
    reservations: usize,
    active: usize,
}
impl Counts {
    fn removable(&self) -> bool {
        self.upload == 0
            && self.download == 0
            && self.reserved_upload == 0
            && self.reserved_download == 0
            && self.active == 0
            && self.reservations == 0
    }
}
struct Online {
    active: usize,
    version: u64,
    pending: bool,
}
struct State {
    traffic: BTreeMap<SubscriptionId, Counts>,
    online: BTreeMap<(SubscriptionId, IpAddr), Online>,
    traffic_inflight: bool,
    online_inflight: bool,
    version: u64,
    traffic_cursor: Option<SubscriptionId>,
}
struct Inner {
    limit: usize,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct Reports {
    inner: Arc<Inner>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub traffic_users: usize,
    pub online_ips: usize,
    pub traffic_inflight: bool,
    pub online_inflight: bool,
    pub pending_bytes: u128,
}
impl Reports {
    pub fn new(limit: usize) -> Result<Self, Error> {
        if limit == 0 {
            return Err(Error::InvalidLimit);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                limit,
                state: Mutex::new(State {
                    traffic: BTreeMap::new(),
                    online: BTreeMap::new(),
                    traffic_inflight: false,
                    online_inflight: false,
                    version: 0,
                    traffic_cursor: None,
                }),
            }),
        })
    }
    pub fn capacity(&self) -> usize {
        self.inner.limit
    }
    pub fn snapshot(&self) -> Snapshot {
        let s = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        Snapshot {
            traffic_users: s.traffic.len(),
            online_ips: s.online.len(),
            traffic_inflight: s.traffic_inflight,
            online_inflight: s.online_inflight,
            pending_bytes: s
                .traffic
                .values()
                .map(|v| v.upload as u128 + v.download as u128)
                .sum(),
        }
    }
    /// Caller must handle Full/Overflow and stop or retain the unrecorded delta;
    /// this API never silently drops or saturates billable traffic.
    pub fn record_traffic(&self, traffic: Traffic) -> Result<(), Error> {
        if traffic.upload == 0 && traffic.download == 0 {
            return Ok(());
        }
        let mut s = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if !s.traffic.contains_key(&traffic.id) && s.traffic.len() >= self.inner.limit {
            return Err(Error::Full);
        }
        let old = s.traffic.get(&traffic.id).copied().unwrap_or_default();
        old.upload
            .checked_add(old.reserved_upload)
            .and_then(|v| v.checked_add(traffic.upload))
            .ok_or(Error::Overflow)?;
        old.download
            .checked_add(old.reserved_download)
            .and_then(|v| v.checked_add(traffic.download))
            .ok_or(Error::Overflow)?;
        let next = Counts {
            upload: old.upload + traffic.upload,
            download: old.download + traffic.download,
            ..old
        };
        s.traffic.insert(traffic.id, next);
        Ok(())
    }
    /// Reserve a counter slot before forwarding any authenticated payload.
    pub fn traffic_lease(&self, id: SubscriptionId) -> Result<TrafficLease, Error> {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if !state.traffic.contains_key(&id) && state.traffic.len() >= self.inner.limit {
            return Err(Error::Full);
        }
        let entry = state.traffic.entry(id).or_default();
        entry.active = entry.active.checked_add(1).ok_or(Error::Overflow)?;
        Ok(TrafficLease {
            reports: self.clone(),
            id,
        })
    }
    pub fn traffic_batch(
        &self,
        threshold: u64,
        max_items: usize,
    ) -> Result<Option<TrafficBatch>, Error> {
        if max_items == 0 {
            return Err(Error::InvalidLimit);
        }
        let mut s = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.traffic_inflight {
            return Err(Error::Busy);
        }
        let values: Vec<_> = s
            .traffic
            .iter()
            .filter(|(id, _)| s.traffic_cursor.is_none_or(|cursor| **id > cursor))
            .chain(
                s.traffic
                    .iter()
                    .filter(|(id, _)| s.traffic_cursor.is_some_and(|cursor| **id <= cursor)),
            )
            .filter(|(_, v)| v.upload as u128 + v.download as u128 > threshold as u128)
            .take(max_items)
            .map(|(&id, v)| {
                let upload = v.upload.min(MAX_TRAFFIC);
                let download = v.download.min(MAX_TRAFFIC - upload);
                Traffic {
                    id,
                    upload,
                    download,
                }
            })
            .collect();
        if values.is_empty() {
            return Ok(None);
        }
        s.traffic_inflight = true;
        Ok(Some(TrafficBatch {
            reports: self.clone(),
            values,
            acknowledged: 0,
        }))
    }
    pub fn online(&self, id: SubscriptionId, ip: IpAddr) -> Result<OnlineLease, Error> {
        let ip = canonical(ip);
        if ip.is_unspecified() || ip.is_multicast() {
            return Err(Error::InvalidAddress);
        }
        let mut s = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        let key = (id, ip);
        if !s.online.contains_key(&key) && s.online.len() >= self.inner.limit {
            return Err(Error::Full);
        }
        let version = s.version.checked_add(1).ok_or(Error::Overflow)?;
        let active = s
            .online
            .get(&key)
            .map_or(0, |v| v.active)
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        s.version = version;
        s.online.insert(
            key,
            Online {
                active,
                version,
                pending: true,
            },
        );
        Ok(OnlineLease {
            reports: self.clone(),
            key,
        })
    }
    /// Snapshot all active and unconfirmed short-lived addresses. Controller
    /// sends bounded chunks and acknowledges each successful chunk separately.
    pub fn online_batch(&self) -> Result<Option<OnlineBatch>, Error> {
        let mut s = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if s.online_inflight {
            return Err(Error::Busy);
        }
        let records: Vec<_> = s
            .online
            .iter()
            .filter(|(_, v)| v.active > 0 || v.pending)
            .map(|(&(id, ip), v)| (OnlineUser { id, ip }, v.version))
            .collect();
        if records.is_empty() {
            return Ok(None);
        }
        s.online_inflight = true;
        Ok(Some(OnlineBatch {
            reports: self.clone(),
            records,
            acknowledged: 0,
        }))
    }
}
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

pub struct TrafficBatch {
    reports: Reports,
    values: Vec<Traffic>,
    acknowledged: usize,
}
impl TrafficBatch {
    pub fn values(&self) -> &[Traffic] {
        &self.values[self.acknowledged..]
    }
    pub fn acknowledge_chunk(&mut self, count: usize) {
        assert!(count <= self.values().len());
        let end = self.acknowledged + count;
        let mut s = self
            .reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for delta in &self.values[self.acknowledged..end] {
            let current = s
                .traffic
                .get_mut(&delta.id)
                .expect("reserved traffic entry");
            current.upload -= delta.upload;
            current.download -= delta.download;
            if current.removable() {
                s.traffic.remove(&delta.id);
            }
            s.traffic_cursor = Some(delta.id);
        }
        self.acknowledged = end;
    }
    pub fn acknowledge(mut self) {
        let count = self.values().len();
        self.acknowledge_chunk(count);
    }
}
impl Drop for TrafficBatch {
    fn drop(&mut self) {
        self.reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .traffic_inflight = false;
    }
}
pub struct OnlineLease {
    reports: Reports,
    key: (SubscriptionId, IpAddr),
}
impl Drop for OnlineLease {
    fn drop(&mut self) {
        let mut s = self
            .reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = s.online.get_mut(&self.key).expect("live online entry");
        entry.active -= 1;
        if entry.active == 0 && !entry.pending {
            s.online.remove(&self.key);
        }
    }
}
pub struct OnlineBatch {
    reports: Reports,
    records: Vec<(OnlineUser, u64)>,
    acknowledged: usize,
}
impl OnlineBatch {
    pub fn remaining(&self) -> usize {
        self.records.len() - self.acknowledged
    }
    pub fn next_chunk(&self, maximum: usize) -> Vec<OnlineUser> {
        self.records[self.acknowledged..]
            .iter()
            .take(maximum)
            .map(|v| v.0)
            .collect()
    }
    pub fn acknowledge_chunk(&mut self, count: usize) {
        assert!(count <= self.remaining());
        let end = self.acknowledged + count;
        let mut s = self
            .reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        for (user, version) in &self.records[self.acknowledged..end] {
            let key = (user.id, user.ip);
            if let Some(entry) = s.online.get_mut(&key)
                && entry.version == *version
            {
                entry.pending = false;
                if entry.active == 0 {
                    s.online.remove(&key);
                }
            }
        }
        self.acknowledged = end;
    }
}
impl Drop for OnlineBatch {
    fn drop(&mut self) {
        self.reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .online_inflight = false;
    }
}

/// Keeps the user's counter entry alive across empty ACKs and concurrent writes.
pub struct TrafficLease {
    reports: Reports,
    id: SubscriptionId,
}
impl TrafficLease {
    pub fn reserve(&self, upload: bool, bytes: u64) -> Result<TrafficReservation, Error> {
        let mut state = self
            .reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = state.traffic.get_mut(&self.id).expect("leased counter");
        let count = entry.reservations.checked_add(1).ok_or(Error::Overflow)?;
        let (current, reserved) = if upload {
            (entry.upload, &mut entry.reserved_upload)
        } else {
            (entry.download, &mut entry.reserved_download)
        };
        current
            .checked_add(*reserved)
            .and_then(|v| v.checked_add(bytes))
            .ok_or(Error::Overflow)?;
        *reserved += bytes;
        entry.reservations = count;
        Ok(TrafficReservation {
            reports: self.reports.clone(),
            id: self.id,
            upload,
            remaining: bytes,
        })
    }
}
impl Drop for TrafficLease {
    fn drop(&mut self) {
        let mut state = self
            .reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = state.traffic.get_mut(&self.id).expect("leased counter");
        entry.active -= 1;
        if entry.removable() {
            state.traffic.remove(&self.id);
        }
    }
}
/// Counter headroom is reserved before I/O; only the successful prefix is
/// committed, so accounting cannot fail after the socket accepted bytes.
pub struct TrafficReservation {
    reports: Reports,
    id: SubscriptionId,
    upload: bool,
    remaining: u64,
}
impl TrafficReservation {
    pub fn commit(&mut self, bytes: u64) {
        assert!(bytes <= self.remaining);
        let mut state = self
            .reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = state.traffic.get_mut(&self.id).expect("reserved counter");
        if self.upload {
            entry.reserved_upload -= bytes;
            entry.upload += bytes;
        } else {
            entry.reserved_download -= bytes;
            entry.download += bytes;
        }
        self.remaining -= bytes;
    }
}
impl Drop for TrafficReservation {
    fn drop(&mut self) {
        let mut state = self
            .reports
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let entry = state.traffic.get_mut(&self.id).expect("reserved counter");
        entry.reservations -= 1;
        if self.upload {
            entry.reserved_upload -= self.remaining;
        } else {
            entry.reserved_download -= self.remaining;
        }
        if entry.removable() {
            state.traffic.remove(&self.id);
        }
    }
}
