// SPDX-License-Identifier: GPL-3.0-only
mod resolver;
mod strategy;
pub mod system;
mod transport;
pub mod wire;
use crate::time::{Deadline, StopReason};
pub use resolver::{Resolver, Snapshot};
use serde::Deserialize;
use std::{collections::BTreeMap, net::IpAddr, path::PathBuf, time::Duration};
pub use strategy::Strategy;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration(&'static str),
    InvalidQuery,
    InvalidResponse,
    NoResolver,
    NoRecords,
    ServerFailure,
    Transport,
    Tls,
    HttpStatus(u16),
    TooLarge,
    Capacity,
    Closed,
    Stopped(StopReason),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "dns: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub cache_entries: usize,
    pub cache_bytes: usize,
    pub concurrency: usize,
    pub max_waiters: usize,
    pub timeout_seconds: u64,
    pub max_ttl_seconds: u32,
    pub negative_ttl_seconds: u32,
    pub max_answers: usize,
    pub ca_file: Option<PathBuf>,
    pub bootstrap: BTreeMap<String, Vec<IpAddr>>,
    pub intercept: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            cache_entries: 1024,
            cache_bytes: 8 << 20,
            concurrency: 64,
            max_waiters: 4096,
            timeout_seconds: 5,
            max_ttl_seconds: 86400,
            negative_ttl_seconds: 300,
            max_answers: 64,
            ca_file: None,
            bootstrap: BTreeMap::new(),
            intercept: true,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        if self.cache_entries > 100_000
            || self.cache_bytes > 256 << 20
            || self.concurrency == 0
            || self.concurrency > 1024
            || self.max_waiters == 0
            || self.max_waiters > 100_000
            || self.timeout_seconds == 0
            || self.timeout_seconds > 300
            || self.max_answers == 0
            || self.max_answers > 256
            || self.bootstrap.len() > 128
            || self
                .bootstrap
                .values()
                .any(|v| v.is_empty() || v.len() > 16)
        {
            return Err(Error::Configuration("limits"));
        }
        Deadline::after(Duration::from_secs(self.timeout_seconds))
            .map_err(|_| Error::Configuration("timeout"))?;
        Ok(())
    }
}

pub(crate) use transport::tls_config;
