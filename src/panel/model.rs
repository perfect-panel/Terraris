// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
    time::Duration,
};

use super::{Endpoint, Error, Result};

mod configuration;
pub use configuration::*;

/// Never formatted or serialized implicitly. Callers must explicitly expose it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Arc<str>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Arc::from(value.into()))
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerId(i64);

impl ServerId {
    pub fn new(id: i64) -> Result<Self> {
        if id <= 0 {
            return Err(Error::input(
                Endpoint::Connection,
                "server ID must be positive",
            ));
        }
        Ok(Self(id))
    }
    pub fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubscriptionId(i64);

impl SubscriptionId {
    pub fn new(id: i64) -> Result<Self> {
        if id <= 0 {
            return Err(Error::input(
                Endpoint::Users,
                "subscription ID must be positive",
            ));
        }
        Ok(Self(id))
    }
    pub fn get(self) -> i64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolName(String);

impl ProtocolName {
    /// Unknown protocol names are retained; this is not a runtime support check.
    pub fn new(name: &str) -> Result<Self> {
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::input(Endpoint::Connection, "invalid protocol name"));
        }
        Ok(Self(if name == "hysteria2" {
            "hysteria".into()
        } else {
            name
        }))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A wire-neutral value for plugin options and future configuration fields.
/// Debug intentionally hides values, which can contain plugin credentials.
#[derive(Clone, PartialEq)]
pub enum ConfigValue {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    Float(f64),
    String(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl fmt::Debug for ConfigValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfigValue([redacted])")
    }
}

#[derive(Clone, PartialEq)]
pub struct ServerConfig {
    pub pull_interval: Duration,
    pub push_interval: Duration,
    pub traffic_report_threshold: u64,
    pub ip_strategy: String,
    pub dns: Vec<DnsResolver>,
    pub block: Vec<String>,
    pub outbounds: Vec<Outbound>,
    pub protocols: Vec<ProtocolConfig>,
    pub extensions: BTreeMap<String, ConfigValue>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("pull_interval", &self.pull_interval)
            .field("push_interval", &self.push_interval)
            .field("protocol_count", &self.protocols.len())
            .field("outbound_count", &self.outbounds.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: SubscriptionId,
    pub credential: Secret,
    pub speed_limit_mbps: u64,
    pub device_limit: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Json,
    Protobuf,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WireMode {
    #[default]
    Auto,
    Json,
    Protobuf,
}

/// A candidate validator is returned with a response, never committed by the
/// client. The controller must retain it only after applying the associated data.
#[derive(Clone)]
pub struct Validator {
    pub(crate) owner: Arc<()>,
    pub(crate) endpoint: Endpoint,
    pub(crate) protocol: Option<ProtocolName>,
    pub(crate) encoding: Encoding,
    pub(crate) etag: Option<String>,
    pub(crate) digest: [u8; 32],
}

impl Validator {
    pub fn encoding(&self) -> Encoding {
        self.encoding
    }
    pub fn has_etag(&self) -> bool {
        self.etag.is_some()
    }
}

impl fmt::Debug for Validator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Validator")
            .field("endpoint", &self.endpoint)
            .field("encoding", &self.encoding)
            .field("has_etag", &self.has_etag())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub enum Fetch<T> {
    Changed { value: T, validator: Validator },
    Unchanged { validator: Validator },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceClaim {
    pub allowed: bool,
    pub ttl: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OnlineUser {
    pub id: SubscriptionId,
    pub ip: IpAddr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Traffic {
    pub id: SubscriptionId,
    pub upload: u64,
    pub download: u64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NodeStatus {
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub updated_at_millis: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateFingerprint(String);

impl CertificateFingerprint {
    pub fn new(value: &str) -> Result<Self> {
        if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::input(
                Endpoint::Status,
                "certificate fingerprint must be 64 hexadecimal characters",
            ));
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        other => other,
    }
}

pub(crate) fn valid_source(ip: IpAddr) -> bool {
    let ip = canonical_ip(ip);
    !ip.is_unspecified() && !ip.is_multicast() && ip != IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}
