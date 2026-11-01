// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    net::{SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    str::FromStr,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    InvalidDomain,
    NameTooLong,
    ZeroPort,
    InvalidAuthority,
}
impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidDomain => {
                "invalid ASCII DNS hostname (use IDNA ASCII form for international names)"
            }
            Self::NameTooLong => "DNS hostname exceeds length limit",
            Self::ZeroPort => "destination port must be nonzero",
            Self::InvalidAuthority => "expected hostname:port or bracketed IPv6:port",
        })
    }
}
impl std::error::Error for AddressError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DomainName(String);
impl DomainName {
    /// DNS hostname syntax, without any lookup or search-domain expansion.
    /// Case is normalized; an explicit trailing root dot is retained.
    pub fn new(value: &str) -> Result<Self, AddressError> {
        let name = value.strip_suffix('.').unwrap_or(value);
        if name.len() > 253 {
            return Err(AddressError::NameTooLong);
        }
        if name.is_empty()
            || !name.is_ascii()
            || name.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(AddressError::InvalidDomain);
        }
        Ok(Self(value.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address(AddressKind);
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum AddressKind {
    Socket(SocketAddr),
    Domain { host: DomainName, port: NonZeroU16 },
}
impl Address {
    pub fn from_socket(address: SocketAddr) -> Result<Self, AddressError> {
        if address.port() == 0 {
            return Err(AddressError::ZeroPort);
        }
        Ok(Self(AddressKind::Socket(canonical_socket(address))))
    }
    pub fn from_domain(host: &str, port: u16) -> Result<Self, AddressError> {
        Ok(Self(AddressKind::Domain {
            host: DomainName::new(host)?,
            port: NonZeroU16::new(port).ok_or(AddressError::ZeroPort)?,
        }))
    }
    pub fn port(&self) -> u16 {
        match &self.0 {
            AddressKind::Socket(a) => a.port(),
            AddressKind::Domain { port, .. } => port.get(),
        }
    }
    pub fn domain_name(&self) -> Option<&DomainName> {
        match &self.0 {
            AddressKind::Domain { host, .. } => Some(host),
            _ => None,
        }
    }
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match &self.0 {
            AddressKind::Socket(a) => Some(*a),
            AddressKind::Domain { .. } => None,
        }
    }
}
impl FromStr for Address {
    type Err = AddressError;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if let Ok(address) = value.parse::<SocketAddr>() {
            return Self::from_socket(address);
        }
        let (host, port) = value
            .rsplit_once(':')
            .ok_or(AddressError::InvalidAuthority)?;
        if host.contains(':') || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
            return Err(AddressError::InvalidAuthority);
        }
        Self::from_domain(
            host,
            port.parse().map_err(|_| AddressError::InvalidAuthority)?,
        )
    }
}
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            AddressKind::Socket(a) => a.fmt(f),
            AddressKind::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

/// Preserve IPv6 flow/scope information; only map an unscoped mapped address.
pub fn canonical_socket(address: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = address
        && v6.scope_id() == 0
        && v6.flowinfo() == 0
        && let Some(ip) = v6.ip().to_ipv4_mapped()
    {
        return SocketAddr::V4(SocketAddrV4::new(ip, v6.port()));
    }
    address
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowMetadata {
    pub network: Network,
    pub source: SocketAddr,
    pub destination: Address,
}
impl FlowMetadata {
    pub fn new(network: Network, source: SocketAddr, destination: Address) -> Self {
        Self {
            network,
            source: canonical_socket(source),
            destination,
        }
    }
}
