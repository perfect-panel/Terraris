// SPDX-License-Identifier: GPL-3.0-only
//! SOCKS endpoint metadata, including zero-port control destinations used by UoT.
use crate::network::Address;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::io::{AsyncRead, AsyncReadExt};
#[derive(Clone, Copy)]
pub enum Format {
    Socks,
    Uot,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    Ip(IpAddr),
    Domain(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: Host,
    pub port: u16,
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
impl Endpoint {
    pub fn from_address(address: &Address) -> io::Result<Self> {
        let host = if let Some(socket) = address.socket_addr() {
            if let SocketAddr::V6(v6) = socket
                && (v6.scope_id() != 0 || v6.flowinfo() != 0)
            {
                return Err(invalid());
            }
            Host::Ip(socket.ip())
        } else {
            Host::Domain(
                address
                    .domain_name()
                    .ok_or_else(invalid)?
                    .as_str()
                    .to_owned(),
            )
        };
        Ok(Self {
            host,
            port: address.port(),
        })
    }
    pub fn address(&self) -> io::Result<Address> {
        match &self.host {
            Host::Ip(ip) => Address::from_socket(SocketAddr::new(*ip, self.port)),
            Host::Domain(name) => Address::from_domain(name, self.port),
        }
        .map_err(|_| invalid())
    }
    /// Magic domains identify a control request, not a dialable destination.
    /// Internally use port 1 because Address rejects zero ports; encoders preserve
    /// the raw endpoint's port when writing control requests.
    pub fn target(&self) -> io::Result<Address> {
        if let Host::Domain(name) = &self.host
            && super::uot::Version::for_domain(name).is_some()
        {
            return Address::from_domain(name, self.port.max(1)).map_err(|_| invalid());
        }
        self.address()
    }
    pub fn encode(&self, format: Format) -> io::Result<Vec<u8>> {
        let (v4, v6, domain) = match format {
            Format::Socks => (1, 4, 3),
            Format::Uot => (0, 1, 2),
        };
        let mut data = Vec::with_capacity(259);
        match &self.host {
            Host::Ip(IpAddr::V4(ip)) => {
                data.push(v4);
                data.extend(ip.octets());
            }
            Host::Ip(IpAddr::V6(ip)) => {
                data.push(v6);
                data.extend(ip.octets());
            }
            Host::Domain(name) => {
                crate::network::DomainName::new(name).map_err(|_| invalid())?;
                data.push(domain);
                data.push(u8::try_from(name.len()).map_err(|_| invalid())?);
                data.extend(name.as_bytes());
            }
        }
        data.extend(self.port.to_be_bytes());
        Ok(data)
    }
    pub fn parse(data: &[u8], format: Format) -> io::Result<Option<(Self, usize)>> {
        let Some(kind) = data.first() else {
            return Ok(None);
        };
        let (v4, v6, domain) = match format {
            Format::Socks => (1, 4, 3),
            Format::Uot => (0, 1, 2),
        };
        let (start, length) = if *kind == v4 {
            (1, 4)
        } else if *kind == v6 {
            (1, 16)
        } else if *kind == domain {
            let Some(length) = data.get(1) else {
                return Ok(None);
            };
            if *length == 0 {
                return Err(invalid());
            }
            (2, *length as usize)
        } else {
            return Err(invalid());
        };
        let end = start + length;
        if data.len() < end + 2 {
            return Ok(None);
        }
        let host = if *kind == v4 {
            Host::Ip(Ipv4Addr::from(<[u8; 4]>::try_from(&data[start..end]).expect("width")).into())
        } else if *kind == v6 {
            Host::Ip(Ipv6Addr::from(<[u8; 16]>::try_from(&data[start..end]).expect("width")).into())
        } else {
            let name = std::str::from_utf8(&data[start..end]).map_err(|_| invalid())?;
            Host::Domain(
                crate::network::DomainName::new(name)
                    .map_err(|_| invalid())?
                    .as_str()
                    .to_owned(),
            )
        };
        Ok(Some((
            Self {
                host,
                port: u16::from_be_bytes([data[end], data[end + 1]]),
            },
            end + 2,
        )))
    }
    pub async fn read<R: AsyncRead + Unpin + ?Sized>(
        reader: &mut R,
        format: Format,
    ) -> io::Result<Self> {
        let mut data = [0; 259];
        for end in 1..=data.len() {
            reader.read_exact(&mut data[end - 1..end]).await?;
            if let Some((address, _)) = Self::parse(&data[..end], format)? {
                return Ok(address);
            }
        }
        Err(invalid())
    }
}
