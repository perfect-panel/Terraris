// SPDX-License-Identifier: GPL-3.0-only
//! Concrete outbound transports. A selected unsupported transport fails closed;
//! it is never replaced with an implicit direct connection.
mod packet;
mod proxy;
use crate::{network::Address, time::StopReason};
pub use packet::{Direct, Packet, PacketPort};
pub use proxy::{Kind, Proxy};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration(&'static str),
    Unsupported,
    Authentication,
    Protocol,
    Closed,
    Capacity,
    Io(std::io::ErrorKind),
    Stopped(StopReason),
    Resolve,
    Tls,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "outbound: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.kind())
    }
}
impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        std::io::Error::new(std::io::ErrorKind::ConnectionAborted, value)
    }
}
pub(crate) fn socks_address(address: &Address, out: &mut Vec<u8>) -> Result<(), Error> {
    if let Some(socket) = address.socket_addr() {
        match socket.ip() {
            std::net::IpAddr::V4(ip) => {
                out.push(1);
                out.extend(ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                if let std::net::SocketAddr::V6(value) = socket
                    && (value.scope_id() != 0 || value.flowinfo() != 0)
                {
                    return Err(Error::Protocol);
                }
                out.push(4);
                out.extend(ip.octets());
            }
        }
    } else {
        let name = address
            .domain_name()
            .ok_or(Error::Protocol)?
            .as_str()
            .as_bytes();
        out.push(3);
        out.push(u8::try_from(name.len()).map_err(|_| Error::Protocol)?);
        out.extend(name);
    }
    out.extend(address.port().to_be_bytes());
    Ok(())
}
