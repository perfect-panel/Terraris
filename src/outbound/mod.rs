// SPDX-License-Identifier: GPL-3.0-only
//! Concrete outbound transports. A selected unsupported transport fails closed;
//! it is never replaced with an implicit direct connection.
mod packet;
mod proxy;
pub mod registry;
use crate::{network::Address, time::StopReason};
pub use packet::{Direct, Packet, PacketPort};
pub use proxy::{Kind, Proxy};
pub use registry::{Connector, Registry};
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
impl From<crate::transport::Error> for Error {
    fn from(error: crate::transport::Error) -> Self {
        use crate::transport::Error as T;
        match error {
            T::Unsupported => Self::Unsupported,
            T::Configuration(reason) => Self::Configuration(reason),
            T::Io(kind) => Self::Io(kind),
            T::Tls => Self::Tls,
            T::Stopped(reason) => Self::Stopped(reason),
        }
    }
}
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

pub(crate) fn validate_builtin(value: &crate::panel::Outbound) -> Result<(), Error> {
    if !value.address.is_empty()
        || value.port != 0
        || !value.user.is_empty()
        || !value.password.expose().is_empty()
        || !value.uuid.expose().is_empty()
        || !value.cipher.is_empty()
        || !value.plugin.is_empty()
        || value.plugin_options != crate::panel::ConfigValue::Null
        || !value.security.is_empty()
        || !value.sni.is_empty()
        || !value.alpn.is_empty()
        || value.allow_insecure
        || !value.fingerprint.is_empty()
        || !value.transport.is_empty()
        || !value.host.is_empty()
        || !value.path.is_empty()
        || !value.service_name.is_empty()
        || !value.xhttp_mode.is_empty()
        || !value.xhttp_extra.is_empty()
        || !value.flow.is_empty()
        || !value.encryption.is_empty()
        || !value.encryption_mode.is_empty()
        || !value.encryption_rtt.is_empty()
        || !value.encryption_ticket.expose().is_empty()
        || !value.encryption_client_padding.is_empty()
        || !value.encryption_password.expose().is_empty()
        || !value.multiplex.is_empty()
        || value.uot
        || value.uot_version != 0
        || !value.congestion_controller.is_empty()
        || value.udp_stream
        || value.reduce_rtt
        || value.heartbeat != 0
        || !value.reality_public_key.is_empty()
        || !value.reality_short_id.is_empty()
        || !value.spider_x.is_empty()
        || !value.settings.is_empty()
        || !value.stream_settings.is_empty()
        || !value.extensions.is_empty()
    {
        return Err(Error::Configuration("unused builtin outbound fields"));
    }
    Ok(())
}
