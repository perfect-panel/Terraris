// SPDX-License-Identifier: MPL-2.0
// VLESS wire layout follows XTLS/Xray-core; see THIRD_PARTY.md.

use crate::network::Address;
use prost::Message;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Io(io::ErrorKind),
    Version,
    Command,
    Address,
    Addons,
    UnsupportedFlow,
    Frame,
    TooLarge,
    Resource,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "VLESS wire: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e.kind())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
    Xudp,
}
#[derive(Clone, PartialEq, Message)]
struct Addons {
    #[prost(string, tag = "1")]
    flow: String,
    #[prost(bytes, tag = "2")]
    seed: Vec<u8>,
}
pub struct Request {
    pub uuid: [u8; 16],
    pub command: Command,
    pub target: Option<Address>,
}
impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessRequest")
            .field("command", &self.command)
            .finish_non_exhaustive()
    }
}
impl Request {
    pub async fn read<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        let mut header = [0; 18];
        reader.read_exact(&mut header).await?;
        if header[0] != 0 {
            return Err(Error::Version);
        }
        let uuid = header[1..17].try_into().expect("UUID");
        let length = header[17] as usize;
        let mut extra = [0; 255];
        reader.read_exact(&mut extra[..length]).await?;
        let addons = Addons::decode(&extra[..length]).map_err(|_| Error::Addons)?;
        if !addons.flow.is_empty() || !addons.seed.is_empty() {
            return Err(Error::UnsupportedFlow);
        }
        let command = match reader.read_u8().await? {
            1 => Command::Tcp,
            2 => Command::Udp,
            3 => Command::Xudp,
            _ => return Err(Error::Command),
        };
        let target = if command == Command::Xudp {
            None
        } else {
            Some(read_address(reader).await?)
        };
        Ok(Self {
            uuid,
            command,
            target,
        })
    }
    pub async fn write<W: AsyncWrite + Unpin + ?Sized>(&self, writer: &mut W) -> Result<(), Error> {
        let mut bytes = [0u8; 19 + 259];
        bytes[1..17].copy_from_slice(&self.uuid);
        bytes[18] = match self.command {
            Command::Tcp => 1,
            Command::Udp => 2,
            Command::Xudp => 3,
        };
        let length = if self.command == Command::Xudp {
            19
        } else {
            19 + encode_address(
                self.target.as_ref().ok_or(Error::Address)?,
                &mut bytes[19..],
            )?
        };
        writer.write_all(&bytes[..length]).await?;
        Ok(())
    }
}
pub async fn write_response<W: AsyncWrite + Unpin + ?Sized>(writer: &mut W) -> Result<(), Error> {
    writer.write_all(&[0, 0]).await?;
    writer.flush().await?;
    Ok(())
}
pub async fn read_address<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<Address, Error> {
    let mut header = [0; 3];
    reader.read_exact(&mut header).await?;
    let port = u16::from_be_bytes([header[0], header[1]]);
    match header[2] {
        1 => {
            let mut ip = [0; 4];
            reader.read_exact(&mut ip).await?;
            Address::from_socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port))
                .map_err(|_| Error::Address)
        }
        3 => {
            let mut ip = [0; 16];
            reader.read_exact(&mut ip).await?;
            Address::from_socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
                .map_err(|_| Error::Address)
        }
        2 => {
            let length = reader.read_u8().await? as usize;
            let mut host = [0; 255];
            reader.read_exact(&mut host[..length]).await?;
            Address::from_domain(
                std::str::from_utf8(&host[..length]).map_err(|_| Error::Address)?,
                port,
            )
            .map_err(|_| Error::Address)
        }
        _ => Err(Error::Address),
    }
}
pub(crate) fn decode_address(data: &[u8]) -> Result<(Address, usize), Error> {
    if data.len() < 3 {
        return Err(Error::Address);
    }
    let port = u16::from_be_bytes([data[0], data[1]]);
    match data[2] {
        1 => {
            let bytes: [u8; 4] = data
                .get(3..7)
                .ok_or(Error::Address)?
                .try_into()
                .map_err(|_| Error::Address)?;
            Ok((
                Address::from_socket(SocketAddr::new(IpAddr::V4(bytes.into()), port))
                    .map_err(|_| Error::Address)?,
                7,
            ))
        }
        3 => {
            let bytes: [u8; 16] = data
                .get(3..19)
                .ok_or(Error::Address)?
                .try_into()
                .map_err(|_| Error::Address)?;
            Ok((
                Address::from_socket(SocketAddr::new(IpAddr::V6(bytes.into()), port))
                    .map_err(|_| Error::Address)?,
                19,
            ))
        }
        2 => {
            let length = *data.get(3).ok_or(Error::Address)? as usize;
            let host = std::str::from_utf8(data.get(4..4 + length).ok_or(Error::Address)?)
                .map_err(|_| Error::Address)?;
            Ok((
                Address::from_domain(host, port).map_err(|_| Error::Address)?,
                4 + length,
            ))
        }
        _ => Err(Error::Address),
    }
}
pub(crate) fn encode_address(address: &Address, data: &mut [u8]) -> Result<usize, Error> {
    if data.len() < 3 {
        return Err(Error::Address);
    }
    data[..2].copy_from_slice(&address.port().to_be_bytes());
    if let Some(socket) = address.socket_addr() {
        match socket.ip() {
            IpAddr::V4(ip) => {
                data[2] = 1;
                data.get_mut(3..7)
                    .ok_or(Error::Address)?
                    .copy_from_slice(&ip.octets());
                Ok(7)
            }
            IpAddr::V6(ip) => {
                if let SocketAddr::V6(socket) = socket
                    && (socket.scope_id() != 0 || socket.flowinfo() != 0)
                {
                    return Err(Error::Address);
                }
                data[2] = 3;
                data.get_mut(3..19)
                    .ok_or(Error::Address)?
                    .copy_from_slice(&ip.octets());
                Ok(19)
            }
        }
    } else {
        let host = address
            .domain_name()
            .ok_or(Error::Address)?
            .as_str()
            .as_bytes();
        if host.len() > 255 || data.len() < 4 + host.len() {
            return Err(Error::Address);
        }
        data[2] = 2;
        data[3] = host.len() as u8;
        data[4..4 + host.len()].copy_from_slice(host);
        Ok(4 + host.len())
    }
}

/// Cancellation-safe framing for ordinary VLESS UDP (one target per carrier).
pub struct PacketReader<R> {
    io: R,
    buffers: crate::buffer::BufferScope,
    prefix: [u8; 2],
    prefix_have: usize,
    body: Option<crate::buffer::BufferLease>,
    have: usize,
    maximum: usize,
}
impl<R: AsyncRead + Unpin> PacketReader<R> {
    pub fn new(io: R, buffers: crate::buffer::BufferScope, maximum: usize) -> Self {
        Self {
            io,
            buffers,
            prefix: [0; 2],
            prefix_have: 0,
            body: None,
            have: 0,
            maximum,
        }
    }
    pub async fn next(&mut self) -> Result<Option<crate::buffer::SharedBuffer>, Error> {
        while self.prefix_have < 2 {
            let n = self.io.read(&mut self.prefix[self.prefix_have..]).await?;
            if n == 0 {
                if self.prefix_have == 0 {
                    return Ok(None);
                }
                return Err(Error::Frame);
            }
            self.prefix_have += n;
        }
        let length = u16::from_be_bytes(self.prefix) as usize;
        if length > self.maximum {
            return Err(Error::TooLarge);
        }
        if self.body.is_none() {
            let mut body = self
                .buffers
                .try_lease(
                    crate::buffer::BufferLayout::new(0, length, 0).map_err(|_| Error::Resource)?,
                )
                .map_err(|_| Error::Resource)?;
            body.append_zeroed(length).map_err(|_| Error::Resource)?;
            self.body = Some(body);
        }
        while self.have < length {
            let n = self
                .io
                .read(&mut self.body.as_mut().expect("packet").as_mut_slice()[self.have..])
                .await?;
            if n == 0 {
                return Err(Error::Frame);
            }
            self.have += n;
        }
        let packet = self.body.take().expect("packet").freeze();
        self.prefix_have = 0;
        self.have = 0;
        Ok(Some(packet))
    }
}
