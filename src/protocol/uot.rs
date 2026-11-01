// SPDX-License-Identifier: GPL-3.0-only
//! SagerNet UDP-over-TCP v1/v2 control headers. Packet framing lives in packet.
use super::{
    packet::Codec,
    socksaddr::{Endpoint, Format, Host},
};
use crate::network::Address;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
}
impl Version {
    pub fn from_config(version: u64) -> io::Result<Self> {
        match version {
            0 | 2 => Ok(Self::V2),
            1 => Ok(Self::V1),
            _ => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
    pub fn domain(self) -> &'static str {
        match self {
            Self::V1 => "sp.udp-over-tcp.arpa",
            Self::V2 => "sp.v2.udp-over-tcp.arpa",
        }
    }
    pub fn for_domain(domain: &str) -> Option<Self> {
        [Self::V1, Self::V2].into_iter().find(|v| {
            v.domain()
                .eq_ignore_ascii_case(domain.trim_end_matches('.'))
        })
    }
    pub fn for_target(address: &Address) -> Option<Self> {
        Self::for_domain(address.domain_name()?.as_str())
    }
    pub fn endpoint(self) -> Endpoint {
        Endpoint {
            host: Host::Domain(self.domain().into()),
            port: 0,
        }
    }
    pub async fn read<R: AsyncRead + Unpin + ?Sized>(self, reader: &mut R) -> io::Result<Codec> {
        if self == Self::V1 {
            return Ok(Codec::Uot { connected: None });
        }
        let flag = reader.read_u8().await?;
        if flag > 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let endpoint = Endpoint::read(reader, Format::Socks).await?;
        Ok(Codec::Uot {
            connected: if flag == 1 {
                Some(endpoint.address()?)
            } else {
                None
            },
        })
    }
    pub async fn write<W: AsyncWrite + Unpin + ?Sized>(
        self,
        writer: &mut W,
        connected: Option<&Address>,
    ) -> io::Result<Codec> {
        if self == Self::V1 {
            if connected.is_some() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            return Ok(Codec::Uot { connected: None });
        }
        writer.write_u8(u8::from(connected.is_some())).await?;
        let endpoint = if let Some(target) = connected {
            Endpoint::from_address(target)?
        } else {
            Endpoint {
                host: Host::Ip(std::net::Ipv4Addr::UNSPECIFIED.into()),
                port: 0,
            }
        };
        writer.write_all(&endpoint.encode(Format::Socks)?).await?;
        writer.flush().await?;
        Ok(Codec::Uot {
            connected: connected.cloned(),
        })
    }
}
