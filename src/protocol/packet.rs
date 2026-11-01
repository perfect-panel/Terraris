// SPDX-License-Identifier: GPL-3.0-only
//! Cancellation-safe addressed UDP frames shared by Trojan and UoT.
use super::socksaddr::{Endpoint, Format};
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope, SharedBuffer},
    network::Address,
};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub const MAX_PAYLOAD: usize = 65507;
#[derive(Clone)]
pub enum Codec {
    Trojan,
    Uot { connected: Option<Address> },
}
pub struct Packet {
    pub address: Address,
    pub payload: SharedBuffer,
}
pub struct Reader<R> {
    io: R,
    codec: Codec,
    scope: BufferScope,
    header: [u8; 263],
    have: usize,
    target: Option<Address>,
    length: Option<usize>,
    body: Option<BufferLease>,
    body_have: usize,
    poisoned: bool,
}
impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(io: R, codec: Codec, scope: BufferScope) -> Self {
        Self {
            io,
            codec,
            scope,
            header: [0; 263],
            have: 0,
            target: None,
            length: None,
            body: None,
            body_have: 0,
            poisoned: false,
        }
    }
    fn parse_header(&mut self) -> io::Result<()> {
        let (target, offset) = match &self.codec {
            Codec::Uot {
                connected: Some(address),
            } => (address.clone(), 0),
            codec => {
                let format = if matches!(codec, Codec::Trojan) {
                    Format::Socks
                } else {
                    Format::Uot
                };
                let Some((endpoint, end)) = Endpoint::parse(&self.header[..self.have], format)?
                else {
                    return Ok(());
                };
                (endpoint.address()?, end)
            }
        };
        let extra = if matches!(self.codec, Codec::Trojan) {
            4
        } else {
            2
        };
        if self.have < offset + extra {
            return Ok(());
        }
        if extra == 4 && self.header[offset + 2..offset + 4] != *b"\r\n" {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let n = u16::from_be_bytes([self.header[offset], self.header[offset + 1]]) as usize;
        if n > MAX_PAYLOAD {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.target = Some(target);
        self.length = Some(n);
        Ok(())
    }
    pub async fn next(&mut self) -> io::Result<Option<Packet>> {
        if self.poisoned {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let result = self.next_inner().await;
        if result.is_err() {
            self.poisoned = true;
            self.body.take();
        }
        result
    }
    async fn next_inner(&mut self) -> io::Result<Option<Packet>> {
        while self.length.is_none() {
            if self.have == self.header.len() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let n = self
                .io
                .read(&mut self.header[self.have..self.have + 1])
                .await?;
            if n == 0 {
                return if self.have == 0 {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            self.have += n;
            self.parse_header()?;
        }
        let length = self.length.expect("parsed length");
        if self.body.is_none() {
            let mut body = self
                .scope
                .try_lease(BufferLayout::new(0, length, 0).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
            body.append_zeroed(length).map_err(io::Error::other)?;
            self.body = Some(body);
        }
        while self.body_have < length {
            let n = self
                .io
                .read(&mut self.body.as_mut().expect("body").as_mut_slice()[self.body_have..])
                .await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.body_have += n;
        }
        let packet = Packet {
            address: self.target.take().expect("target"),
            payload: self.body.take().expect("body").freeze(),
        };
        self.have = 0;
        self.length = None;
        self.body_have = 0;
        Ok(Some(packet))
    }
}
pub async fn write<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    codec: &Codec,
    target: &Address,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut header = match codec {
        Codec::Uot {
            connected: Some(address),
        } => {
            if target != address {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            Vec::new()
        }
        codec => Endpoint::from_address(target)?.encode(if matches!(codec, Codec::Trojan) {
            Format::Socks
        } else {
            Format::Uot
        })?,
    };
    header.extend((payload.len() as u16).to_be_bytes());
    if matches!(codec, Codec::Trojan) {
        header.extend(b"\r\n");
    }
    writer.write_all(&header).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}
