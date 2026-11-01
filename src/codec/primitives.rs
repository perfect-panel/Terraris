// SPDX-License-Identifier: GPL-3.0-only

use super::{Error, LengthPrefix};
use crate::{
    buffer::BufferLease,
    network::{Address, AddressError},
};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

pub struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8], limit: usize) -> Result<Self, Error> {
        if data.len() > limit {
            return Err(Error::LimitExceeded {
                requested: data.len(),
                limit,
            });
        }
        Ok(Self { data, position: 0 })
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        if length > self.remaining() {
            return Err(Error::UnexpectedEof);
        }
        let start = self.position;
        self.position += length;
        Ok(&self.data[start..self.position])
    }
    pub fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub fn u16_be(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("checked u16 width"),
        ))
    }
    pub fn u32_be(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("checked u32 width"),
        ))
    }
    pub fn u64_be(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("checked u64 width"),
        ))
    }
    pub fn finish(&self) -> Result<(), Error> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::TrailingData)
        }
    }

    /// Reads ATYP + address + big-endian destination port. Any failure restores
    /// the reader position; raw input never appears in an error.
    pub fn address(&mut self) -> Result<Address, Error> {
        let saved = self.position;
        let result = (|| {
            let kind = self.u8()?;
            match kind {
                1 => {
                    let ip = Ipv4Addr::from(
                        <[u8; 4]>::try_from(self.take(4)?).expect("checked IPv4 width"),
                    );
                    let port = self.u16_be()?;
                    Ok(Address::from_socket(SocketAddr::new(IpAddr::V4(ip), port))?)
                }
                4 => {
                    let ip = Ipv6Addr::from(
                        <[u8; 16]>::try_from(self.take(16)?).expect("checked IPv6 width"),
                    );
                    let port = self.u16_be()?;
                    Ok(Address::from_socket(SocketAddr::new(IpAddr::V6(ip), port))?)
                }
                3 => {
                    let length = self.u8()? as usize;
                    let host = std::str::from_utf8(self.take(length)?)
                        .map_err(|_| Error::Address(AddressError::InvalidDomain))?;
                    let port = self.u16_be()?;
                    Ok(Address::from_domain(host, port)?)
                }
                _ => Err(Error::InvalidAddressType(kind)),
            }
        })();
        if result.is_err() {
            self.position = saved;
        }
        result
    }
}
impl fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reader")
            .field("position", &self.position)
            .field("remaining", &self.remaining())
            .finish()
    }
}

pub struct Writer<'a> {
    buffer: &'a mut BufferLease,
}
impl<'a> Writer<'a> {
    pub fn new(buffer: &'a mut BufferLease) -> Self {
        Self { buffer }
    }
    pub fn bytes(&mut self, value: &[u8]) -> Result<(), Error> {
        self.buffer.append_payload(value).map_err(Into::into)
    }
    pub fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.bytes(&[value])
    }
    pub fn u16_be(&mut self, value: u16) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }
    pub fn u32_be(&mut self, value: u32) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }
    pub fn u64_be(&mut self, value: u64) -> Result<(), Error> {
        self.bytes(&value.to_be_bytes())
    }

    /// Assemble bounded address metadata on the stack, then append once. A
    /// malformed or unrepresentable address cannot partially mutate the buffer.
    pub fn address(&mut self, address: &Address) -> Result<(), Error> {
        let mut encoded = [0u8; 259];
        let mut end;
        if let Some(socket) = address.socket_addr() {
            match socket {
                SocketAddr::V4(v4) => {
                    encoded[0] = 1;
                    encoded[1..5].copy_from_slice(&v4.ip().octets());
                    end = 5;
                }
                SocketAddr::V6(v6) => {
                    if v6.scope_id() != 0 || v6.flowinfo() != 0 {
                        return Err(Error::UnsupportedAddressMetadata);
                    }
                    encoded[0] = 4;
                    encoded[1..17].copy_from_slice(&v6.ip().octets());
                    end = 17;
                }
            }
        } else {
            let host = address
                .domain_name()
                .expect("domain address")
                .as_str()
                .as_bytes();
            let length =
                u8::try_from(host.len()).map_err(|_| Error::Address(AddressError::NameTooLong))?;
            encoded[0] = 3;
            encoded[1] = length;
            encoded[2..2 + host.len()].copy_from_slice(host);
            end = 2 + host.len();
        }
        encoded[end..end + 2].copy_from_slice(&address.port().to_be_bytes());
        end += 2;
        self.bytes(&encoded[..end])
    }

    /// Explicit length framing; not a replacement for protocol-specific codecs.
    /// Size/prefix/capacity checks all precede any visible buffer mutation.
    pub fn frame(
        &mut self,
        prefix: LengthPrefix,
        maximum: usize,
        payload: &[u8],
    ) -> Result<(), Error> {
        let limit = maximum.min(prefix.maximum());
        if payload.len() > limit {
            return Err(Error::LimitExceeded {
                requested: payload.len(),
                limit,
            });
        }
        let total = prefix
            .width()
            .checked_add(payload.len())
            .ok_or(Error::LimitExceeded {
                requested: usize::MAX,
                limit,
            })?;
        let target = self.buffer.append_zeroed(total)?;
        match prefix {
            LengthPrefix::U16 => target[..2].copy_from_slice(&(payload.len() as u16).to_be_bytes()),
            LengthPrefix::U32 => target[..4].copy_from_slice(&(payload.len() as u32).to_be_bytes()),
        }
        target[prefix.width()..].copy_from_slice(payload);
        Ok(())
    }
}
impl fmt::Debug for Writer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writer")
            .field("buffer", &self.buffer)
            .finish()
    }
}
