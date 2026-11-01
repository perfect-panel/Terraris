// SPDX-License-Identifier: MPL-2.0
// Xray mux/XUDP wire layout; see THIRD_PARTY.md.

use super::wire::{Error, decode_address, encode_address};
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope, SharedBuffer},
    network::Address,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    New,
    Keep,
    End,
    KeepAlive,
}
#[derive(Clone, Debug)]
pub struct Metadata {
    pub id: u16,
    pub status: Status,
    pub data: bool,
    pub error: bool,
    pub target: Option<Address>,
    pub global_id: Option<[u8; 8]>,
}
pub struct Frame {
    pub metadata: Metadata,
    pub payload: Option<SharedBuffer>,
}
/// All partial input is kept here, so selecting another future while `next`
/// waits cannot lose a frame prefix or an allocated packet.
pub struct Reader<R> {
    io: R,
    buffers: BufferScope,
    prefix: [u8; 2],
    prefix_have: usize,
    metadata: [u8; 512],
    metadata_length: Option<usize>,
    metadata_have: usize,
    decoded: Option<Metadata>,
    data_prefix: [u8; 2],
    data_prefix_have: usize,
    body: Option<BufferLease>,
    body_have: usize,
    max_packet: usize,
    failed: bool,
}
impl<R: AsyncRead + Unpin> Reader<R> {
    pub fn new(io: R, buffers: BufferScope, max_packet: usize) -> Result<Self, Error> {
        if max_packet > 65535 || max_packet > buffers.max_allocation() {
            return Err(Error::TooLarge);
        }
        Ok(Self {
            io,
            buffers,
            prefix: [0; 2],
            prefix_have: 0,
            metadata: [0; 512],
            metadata_length: None,
            metadata_have: 0,
            decoded: None,
            data_prefix: [0; 2],
            data_prefix_have: 0,
            body: None,
            body_have: 0,
            max_packet,
            failed: false,
        })
    }
    pub async fn next(&mut self) -> Result<Option<Frame>, Error> {
        if self.failed {
            return Err(Error::Frame);
        }
        let result = self.read_frame().await;
        if result.is_err() {
            self.failed = true;
            self.body.take();
        }
        result
    }
    async fn read_frame(&mut self) -> Result<Option<Frame>, Error> {
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
        let length = *self
            .metadata_length
            .get_or_insert(u16::from_be_bytes(self.prefix) as usize);
        if !(4..=512).contains(&length) {
            return Err(Error::Frame);
        }
        while self.metadata_have < length {
            let n = self
                .io
                .read(&mut self.metadata[self.metadata_have..length])
                .await?;
            if n == 0 {
                return Err(Error::Frame);
            }
            self.metadata_have += n;
        }
        if self.decoded.is_none() {
            self.decoded = Some(decode_metadata(&self.metadata[..length])?);
        }
        if self.decoded.as_ref().expect("metadata").data {
            while self.data_prefix_have < 2 {
                let n = self
                    .io
                    .read(&mut self.data_prefix[self.data_prefix_have..])
                    .await?;
                if n == 0 {
                    return Err(Error::Frame);
                }
                self.data_prefix_have += n;
            }
            let length = u16::from_be_bytes(self.data_prefix) as usize;
            if length > self.max_packet {
                return Err(Error::TooLarge);
            }
            if self.body.is_none() {
                let mut body = self
                    .buffers
                    .try_lease(BufferLayout::new(0, length, 0).map_err(|_| Error::Resource)?)
                    .map_err(|_| Error::Resource)?;
                body.append_zeroed(length).map_err(|_| Error::Resource)?;
                self.body = Some(body);
            }
            while self.body_have < length {
                let n = self
                    .io
                    .read(&mut self.body.as_mut().expect("packet").as_mut_slice()[self.body_have..])
                    .await?;
                if n == 0 {
                    return Err(Error::Frame);
                }
                self.body_have += n;
            }
        }
        let frame = Frame {
            metadata: self.decoded.take().expect("metadata"),
            payload: self.body.take().map(BufferLease::freeze),
        };
        self.prefix_have = 0;
        self.metadata_length = None;
        self.metadata_have = 0;
        self.data_prefix_have = 0;
        self.body_have = 0;
        Ok(Some(frame))
    }
}
fn decode_metadata(bytes: &[u8]) -> Result<Metadata, Error> {
    if bytes.len() < 4 || bytes[3] & !3 != 0 {
        return Err(Error::Frame);
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let status = match bytes[2] {
        1 => Status::New,
        2 => Status::Keep,
        3 => Status::End,
        4 => Status::KeepAlive,
        _ => return Err(Error::Frame),
    };
    let data = bytes[3] & 1 != 0;
    let error = bytes[3] & 2 != 0;
    let mut offset = 4;
    let mut target = None;
    let mut global_id = None;
    if status == Status::New || status == Status::Keep && bytes.len() > 4 {
        if bytes.get(4) != Some(&2) {
            return Err(Error::Command);
        }
        let (address, n) = decode_address(&bytes[5..])?;
        target = Some(address);
        offset = 5 + n;
        if status == Status::New && data && bytes.len() == offset + 8 {
            global_id = Some(bytes[offset..].try_into().map_err(|_| Error::Frame)?);
            offset += 8;
        }
    }
    if offset != bytes.len() || status == Status::KeepAlive && (data || error) {
        return Err(Error::Frame);
    }
    Ok(Metadata {
        id,
        status,
        data,
        error,
        target,
        global_id,
    })
}
pub async fn write<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    metadata: &Metadata,
    payload: Option<&[u8]>,
) -> Result<(), Error> {
    if metadata.status == Status::KeepAlive
        && (metadata.data
            || metadata.error
            || metadata.target.is_some()
            || metadata.global_id.is_some())
    {
        return Err(Error::Frame);
    }
    if metadata.data != payload.is_some() || payload.is_some_and(|p| p.len() > 65535) {
        return Err(Error::Frame);
    }
    let mut bytes = [0; 512 + 4];
    bytes[2..4].copy_from_slice(&metadata.id.to_be_bytes());
    bytes[4] = match metadata.status {
        Status::New => 1,
        Status::Keep => 2,
        Status::End => 3,
        Status::KeepAlive => 4,
    };
    bytes[5] = u8::from(metadata.data) | (u8::from(metadata.error) * 2);
    let mut end = 6;
    if let Some(target) = &metadata.target {
        if !matches!(metadata.status, Status::New | Status::Keep) {
            return Err(Error::Frame);
        }
        bytes[end] = 2;
        end += 1;
        end += encode_address(target, &mut bytes[end..])?;
    } else if metadata.status == Status::New {
        return Err(Error::Frame);
    }
    if let Some(id) = metadata.global_id {
        if metadata.status != Status::New || !metadata.data {
            return Err(Error::Frame);
        }
        bytes[end..end + 8].copy_from_slice(&id);
        end += 8;
    }
    bytes[..2].copy_from_slice(&((end - 2) as u16).to_be_bytes());
    if let Some(payload) = payload {
        bytes[end..end + 2].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        end += 2;
        writer.write_all(&bytes[..end]).await?;
        writer.write_all(payload).await?;
    } else {
        writer.write_all(&bytes[..end]).await?;
    }
    writer.flush().await?;
    Ok(())
}
