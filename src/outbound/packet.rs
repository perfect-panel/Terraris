// SPDX-License-Identifier: GPL-3.0-only
use super::{Error, socks_address};
use crate::{
    buffer::{BufferLayout, BufferScope, SharedBuffer},
    network::{Address, DatagramEndpoint, Stream},
    protocol::vless::xudp,
    task::CancellationToken,
    telemetry::Metrics,
    time::OperationContext,
};
use async_trait::async_trait;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, ReadHalf, WriteHalf},
    net::UdpSocket,
    sync::Mutex,
};
#[derive(Clone, Debug)]
pub struct Packet {
    pub source: Address,
    pub payload: SharedBuffer,
}
#[async_trait]
pub trait PacketPort: Send + Sync {
    async fn send(
        &self,
        target: &Address,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), Error>;
    async fn recv(&self, context: &OperationContext) -> Result<Packet, Error>;
    fn abort(&self);
}
pub struct Direct {
    endpoint: DatagramEndpoint,
    cancel: CancellationToken,
}
impl Direct {
    pub async fn bind(
        address: SocketAddr,
        scope: BufferScope,
        metrics: Metrics,
        context: &OperationContext,
    ) -> Result<Self, Error> {
        let endpoint = DatagramEndpoint::bind(address, scope, 65507, metrics, context)
            .await
            .map_err(|_| Error::Io(std::io::ErrorKind::AddrNotAvailable))?;
        Ok(Self {
            endpoint,
            cancel: CancellationToken::new(),
        })
    }
}
#[async_trait]
impl PacketPort for Direct {
    async fn send(
        &self,
        target: &Address,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), Error> {
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Closed),result=self.endpoint.send_to(target.socket_addr().ok_or(Error::Resolve)?,payload,context)=>result.map_err(|_|Error::Io(std::io::ErrorKind::ConnectionAborted))}
    }
    async fn recv(&self, context: &OperationContext) -> Result<Packet, Error> {
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Closed),result=self.endpoint.recv(context)=>{let packet=result.map_err(|_|Error::Io(std::io::ErrorKind::ConnectionAborted))?;Ok(Packet{source:Address::from_socket(packet.source).map_err(|_|Error::Protocol)?,payload:packet.payload})}}
    }
    fn abort(&self) {
        self.cancel.cancel();
    }
}
pub(super) struct SocksPacket {
    socket: UdpSocket,
    control: Mutex<Stream>,
    read_gate: Mutex<()>,
    scope: BufferScope,
    cancel: CancellationToken,
}
impl SocksPacket {
    pub(super) async fn new(
        control: Stream,
        relay: SocketAddr,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Self, Error> {
        if relay.port() == 0 {
            return Err(Error::Protocol);
        }
        let bind = if relay.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = context
            .run(UdpSocket::bind(bind))
            .await
            .map_err(Error::Stopped)??;
        context
            .run(socket.connect(relay))
            .await
            .map_err(Error::Stopped)??;
        Ok(Self {
            socket,
            control: Mutex::new(control),
            read_gate: Mutex::new(()),
            scope,
            cancel: CancellationToken::new(),
        })
    }
}
#[async_trait]
impl PacketPort for SocksPacket {
    async fn send(
        &self,
        target: &Address,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), Error> {
        let mut header = vec![0, 0, 0];
        socks_address(target, &mut header)?;
        if header.len() + payload.len() > 65507 {
            return Err(Error::Capacity);
        }
        let mut data = self
            .scope
            .try_lease(
                BufferLayout::new(0, header.len() + payload.len(), 0)
                    .map_err(|_| Error::Capacity)?,
            )
            .map_err(|_| Error::Capacity)?;
        data.append_payload(&header).map_err(|_| Error::Capacity)?;
        data.append_payload(payload).map_err(|_| Error::Capacity)?;
        let n = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Closed),result=context.run(self.socket.send(data.as_slice()))=>result.map_err(Error::Stopped)??};
        if n != data.len() {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    async fn recv(&self, context: &OperationContext) -> Result<Packet, Error> {
        let _guard = context
            .run(self.read_gate.lock())
            .await
            .map_err(Error::Stopped)?;
        let mut control = context
            .run(self.control.lock())
            .await
            .map_err(Error::Stopped)?;
        let mut data = self
            .scope
            .try_lease(BufferLayout::new(0, 65536, 0).map_err(|_| Error::Capacity)?)
            .map_err(|_| Error::Capacity)?;
        data.append_zeroed(65536).map_err(|_| Error::Capacity)?;
        let mut signal = [0];
        loop {
            let n = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Closed),_=control.read(&mut signal)=>return Err(Error::Closed),result=context.run(self.socket.recv(data.as_mut_slice()))=>result.map_err(Error::Stopped)??};
            if n < 4 || data.as_slice()[..3] != [0, 0, 0] {
                continue;
            }
            let (source, length) = decode_socks(&data.as_slice()[3..n])?;
            let offset = 3 + length;
            if n - offset > 65507 {
                continue;
            }
            data.truncate(n).map_err(|_| Error::Protocol)?;
            data.consume(offset).map_err(|_| Error::Protocol)?;
            return Ok(Packet {
                source,
                payload: data.freeze(),
            });
        }
    }
    fn abort(&self) {
        self.cancel.cancel();
    }
}
pub(super) struct VlessPacket {
    reader: Mutex<xudp::Reader<ReadHalf<Stream>>>,
    writer: Mutex<(WriteHalf<Stream>, bool)>,
    cancel: CancellationToken,
    global: [u8; 8],
}
impl VlessPacket {
    pub(super) fn new(stream: Stream, scope: BufferScope) -> Result<Self, Error> {
        let (read, write) = tokio::io::split(stream);
        let mut global = [0; 8];
        getrandom::fill(&mut global).map_err(|_| Error::Protocol)?;
        Ok(Self {
            reader: Mutex::new(xudp::Reader::new(read, scope, 65507).map_err(|_| Error::Capacity)?),
            writer: Mutex::new((write, false)),
            cancel: CancellationToken::new(),
            global,
        })
    }
}
#[async_trait]
impl PacketPort for VlessPacket {
    async fn send(
        &self,
        target: &Address,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), Error> {
        let mut writer = context
            .run(self.writer.lock())
            .await
            .map_err(Error::Stopped)?;
        let metadata = xudp::Metadata {
            id: 1,
            status: if writer.1 {
                xudp::Status::Keep
            } else {
                xudp::Status::New
            },
            data: true,
            error: false,
            target: Some(target.clone()),
            global_id: if writer.1 { None } else { Some(self.global) },
        };
        // Cancelling a partially written frame poisons the carrier, including
        // when the caller drops this future before it returns an error.
        let mut guard = FrameWrite {
            cancel: self.cancel.clone(),
            complete: false,
        };
        let result = tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Closed),result=context.run(xudp::write(&mut writer.0,&metadata,Some(payload)))=>result.map_err(Error::Stopped).and_then(|v|v.map_err(|_|Error::Protocol))};
        if result.is_err() {
            self.cancel.cancel();
        }
        result?;
        writer.1 = true;
        guard.complete = true;
        Ok(())
    }
    async fn recv(&self, context: &OperationContext) -> Result<Packet, Error> {
        let mut reader = context
            .run(self.reader.lock())
            .await
            .map_err(Error::Stopped)?;
        loop {
            let frame = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Closed),result=context.run(reader.next())=>result.map_err(Error::Stopped)?.map_err(|_|Error::Protocol)?};
            let frame = frame.ok_or(Error::Closed)?;
            if frame.metadata.status == xudp::Status::KeepAlive {
                continue;
            }
            if frame.metadata.id != 1
                || frame.metadata.error
                || frame.metadata.status == xudp::Status::End
            {
                return Err(Error::Closed);
            }
            if let Some(payload) = frame.payload {
                return Ok(Packet {
                    source: frame.metadata.target.ok_or(Error::Protocol)?,
                    payload,
                });
            }
        }
    }
    fn abort(&self) {
        self.cancel.cancel();
    }
}
fn decode_socks(data: &[u8]) -> Result<(Address, usize), Error> {
    let kind = *data.first().ok_or(Error::Protocol)?;
    let (ip, host, offset) = match kind {
        1 => {
            let bytes: [u8; 4] = data
                .get(1..5)
                .ok_or(Error::Protocol)?
                .try_into()
                .map_err(|_| Error::Protocol)?;
            (Some(std::net::IpAddr::V4(bytes.into())), None, 5)
        }
        4 => {
            let bytes: [u8; 16] = data
                .get(1..17)
                .ok_or(Error::Protocol)?
                .try_into()
                .map_err(|_| Error::Protocol)?;
            (Some(std::net::IpAddr::V6(bytes.into())), None, 17)
        }
        3 => {
            let length = *data.get(1).ok_or(Error::Protocol)? as usize;
            let host = std::str::from_utf8(data.get(2..2 + length).ok_or(Error::Protocol)?)
                .map_err(|_| Error::Protocol)?;
            (None, Some(host), 2 + length)
        }
        _ => return Err(Error::Protocol),
    };
    let port = data.get(offset..offset + 2).ok_or(Error::Protocol)?;
    let port = u16::from_be_bytes([port[0], port[1]]);
    let address = if let Some(ip) = ip {
        Address::from_socket(SocketAddr::new(ip, port))
    } else {
        Address::from_domain(host.expect("domain"), port)
    }
    .map_err(|_| Error::Protocol)?;
    Ok((address, offset + 2))
}

struct FrameWrite {
    cancel: CancellationToken,
    complete: bool,
}
impl Drop for FrameWrite {
    fn drop(&mut self) {
        if !self.complete {
            self.cancel.cancel();
        }
    }
}

pub(crate) struct FramedPacket {
    read: Mutex<crate::protocol::packet::Reader<ReadHalf<Stream>>>,
    write: Mutex<WriteHalf<Stream>>,
    codec: crate::protocol::packet::Codec,
    cancel: CancellationToken,
}
impl FramedPacket {
    pub(crate) fn new(
        stream: Stream,
        codec: crate::protocol::packet::Codec,
        scope: BufferScope,
    ) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            read: Mutex::new(crate::protocol::packet::Reader::new(
                read,
                codec.clone(),
                scope,
            )),
            write: Mutex::new(write),
            codec,
            cancel: CancellationToken::new(),
        }
    }
}
#[async_trait]
impl PacketPort for FramedPacket {
    async fn send(
        &self,
        target: &Address,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), Error> {
        let mut write = context
            .run(self.write.lock())
            .await
            .map_err(Error::Stopped)?;
        let mut guard = PacketWriteGuard {
            cancel: self.cancel.clone(),
            complete: false,
        };
        let result = tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Closed),result=context.run(crate::protocol::packet::write(&mut *write,&self.codec,target,payload))=>result.map_err(Error::Stopped).and_then(|result| result.map_err(Error::from))};
        guard.complete = result.is_ok();
        // A partially emitted frame cannot be reused after a cancelled write.
        if result.is_err() {
            self.cancel.cancel();
        }
        result
    }
    async fn recv(&self, context: &OperationContext) -> Result<Packet, Error> {
        let mut read = context
            .run(self.read.lock())
            .await
            .map_err(Error::Stopped)?;
        let result = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Closed),result=context.run(read.next())=>result.map_err(Error::Stopped)?};
        match result {
            Ok(Some(packet)) => Ok(Packet {
                source: packet.address,
                payload: packet.payload,
            }),
            Ok(None) => {
                self.abort();
                Err(Error::Closed)
            }
            Err(error) => {
                self.abort();
                Err(error.into())
            }
        }
    }
    fn abort(&self) {
        self.cancel.cancel();
    }
}
impl Drop for FramedPacket {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

struct PacketWriteGuard {
    cancel: CancellationToken,
    complete: bool,
}
impl Drop for PacketWriteGuard {
    fn drop(&mut self) {
        if !self.complete {
            self.cancel.cancel();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn dropped_partial_uot_write_closes_both_directions() {
        let budget =
            crate::resource::Budget::new(crate::resource::Limits::new(1 << 20, 32).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        let (a, _b) = tokio::io::duplex(1);
        let port = FramedPacket::new(
            Box::new(a),
            crate::protocol::packet::Codec::Uot { connected: None },
            scope,
        );
        let target = Address::from_domain("test.example", 53).unwrap();
        let context = OperationContext::new(CancellationToken::new(), None);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                port.send(&target, b"payload", &context)
            )
            .await
            .is_err()
        );
        assert!(matches!(
            port.send(&target, b"later", &context).await,
            Err(Error::Closed)
        ));
        assert!(matches!(port.recv(&context).await, Err(Error::Closed)));
        drop(port);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    #[tokio::test]
    async fn dropped_partial_xudp_write_poison_carrier() {
        let budget =
            crate::resource::Budget::new(crate::resource::Limits::new(1 << 20, 32).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        let (a, _b) = tokio::io::duplex(1);
        let port = VlessPacket::new(Box::new(a), scope).unwrap();
        let target = Address::from_domain("test.example", 53).unwrap();
        let context = OperationContext::new(CancellationToken::new(), None);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                port.send(&target, b"payload", &context)
            )
            .await
            .is_err()
        );
        assert!(matches!(
            port.send(&target, b"later", &context).await,
            Err(Error::Closed)
        ));
        drop(port);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}
