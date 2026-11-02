// SPDX-License-Identifier: GPL-3.0-only
use super::{Client, Datagrams, Method, packet::MAX_WIRE, replay::Protection};
use crate::{
    buffer::{BufferLayout, BufferScope},
    dns::system::System,
    network::{Address, Network, Stream},
    outbound::{self, Error, Packet, PacketPort, registry},
    panel,
    protocol::{socksaddr::Endpoint, uot},
    task::CancellationToken,
    time::OperationContext,
};
use async_trait::async_trait;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::{net::UdpSocket, sync::Mutex as AsyncMutex};
pub(crate) struct Factory {
    protection: Arc<Protection>,
}
impl Default for Factory {
    fn default() -> Self {
        Self {
            protection: Protection::new(),
        }
    }
}
impl registry::Factory for Factory {
    fn kind(&self) -> registry::Kind {
        registry::Kind::Proxy
    }
    fn compile(
        &self,
        c: &panel::Outbound,
        context: &registry::Context,
    ) -> Result<Option<Arc<dyn registry::Connector>>, Error> {
        if c.address.is_empty()
            || c.port == 0
            || c.address.len() > 253
            || !c.user.is_empty()
            || !c.uuid.expose().is_empty()
            || !c.plugin.is_empty()
            || c.plugin_options != panel::ConfigValue::Null
            || !c.flow.is_empty()
            || !c.multiplex.is_empty()
            || !c.congestion_controller.is_empty()
            || c.udp_stream
            || c.reduce_rtt
            || c.heartbeat != 0
            || !c.settings.is_empty()
            || !c.extensions.is_empty()
            || !matches!(c.encryption.as_str(), "" | "none")
            || !c.encryption_mode.is_empty()
            || !c.encryption_rtt.is_empty()
            || !c.encryption_ticket.expose().is_empty()
            || !c.encryption_client_padding.is_empty()
            || !c.encryption_password.expose().is_empty()
        {
            return Err(Error::Unsupported);
        }
        let method =
            Method::parse(&c.cipher).map_err(|_| Error::Configuration("Shadowsocks cipher"))?;
        let keys = method
            .password(c.password.expose())
            .map_err(|_| Error::Configuration("Shadowsocks key"))?;
        let host = c.address.trim_matches(['[', ']']).to_owned();
        if host.parse::<IpAddr>().is_err() {
            Address::from_domain(&host, c.port)
                .map_err(|_| Error::Configuration("Shadowsocks hostname"))?;
        }
        let uot = if c.uot {
            Some(uot::Version::from_config(c.uot_version).map_err(|_| Error::Unsupported)?)
        } else {
            if c.uot_version != 0 {
                return Err(Error::Unsupported);
            }
            None
        };
        let mut base = c.clone();
        base.cipher.clear();
        let transport = context.transports.outbound(&base, context.tls.clone())?;
        Ok(Some(Arc::new(Connector {
            host,
            port: c.port,
            codec: Client {
                method,
                keys,
                protection: self.protection.clone(),
            },
            transport,
            system: context.system.clone(),
            uot,
            native_udp: matches!(
                c.transport.trim().to_ascii_lowercase().as_str(),
                "" | "tcp" | "raw"
            ),
            cancel: CancellationToken::new(),
        })))
    }
}
struct Connector {
    host: String,
    port: u16,
    codec: Client,
    transport: Arc<dyn crate::transport::Outbound>,
    system: Arc<System>,
    uot: Option<uot::Version>,
    native_udp: bool,
    cancel: CancellationToken,
}
impl Connector {
    async fn addresses(&self, context: &OperationContext) -> Result<Vec<SocketAddr>, Error> {
        if self.cancel.is_cancelled() {
            return Err(Error::Closed);
        }
        Ok(self
            .system
            .lookup(&self.host, context)
            .await
            .map_err(|_| Error::Resolve)?
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .collect())
    }
    async fn dial(
        &self,
        target: &Endpoint,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error> {
        let addresses = self.addresses(context).await?;
        let (raw, _) = self.transport.connect(&addresses, scope, context).await?;
        tokio::select! {biased;_=self.cancel.cancelled()=>Err(Error::Closed),result=context.run(self.codec.connect(raw,target,scope,context))=>result.map_err(Error::Stopped)?.map_err(|_|Error::Protocol)}
    }
}
#[async_trait]
impl registry::Connector for Connector {
    fn abort(&self) {
        self.cancel.cancel();
        self.transport.abort();
    }
    fn idle(&self) -> bool {
        self.transport.idle()
    }
    async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        self.abort();
        self.transport.close(context).await.map_err(Error::from)
    }
    fn supports(&self, network: Network) -> bool {
        network == Network::Tcp || self.uot.is_some() || self.native_udp
    }
    async fn connect(
        &self,
        target: &Address,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error> {
        self.dial(
            &Endpoint::from_address(target).map_err(|_| Error::Protocol)?,
            scope,
            context,
        )
        .await
    }
    async fn packet(
        &self,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Arc<dyn PacketPort>, Error> {
        if let Some(version) = self.uot {
            let mut stream = self.dial(&version.endpoint(), &scope, context).await?;
            let codec = context
                .run(version.write(&mut stream, None))
                .await
                .map_err(Error::Stopped)??;
            return Ok(Arc::new(outbound::FramedPacket::new(stream, codec, scope)));
        }
        if !self.native_udp {
            return Err(Error::Unsupported);
        }
        let addresses = self.addresses(context).await?;
        let address = *addresses.first().ok_or(Error::Resolve)?;
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = context
            .run(UdpSocket::bind(bind))
            .await
            .map_err(Error::Stopped)??;
        context
            .run(socket.connect(address))
            .await
            .map_err(Error::Stopped)??;
        Ok(Arc::new(DatagramPort {
            socket,
            state: Mutex::new(
                self.codec
                    .datagrams()
                    .map_err(|_| Error::Configuration("UDP session"))?,
            ),
            read: AsyncMutex::new(()),
            write: AsyncMutex::new(()),
            scope,
            cancel: self.cancel.child_token(),
        }))
    }
}
struct DatagramPort {
    socket: UdpSocket,
    state: Mutex<Datagrams>,
    read: AsyncMutex<()>,
    write: AsyncMutex<()>,
    scope: BufferScope,
    cancel: CancellationToken,
}
#[async_trait]
impl PacketPort for DatagramPort {
    async fn send(
        &self,
        target: &Address,
        payload: &[u8],
        context: &OperationContext,
    ) -> Result<(), Error> {
        let _guard = context
            .run(self.write.lock())
            .await
            .map_err(Error::Stopped)?;
        let data = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .encode(
                &Endpoint::from_address(target).map_err(|_| Error::Protocol)?,
                payload,
                &self.scope,
            )
            .map_err(|_| Error::Protocol)?;
        let n = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Closed),result=context.run(self.socket.send(data.as_slice()))=>result.map_err(Error::Stopped)??};
        if n != data.len() {
            return Err(Error::Protocol);
        }
        Ok(())
    }
    async fn recv(&self, context: &OperationContext) -> Result<Packet, Error> {
        let _guard = context
            .run(self.read.lock())
            .await
            .map_err(Error::Stopped)?;
        let mut wire = self
            .scope
            .try_lease(BufferLayout::new(0, MAX_WIRE + 1, 0).map_err(|_| Error::Capacity)?)
            .map_err(|_| Error::Capacity)?;
        wire.append_zeroed(MAX_WIRE + 1)
            .map_err(|_| Error::Capacity)?;
        loop {
            let n = tokio::select! {biased;_=self.cancel.cancelled()=>return Err(Error::Closed),result=context.run(self.socket.recv(wire.as_mut_slice()))=>result.map_err(Error::Stopped)??};
            if n > MAX_WIRE {
                continue;
            }
            let decoded = self
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .decode(&wire.as_slice()[..n], &self.scope);
            if let Ok((source, payload)) = decoded {
                return Ok(Packet {
                    source: source.address().map_err(|_| Error::Protocol)?,
                    payload: payload.freeze(),
                });
            }
        }
    }
    fn abort(&self) {
        self.cancel.cancel();
    }
}
