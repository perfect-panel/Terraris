// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    buffer::BufferScope,
    dataplane::{DataPlane, TransferConfig},
    egress::{Handle, PortKey},
    network::{Address, Network, Stream},
    outbound::{Packet, PacketPort},
    protocol::{
        flow::{Error, Metered, Session},
        packet::{self, Codec},
    },
    telemetry::Metrics,
    time::{Deadline, OperationContext},
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

pub async fn tcp(
    client: Stream,
    upstream: Stream,
    session: Arc<Session>,
    scope: BufferScope,
    idle: Duration,
    metrics: Metrics,
) -> Result<(), Error> {
    DataPlane::new(
        scope,
        TransferConfig::new(16384, Some(idle)).map_err(|_| Error::InvalidOptions)?,
        metrics,
    )
    .map_err(|_| Error::InvalidOptions)?
    .relay_tcp(
        Metered::new(client, session.clone(), false),
        Metered::new(upstream, session.clone(), true),
        &session.context(),
    )
    .await
    .map_err(|_| Error::Io(std::io::ErrorKind::ConnectionAborted))?;
    Ok(())
}
type Receive =
    Pin<Box<dyn Future<Output = (PortKey, Result<Packet, crate::outbound::Error>)> + Send>>;
struct Port {
    socket: Arc<dyn PacketPort>,
    allowed: HashSet<Address>,
    remote_domain: bool,
}
impl Drop for Port {
    fn drop(&mut self) {
        self.socket.abort();
    }
}
fn receive(key: PortKey, socket: Arc<dyn PacketPort>, context: OperationContext) -> Receive {
    Box::pin(async move { (key, socket.recv(&context).await) })
}
pub struct UdpOptions {
    pub idle: Duration,
    pub operation_timeout: Duration,
    pub max_ports: usize,
}
pub async fn udp(
    stream: Stream,
    codec: Codec,
    egress: Arc<Handle>,
    session: Arc<Session>,
    scope: BufferScope,
    options: UdpOptions,
) -> Result<(), Error> {
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = packet::Reader::new(read, codec.clone(), scope.clone());
    let mut ports: HashMap<PortKey, Port> = HashMap::new();
    let mut receives = FuturesUnordered::<Receive>::new();
    let mut last = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(last + options.idle) => return Ok(()),
            packet = reader.next() => {
                let Some(packet) = packet.map_err(|e| Error::Io(e.kind()))? else {
                    return Ok(());
                };
                let operation = session.context().child_with_deadline(
                    Deadline::after(options.operation_timeout).map_err(|_| Error::InvalidOptions)?,
                );
                let plan = match session.run(egress.plan(&packet.address, Network::Udp, &operation)).await? {
                    Ok(plan) => plan,
                    Err(crate::egress::Error::Blocked) => continue,
                    Err(_) => return Err(Error::Resolve),
                };
                let key = plan.port_key;
                if !ports.contains_key(&key) {
                    if ports.len() >= options.max_ports {
                        return Err(Error::Capacity);
                    }
                    let socket = session.run(egress.packet(&plan, scope.clone(), &operation))
                        .await?.map_err(|_| Error::Resolve)?;
                    receives.push(receive(key, socket.clone(), session.context()));
                    ports.insert(key, Port { socket, allowed: HashSet::new(), remote_domain: false });
                }
                let port = ports.get_mut(&key).expect("port");
                if !port.allowed.contains(&plan.address) && port.allowed.len() >= 256 {
                    return Err(Error::Capacity);
                }
                port.remote_domain |= plan.address.domain_name().is_some();
                port.allowed.insert(plan.address.clone());
                let n = packet.payload.len();
                let mut quota = session.quota(n).await?;
                let mut counter = session.reserve(true, n)?;
                session.run(port.socket.send(&plan.address, packet.payload.as_slice(), &operation))
                    .await?.map_err(|_| Error::Io(std::io::ErrorKind::ConnectionAborted))?;
                quota.commit(n);
                counter.commit(n as u64);
                last = tokio::time::Instant::now();
            }
            received = receives.next(), if !receives.is_empty() => {
                let (key, packet) = received.expect("receive");
                let packet = packet.map_err(|_| Error::Io(std::io::ErrorKind::ConnectionAborted))?;
                let port = ports.get(&key).expect("port");
                receives.push(receive(key, port.socket.clone(), session.context()));
                if !port.allowed.contains(&packet.source) && !port.remote_domain {
                    continue;
                }
                let reply_address = match &codec {
                    Codec::Uot { connected: Some(address) } => address,
                    _ => &packet.source,
                };
                let n = packet.payload.len();
                let mut quota = session.quota(n).await?;
                let mut counter = session.reserve(false, n)?;
                session.run(packet::write(&mut write, &codec, reply_address, packet.payload.as_slice()))
                    .await?.map_err(|e| Error::Io(e.kind()))?;
                quota.commit(n);
                counter.commit(n as u64);
                last = tokio::time::Instant::now();
            }
        }
    }
}
