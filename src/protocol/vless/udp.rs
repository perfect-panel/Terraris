// SPDX-License-Identifier: GPL-3.0-only

use super::{
    server::{Driver, Stream},
    wire, xudp,
};
use crate::{
    buffer::{BufferScope, QueueItem, QueueLimits, SharedBuffer, bounded_queue},
    network::{Address, Datagram, DatagramEndpoint},
    protocol::flow::{Error, Session},
    time::{Deadline, OperationContext},
    users::Identity,
};
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};
const MAX_PACKET: usize = 65507;
async fn endpoint(
    driver: &Driver,
    target: SocketAddr,
    buffers: BufferScope,
    session: &Session,
) -> Result<DatagramEndpoint, Error> {
    let bind = if target.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    session
        .run(DatagramEndpoint::bind(
            bind,
            buffers,
            MAX_PACKET,
            driver.core.metrics().clone(),
            &session.context(),
        ))
        .await?
        .map_err(|_| Error::Io(std::io::ErrorKind::AddrNotAvailable))
}
async fn target(
    driver: &Driver,
    address: &Address,
    session: &Session,
) -> Result<SocketAddr, Error> {
    let context = session.context().child_with_deadline(
        Deadline::after(driver.options.handshake_timeout).map_err(|_| Error::InvalidOptions)?,
    );
    Ok(session
        .run(driver.egress.resolve(address, &context))
        .await?
        .map_err(|_| Error::Resolve)?[0])
}
async fn send(
    socket: &DatagramEndpoint,
    address: SocketAddr,
    packet: &[u8],
    session: &Arc<Session>,
    context: &OperationContext,
) -> Result<(), Error> {
    let mut quota = session.quota(packet.len()).await?;
    let mut counter = session.reserve(true, packet.len())?;
    session
        .run(socket.send_to(address, packet, context))
        .await?
        .map_err(|_| Error::Io(std::io::ErrorKind::ConnectionAborted))?;
    quota.commit(packet.len());
    counter.commit(packet.len() as u64);
    Ok(())
}
pub(super) async fn standard(
    driver: &Driver,
    mut stream: Stream,
    address: Address,
    session: Arc<Session>,
    buffers: BufferScope,
) -> Result<(), Error> {
    let destination = target(driver, &address, &session).await?;
    let socket = endpoint(driver, destination, buffers.clone(), &session).await?;
    session
        .run(wire::write_response(&mut stream))
        .await?
        .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe))?;
    let (read, mut write) = tokio::io::split(stream);
    let mut reader = wire::PacketReader::new(read, buffers, MAX_PACKET);
    let mut last = tokio::time::Instant::now();
    loop {
        let context = session.context();
        tokio::select! {
            _=tokio::time::sleep_until(last+driver.options.udp_idle_timeout)=>return Ok(()),
            packet=reader.next()=>{let Some(packet)=packet.map_err(|_|Error::Io(std::io::ErrorKind::InvalidData))?else{return Ok(());};send(&socket,destination,packet.as_slice(),&session,&context).await?;last=tokio::time::Instant::now();}
            received=socket.recv(&context)=>{let received=received.map_err(|_|Error::Io(std::io::ErrorKind::ConnectionAborted))?;if received.source!=destination{continue;}let n=received.payload.len();let mut quota=session.quota(n).await?;let mut counter=session.reserve(false,n)?;session.run(async{write.write_all(&(n as u16).to_be_bytes()).await?;write.write_all(received.payload.as_slice()).await?;write.flush().await}).await?.map_err(|e:std::io::Error|Error::Io(e.kind()))?;quota.commit(n);counter.commit(n as u64);last=tokio::time::Instant::now();}
        }
    }
}
struct StreamState {
    sequence: u64,
    session: Arc<Session>,
    context: OperationContext,
    target: Address,
    sockets: BTreeMap<bool, DatagramEndpoint>,
    last: tokio::time::Instant,
}
impl Drop for StreamState {
    fn drop(&mut self) {
        self.context.cancellation().cancel();
    }
}
struct Output {
    metadata: xudp::Metadata,
    payload: Option<SharedBuffer>,
    session: Arc<Session>,
    valid: OperationContext,
}
impl QueueItem for Output {
    fn queue_bytes(&self) -> usize {
        self.payload.as_ref().map_or(0, SharedBuffer::len)
    }
}
type Received = BoxFuture<'static, (u16, u64, Result<Datagram, crate::network::Error>)>;
fn receive(
    id: u16,
    sequence: u64,
    socket: DatagramEndpoint,
    context: OperationContext,
) -> Received {
    async move { (id, sequence, socket.recv(&context).await) }.boxed()
}
pub(super) async fn multiplex(
    driver: &Driver,
    mut stream: Stream,
    identity: &Identity,
    source: IpAddr,
    carrier: Arc<Session>,
    buffers: BufferScope,
) -> Result<(), Error> {
    carrier
        .run(wire::write_response(&mut stream))
        .await?
        .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe))?;
    let (read, write) = tokio::io::split(stream);
    let mut reader =
        xudp::Reader::new(read, buffers.clone(), MAX_PACKET).map_err(|_| Error::InvalidOptions)?;
    let limits = QueueLimits::new(
        driver.options.queue_packets * MAX_PACKET,
        driver.options.queue_packets,
        1,
    )
    .map_err(|_| Error::InvalidOptions)?;
    let (sender, queue) = bounded_queue(limits).map_err(|_| Error::InvalidOptions)?;
    let writer = write_outputs(write, queue, carrier.clone());
    let manager = async {
        let mut streams: BTreeMap<u16, StreamState> = BTreeMap::new();
        let mut reads: FuturesUnordered<Received> = FuturesUnordered::new();
        let mut sequence = 0u64;
        let mut idle = tokio::time::Instant::now();
        loop {
            let context = carrier.context();
            let next_idle = streams
                .values()
                .map(|s| s.last + driver.options.udp_idle_timeout)
                .min()
                .unwrap_or(idle + driver.options.udp_idle_timeout);
            tokio::select! {
                _=tokio::time::sleep_until(next_idle)=>{let now=tokio::time::Instant::now();streams.retain(|_,state|now.duration_since(state.last)<driver.options.udp_idle_timeout);if streams.is_empty()&&now.duration_since(idle)>=driver.options.udp_idle_timeout{return Ok(());}}
                event=reads.next(),if !reads.is_empty()=>{
                    let(id,sequence,result)=event.expect("receive future");let Some(state)=streams.get_mut(&id).filter(|s|s.sequence==sequence)else{continue;};
                    let packet=match result{Ok(packet)=>packet,Err(_)=>{streams.remove(&id);continue;}};state.session.check()?;state.last=tokio::time::Instant::now();idle=state.last;
                    let family=packet.local_addr.is_ipv6();let socket=state.sockets[&family].clone();reads.push(receive(id,sequence,socket,state.context.clone()));
                    let metadata=xudp::Metadata{id,status:xudp::Status::Keep,data:true,error:false,target:Some(Address::from_socket(packet.source).map_err(|_|Error::Resolve)?),global_id:None};
                    // UDP backpressure drops a complete unbilled packet when full.
                    let _=sender.try_send(Output{metadata,payload:Some(packet.payload),session:state.session.clone(),valid:state.context.clone()});
                }
                frame=reader.next()=>{
                    let Some(frame)=frame.map_err(|_|Error::Io(std::io::ErrorKind::InvalidData))?else{return Ok(());};let id=frame.metadata.id;idle=tokio::time::Instant::now();
                    match frame.metadata.status{
                        xudp::Status::KeepAlive=>continue,
                        xudp::Status::End=>{streams.remove(&id);continue;}
                        xudp::Status::New=>{
                            let duplicate=streams.remove(&id).is_some();
                            if duplicate||streams.len()>=driver.options.max_xudp_sessions||reads.len()>=driver.options.max_xudp_sessions*2{
                                sender.try_send(Output{metadata:end(id),payload:None,session:carrier.clone(),valid:carrier.context()}).map_err(|_|Error::Capacity)?;continue;
                            }
                            let session=match carrier.run(driver.policies.admit(&driver.core,identity,source,driver.client.clone())).await?{Ok(session)=>session,Err(_)=>{sender.try_send(Output{metadata:end(id),payload:None,session:carrier.clone(),valid:carrier.context()}).map_err(|_|Error::Capacity)?;continue;}};
                            sequence=sequence.checked_add(1).ok_or(Error::Capacity)?;let context=session.context().child();streams.insert(id,StreamState{sequence,context,session,target:frame.metadata.target.clone().ok_or(Error::Resolve)?,sockets:BTreeMap::new(),last:idle});
                        }
                        xudp::Status::Keep=>{}
                    }
                    if frame.metadata.error{streams.remove(&id);continue;}
                    let Some(state)=streams.get_mut(&id)else{sender.try_send(Output{metadata:end(id),payload:None,session:carrier.clone(),valid:carrier.context()}).map_err(|_|Error::Capacity)?;continue;};
                    let Some(payload)=frame.payload else{continue;};state.session.check()?;let address=frame.metadata.target.as_ref().unwrap_or(&state.target);let destination=target(driver,address,&state.session).await?;let family=destination.is_ipv6();
                    if let std::collections::btree_map::Entry::Vacant(entry)=state.sockets.entry(family){let socket=endpoint(driver,destination,buffers.clone(),&state.session).await?;reads.push(receive(id,state.sequence,socket.clone(),state.context.clone()));entry.insert(socket);}
                    send(&state.sockets[&family],destination,payload.as_slice(),&state.session,&context).await?;state.last=tokio::time::Instant::now();
                }
            }
        }
    };
    tokio::pin!(manager, writer);
    tokio::select! {result=&mut manager=>result,result=&mut writer=>result}
}
fn end(id: u16) -> xudp::Metadata {
    xudp::Metadata {
        id,
        status: xudp::Status::End,
        data: false,
        error: true,
        target: None,
        global_id: None,
    }
}
async fn write_outputs<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut queue: crate::buffer::BufferQueue<Output>,
    carrier: Arc<Session>,
) -> Result<(), Error> {
    while let Some(output) = carrier.run(queue.recv()).await? {
        if output.valid.check().is_err() {
            continue;
        }
        let n = output.payload.as_ref().map_or(0, SharedBuffer::len);
        let mut quota = output.session.quota(n).await?;
        if output.valid.check().is_err() {
            continue;
        }
        let mut count = output.session.reserve(false, n)?;
        carrier
            .run(xudp::write(
                &mut writer,
                &output.metadata,
                output.payload.as_ref().map(SharedBuffer::as_slice),
            ))
            .await?
            .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe))?;
        quota.commit(n);
        count.commit(n as u64);
    }
    Ok(())
}
