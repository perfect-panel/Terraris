// SPDX-License-Identifier: GPL-3.0-only

use super::{
    server::{Driver, Stream},
    wire, xudp,
};
use crate::{
    buffer::{BufferScope, QueueLimits, bounded_queue},
    network::Address,
    protocol::flow::{Error, Session},
    time::{Deadline, OperationContext},
    users::Identity,
};
use std::{collections::BTreeMap, net::IpAddr, sync::Arc};
use tokio::io::{AsyncWrite, AsyncWriteExt};
const MAX_PACKET: usize = 65507;
async fn target(
    driver: &Driver,
    address: &Address,
    session: &Session,
) -> Result<crate::egress::Plan, Error> {
    let context = session.context().child_with_deadline(
        Deadline::after(driver.options.handshake_timeout).map_err(|_| Error::InvalidOptions)?,
    );
    session
        .run(
            driver
                .egress
                .plan(address, crate::network::Network::Udp, &context),
        )
        .await?
        .map_err(|error| {
            if error == crate::egress::Error::Blocked {
                Error::Blocked
            } else {
                Error::Resolve
            }
        })
}
async fn send(
    socket: &dyn crate::outbound::PacketPort,
    address: &Address,
    packet: &[u8],
    session: &Arc<Session>,
    context: &OperationContext,
) -> Result<(), Error> {
    let mut quota = session.quota(packet.len()).await?;
    let mut counter = session.reserve(true, packet.len())?;
    session
        .run(socket.send(address, packet, context))
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
    let socket = driver
        .egress
        .packet(&destination, buffers.clone(), &session.context())
        .await
        .map_err(|_| Error::Resolve)?;
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
            packet=reader.next()=>{let Some(packet)=packet.map_err(|_|Error::Io(std::io::ErrorKind::InvalidData))?else{return Ok(());};send(socket.as_ref(),&destination.address,packet.as_slice(),&session,&context).await?;last=tokio::time::Instant::now();}
            received=socket.recv(&context)=>{let received=received.map_err(|_|Error::Io(std::io::ErrorKind::ConnectionAborted))?;if destination.address.socket_addr().is_some()&&received.source!=destination.address{continue;}let n=received.payload.len();let mut quota=session.quota(n).await?;let mut counter=session.reserve(false,n)?;session.run(async{write.write_all(&(n as u16).to_be_bytes()).await?;write.write_all(received.payload.as_slice()).await?;write.flush().await}).await?.map_err(|e:std::io::Error|Error::Io(e.kind()))?;quota.commit(n);counter.commit(n as u64);last=tokio::time::Instant::now();}
        }
    }
}
struct StreamState {
    lease: super::associations::Lease,
}
pub(super) async fn multiplex(
    driver: &Driver,
    mut stream: Stream,
    identity: &Identity,
    source: IpAddr,
    carrier: Arc<Session>,
    buffers: BufferScope,
) -> Result<(), Error> {
    use super::associations::{Carrier, Output};
    carrier
        .run(wire::write_response(&mut stream))
        .await?
        .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe))?;
    let (read, write) = tokio::io::split(stream);
    let mut reader =
        xudp::Reader::new(read, buffers, MAX_PACKET).map_err(|_| Error::InvalidOptions)?;
    let limits = QueueLimits::new(
        driver.options.queue_packets * MAX_PACKET,
        driver.options.queue_packets,
        1,
    )
    .map_err(|_| Error::InvalidOptions)?;
    let (sender, queue) = bounded_queue(limits).map_err(|_| Error::InvalidOptions)?;
    let routes = Carrier::new();
    let writer = write_outputs(write, queue, carrier.clone());
    let manager = async {
        let mut streams: BTreeMap<u16, StreamState> = BTreeMap::new();
        let mut serial = 0u64;
        loop {
            tokio::task::yield_now().await;
            streams.retain(|_, stream| stream.lease.valid());
            let idle = routes.last() + driver.options.udp_idle_timeout;
            let frame = tokio::select! {
                _=tokio::time::sleep_until(idle)=>{if routes.last().elapsed()>=driver.options.udp_idle_timeout{return Ok(());}continue;}
                frame=reader.next()=>frame.map_err(|_|Error::Io(std::io::ErrorKind::InvalidData))?
            };
            let Some(frame) = frame else {
                return Ok(());
            };
            let id = frame.metadata.id;
            routes.touch();
            match frame.metadata.status {
                xudp::Status::KeepAlive => continue,
                xudp::Status::End => {
                    streams.remove(&id);
                    continue;
                }
                xudp::Status::New => {
                    let duplicate = streams.remove(&id).is_some();
                    serial = serial.checked_add(1).ok_or(Error::Capacity)?;
                    if duplicate || streams.len() >= driver.options.max_xudp_sessions {
                        sender
                            .try_send(Output::End {
                                id,
                                serial,
                                carrier: routes.clone(),
                                error: true,
                            })
                            .map_err(|_| Error::Capacity)?;
                        continue;
                    }
                    let session = match carrier
                        .run(driver.policies.admit(
                            &driver.core,
                            identity,
                            source,
                            driver.client.clone(),
                        ))
                        .await?
                    {
                        Ok(session) => session,
                        Err(_) => {
                            sender
                                .try_send(Output::End {
                                    id,
                                    serial,
                                    carrier: routes.clone(),
                                    error: true,
                                })
                                .map_err(|_| Error::Capacity)?;
                            continue;
                        }
                    };
                    let target = frame.metadata.target.clone().ok_or(Error::Resolve)?;
                    routes.install(id, serial);
                    match driver.associations.attach(
                        &driver.core,
                        identity,
                        driver.egress.migration_scope(),
                        frame.metadata.global_id,
                        id,
                        serial,
                        target,
                        session,
                        sender.clone(),
                        routes.clone(),
                    ) {
                        Ok(lease) => {
                            streams.insert(id, StreamState { lease });
                        }
                        Err(_) => {
                            routes.remove(id, serial);
                            sender
                                .try_send(Output::End {
                                    id,
                                    serial,
                                    carrier: routes.clone(),
                                    error: true,
                                })
                                .map_err(|_| Error::Capacity)?;
                            continue;
                        }
                    }
                }
                xudp::Status::Keep => {}
            }
            if frame.metadata.error {
                streams.remove(&id);
                continue;
            }
            let Some(state) = streams.get(&id) else {
                sender
                    .try_send(Output::End {
                        id,
                        serial,
                        carrier: routes.clone(),
                        error: true,
                    })
                    .map_err(|_| Error::Capacity)?;
                continue;
            };
            let Some(payload) = frame.payload else {
                continue;
            };
            let address = frame
                .metadata
                .target
                .as_ref()
                .unwrap_or(&state.lease.target);
            let operation = async {
                let destination = target(driver, address, &state.lease.binding.session).await?;
                state
                    .lease
                    .send(&destination, &driver.egress, payload.as_slice())
                    .await
            };
            let result = state.lease.binding.context.run(operation).await;
            if matches!(result, Ok(Err(Error::Blocked))) {
                continue;
            }
            if !matches!(result, Ok(Ok(()))) {
                streams.remove(&id);
                sender
                    .try_send(Output::End {
                        id,
                        serial,
                        carrier: routes.clone(),
                        error: true,
                    })
                    .map_err(|_| Error::Capacity)?;
            }
        }
    };
    tokio::pin!(manager, writer);
    tokio::select! {result=&mut manager=>result,result=&mut writer=>result}
}
async fn write_outputs<W: AsyncWrite + Unpin>(
    mut writer: W,
    mut queue: crate::buffer::BufferQueue<super::associations::Output>,
    carrier: Arc<Session>,
) -> Result<(), Error> {
    use super::associations::Output;
    while let Some(output) = carrier.run(queue.recv()).await? {
        match output {
            Output::End {
                id,
                serial,
                carrier: routes,
                error,
            } => {
                if !routes.matches(id, serial) {
                    continue;
                }
                let metadata = xudp::Metadata {
                    id,
                    status: xudp::Status::End,
                    data: false,
                    error,
                    target: None,
                    global_id: None,
                };
                carrier
                    .run(xudp::write(&mut writer, &metadata, None))
                    .await?
                    .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe))?;
            }
            Output::Data {
                packet,
                binding,
                entry,
            } => {
                if binding.context.check().is_err() {
                    if let Some(entry) = entry.upgrade() {
                        entry.deliver(packet);
                    }
                    continue;
                }
                let mut started = false;
                let n = packet.payload.len();
                let result = binding
                    .context
                    .run(async {
                        let mut quota = binding.session.quota(n).await?;
                        let mut counter = binding.session.reserve(false, n)?;
                        let metadata = xudp::Metadata {
                            id: binding.id,
                            status: xudp::Status::Keep,
                            data: true,
                            error: false,
                            target: Some(packet.source.clone()),
                            global_id: None,
                        };
                        started = true;
                        carrier
                            .run(xudp::write_progress(
                                &mut writer,
                                &metadata,
                                Some(packet.payload.as_slice()),
                                |written| quota.commit(written),
                            ))
                            .await?
                            .map_err(|_| Error::Io(std::io::ErrorKind::BrokenPipe))?;
                        counter.commit(n as u64);
                        Ok(())
                    })
                    .await;
                match result {
                    Ok(Ok(())) => {
                        carrier
                            .run(writer.flush())
                            .await?
                            .map_err(|e| Error::Io(e.kind()))?;
                    }
                    Err(_) => {
                        if let Some(entry) = entry.upgrade() {
                            entry.deliver(packet);
                        }
                        if started {
                            return Err(Error::Stopped);
                        }
                    }
                    Ok(Err(error)) => return Err(error),
                }
            }
        }
    }
    Ok(())
}
