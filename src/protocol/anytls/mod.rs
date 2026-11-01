// SPDX-License-Identifier: GPL-3.0-only
//! AnyTLS v1/v2 server with bounded logical streams and reusable TLS sessions.
#[path = "io.rs"]
mod mux_io;
pub mod padding;
pub mod wire;
use crate::{
    buffer::{BufferLayout, BufferScope, SharedBuffer},
    network::Stream,
    protocol::{
        flow,
        socksaddr::{Endpoint, Format},
        stream::{self, Authenticated, Engine, Handshake, relay},
        uot,
    },
    runtime,
    time::OperationContext,
    users,
};
use async_trait::async_trait;
use futures_util::{StreamExt, stream::FuturesUnordered};
use mux_io::{MuxStream, State};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
};
use tokio::{io::AsyncReadExt, sync::mpsc};
pub const NAME: &str = "anytls";
pub struct Factory;
impl stream::EngineFactory for Factory {
    fn prepare(
        &self,
        config: &crate::panel::ProtocolConfig,
    ) -> Result<Arc<dyn Engine>, runtime::Error> {
        stream::validate_fields(config, true)?;
        Ok(Arc::new(AnyTls {
            padding: Arc::new(padding::Scheme::parse(&config.padding_scheme)?),
        }))
    }
}
struct AnyTls {
    padding: Arc<padding::Scheme>,
}
#[async_trait]
impl Engine for AnyTls {
    fn credential(&self, password: &str) -> Result<Vec<u8>, users::Error> {
        if password.is_empty() {
            return Err(users::Error::InvalidUser);
        }
        Ok(Sha256::digest(password.as_bytes()).to_vec())
    }
    async fn handshake(
        &self,
        mut stream: Stream,
        scope: &BufferScope,
        _: &OperationContext,
    ) -> io::Result<Handshake> {
        let mut key = vec![0; 32];
        stream.read_exact(&mut key).await?;
        let length = stream.read_u16().await? as usize;
        let mut padding = scope
            .try_lease(BufferLayout::new(0, length, 0).map_err(io::Error::other)?)
            .map_err(io::Error::other)?;
        padding.append_zeroed(length).map_err(io::Error::other)?;
        stream.read_exact(padding.as_mut_slice()).await?;
        Ok(Handshake {
            key,
            connection: Box::new(Connection {
                stream,
                padding: self.padding.clone(),
            }),
        })
    }
}
struct Connection {
    stream: Stream,
    padding: Arc<padding::Scheme>,
}
struct Active {
    sender: mpsc::Sender<SharedBuffer>,
    state: Arc<State>,
}
type Job = Pin<Box<dyn Future<Output = u32> + Send>>;
type Control = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
fn control(
    jobs: &mut FuturesUnordered<Control>,
    writer: &Arc<wire::Writer>,
    command: u8,
    id: u32,
    data: &'static [u8],
) -> Result<(), flow::Error> {
    if jobs.len() >= 64 {
        return Err(flow::Error::Capacity);
    }
    let writer = writer.clone();
    jobs.push(Box::pin(
        async move { writer.bytes(command, id, data).await },
    ));
    Ok(())
}
fn settings(data: &[u8]) -> io::Result<BTreeMap<&str, &str>> {
    if data.len() > 4096 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let text = std::str::from_utf8(data).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').ok_or(io::ErrorKind::InvalidData)?;
        if k.is_empty() || k.len() > 64 || values.len() >= 32 || values.insert(k, v).is_some() {
            return Err(io::ErrorKind::InvalidData.into());
        }
    }
    Ok(values)
}
#[async_trait]
impl Authenticated for Connection {
    async fn serve(self: Box<Self>, context: Arc<stream::Context>) -> Result<(), flow::Error> {
        let Self { stream, padding } = *self;
        let (read, write) = tokio::io::split(stream);
        let writer = wire::Writer::new(
            write,
            context.buffers.clone(),
            context.session.context().cancellation().clone(),
            context.options.handshake_timeout,
        );
        let mut reader = wire::Reader::new(read, context.buffers.clone());
        let operation = context.operation()?;
        let first = loop {
            let frame = operation
                .run(reader.next())
                .await
                .map_err(|_| flow::Error::Stopped)?
                .map_err(|e| flow::Error::Io(e.kind()))?
                .ok_or(flow::Error::Stopped)?;
            if frame.command != wire::WASTE {
                break frame;
            }
        };
        if first.command != wire::SETTINGS || first.id != 0 {
            let _ = writer
                .bytes(wire::ALERT, 0, b"client must send settings before streams")
                .await;
            return Err(flow::Error::InvalidOptions);
        }
        let settings = settings(first.data.as_slice()).map_err(|_| flow::Error::InvalidOptions)?;
        let version = match settings.get("v").copied() {
            Some("1") => 1,
            Some("2") => 2,
            _ => {
                let _ = writer
                    .bytes(wire::ALERT, 0, b"unsupported client version")
                    .await;
                return Err(flow::Error::InvalidOptions);
            }
        };
        if settings.get("padding-md5").copied() != Some(padding.md5.as_str()) {
            writer
                .bytes(wire::PADDING, 0, padding.raw.as_bytes())
                .await
                .map_err(|e| flow::Error::Io(e.kind()))?;
        }
        if version >= 2 {
            writer
                .bytes(wire::SERVER_SETTINGS, 0, b"v=2")
                .await
                .map_err(|e| flow::Error::Io(e.kind()))?;
        }
        drop(first);
        let mut active = BTreeMap::<u32, Active>::new();
        let mut jobs = FuturesUnordered::<Job>::new();
        let mut controls = FuturesUnordered::<Control>::new();
        let mut last_id = 0;
        let mut retirement = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            enum Event {
                Idle,
                Retirement,
                Control(io::Result<()>),
                Finished(u32),
                Frame(io::Result<Option<wire::Frame>>),
            }
            let event = tokio::select! {
                _ = tokio::time::sleep_until(writer.last() + context.options.idle_timeout) => Event::Idle,
                _ = retirement.tick() => Event::Retirement,
                result = controls.next(), if !controls.is_empty() => Event::Control(result.expect("control")),
                done = jobs.next(), if !jobs.is_empty() => Event::Finished(done.expect("stream")),
                frame = reader.next() => Event::Frame(frame),
            };
            match event {
                Event::Idle => {
                    if writer.last().elapsed() >= context.options.idle_timeout {
                        return Ok(());
                    }
                }
                Event::Retirement => {
                    if !context.core.is_current()
                        && active.is_empty()
                        && jobs.is_empty()
                        && controls.is_empty()
                    {
                        return Ok(());
                    }
                }
                Event::Control(result) => result.map_err(|error| flow::Error::Io(error.kind()))?,
                Event::Finished(id) => {
                    if let Some(stream) = active.remove(&id) {
                        stream.state.cancel.cancel();
                        if !stream.state.remote_closed.load(Ordering::Acquire)
                            && !stream.state.fin_sent.swap(true, Ordering::AcqRel)
                        {
                            control(&mut controls, &writer, wire::FIN, id, b"")?;
                        }
                    }
                }
                Event::Frame(frame) => {
                    let Some(frame) = frame.map_err(|error| flow::Error::Io(error.kind()))? else {
                        return Ok(());
                    };
                    writer.touch();
                    match frame.command {
                        wire::WASTE => {}
                        wire::SYN => {
                            if !frame.data.is_empty() || frame.id == 0 || frame.id <= last_id {
                                return Err(flow::Error::InvalidOptions);
                            }
                            last_id = frame.id;
                            let retired = !context.core.is_current();
                            // Include finished-but-unpolled futures in the capacity bound.
                            if retired || jobs.len() >= context.options.max_streams {
                                if controls.len() >= 64 {
                                    return Err(flow::Error::Capacity);
                                }
                                let writer = writer.clone();
                                controls.push(Box::pin(async move {
                                    if version >= 2 {
                                        writer
                                            .bytes(
                                                wire::SYNACK,
                                                frame.id,
                                                if retired {
                                                    b"generation retired"
                                                } else {
                                                    b"stream capacity"
                                                },
                                            )
                                            .await?;
                                    }
                                    writer.bytes(wire::FIN, frame.id, b"").await
                                }));
                                continue;
                            }
                            let (sender, receiver) = mpsc::channel(context.options.queue_packets);
                            let state = State::new();
                            let stream =
                                MuxStream::new(frame.id, writer.clone(), receiver, state.clone());
                            active.insert(
                                frame.id,
                                Active {
                                    sender,
                                    state: state.clone(),
                                },
                            );
                            let context = context.clone();
                            let writer = writer.clone();
                            let id = frame.id;
                            jobs.push(Box::pin(async move {
                                tokio::select! {
                                    biased;
                                    _ = state.cancel.cancelled() => {}
                                    _ = serve_stream(stream, context, writer, version) => {}
                                }
                                id
                            }));
                        }
                        wire::PSH => {
                            if let Some(stream) = active.get(&frame.id)
                                && stream.sender.try_send(frame.data).is_err()
                            {
                                let stream = active.remove(&frame.id).expect("active");
                                stream.state.cancel.cancel();
                                if !stream.state.fin_sent.swap(true, Ordering::AcqRel) {
                                    control(&mut controls, &writer, wire::FIN, frame.id, b"")?;
                                }
                            }
                        }
                        wire::FIN => {
                            if !frame.data.is_empty() {
                                return Err(flow::Error::InvalidOptions);
                            }
                            if let Some(stream) = active.remove(&frame.id) {
                                stream.state.remote_closed.store(true, Ordering::Release);
                                stream.state.cancel.cancel();
                            }
                        }
                        wire::HEART_REQUEST => {
                            if version < 2 || !frame.data.is_empty() {
                                return Err(flow::Error::InvalidOptions);
                            }
                            control(&mut controls, &writer, wire::HEART_RESPONSE, frame.id, b"")?;
                        }
                        wire::HEART_RESPONSE => {
                            if version < 2 || !frame.data.is_empty() {
                                return Err(flow::Error::InvalidOptions);
                            }
                        }
                        _ => return Err(flow::Error::InvalidOptions),
                    }
                }
            }
        }
    }
}
async fn serve_stream(
    mut stream: MuxStream,
    context: Arc<stream::Context>,
    writer: Arc<wire::Writer>,
    version: u8,
) -> Result<(), flow::Error> {
    let id = stream.id;
    let mut acknowledged = false;
    let result = async {
        let session = context.admit().await?;
        let operation = context.operation()?;
        let target = operation
            .run(Endpoint::read(&mut stream, Format::Socks))
            .await
            .map_err(|_| flow::Error::Stopped)?
            .map_err(|e| flow::Error::Io(e.kind()))?
            .target()
            .map_err(|e| flow::Error::Io(e.kind()))?;
        let forwarding = async {
            if let Some(uot) = uot::Version::for_target(&target) {
                let codec = operation
                    .run(uot.read(&mut stream))
                    .await
                    .map_err(|_| flow::Error::Stopped)?
                    .map_err(|e| flow::Error::Io(e.kind()))?;
                if version >= 2 {
                    writer
                        .bytes(wire::SYNACK, id, b"")
                        .await
                        .map_err(|e| flow::Error::Io(e.kind()))?;
                    acknowledged = true;
                }
                relay::udp(
                    Box::new(stream),
                    codec,
                    context.egress.clone(),
                    session.clone(),
                    context.buffers.clone(),
                    relay::UdpOptions {
                        idle: context.options.udp_idle_timeout,
                        operation_timeout: context.options.handshake_timeout,
                        max_ports: context.options.max_udp_ports,
                    },
                )
                .await
            } else {
                let upstream = session
                    .run(
                        context
                            .egress
                            .connect(&target, &operation, context.buffers.clone()),
                    )
                    .await?
                    .map_err(|_| flow::Error::Resolve)?;
                if version >= 2 {
                    writer
                        .bytes(wire::SYNACK, id, b"")
                        .await
                        .map_err(|e| flow::Error::Io(e.kind()))?;
                    acknowledged = true;
                }
                relay::tcp(
                    Box::new(stream),
                    upstream,
                    session.clone(),
                    context.buffers.clone(),
                    context.options.idle_timeout,
                    context.core.metrics().clone(),
                )
                .await
            }
        };
        tokio::select! {result=session.run(forwarding)=>result?,result=session.maintain()=>result}
    }
    .await;
    if result.is_err() && !acknowledged && version >= 2 {
        let _ = writer.bytes(wire::SYNACK, id, b"connection failed").await;
    }
    result
}
