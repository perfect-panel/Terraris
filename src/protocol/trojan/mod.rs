// SPDX-License-Identifier: GPL-3.0-only
//! Trojan password authentication and TCP / addressed UDP over TLS.
use crate::{
    buffer::BufferScope,
    network::Stream,
    panel::ProtocolConfig,
    protocol::{
        flow,
        packet::Codec,
        socksaddr::{Endpoint, Format},
        stream::{self, Authenticated, Engine, Handshake, relay},
        uot,
    },
    runtime,
    time::OperationContext,
    users,
};
use async_trait::async_trait;
use sha2::{Digest, Sha224};
use std::{io, sync::Arc};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub const NAME: &str = "trojan";
pub struct Factory;
impl stream::EngineFactory for Factory {
    fn prepare(&self, config: &ProtocolConfig) -> Result<Arc<dyn Engine>, runtime::Error> {
        stream::validate_fields(config, false)?;
        if !config.uot && config.uot_version != 0 {
            return Err(runtime::Error::Unsupported);
        }
        Ok(Arc::new(Trojan { uot: config.uot }))
    }
}
struct Trojan {
    uot: bool,
}
#[async_trait]
impl Engine for Trojan {
    fn credential(&self, password: &str) -> Result<Vec<u8>, users::Error> {
        if password.is_empty() {
            return Err(users::Error::InvalidUser);
        }
        Ok(Sha224::digest(password.as_bytes()).to_vec())
    }
    async fn handshake(
        &self,
        mut stream: Stream,
        _: &BufferScope,
        _: &OperationContext,
    ) -> io::Result<Handshake> {
        let (key, command, endpoint) = read_request(&mut stream).await?;
        let target = if command == 1 {
            Some(endpoint.target()?)
        } else {
            None
        };
        if target
            .as_ref()
            .is_some_and(|target| uot::Version::for_target(target).is_some())
            && !self.uot
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(Handshake {
            key,
            connection: Box::new(TrojanConnection { stream, target }),
        })
    }
}
pub async fn read_request<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
) -> io::Result<(Vec<u8>, u8, Endpoint)> {
    let mut hash = [0; 56];
    reader.read_exact(&mut hash).await?;
    let mut digest = vec![0; 28];
    for (i, pair) in hash.chunks_exact(2).enumerate() {
        fn digit(v: u8) -> io::Result<u8> {
            match v {
                b'0'..=b'9' => Ok(v - b'0'),
                b'a'..=b'f' => Ok(v - b'a' + 10),
                _ => Err(io::ErrorKind::InvalidData.into()),
            }
        }
        digest[i] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    crlf(reader).await?;
    let command = reader.read_u8().await?;
    if !matches!(command, 1 | 3) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let endpoint = Endpoint::read(reader, Format::Socks).await?;
    crlf(reader).await?;
    Ok((digest, command, endpoint))
}
async fn crlf<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<()> {
    let mut bytes = [0; 2];
    reader.read_exact(&mut bytes).await?;
    if bytes != *b"\r\n" {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(())
}
pub async fn write_request<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    password: &str,
    command: u8,
    endpoint: &Endpoint,
) -> io::Result<()> {
    if !matches!(command, 1 | 3) || password.is_empty() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let hash = Sha224::digest(password.as_bytes());
    let mut header = Vec::with_capacity(320);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in hash {
        header.push(HEX[(byte >> 4) as usize]);
        header.push(HEX[(byte & 15) as usize]);
    }
    header.extend(b"\r\n");
    header.push(command);
    header.extend(endpoint.encode(Format::Socks)?);
    header.extend(b"\r\n");
    writer.write_all(&header).await?;
    writer.flush().await
}
struct TrojanConnection {
    stream: Stream,
    target: Option<crate::network::Address>,
}
#[async_trait]
impl Authenticated for TrojanConnection {
    async fn serve(self: Box<Self>, context: Arc<stream::Context>) -> Result<(), flow::Error> {
        let Self { mut stream, target } = *self;
        let operation = context.operation()?;
        let codec = if let Some(target) = target {
            if let Some(version) = uot::Version::for_target(&target) {
                Some(
                    operation
                        .run(version.read(&mut stream))
                        .await
                        .map_err(|_| flow::Error::Stopped)?
                        .map_err(|e| flow::Error::Io(e.kind()))?,
                )
            } else {
                let upstream = context
                    .session
                    .run(
                        context
                            .egress
                            .connect(&target, &operation, context.buffers.clone()),
                    )
                    .await?
                    .map_err(|_| flow::Error::Resolve)?;
                return relay::tcp(
                    stream,
                    upstream,
                    context.session.clone(),
                    context.buffers.clone(),
                    context.options.idle_timeout,
                    context.core.metrics().clone(),
                )
                .await;
            }
        } else {
            Some(Codec::Trojan)
        };
        relay::udp(
            stream,
            codec.expect("UDP codec"),
            context.egress.clone(),
            context.session.clone(),
            context.buffers.clone(),
            relay::UdpOptions {
                idle: context.options.udp_idle_timeout,
                operation_timeout: context.options.handshake_timeout,
                max_ports: context.options.max_udp_ports,
            },
        )
        .await
    }
}
