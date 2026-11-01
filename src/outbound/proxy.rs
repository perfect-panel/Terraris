// SPDX-License-Identifier: GPL-3.0-only
use super::{
    Error,
    packet::{PacketPort, SocksPacket, VlessPacket},
    socks_address,
};
use crate::{
    buffer::BufferScope,
    dns::system::System,
    network::{Address, Stream},
    panel::{Outbound, Secret},
    protocol::vless::{encryption, wire},
    time::OperationContext,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Socks5,
    Http,
    Vless,
}
pub struct Proxy {
    pub(crate) kind: Kind,
    pub(crate) host: String,
    pub(crate) port: u16,
    user: String,
    password: Secret,
    uuid: Option<[u8; 16]>,
    pub(super) transport: Arc<dyn crate::transport::Outbound>,
    encryption: Option<Arc<encryption::Client>>,
    pub(crate) uot: Option<crate::protocol::uot::Version>,
    system: Arc<System>,
}
impl Proxy {
    pub(crate) fn compile_kind(
        kind: Kind,
        config: &Outbound,
        context: &super::registry::Context,
    ) -> Result<Self, Error> {
        validate_extra(config)?;
        let uot = if config.uot {
            Some(
                crate::protocol::uot::Version::from_config(config.uot_version)
                    .map_err(|_| Error::Unsupported)?,
            )
        } else {
            if config.uot_version != 0 {
                return Err(Error::Unsupported);
            }
            None
        };
        if config.address.is_empty() || config.address.len() > 253 || config.port == 0 {
            return Err(Error::Configuration("proxy endpoint"));
        }
        let host = config.address.trim_matches(['[', ']']).to_owned();
        if host.parse::<IpAddr>().is_err() {
            Address::from_domain(&host, config.port)
                .map_err(|_| Error::Configuration("proxy hostname"))?;
        }
        let mut transport_config = config.clone();
        if kind == Kind::Http
            && config.security == "tls"
            && matches!(config.transport.as_str(), "" | "tcp" | "raw")
        {
            if config.alpn.iter().any(|value| value != "http/1.1") {
                return Err(Error::Unsupported);
            }
            transport_config.alpn = vec!["http/1.1".into()];
        }
        let transport = context
            .transports
            .outbound(&transport_config, context.tls.clone())?;
        let (uuid, encryption) = if kind == Kind::Vless {
            if !config.user.is_empty() || !config.password.expose().is_empty() {
                return Err(Error::Unsupported);
            }
            let uuid = uuid::Uuid::parse_str(config.uuid.expose())
                .map_err(|_| Error::Configuration("VLESS UUID"))?;
            let encryption = encryption::ClientConfig::from_panel(config)
                .map_err(|_| Error::Configuration("VLESS encryption"))?
                .map(|config| Arc::new(encryption::Client::new(config)));
            (Some(*uuid.as_bytes()), encryption)
        } else {
            if !config.uuid.expose().is_empty()
                || !config.encryption.is_empty() && config.encryption != "none"
                || !config.encryption_mode.is_empty()
                || !config.encryption_rtt.is_empty()
                || !config.encryption_password.expose().is_empty()
                || !config.encryption_ticket.expose().is_empty()
                || !config.encryption_client_padding.is_empty()
            {
                return Err(Error::Unsupported);
            }
            if config.user.len() > 255
                || config.password.expose().len() > 255
                || config.user.contains(':')
            {
                return Err(Error::Configuration("proxy credentials"));
            }
            (None, None)
        };
        Ok(Self {
            kind,
            host,
            port: config.port,
            user: config.user.clone(),
            password: config.password.clone(),
            uuid,
            transport,
            encryption,
            uot,
            system: context.system.clone(),
        })
    }
    async fn transport(
        &self,
        context: &OperationContext,
        scope: &BufferScope,
    ) -> Result<(Stream, SocketAddr), Error> {
        let ips = self
            .system
            .lookup(&self.host, context)
            .await
            .map_err(|_| Error::Resolve)?;
        let addresses = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, self.port))
            .collect::<Vec<_>>();
        let (stream, peer) = self.transport.connect(&addresses, scope, context).await?;
        let stream: Stream = if let Some(encryption) = &self.encryption {
            Box::new(
                Box::pin(encryption.handshake(stream, scope, context))
                    .await
                    .map_err(|_| Error::Protocol)?,
            )
        } else {
            stream
        };
        Ok((stream, peer))
    }
    pub async fn connect(
        &self,
        target: &Address,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error> {
        let (mut stream, _peer) = self.transport(context, scope).await?;
        match self.kind {
            Kind::Socks5 => {
                self.socks_auth(&mut stream, context).await?;
                let mut request = vec![5, 1, 0];
                socks_address(target, &mut request)?;
                context
                    .run(stream.write_all(&request))
                    .await
                    .map_err(Error::Stopped)??;
                context
                    .run(stream.flush())
                    .await
                    .map_err(Error::Stopped)??;
                self.socks_reply(&mut stream, context).await?;
                Ok(stream)
            }
            Kind::Http => {
                let authority = target.to_string();
                let auth = if self.user.is_empty() && self.password.expose().is_empty() {
                    String::new()
                } else {
                    format!(
                        "Proxy-Authorization: Basic {}\r\n",
                        STANDARD.encode(format!("{}:{}", self.user, self.password.expose()))
                    )
                };
                let request = zeroize::Zeroizing::new(format!(
                    "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth}\r\n"
                ));
                context
                    .run(stream.write_all(request.as_bytes()))
                    .await
                    .map_err(Error::Stopped)??;
                context
                    .run(stream.flush())
                    .await
                    .map_err(Error::Stopped)??;
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    if header.len() >= 16384 {
                        return Err(Error::Protocol);
                    }
                    header.push(
                        context
                            .run(stream.read_u8())
                            .await
                            .map_err(Error::Stopped)??,
                    );
                }
                let status = std::str::from_utf8(
                    header
                        .split(|b| *b == b'\n')
                        .next()
                        .ok_or(Error::Protocol)?,
                )
                .map_err(|_| Error::Protocol)?;
                let mut words = status.split_ascii_whitespace();
                if !matches!(words.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
                    return Err(Error::Protocol);
                }
                let code = words
                    .next()
                    .ok_or(Error::Protocol)?
                    .parse::<u16>()
                    .map_err(|_| Error::Protocol)?;
                if !(200..300).contains(&code) {
                    return Err(Error::Authentication);
                }
                Ok(stream)
            }
            Kind::Vless => {
                let request = wire::Request {
                    uuid: self.uuid.expect("compiled UUID"),
                    command: wire::Command::Tcp,
                    target: Some(target.clone()),
                };
                context
                    .run(request.write(&mut stream))
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| Error::Protocol)?;
                context
                    .run(stream.flush())
                    .await
                    .map_err(Error::Stopped)??;
                Ok(Box::new(ResponseStream::new(stream)))
            }
        }
    }
    pub async fn packet(
        &self,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Arc<dyn PacketPort>, Error> {
        if let Some(version) = self.uot {
            let mut stream = self
                .connect(
                    &Address::from_domain(version.domain(), 1).map_err(|_| Error::Protocol)?,
                    &scope,
                    context,
                )
                .await?;
            let codec = context
                .run(version.write(&mut stream, None))
                .await
                .map_err(Error::Stopped)??;
            return Ok(Arc::new(super::packet::FramedPacket::new(
                stream, codec, scope,
            )));
        }
        match self.kind {
            Kind::Http => Err(Error::Unsupported),
            Kind::Socks5 => {
                let (mut stream, peer) = self.transport(context, &scope).await?;
                self.socks_auth(&mut stream, context).await?;
                context
                    .run(stream.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]))
                    .await
                    .map_err(Error::Stopped)??;
                context
                    .run(stream.flush())
                    .await
                    .map_err(Error::Stopped)??;
                let relay = self.socks_reply(&mut stream, context).await?;
                let relay = match relay {
                    SocksReply::Ip(mut address) => {
                        if address.ip().is_unspecified() {
                            address.set_ip(peer.ip());
                        }
                        address
                    }
                    SocksReply::Domain(host, port) => SocketAddr::new(
                        self.system
                            .lookup(&host, context)
                            .await
                            .map_err(|_| Error::Resolve)?
                            .into_iter()
                            .next()
                            .ok_or(Error::Resolve)?,
                        port,
                    ),
                };
                Ok(Arc::new(
                    SocksPacket::new(stream, relay, scope, context).await?,
                ))
            }
            Kind::Vless => {
                let (mut stream, _peer) = self.transport(context, &scope).await?;
                context
                    .run(
                        wire::Request {
                            uuid: self.uuid.expect("UUID"),
                            command: wire::Command::Xudp,
                            target: None,
                        }
                        .write(&mut stream),
                    )
                    .await
                    .map_err(Error::Stopped)?
                    .map_err(|_| Error::Protocol)?;
                context
                    .run(stream.flush())
                    .await
                    .map_err(Error::Stopped)??;
                Ok(Arc::new(VlessPacket::new(
                    Box::new(ResponseStream::new(stream)),
                    scope,
                )?))
            }
        }
    }
    async fn socks_auth(
        &self,
        stream: &mut Stream,
        context: &OperationContext,
    ) -> Result<(), Error> {
        let auth = !(self.user.is_empty() && self.password.expose().is_empty());
        let method = if auth { 2 } else { 0 };
        context
            .run(stream.write_all(&[5, 1, method]))
            .await
            .map_err(Error::Stopped)??;
        context
            .run(stream.flush())
            .await
            .map_err(Error::Stopped)??;
        let mut reply = [0; 2];
        context
            .run(stream.read_exact(&mut reply))
            .await
            .map_err(Error::Stopped)??;
        if reply != [5, method] {
            return Err(Error::Authentication);
        }
        if auth {
            let mut request = zeroize::Zeroizing::new(vec![1, self.user.len() as u8]);
            request.extend(self.user.as_bytes());
            request.push(self.password.expose().len() as u8);
            request.extend(self.password.expose().as_bytes());
            context
                .run(stream.write_all(&request))
                .await
                .map_err(Error::Stopped)??;
            context
                .run(stream.flush())
                .await
                .map_err(Error::Stopped)??;
            context
                .run(stream.read_exact(&mut reply))
                .await
                .map_err(Error::Stopped)??;
            if reply != [1, 0] {
                return Err(Error::Authentication);
            }
        }
        Ok(())
    }
    async fn socks_reply(
        &self,
        stream: &mut Stream,
        context: &OperationContext,
    ) -> Result<SocksReply, Error> {
        let mut header = [0; 4];
        context
            .run(stream.read_exact(&mut header))
            .await
            .map_err(Error::Stopped)??;
        if header[..3] != [5, 0, 0] {
            return Err(Error::Protocol);
        }
        let reply = match header[3] {
            1 => {
                let mut ip = [0; 4];
                context
                    .run(stream.read_exact(&mut ip))
                    .await
                    .map_err(Error::Stopped)??;
                SocksReply::Ip(SocketAddr::new(IpAddr::V4(ip.into()), 0))
            }
            4 => {
                let mut ip = [0; 16];
                context
                    .run(stream.read_exact(&mut ip))
                    .await
                    .map_err(Error::Stopped)??;
                SocksReply::Ip(SocketAddr::new(IpAddr::V6(ip.into()), 0))
            }
            3 => {
                let length = context
                    .run(stream.read_u8())
                    .await
                    .map_err(Error::Stopped)?? as usize;
                let mut host = vec![0; length];
                context
                    .run(stream.read_exact(&mut host))
                    .await
                    .map_err(Error::Stopped)??;
                SocksReply::Domain(String::from_utf8(host).map_err(|_| Error::Protocol)?, 0)
            }
            _ => return Err(Error::Protocol),
        };
        let port = context
            .run(stream.read_u16())
            .await
            .map_err(Error::Stopped)??;
        Ok(match reply {
            SocksReply::Ip(mut address) => {
                address.set_port(port);
                SocksReply::Ip(address)
            }
            SocksReply::Domain(name, _) => SocksReply::Domain(name, port),
        })
    }
}
enum SocksReply {
    Ip(SocketAddr),
    Domain(String, u16),
}
struct ResponseStream<S> {
    io: S,
    header: [u8; 2],
    have: usize,
    addons: [u8; 255],
    skipped: usize,
    ready: bool,
}
impl<S> ResponseStream<S> {
    fn new(io: S) -> Self {
        Self {
            io,
            header: [0; 2],
            have: 0,
            addons: [0; 255],
            skipped: 0,
            ready: false,
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for ResponseStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if read.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if !this.ready {
            while this.have < 2 {
                let mut buf = ReadBuf::new(&mut this.header[this.have..]);
                match Pin::new(&mut this.io).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        this.have += n;
                    }
                }
            }
            if this.header[0] != 0 {
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            while this.skipped < this.header[1] as usize {
                let mut buf = ReadBuf::new(&mut this.addons[this.skipped..this.header[1] as usize]);
                match Pin::new(&mut this.io).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = buf.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                        this.skipped += n;
                    }
                }
            }
            this.ready = true;
        }
        Pin::new(&mut this.io).poll_read(cx, read)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
fn validate_extra(config: &Outbound) -> Result<(), Error> {
    if !config.cipher.is_empty()
        || !config.plugin.is_empty()
        || config.plugin_options != crate::panel::ConfigValue::Null
        || !config.flow.is_empty()
        || !config.multiplex.is_empty()
        || !config.congestion_controller.is_empty()
        || config.udp_stream
        || config.reduce_rtt
        || config.heartbeat != 0
        || !config.settings.is_empty()
        || !config.extensions.is_empty()
    {
        return Err(Error::Unsupported);
    }
    Ok(())
}
