// SPDX-License-Identifier: GPL-3.0-only
//! Extensible stream transports. Preparation is synchronous and side-effect free;
//! bind/connect and connection handshakes run with the caller's cancellation budget.
mod grpc;
mod h2_pool;
mod http1;
mod jobs;
mod tls;
mod web;
mod websocket;
mod ws_early;
mod xhttp;
use crate::{
    buffer::BufferScope, network::Stream, panel, registry::Catalog, time::OperationContext,
};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
pub use web::{Kind as WebKind, Web};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Configuration(&'static str),
    Io(std::io::ErrorKind),
    Tls,
    Stopped(crate::time::StopReason),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

pub enum Accepted {
    Stream(Stream),
    Quic(Box<quinn::Incoming>),
}
#[async_trait]
pub trait Listener: Send + Sync {
    async fn close(&self) {}
    async fn accept_carrier(
        &self,
        context: &OperationContext,
    ) -> Result<(Accepted, SocketAddr), Error> {
        let (stream, peer) = self.accept(context).await?;
        Ok((Accepted::Stream(stream), peer))
    }

    fn local_addr(&self) -> Result<SocketAddr, Error>;
    /// Return the raw accepted stream promptly. Expensive per-connection work
    /// belongs in Inbound::handshake, under the protocol's admission limits.
    async fn accept(&self, context: &OperationContext) -> Result<(Stream, SocketAddr), Error>;
}
#[async_trait]
pub trait Inbound: Send + Sync {
    async fn open_carrier(
        &self,
        carrier: Accepted,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Incoming, Error> {
        match carrier {
            Accepted::Stream(stream) => self.open(stream, scope, context).await,
            Accepted::Quic(_) => Err(Error::Unsupported),
        }
    }

    fn abort(&self) {}
    async fn close(&self, _context: &OperationContext) -> Result<(), Error> {
        self.abort();
        Ok(())
    }

    /// Opens a physical carrier. Multiplexing transports yield independently
    /// authenticated byte streams, and remain driven by their owning task.
    async fn open(
        &self,
        stream: Stream,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Incoming, Error> {
        self.handshake(stream, scope, context)
            .await
            .map(Incoming::Single)
    }

    fn reload_required(&self) -> Result<bool, Error> {
        Ok(false)
    }
    /// The provider must validate and enforce transport security before returning
    /// true. VLESS can then omit its own encryption without allow_plaintext.
    fn is_encrypted(&self) -> bool {
        false
    }
    fn certificate(&self) -> Option<panel::CertificateFingerprint> {
        None
    }
    /// Equal keys promise interchangeable physical listeners across generations.
    /// Include every bind-time option; exclude per-connection handshake settings.
    fn binding_key(&self) -> &str;
    async fn bind(
        &self,
        address: SocketAddr,
        context: &OperationContext,
    ) -> Result<Box<dyn Listener>, Error>;
    async fn handshake(
        &self,
        stream: Stream,
        _scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error> {
        context.check().map_err(Error::Stopped)?;
        Ok(stream)
    }
}
/// Maximum concurrent logical streams owned by one multiplexed carrier.
pub const MAX_MULTIPLEX_STREAMS: usize = 32;
/// The caller must keep polling a multiplexed carrier while its streams run.
pub enum Incoming {
    Single(Stream),
    Multiplexed(Box<dyn Multiplexed>),
}
pub trait Multiplexed: Send + Unpin {
    /// Cancel and join transport-owned helpers after all logical flows are dropped.
    fn close(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }

    fn busy(&self) -> bool {
        false
    }
    fn last_activity(&self) -> Option<tokio::time::Instant> {
        None
    }

    fn poll_accept(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<Stream>, Error>>;
    /// Stop new streams while allowing accepted streams to finish.
    fn drain(&mut self);
}
#[async_trait]
pub trait Outbound: Send + Sync {
    fn abort(&self) {}
    fn idle(&self) -> bool {
        true
    }
    async fn close(&self, _context: &OperationContext) -> Result<(), Error> {
        self.abort();
        Ok(())
    }
    /// Addresses have already been resolved under the owning egress policy.
    async fn connect(
        &self,
        addresses: &[SocketAddr],
        _scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<(Stream, SocketAddr), Error>;
}
pub trait Factory: Send + Sync {
    fn inbound(&self, config: &panel::ProtocolConfig) -> Result<Arc<dyn Inbound>, Error>;
    fn outbound(
        &self,
        config: &panel::Outbound,
        roots: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<dyn Outbound>, Error>;
}
#[derive(Default)]
pub struct Builder {
    providers: Catalog<dyn Factory>,
}
impl Builder {
    pub fn register(
        &mut self,
        name: &str,
        aliases: &[&str],
        provider: Arc<dyn Factory>,
    ) -> Result<&mut Self, crate::registry::Error> {
        self.providers.register(name, aliases, provider)?;
        Ok(self)
    }
    pub fn build(self) -> Registry {
        Registry {
            providers: self.providers,
        }
    }
}
pub struct Registry {
    providers: Catalog<dyn Factory>,
}
impl Default for Registry {
    fn default() -> Self {
        Self::builtin()
    }
}
impl Registry {
    pub fn builder() -> Builder {
        Builder::default()
    }
    pub fn builtin_builder() -> Builder {
        let mut builder = Builder::default();
        builder
            .register("tcp", &["raw"], Arc::new(Tcp))
            .expect("builtin transport");
        web::register(&mut builder, crate::certificate::Settings::default())
            .expect("builtin web transports");
        builder
            .register(
                "xhttp",
                &["splithttp"],
                Arc::new(xhttp::Xhttp::new(crate::certificate::Settings::default())),
            )
            .expect("builtin XHTTP");
        builder
    }
    pub fn builtin() -> Self {
        Self::builtin_builder().build()
    }
    pub fn with_tls(settings: crate::certificate::Settings) -> Result<Self, Error> {
        settings.validate()?;
        let mut builder = Self::builder();
        builder
            .register("tcp", &["raw"], Arc::new(TcpWithTls(settings.clone())))
            .map_err(|_| Error::Configuration("TCP registration"))?;
        web::register(&mut builder, settings.clone())?;
        builder
            .register(
                "xhttp",
                &["splithttp"],
                Arc::new(xhttp::Xhttp::new(settings)),
            )
            .map_err(|_| Error::Configuration("XHTTP registration"))?;
        Ok(builder.build())
    }
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.providers.entries().map(|(name, _)| name)
    }
    fn get(&self, name: &str) -> Result<(&str, &Arc<dyn Factory>), Error> {
        self.providers
            .get(if name.is_empty() { "tcp" } else { name })
            .ok_or(Error::Unsupported)
    }
    pub fn inbound(&self, config: &panel::ProtocolConfig) -> Result<Arc<dyn Inbound>, Error> {
        // PPanel may carry the stream selection in either network or transport.
        let selected = if config.transport.is_empty() {
            &config.network
        } else {
            &config.transport
        };
        let (name, factory) = self.get(selected)?;
        if !config.network.is_empty()
            && !config.transport.is_empty()
            && self.get(&config.network)?.0 != name
        {
            return Err(Error::Configuration("conflicting transport selections"));
        }
        factory.inbound(config)
    }
    pub fn outbound(
        &self,
        config: &panel::Outbound,
        roots: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<dyn Outbound>, Error> {
        self.get(&config.transport)?.1.outbound(config, roots)
    }
}

/// TCP/raw server; TCP/raw with optional TLS client. TLS server certificates
/// and other stream transports require separate providers.
pub struct Tcp;
impl Factory for Tcp {
    fn inbound(&self, config: &panel::ProtocolConfig) -> Result<Arc<dyn Inbound>, Error> {
        if !matches!(config.security.as_str(), "" | "none")
            || !matches!(config.cert_mode.as_str(), "" | "none")
            || !config.sni.is_empty()
            || !config.alpn.is_empty()
            || config.allow_insecure
            || !config.fingerprint.is_empty()
            || !config.host.is_empty()
            || !config.path.is_empty()
            || !config.service_name.is_empty()
            || config.accept_proxy_protocol
            || !config.xhttp_mode.is_empty()
            || !config.xhttp_extra.is_empty()
            || !config.reality_server_addr.is_empty()
            || config.reality_server_port != 0
            || !config.reality_private_key.expose().is_empty()
            || !config.reality_public_key.is_empty()
            || !config.reality_short_id.is_empty()
            || config.disable_sni
            || config.ech_enable
            || !config.ech_server_name.is_empty()
            || !config.cert_dns_provider.is_empty()
            || !config.cert_dns_env.expose().is_empty()
        {
            return Err(Error::Unsupported);
        }
        Ok(Arc::new(Tcp))
    }
    fn outbound(
        &self,
        config: &panel::Outbound,
        roots: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<dyn Outbound>, Error> {
        if !config.fingerprint.is_empty()
            || !config.host.is_empty()
            || !config.path.is_empty()
            || !config.service_name.is_empty()
            || !config.xhttp_mode.is_empty()
            || !config.xhttp_extra.is_empty()
            || !config.reality_public_key.is_empty()
            || !config.reality_short_id.is_empty()
            || !config.spider_x.is_empty()
            || !config.stream_settings.is_empty()
        {
            return Err(Error::Unsupported);
        }
        let tls = tls::configure(config, roots)?;
        let name = if config.sni.is_empty() {
            config.address.trim_matches(['[', ']']).to_owned()
        } else {
            config.sni.clone()
        };
        let server_name = if tls.is_some() {
            Some(
                rustls::pki_types::ServerName::try_from(name)
                    .map_err(|_| Error::Configuration("TLS server name"))?,
            )
        } else {
            None
        };
        Ok(Arc::new(TcpClient { tls, server_name }))
    }
}
#[async_trait]
impl Inbound for Tcp {
    fn binding_key(&self) -> &str {
        "tcp"
    }
    async fn bind(
        &self,
        address: SocketAddr,
        context: &OperationContext,
    ) -> Result<Box<dyn Listener>, Error> {
        let listener = context
            .run(tokio::net::TcpListener::bind(address))
            .await
            .map_err(Error::Stopped)??;
        Ok(Box::new(listener))
    }
}
#[async_trait]
impl Listener for tokio::net::TcpListener {
    fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.local_addr()?)
    }
    async fn accept(&self, context: &OperationContext) -> Result<(Stream, SocketAddr), Error> {
        let (stream, peer) = context.run(self.accept()).await.map_err(Error::Stopped)??;
        Ok((Box::new(stream), crate::network::canonical_socket(peer)))
    }
}
struct TcpClient {
    tls: Option<Arc<rustls::ClientConfig>>,
    server_name: Option<rustls::pki_types::ServerName<'static>>,
}
#[async_trait]
impl Outbound for TcpClient {
    async fn connect(
        &self,
        addresses: &[SocketAddr],
        _scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<(Stream, SocketAddr), Error> {
        context.check().map_err(Error::Stopped)?;
        let mut last = Error::Io(std::io::ErrorKind::ConnectionRefused);
        for address in addresses {
            if address.port() == 0 {
                return Err(Error::Configuration("zero port"));
            }
            let socket = match context
                .run(tokio::net::TcpStream::connect(address))
                .await
                .map_err(Error::Stopped)?
            {
                Ok(socket) => socket,
                Err(error) => {
                    last = error.into();
                    continue;
                }
            };
            let peer = crate::network::canonical_socket(socket.peer_addr()?);
            let stream: Stream = if let Some(tls) = &self.tls {
                Box::new(
                    context
                        .run(tokio_rustls::TlsConnector::from(tls.clone()).connect(
                            self.server_name.clone().expect("validated TLS name"),
                            socket,
                        ))
                        .await
                        .map_err(Error::Stopped)?
                        .map_err(|_| Error::Tls)?,
                )
            } else {
                Box::new(socket)
            };
            return Ok((stream, peer));
        }
        Err(last)
    }
}

struct TcpWithTls(crate::certificate::Settings);
impl Factory for TcpWithTls {
    fn inbound(&self, config: &panel::ProtocolConfig) -> Result<Arc<dyn Inbound>, Error> {
        if config.security != "tls" {
            return Tcp.inbound(config);
        }
        if !matches!(config.cert_mode.as_str(), "" | "file" | "self")
            || config.allow_insecure
            || config.disable_sni
            || !config.cert_dns_provider.is_empty()
            || !config.cert_dns_env.expose().is_empty()
        {
            return Err(Error::Unsupported);
        }
        let mut plain = config.clone();
        plain.security.clear();
        plain.cert_mode.clear();
        plain.sni.clear();
        plain.alpn.clear();
        Tcp.inbound(&plain)?; // Reject all other unsupported transport fields.
        Ok(Arc::new(TlsInbound(self.0.prepare(config)?)))
    }
    fn outbound(
        &self,
        config: &panel::Outbound,
        roots: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<dyn Outbound>, Error> {
        Tcp.outbound(config, roots)
    }
}
struct TlsInbound(crate::certificate::Identity);
#[async_trait]
impl Inbound for TlsInbound {
    fn binding_key(&self) -> &str {
        "tcp"
    }
    fn is_encrypted(&self) -> bool {
        true
    }
    fn certificate(&self) -> Option<panel::CertificateFingerprint> {
        Some(self.0.fingerprint.clone())
    }
    fn reload_required(&self) -> Result<bool, Error> {
        self.0.reload_required()
    }
    async fn bind(
        &self,
        address: SocketAddr,
        context: &OperationContext,
    ) -> Result<Box<dyn Listener>, Error> {
        Tcp.bind(address, context).await
    }
    async fn handshake(
        &self,
        stream: Stream,
        _: &BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error> {
        let stream = context
            .run(tokio_rustls::TlsAcceptor::from(self.0.config.clone()).accept(stream))
            .await
            .map_err(Error::Stopped)?
            .map_err(|_| Error::Tls)?;
        Ok(Box::new(stream))
    }
}
