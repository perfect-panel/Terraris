// SPDX-License-Identifier: GPL-3.0-only
use super::{Builder, Error, Factory, Inbound, Incoming, Listener, Outbound, Tcp, TcpWithTls};
use crate::{buffer::BufferScope, network::Stream, panel, time::OperationContext};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    WebSocket,
    HttpUpgrade,
    Grpc,
}
pub struct Web {
    kind: Kind,
    certificates: crate::certificate::Settings,
}
impl Web {
    pub fn new(kind: Kind, certificates: crate::certificate::Settings) -> Self {
        Self { kind, certificates }
    }
}
pub(super) fn register(
    builder: &mut Builder,
    certificates: crate::certificate::Settings,
) -> Result<(), Error> {
    for (name, aliases, kind) in [
        ("ws", &["websocket"][..], Kind::WebSocket),
        ("httpupgrade", &["http-upgrade"][..], Kind::HttpUpgrade),
        ("grpc", &[][..], Kind::Grpc),
    ] {
        builder
            .register(
                name,
                aliases,
                Arc::new(Web::new(kind, certificates.clone())),
            )
            .map_err(|_| Error::Configuration("web transport registration"))?;
    }
    Ok(())
}
#[derive(Clone)]
pub(super) struct Options {
    pub kind: Kind,
    pub host: String,
    pub path: String,
    pub service: String,
    pub early_data: usize,
}
impl Options {
    fn new(kind: Kind, host: &str, path: &str, service: &str) -> Result<Self, Error> {
        if host.len() > 255 || (!host.is_empty() && authority(host).is_err()) {
            return Err(Error::Configuration("HTTP host"));
        }
        if kind == Kind::Grpc {
            if !path.is_empty()
                || service.len() > 128
                || !service
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            {
                return Err(Error::Configuration("gRPC service name or path"));
            }
        } else if !service.is_empty() {
            return Err(Error::Unsupported);
        }
        let mut path = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };
        if path.len() > 2048
            || path.contains('#')
            || path.starts_with("//")
            || path.bytes().any(|b| b <= 32 || b >= 127)
        {
            return Err(Error::Configuration("HTTP path"));
        }
        let _: http::uri::PathAndQuery = path
            .parse()
            .map_err(|_| Error::Configuration("HTTP path"))?;
        let mut early_data = 0;
        if let Some((base, query)) = path.split_once('?') {
            let mut remaining = Vec::new();
            let mut seen = false;
            for item in query.split('&') {
                let decoded = url::form_urlencoded::parse(item.as_bytes()).collect::<Vec<_>>();
                if decoded.first().is_some_and(|(key, _)| key == "ed") {
                    if seen || kind != Kind::WebSocket {
                        return Err(Error::Configuration("WebSocket early data option"));
                    }
                    seen = true;
                    early_data = decoded[0]
                        .1
                        .parse::<usize>()
                        .map_err(|_| Error::Configuration("WebSocket early data size"))?;
                    if early_data > 3072 {
                        return Err(Error::Configuration("WebSocket early data size"));
                    }
                } else {
                    remaining.push(item);
                }
            }
            if seen {
                path = if remaining.is_empty() {
                    base.to_owned()
                } else {
                    format!("{base}?{}", remaining.join("&"))
                };
            }
        }
        Ok(Self {
            kind,
            host: host.to_owned(),
            path,
            service: service.to_owned(),
            early_data,
        })
    }
    pub fn matches(&self, host: &str, path: &str) -> bool {
        let Ok(got) = authority(host) else {
            return false;
        };
        let host_matches = if self.host.is_empty() {
            true
        } else {
            let expected = authority(&self.host).expect("validated host");
            expected.host().eq_ignore_ascii_case(got.host())
                && expected
                    .port_u16()
                    .is_none_or(|port| Some(port) == got.port_u16())
        };
        host_matches && path.split('?').next() == self.path.split('?').next()
    }
    pub fn grpc_path(&self, multi: bool) -> String {
        format!(
            "/{}/{}",
            self.service,
            if multi { "TunMulti" } else { "Tun" }
        )
    }
}
fn authority(host: &str) -> Result<http::uri::Authority, Error> {
    if host.is_empty()
        || host
            .bytes()
            .any(|b| b <= 32 || b >= 127 || matches!(b, b'@' | b',' | b'\\'))
    {
        return Err(Error::Configuration("HTTP authority"));
    }
    host.parse()
        .map_err(|_| Error::Configuration("HTTP authority"))
}
fn alpn(kind: Kind, security: &str, values: &mut Vec<String>) -> Result<(), Error> {
    if security == "tls" {
        let required = if kind == Kind::Grpc { "h2" } else { "http/1.1" };
        if values.iter().any(|value| value != required) {
            return Err(Error::Configuration("transport ALPN"));
        }
        *values = vec![required.to_owned()];
    }
    Ok(())
}
impl Factory for Web {
    fn inbound(&self, config: &panel::ProtocolConfig) -> Result<Arc<dyn Inbound>, Error> {
        let options = Options::new(self.kind, &config.host, &config.path, &config.service_name)?;
        let mut base = config.clone();
        base.host.clear();
        base.path.clear();
        base.service_name.clear();
        alpn(self.kind, &base.security, &mut base.alpn)?;
        let inner = TcpWithTls(self.certificates.clone()).inbound(&base)?;
        Ok(Arc::new(Server { inner, options }))
    }
    fn outbound(
        &self,
        config: &panel::Outbound,
        roots: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<dyn Outbound>, Error> {
        let mut options =
            Options::new(self.kind, &config.host, &config.path, &config.service_name)?;
        if options.host.is_empty() {
            options.host = if !config.sni.is_empty() {
                config.sni.clone()
            } else {
                let host = config.address.trim_matches(['[', ']']);
                if host.contains(':') {
                    format!("[{host}]:{}", config.port)
                } else {
                    format!("{host}:{}", config.port)
                }
            };
            authority(&options.host)?;
        }
        let mut base = config.clone();
        base.host.clear();
        base.path.clear();
        base.service_name.clear();
        alpn(self.kind, &base.security, &mut base.alpn)?;
        let inner = Tcp.outbound(&base, roots)?;
        let pool = if self.kind == Kind::Grpc {
            Some(super::h2_pool::Pool::new(inner.clone())?)
        } else {
            None
        };
        Ok(Arc::new(Client {
            inner,
            options,
            secure: config.security == "tls",
            pool,
        }))
    }
}
struct Server {
    inner: Arc<dyn Inbound>,
    options: Options,
}
#[async_trait]
impl Inbound for Server {
    fn binding_key(&self) -> &str {
        self.inner.binding_key()
    }
    fn is_encrypted(&self) -> bool {
        self.inner.is_encrypted()
    }
    fn certificate(&self) -> Option<panel::CertificateFingerprint> {
        self.inner.certificate()
    }
    fn reload_required(&self) -> Result<bool, Error> {
        self.inner.reload_required()
    }
    async fn bind(
        &self,
        address: SocketAddr,
        context: &OperationContext,
    ) -> Result<Box<dyn Listener>, Error> {
        self.inner.bind(address, context).await
    }
    async fn open(
        &self,
        stream: Stream,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Incoming, Error> {
        let stream = self.inner.handshake(stream, scope, context).await?;
        context
            .run(async {
                match self.options.kind {
                    Kind::Grpc => super::grpc::server(stream, scope.clone(), &self.options)
                        .await
                        .map(Incoming::Multiplexed),
                    _ => super::http1::server(stream, scope.clone(), &self.options)
                        .await
                        .map(Incoming::Single),
                }
            })
            .await
            .map_err(Error::Stopped)?
    }
    async fn handshake(
        &self,
        stream: Stream,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error> {
        match self.open(stream, scope, context).await? {
            Incoming::Single(stream) => Ok(stream),
            Incoming::Multiplexed(_) => Err(Error::Unsupported),
        }
    }
}
struct Client {
    inner: Arc<dyn Outbound>,
    options: Options,
    secure: bool,
    pool: Option<Arc<super::h2_pool::Pool>>,
}
#[async_trait]
impl Outbound for Client {
    fn abort(&self) {
        if let Some(pool) = &self.pool {
            pool.abort();
        }
    }
    fn idle(&self) -> bool {
        self.pool.as_ref().is_none_or(|pool| pool.idle())
    }
    async fn close(&self, _context: &OperationContext) -> Result<(), Error> {
        if let Some(pool) = &self.pool {
            pool.close().await;
        }
        Ok(())
    }
    async fn connect(
        &self,
        addresses: &[SocketAddr],
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<(Stream, SocketAddr), Error> {
        if let Some(pool) = &self.pool {
            return super::grpc::client(
                pool,
                addresses,
                scope.clone(),
                &self.options,
                self.secure,
                context,
            )
            .await;
        }
        let (stream, peer) = self.inner.connect(addresses, scope, context).await?;
        if self.options.early_data > 0 {
            return Ok((
                super::ws_early::deferred(
                    stream,
                    scope.clone(),
                    self.options.clone(),
                    context.clone(),
                )?,
                peer,
            ));
        }
        let stream = context
            .run(super::http1::client(stream, scope.clone(), &self.options))
            .await
            .map_err(Error::Stopped)??;
        Ok((stream, peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn early_data_is_bounded_and_removed_without_reencoding_other_query_values() {
        let value = Options::new(
            Kind::WebSocket,
            "localhost",
            "/relay?x=a%2Fb&ed=2048&y=a+b",
            "",
        )
        .unwrap();
        assert_eq!(value.early_data, 2048);
        assert_eq!(value.path, "/relay?x=a%2Fb&y=a+b");
        for path in [
            "/relay?ed=3073",
            "/relay?ed=-1",
            "/relay?ed=x",
            "/relay?ed=1&ed=2",
        ] {
            assert!(Options::new(Kind::WebSocket, "localhost", path, "").is_err());
        }
        assert!(Options::new(Kind::HttpUpgrade, "localhost", "/relay?ed=1", "").is_err());
    }
}
