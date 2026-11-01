// SPDX-License-Identifier: MPL-2.0
// XHTTP/SplitHTTP Rust port of Polaris 56d52fb44958, derived from Xray b17a88f9b46d.
mod body;
mod client;
mod config;
mod h3;
mod pool;
mod queue;
mod server;
mod wire;
use super::{Error, Factory, Inbound, Incoming, Listener, Outbound, TcpWithTls};
use crate::{buffer::BufferScope, network::Stream, panel, time::OperationContext};
use async_trait::async_trait;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};
pub struct Xhttp {
    certificates: crate::certificate::Settings,
    shared: Mutex<BTreeMap<String, Weak<server::Shared>>>,
}
impl Xhttp {
    pub fn new(certificates: crate::certificate::Settings) -> Self {
        Self {
            certificates,
            shared: Mutex::new(BTreeMap::new()),
        }
    }
}
impl Factory for Xhttp {
    fn inbound(&self, c: &panel::ProtocolConfig) -> Result<Arc<dyn Inbound>, Error> {
        let options = config::Config::parse(&c.host, &c.path, &c.xhttp_mode, &c.xhttp_extra)?;
        if options.download.is_some() {
            return Err(Error::Configuration(
                "XHTTP downloadSettings is client-only",
            ));
        }
        let mut base = c.clone();
        base.host.clear();
        base.path.clear();
        base.xhttp_mode.clear();
        base.xhttp_extra.clear();
        if base.security == "tls" {
            if base.alpn.is_empty() {
                base.alpn = vec!["h2".into(), "http/1.1".into()];
            }
            if base.alpn != ["h3"]
                && base
                    .alpn
                    .iter()
                    .any(|v| !matches!(v.as_str(), "h2" | "http/1.1"))
            {
                return Err(Error::Configuration("XHTTP ALPN"));
            }
        }
        let inner = TcpWithTls(self.certificates.clone()).inbound(&base)?;
        let quic = if base.security == "tls" && base.alpn == ["h3"] {
            let identity = self.certificates.prepare(&base)?;
            if inner.certificate().as_ref() != Some(&identity.fingerprint) {
                return Err(Error::Configuration("TLS identity changed"));
            }
            Some(h3::server_config(identity.config, &options)?)
        } else {
            None
        };
        let key = format!(
            "{}:{}:{}",
            c.protocol.as_str(),
            c.port,
            serde_json::to_string(&options).map_err(|_| Error::Configuration("XHTTP options"))?
        );
        let mut shared = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        shared.retain(|_, v| v.strong_count() > 0);
        let state = if let Some(state) = shared
            .get(&key)
            .and_then(Weak::upgrade)
            .filter(|v| v.live())
        {
            state
        } else {
            if shared.len() >= 128 {
                return Err(Error::Configuration("XHTTP server capacity"));
            }
            let state = server::Shared::new(options)?;
            shared.insert(key, Arc::downgrade(&state));
            state
        };
        state.retain();
        Ok(Arc::new(Server {
            inner,
            quic,
            shared: state,
            released: AtomicBool::new(false),
        }))
    }
    fn outbound(
        &self,
        c: &panel::Outbound,
        roots: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<dyn Outbound>, Error> {
        Ok(Arc::new(client::Client::new(c, roots)?))
    }
}
struct Server {
    inner: Arc<dyn Inbound>,
    quic: Option<Arc<quinn::ServerConfig>>,
    shared: Arc<server::Shared>,
    released: AtomicBool,
}
#[async_trait]
impl Inbound for Server {
    fn abort(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.shared.release();
        }
    }
    async fn close(&self, _: &OperationContext) -> Result<(), Error> {
        self.abort();
        self.shared.close_if_unused().await;
        Ok(())
    }
    fn binding_key(&self) -> &str {
        if self.quic.is_some() {
            "xhttp-quic"
        } else {
            self.inner.binding_key()
        }
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
        if let Some(config) = &self.quic {
            context.check().map_err(Error::Stopped)?;
            let endpoint = quinn::Endpoint::server((**config).clone(), address)?;
            Ok(Box::new(h3::QuicListener(endpoint)))
        } else {
            self.inner.bind(address, context).await
        }
    }
    async fn open_carrier(
        &self,
        carrier: super::Accepted,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Incoming, Error> {
        match carrier {
            super::Accepted::Stream(stream) => self.open(stream, scope, context).await,
            super::Accepted::Quic(incoming) => {
                let config = self.quic.clone().ok_or(Error::Unsupported)?;
                Ok(Incoming::Multiplexed(
                    h3::server(
                        *incoming,
                        config,
                        scope.clone(),
                        self.shared.clone(),
                        context,
                    )
                    .await?,
                ))
            }
        }
    }
    async fn open(
        &self,
        stream: Stream,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Incoming, Error> {
        let stream = self.inner.handshake(stream, scope, context).await?;
        Ok(Incoming::Multiplexed(server::tcp(
            stream,
            scope.clone(),
            self.shared.clone(),
        )?))
    }
    async fn handshake(
        &self,
        _: Stream,
        _: &BufferScope,
        _: &OperationContext,
    ) -> Result<Stream, Error> {
        Err(Error::Unsupported)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.abort();
    }
}
