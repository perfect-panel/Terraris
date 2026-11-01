// SPDX-License-Identifier: GPL-3.0-only
use super::{Error, PacketPort, Proxy};
use crate::{
    buffer::BufferScope,
    dns::system::System,
    network::{Address, Network, Stream},
    panel,
    registry::Catalog,
    route::Target,
    time::OperationContext,
    transport,
};
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait Connector: Send + Sync {
    fn supports(&self, network: Network) -> bool;
    async fn connect(
        &self,
        target: &Address,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error>;
    async fn packet(
        &self,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Arc<dyn PacketPort>, Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Direct,
    Block,
    Dns,
    Proxy,
}
impl Kind {
    pub fn target(self, index: usize) -> Target {
        match self {
            Self::Direct => Target::Direct,
            Self::Block => Target::Block,
            Self::Dns => Target::Dns,
            Self::Proxy => Target::Proxy(index),
        }
    }
}
pub struct Context {
    pub tls: Arc<rustls::ClientConfig>,
    pub system: Arc<System>,
    pub transports: Arc<transport::Registry>,
}
pub trait Factory: Send + Sync {
    fn kind(&self) -> Kind;
    /// Pure compilation only; network tasks belong to individual connections.
    /// Proxy providers must return a connector, builtin actions must return None.
    fn compile(
        &self,
        config: &panel::Outbound,
        context: &Context,
    ) -> Result<Option<Arc<dyn Connector>>, Error>;
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
        factory: Arc<dyn Factory>,
    ) -> Result<&mut Self, crate::registry::Error> {
        let name =
            panel::ProtocolName::new(name).map_err(|_| crate::registry::Error::InvalidName)?;
        let aliases = aliases
            .iter()
            .map(|name| {
                panel::ProtocolName::new(name).map_err(|_| crate::registry::Error::InvalidName)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let aliases = aliases
            .iter()
            .map(panel::ProtocolName::as_str)
            .collect::<Vec<_>>();
        self.providers.register(name.as_str(), &aliases, factory)?;
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
        for (name, aliases, kind) in [
            ("direct", &["freedom"][..], Kind::Direct),
            ("block", &["blackhole", "reject"][..], Kind::Block),
            ("dns", &[][..], Kind::Dns),
        ] {
            builder
                .register(name, aliases, Arc::new(Builtin(kind)))
                .expect("builtin action");
        }
        for (name, aliases, kind) in [
            ("socks5", &["socks"][..], super::Kind::Socks5),
            ("http", &[][..], super::Kind::Http),
            ("vless", &[][..], super::Kind::Vless),
        ] {
            builder
                .register(name, aliases, Arc::new(ProxyFactory(kind)))
                .expect("builtin proxy");
        }
        builder
    }
    pub fn builtin() -> Self {
        Self::builtin_builder().build()
    }
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.providers.entries().map(|(name, _)| name)
    }
    pub fn kind(&self, name: &str) -> Result<Kind, Error> {
        Ok(self.providers.get(name).ok_or(Error::Unsupported)?.1.kind())
    }
    pub fn compile(
        &self,
        config: &panel::Outbound,
        context: &Context,
    ) -> Result<Option<Arc<dyn Connector>>, Error> {
        let (canonical, factory) = self
            .providers
            .get(config.protocol.as_str())
            .ok_or(Error::Unsupported)?;
        let mut config = config.clone();
        config.protocol = panel::ProtocolName::new(canonical).map_err(|_| Error::Unsupported)?;
        let connector = factory.compile(&config, context)?;
        if (factory.kind() == Kind::Proxy) != connector.is_some() {
            return Err(Error::Configuration("outbound provider contract"));
        }
        Ok(connector)
    }
}
struct Builtin(Kind);
impl Factory for Builtin {
    fn kind(&self) -> Kind {
        self.0
    }
    fn compile(
        &self,
        config: &panel::Outbound,
        _: &Context,
    ) -> Result<Option<Arc<dyn Connector>>, Error> {
        super::validate_builtin(config)?;
        Ok(None)
    }
}
struct ProxyFactory(super::Kind);
impl Factory for ProxyFactory {
    fn kind(&self) -> Kind {
        Kind::Proxy
    }
    fn compile(
        &self,
        config: &panel::Outbound,
        context: &Context,
    ) -> Result<Option<Arc<dyn Connector>>, Error> {
        Ok(Some(Arc::new(Proxy::compile_kind(
            self.0, config, context,
        )?)))
    }
}
#[async_trait]
impl Connector for Proxy {
    fn supports(&self, network: Network) -> bool {
        network == Network::Tcp || self.uot.is_some() || self.kind != super::Kind::Http
    }
    async fn connect(
        &self,
        target: &Address,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> Result<Stream, Error> {
        Proxy::connect(self, target, scope, context).await
    }
    async fn packet(
        &self,
        scope: BufferScope,
        context: &OperationContext,
    ) -> Result<Arc<dyn PacketPort>, Error> {
        Proxy::packet(self, scope, context).await
    }
}
