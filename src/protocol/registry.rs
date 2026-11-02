// SPDX-License-Identifier: GPL-3.0-only
#![doc = include_str!("../../docs/registries.md")]
use crate::{
    buffer::BufferScope,
    egress,
    panel::{ProtocolConfig, ProtocolName, ServerConfig},
    protocol::runtimekit::Core,
    registry::Catalog,
    runtime::{Error, ProtocolDriver, RuntimeFactory},
    telemetry::Metrics,
    time::OperationContext,
};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[async_trait]
pub trait InboundFactory: Send + Sync + 'static {
    /// Process services owned by this protocol only. The registry owns shared egress.
    fn abort(&self) {}
    async fn close(&self, _context: &OperationContext) -> Result<(), Error> {
        Ok(())
    }
    fn published(&self, _shared: &egress::Handle) {}
    /// Return a private driver; cancellation must release partial resources.
    /// The original panel protocol name is preserved, including aliases, so that
    /// user/report scopes remain attached to the configured panel endpoint.
    async fn prepare(
        &self,
        config: ProtocolConfig,
        shared: Arc<egress::Handle>,
        core: Core,
        context: &OperationContext,
    ) -> Result<Arc<dyn ProtocolDriver>, Error>;
}
pub struct Builder {
    providers: Catalog<dyn InboundFactory>,
    egress: Arc<egress::Registry>,
    metrics: Metrics,
}
impl Builder {
    pub fn register(
        &mut self,
        name: &str,
        aliases: &[&str],
        provider: Arc<dyn InboundFactory>,
    ) -> Result<&mut Self, crate::registry::Error> {
        // Panel normalization (e.g. hysteria2) must agree with catalog lookup.
        let name = ProtocolName::new(name).map_err(|_| crate::registry::Error::InvalidName)?;
        let aliases = aliases
            .iter()
            .map(|name| ProtocolName::new(name).map_err(|_| crate::registry::Error::InvalidName))
            .collect::<Result<Vec<_>, _>>()?;
        let aliases = aliases.iter().map(ProtocolName::as_str).collect::<Vec<_>>();
        self.providers.register(name.as_str(), &aliases, provider)?;
        Ok(self)
    }
    pub fn build(self) -> Result<Registry, crate::registry::Error> {
        if self.providers.entries().next().is_none() {
            return Err(crate::registry::Error::Empty);
        }
        Ok(Registry {
            providers: self.providers,
            egress: self.egress,
            metrics: self.metrics,
            closed: AtomicBool::new(false),
        })
    }
}
pub struct Registry {
    providers: Catalog<dyn InboundFactory>,
    egress: Arc<egress::Registry>,
    metrics: Metrics,
    closed: AtomicBool,
}
impl Registry {
    pub fn builder(egress: Arc<egress::Registry>, metrics: Metrics) -> Builder {
        Builder {
            providers: Catalog::default(),
            egress,
            metrics,
        }
    }
    pub fn builtin(
        connection: Arc<dyn crate::panel::Connection>,
        options: super::vless::Options,
        policy: super::flow::Options,
        dns: crate::dns::Settings,
        routing: crate::route::Settings,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        Self::with_tls(
            connection,
            options,
            policy,
            dns,
            routing,
            crate::certificate::Settings::default(),
            metrics,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn with_tls(
        connection: Arc<dyn crate::panel::Connection>,
        options: super::vless::Options,
        policy: super::flow::Options,
        dns: crate::dns::Settings,
        routing: crate::route::Settings,
        tls: crate::certificate::Settings,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        let stream_options = (&options).into();
        Self::with_stream_options(
            connection,
            options,
            stream_options,
            policy,
            dns,
            routing,
            tls,
            metrics,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn with_stream_options(
        connection: Arc<dyn crate::panel::Connection>,
        options: super::vless::Options,
        stream_options: super::stream::Options,
        policy: super::flow::Options,
        dns: crate::dns::Settings,
        routing: crate::route::Settings,
        tls: crate::certificate::Settings,
        metrics: Metrics,
    ) -> Result<Self, Error> {
        let transports = Arc::new(
            crate::transport::Registry::with_tls(tls)
                .map_err(|_| Error::Preparation("TLS settings"))?,
        );
        let egress = egress::Registry::with_providers(
            dns,
            routing,
            options.max_connections,
            Arc::new(crate::outbound::Registry::builtin()),
            transports.clone(),
        )
        .map_err(|_| Error::Preparation("egress settings"))?;
        let vless = Arc::new(super::vless::Factory::with_services(
            connection.clone(),
            options.clone(),
            policy,
            egress.clone(),
            transports.clone(),
            metrics.clone(),
        )?);
        let mut builder = Self::builder(egress, metrics);
        builder
            .register(super::vless::NAME, &[], vless)
            .map_err(|_| Error::Preparation("builtin protocols"))?;
        let trojan = Arc::new(super::stream::Factory::new(
            connection.clone(),
            Arc::new(super::trojan::Factory),
            transports.clone(),
            stream_options.clone(),
            policy,
        )?);
        builder
            .register(super::trojan::NAME, &[], trojan)
            .map_err(|_| Error::Preparation("builtin protocols"))?;
        let shadowsocks = Arc::new(super::shadowsocks::Factory::new(
            connection.clone(),
            transports.clone(),
            stream_options.clone(),
            policy,
            builder.metrics.clone(),
        )?);
        let anytls = Arc::new(super::stream::Factory::new(
            connection,
            Arc::new(super::anytls::Factory),
            transports,
            stream_options,
            policy,
        )?);
        builder
            .register(super::anytls::NAME, &[], anytls)
            .map_err(|_| Error::Preparation("builtin protocols"))?;
        builder
            .register(super::shadowsocks::NAME, &["ss"], shadowsocks)
            .map_err(|_| Error::Preparation("builtin protocols"))?;
        builder
            .build()
            .map_err(|_| Error::Preparation("builtin protocols"))
    }
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.providers.entries().map(|(name, _)| name)
    }
}
#[async_trait]
impl RuntimeFactory for Registry {
    type Shared = egress::Handle;
    fn supports(&self, protocol: &ProtocolName) -> bool {
        self.providers.get(protocol.as_str()).is_some()
    }
    fn abort(&self) {
        self.closed.store(true, Ordering::Release);
        for (_, provider) in self.providers.entries() {
            provider.abort();
        }
        self.egress.abort();
    }
    async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        self.abort();
        let mut result = Ok(());
        // A failing provider must not prevent other providers/services from closing.
        for (_, provider) in self.providers.entries() {
            if let Err(error) = provider.close(context).await
                && result.is_ok()
            {
                result = Err(error);
            }
        }
        if self.egress.close(context).await.is_err() && result.is_ok() {
            result = Err(Error::Preparation("egress close"));
        }
        result
    }
    fn published(&self, shared: &Self::Shared) {
        for (_, provider) in self.providers.entries() {
            provider.published(shared);
        }
    }
    async fn prepare_shared(
        &self,
        config: Arc<ServerConfig>,
        buffers: BufferScope,
        context: &OperationContext,
    ) -> Result<Self::Shared, Error> {
        context.check().map_err(Error::Stopped)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let mut selected = (*config).clone();
        selected.protocols.retain(|p| self.supports(&p.protocol));
        if config.protocols.iter().any(|p| p.enabled)
            && !selected.protocols.iter().any(|p| p.enabled)
        {
            return Err(Error::Unsupported);
        }
        self.egress
            .open(&selected, buffers, self.metrics.clone(), context)
            .await
            .map_err(|_| Error::Preparation("routing/DNS/outbound configuration"))
    }
    async fn prepare_protocol(
        &self,
        config: ProtocolConfig,
        shared: Arc<Self::Shared>,
        core: Core,
        context: &OperationContext,
    ) -> Result<Arc<dyn ProtocolDriver>, Error> {
        context.check().map_err(Error::Stopped)?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        self.providers
            .get(config.protocol.as_str())
            .ok_or(Error::Unsupported)?
            .1
            .prepare(config, shared, core, context)
            .await
    }
}
impl Drop for Registry {
    fn drop(&mut self) {
        self.abort();
    }
}
