// SPDX-License-Identifier: GPL-3.0-only
use crate::{
    network::{Address, connect_tcp},
    panel::ServerConfig,
    runtime::{self, SharedServices},
    task::CancellationToken,
    telemetry::Metrics,
    time::OperationContext,
};
use async_trait::async_trait;
use std::{
    future::poll_fn,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Mutex},
    task::Poll,
};
use tokio::{
    net::TcpStream,
    sync::{Semaphore, oneshot},
    task::JoinSet,
};
const DNS_JOBS: usize = 64;
#[derive(Clone, Copy)]
enum Strategy {
    Any,
    PreferV4,
    PreferV6,
    V4,
    V6,
}
impl Strategy {
    fn select(self, input: impl Iterator<Item = SocketAddr>) -> Vec<SocketAddr> {
        let mut addresses = Vec::new();
        let (mut v4, mut v6) = (0, 0);
        for address in input {
            if matches!(self, Self::V4) && address.is_ipv6()
                || matches!(self, Self::V6) && address.is_ipv4()
                || addresses.contains(&address)
            {
                continue;
            }
            let count = if address.is_ipv4() { &mut v4 } else { &mut v6 };
            if *count >= 16 {
                continue;
            }
            *count += 1;
            addresses.push(address);
            if matches!(self, Self::Any | Self::V4 | Self::V6) && addresses.len() == 16
                || v4 == 16 && v6 == 16
            {
                break;
            }
        }
        match self {
            Self::PreferV4 => addresses.sort_by_key(|a| a.is_ipv6()),
            Self::PreferV6 => addresses.sort_by_key(|a| a.is_ipv4()),
            _ => {}
        }
        addresses.truncate(16);
        addresses
    }
}
/// System resolution runs on bounded owned blocking jobs. Cancelling a request
/// drops its receiver, but retains both its handle and concurrency permit until
/// getaddrinfo actually returns. The OS call itself cannot be forcibly aborted.
pub struct Egress {
    strategy: Strategy,
    dns: Arc<Semaphore>,
    resolutions: Mutex<JoinSet<()>>,
    cancel: CancellationToken,
}
impl Egress {
    pub(super) fn new(config: &ServerConfig) -> Result<Self, runtime::Error> {
        let active = config
            .protocols
            .iter()
            .any(|protocol| protocol.enabled && protocol.protocol.as_str() == "vless");
        if active
            && (!config.dns.is_empty()
                || !config.block.is_empty()
                || !config.outbounds.is_empty()
                || !config.extensions.is_empty())
        {
            return Err(runtime::Error::Unsupported);
        }
        let strategy = match if active {
            config.ip_strategy.as_str()
        } else {
            ""
        } {
            "" | "auto" => Strategy::Any,
            "prefer_ipv4" => Strategy::PreferV4,
            "prefer_ipv6" => Strategy::PreferV6,
            "ipv4_only" => Strategy::V4,
            "ipv6_only" => Strategy::V6,
            _ => return Err(runtime::Error::Unsupported),
        };
        Ok(Self {
            strategy,
            dns: Arc::new(Semaphore::new(DNS_JOBS)),
            resolutions: Mutex::new(JoinSet::new()),
            cancel: CancellationToken::new(),
        })
    }
    pub(super) async fn resolve(
        &self,
        target: &Address,
        context: &OperationContext,
    ) -> Result<Vec<SocketAddr>, runtime::Error> {
        if self.cancel.is_cancelled() {
            return Err(runtime::Error::Closed);
        }
        let addresses = if let Some(address) = target.socket_addr() {
            self.strategy.select(std::iter::once(address))
        } else {
            let permit = context
                .run(self.dns.clone().acquire_owned())
                .await
                .map_err(runtime::Error::Stopped)?
                .map_err(|_| runtime::Error::Closed)?;
            let host = target
                .domain_name()
                .ok_or(runtime::Error::InvalidState)?
                .as_str()
                .to_owned();
            let port = target.port();
            let strategy = self.strategy;
            let (sender, receiver) = oneshot::channel();
            {
                let mut jobs = self.resolutions.lock().unwrap_or_else(|e| e.into_inner());
                while jobs.try_join_next().is_some() {}
                if self.cancel.is_cancelled() {
                    return Err(runtime::Error::Closed);
                }
                if jobs.len() >= DNS_JOBS {
                    return Err(runtime::Error::Preparation("DNS resolver capacity"));
                }
                jobs.spawn_blocking(move || {
                    let _permit = permit;
                    let result = (host.as_str(), port)
                        .to_socket_addrs()
                        .map(|addresses| strategy.select(addresses))
                        .map_err(|_| runtime::Error::Preparation("DNS resolution"));
                    let _ = sender.send(result);
                });
            }
            context
                .run(receiver)
                .await
                .map_err(runtime::Error::Stopped)?
                .map_err(|_| runtime::Error::Closed)??
        };
        if addresses.is_empty() {
            return Err(runtime::Error::Preparation("no permitted address family"));
        }
        Ok(addresses)
    }
    pub(super) async fn connect(
        &self,
        target: &Address,
        context: &OperationContext,
        metrics: &Metrics,
    ) -> Result<TcpStream, runtime::Error> {
        for address in self.resolve(target, context).await? {
            if let Ok(stream) = connect_tcp(address, context, metrics).await {
                return Ok(stream);
            }
            context.check().map_err(runtime::Error::Stopped)?;
        }
        Err(runtime::Error::Preparation("TCP connection"))
    }
}
#[async_trait]
impl SharedServices for Egress {
    fn abort(&self) {
        self.cancel.cancel();
        self.dns.close();
        self.resolutions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .abort_all();
    }
    async fn close(&self, context: &OperationContext) -> Result<(), runtime::Error> {
        self.abort();
        context
            .run(poll_fn(|cx| {
                let mut jobs = self.resolutions.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    match jobs.poll_join_next(cx) {
                        Poll::Ready(Some(_)) => {}
                        Poll::Ready(None) => return Poll::Ready(()),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }))
            .await
            .map_err(runtime::Error::Stopped)
    }
}
impl Drop for Egress {
    fn drop(&mut self) {
        self.abort();
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_family_preference_is_applied_before_the_candidate_limit() {
        let mut addresses: Vec<SocketAddr> = (1..=40)
            .map(|n| SocketAddr::from(([127, 0, 0, n], 80)))
            .collect();
        addresses.push("[::1]:80".parse().unwrap());
        let result = Strategy::PreferV6.select(addresses.clone().into_iter());
        assert!(result[0].is_ipv6());
        assert_eq!(result.len(), 16);
        assert_eq!(Strategy::V6.select(addresses.into_iter()).len(), 1);
    }
}
