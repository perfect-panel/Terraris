// SPDX-License-Identifier: GPL-3.0-only

//! Node assembly for the implemented VLESS/TCP driver. No Go runtime is
//! launched or embedded; Go/Xray are optional interoperability test tools only.
use crate::{
    buffer::{BufferPool, PoolConfig},
    panel::{self, Connection, ProtocolName, ppanel::PPanelConnection},
    protocol::{flow, vless},
    resource::{Budget, Limits},
    supervisor::{self, Supervisor},
    telemetry::Metrics,
    time::{Deadline, OperationContext},
    users,
};
use serde::Deserialize;
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub listen: IpAddr,
    pub allow_plaintext: bool,
    pub memory_bytes: usize,
    pub buffer_slots: usize,
    pub connection_memory_bytes: usize,
    pub connection_buffer_slots: usize,
    pub max_connections: usize,
    pub max_handshakes: usize,
    pub max_xudp_sessions: usize,
    pub queue_packets: usize,
    pub max_users: usize,
    pub report_entries: usize,
    pub user_max_age_seconds: u64,
    pub handshake_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub udp_idle_timeout_seconds: u64,
    pub drain_timeout_seconds: u64,
    pub shutdown_timeout_seconds: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            listen: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            allow_plaintext: false,
            memory_bytes: 64 << 20,
            buffer_slots: 16384,
            connection_memory_bytes: 4 << 20,
            connection_buffer_slots: 256,
            max_connections: 4096,
            max_handshakes: 128,
            max_xudp_sessions: 32,
            queue_packets: 32,
            max_users: 100_000,
            report_entries: 100_000,
            user_max_age_seconds: 900,
            handshake_timeout_seconds: 10,
            idle_timeout_seconds: 300,
            udp_idle_timeout_seconds: 60,
            drain_timeout_seconds: 30,
            shutdown_timeout_seconds: 5,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        if self.connection_memory_bytes > self.memory_bytes
            || self.connection_buffer_slots > self.buffer_slots
            || self.max_users == 0
            || self.max_users > 1_000_000
            || self.report_entries == 0
            || self.report_entries > 1_000_000
            || self.max_connections > 1_000_000
            || self.buffer_slots > 1_000_000
        {
            return Err(Error::Settings);
        }
        Limits::new(self.memory_bytes, self.buffer_slots).map_err(|_| Error::Settings)?;
        for seconds in [
            self.user_max_age_seconds,
            self.handshake_timeout_seconds,
            self.idle_timeout_seconds,
            self.udp_idle_timeout_seconds,
            self.drain_timeout_seconds,
            self.shutdown_timeout_seconds,
        ] {
            if seconds == 0 || seconds > 86400 {
                return Err(Error::Settings);
            }
        }
        self.protocol_options()?
            .validate()
            .map_err(|_| Error::Settings)
    }
    fn protocol_options(&self) -> Result<vless::Options, Error> {
        Ok(vless::Options {
            listen: self.listen,
            allow_plaintext: self.allow_plaintext,
            max_connections: self.max_connections,
            max_handshakes: self.max_handshakes,
            connection_buffers: Limits::new(
                self.connection_memory_bytes,
                self.connection_buffer_slots,
            )
            .map_err(|_| Error::Settings)?,
            handshake_timeout: Duration::from_secs(self.handshake_timeout_seconds),
            idle_timeout: Duration::from_secs(self.idle_timeout_seconds),
            udp_idle_timeout: Duration::from_secs(self.udp_idle_timeout_seconds),
            max_xudp_sessions: self.max_xudp_sessions,
            queue_packets: self.queue_packets,
            ..Default::default()
        })
    }
}
#[derive(Debug)]
pub enum Error {
    Settings,
    Panel(panel::Error),
    Runtime(crate::runtime::Error),
    Supervisor(supervisor::Error),
    Stopped,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Settings => f.write_str("invalid node limits or timeouts"),
            Self::Panel(e) => e.fmt(f),
            Self::Runtime(e) => e.fmt(f),
            Self::Supervisor(e) => e.fmt(f),
            Self::Stopped => f.write_str("node stopped"),
        }
    }
}
impl std::error::Error for Error {}
pub struct Node {
    supervisor: Arc<Supervisor<vless::Factory>>,
    pool: BufferPool,
    budget: Budget,
    metrics: Metrics,
}
impl Node {
    pub fn new(options: panel::ppanel::Options, settings: Settings) -> Result<Self, Error> {
        settings.validate()?;
        let fingerprints = options.fingerprints.clone();
        let timeout = options.timeout;
        let connection: Arc<dyn Connection> =
            Arc::new(PPanelConnection::new(options).map_err(Error::Panel)?);
        let budget = Budget::new(
            Limits::new(settings.memory_bytes, settings.buffer_slots)
                .map_err(|_| Error::Settings)?,
        );
        let pool = BufferPool::new(
            budget.clone(),
            PoolConfig::standard(settings.memory_bytes / 4, settings.buffer_slots / 4, 64),
        )
        .map_err(|_| Error::Settings)?;
        let buffers = pool
            .scope(budget.root_scope(), 128 << 10)
            .map_err(|_| Error::Settings)?;
        let metrics = Metrics::default();
        let factory = Arc::new(
            vless::Factory::new(
                connection.clone(),
                settings.protocol_options()?,
                flow::Options {
                    max_entries: settings.max_users,
                    device_timeout: timeout.min(Duration::from_secs(10)),
                },
            )
            .map_err(Error::Runtime)?,
        );
        let supervisor = Arc::new(
            Supervisor::new(
                connection,
                factory,
                buffers,
                supervisor::Options {
                    runtime_tasks: settings.max_connections,
                    report_entries: settings.report_entries,
                    users: users::Limits {
                        max_users: settings.max_users,
                        max_sessions: settings
                            .max_connections
                            .saturating_mul(settings.max_xudp_sessions + 1),
                        max_age: Duration::from_secs(settings.user_max_age_seconds),
                    },
                    operation_timeout: timeout,
                    drain_timeout: Duration::from_secs(settings.drain_timeout_seconds),
                    close_timeout: Duration::from_secs(settings.shutdown_timeout_seconds),
                    required_protocols: BTreeSet::from([
                        ProtocolName::new("vless").expect("fixed protocol")
                    ]),
                    ..Default::default()
                },
                metrics.clone(),
                fingerprints,
                None,
            )
            .map_err(Error::Supervisor)?,
        );
        Ok(Self {
            supervisor,
            pool,
            budget,
            metrics,
        })
    }
    pub fn snapshot(&self) -> supervisor::Snapshot {
        self.supervisor.snapshot()
    }
    pub fn resources(&self) -> crate::resource::Snapshot {
        self.budget.snapshot()
    }
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
    pub async fn start(&self, context: &OperationContext) -> Result<(), Error> {
        self.supervisor
            .sync_config(context)
            .await
            .map_err(Error::Supervisor)?;
        Ok(())
    }
    pub async fn run(&self, context: &OperationContext) -> Result<(), Error> {
        let result = self
            .supervisor
            .run(context)
            .await
            .map_err(Error::Supervisor);
        self.pool.close();
        result
    }
    pub async fn close(&self, context: &OperationContext) -> Result<(), Error> {
        let result = self
            .supervisor
            .close(context)
            .await
            .map_err(Error::Supervisor);
        self.pool.close();
        result
    }
    pub fn startup_context(parent: &OperationContext) -> Result<OperationContext, Error> {
        Ok(parent.child_with_deadline(
            Deadline::after(Duration::from_secs(120)).map_err(|_| Error::Settings)?,
        ))
    }
}
