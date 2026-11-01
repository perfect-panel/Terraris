// SPDX-License-Identifier: GPL-3.0-only

//! CLI composition. Read-only checks and explicitly requested VLESS node run.

use std::{fmt, path::PathBuf};

use clap::{Parser, Subcommand};

use crate::{
    config,
    panel::{
        self, Connection, Fetch,
        ppanel::{Options, PPanelConnection},
    },
};

#[derive(Parser)]
#[command(
    name = "terraris",
    version,
    about = "PPanel Rust node with VLESS, XUDP and VLESS Encryption"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the VLESS node, synchronizing panel policy and serving configured ports.
    Run {
        #[arg(short, long, default_value = "terraris.toml")]
        config: PathBuf,
    },
    /// Validate local settings; --panel also reads remote configuration, users and alive counts.
    Check {
        #[arg(short, long, default_value = "terraris.toml")]
        config: PathBuf,
        #[arg(long)]
        panel: bool,
    },
    /// Print implemented capabilities.
    Capabilities,
    /// Print the package version.
    Version,
}

#[derive(Debug)]
pub enum Error {
    Config(config::Error),
    Panel(panel::Error),
    Interrupted,
    Node(crate::node::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => e.fmt(f),
            Self::Panel(e) => e.fmt(f),
            Self::Interrupted => f.write_str("check interrupted"),
            Self::Node(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PanelSummary {
    pub protocols: usize,
    /// Sum of per-protocol rows, not a distinct global user count.
    pub user_records: usize,
    pub alive_records: usize,
}

pub async fn check_panel(options: Options) -> panel::Result<PanelSummary> {
    let connection = PPanelConnection::new(options)?;
    let Fetch::Changed { value: config, .. } = connection.server().get_config(None).await? else {
        return Err(panel::Error::new(
            panel::Endpoint::Config,
            panel::ErrorKind::UnexpectedNotModified,
            "initial configuration is unchanged without a snapshot",
        ));
    };
    let mut summary = PanelSummary {
        protocols: 0,
        user_records: 0,
        alive_records: 0,
    };
    for protocol in config.protocols.iter().filter(|p| p.enabled) {
        let client = connection.protocol(protocol.protocol.as_str())?;
        let Fetch::Changed { value: users, .. } = client.get_users(None).await? else {
            return Err(panel::Error::new(
                panel::Endpoint::Users,
                panel::ErrorKind::UnexpectedNotModified,
                "initial users are unchanged without a snapshot",
            ));
        };
        let alive = client.get_alive().await?;
        summary.protocols += 1;
        summary.user_records += users.len();
        summary.alive_records += alive.len();
    }
    Ok(summary)
}

pub async fn run() -> Result<(), Error> {
    match Cli::parse().command {
        Command::Run { config: path } => run_node(path).await?,
        Command::Version => println!("terraris {}", env!("CARGO_PKG_VERSION")),
        Command::Capabilities => {
            println!(
                "panel: ppanel (JSON, HTTP Protobuf, conditional GET, device leases, online/traffic/status reporting)"
            );
            println!(
                "buffers: fixed capacity, shared views, Bytes ownership, bounded cache and byte/message queues"
            );
            println!(
                "infrastructure: tracked tasks, monotonic deadlines, budgeted TCP/UDP I/O, bounded codecs, metrics"
            );
            println!(
                "proxy protocols: {} (TCP, UDP, XUDP; mlkem768x25519plus)",
                crate::protocol::vless::NAME
            );
            println!(
                "transports: {} (raw alias; inbound/outbound), TLS client layer; VLESS encryption native/xorpub/random, 1-RTT/0-RTT",
                crate::transport::Registry::builtin()
                    .names()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "outbound registry: {}",
                crate::outbound::Registry::builtin()
                    .names()
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            println!(
                "registries: immutable protocol/outbound/stream factories; startup aliases and custom providers"
            );
            println!(
                "routing: ordered domain/IP/GeoSite/GeoIP rules; direct/block/DNS/SOCKS5/HTTP/VLESS outbounds"
            );
            println!(
                "dns: scoped UDP/TCP/DoH/DoT, bounded TTL and negative cache, query coalescing"
            );
            println!(
                "runtime: scheduler, transactional users, device admission, shared user rate limits, accounting and generation handoff"
            );
        }
        Command::Check {
            config: path,
            panel,
        } => {
            let config = config::Config::load(&path).map_err(Error::Config)?;
            if panel {
                let options = config.connection_options(&path).map_err(Error::Config)?;
                let summary = tokio::select! {
                    result = check_panel(options) => result.map_err(Error::Panel)?,
                    _ = tokio::signal::ctrl_c() => return Err(Error::Interrupted),
                };
                println!(
                    "Panel check passed: {} enabled protocols, {} user records, {} alive records (per protocol).",
                    summary.protocols, summary.user_records, summary.alive_records
                );
                println!(
                    "Wire contract checked; proxy runtime compatibility is not checked. No listeners or reports were started."
                );
            } else {
                println!(
                    "Local configuration is valid. Secret source and panel connectivity were not checked."
                );
            }
        }
    }
    Ok(())
}

async fn run_node(path: PathBuf) -> Result<(), Error> {
    let config = config::Config::load(&path).map_err(Error::Config)?;
    let options = config.connection_options(&path).map_err(Error::Config)?;
    let node = crate::node::Node::with_network(options, config.node, config.dns, config.routing)
        .map_err(Error::Node)?;
    let cancellation = crate::task::CancellationToken::new();
    let context = crate::time::OperationContext::new(cancellation.clone(), None);
    let run = async {
        node.start(&crate::node::Node::startup_context(&context).map_err(Error::Node)?)
            .await
            .map_err(Error::Node)?;
        let snapshot = node.snapshot();
        println!(
            "Node configuration applied: {} active protocol(s), ready={}",
            snapshot.protocols.len(),
            snapshot.ready
        );
        node.run(&context).await.map_err(Error::Node)
    };
    tokio::pin!(run);
    tokio::select! {
        result=&mut run=>result,
        _=shutdown_signal()=>{
            cancellation.cancel();
            let result=run.await;
            let cleanup=crate::time::OperationContext::new(crate::task::CancellationToken::new(),Some(crate::time::Deadline::after(std::time::Duration::from_secs(120)).expect("fixed timeout")));
            node.close(&cleanup).await.map_err(Error::Node)?;
            match result{Err(Error::Node(crate::node::Error::Supervisor(crate::supervisor::Error::Stopped(_))))=>Ok(()),result=>result}
        }
    }
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=terminate.recv()=>{}}
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
