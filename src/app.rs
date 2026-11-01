// SPDX-License-Identifier: GPL-3.0-only

//! CLI composition. No proxy listener or fictitious online heartbeat is started.

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
    about = "PPanel control-plane foundation; proxy runtimes are not yet implemented"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => e.fmt(f),
            Self::Panel(e) => e.fmt(f),
            Self::Interrupted => f.write_str("check interrupted"),
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
        Command::Version => println!("terraris {}", env!("CARGO_PKG_VERSION")),
        Command::Capabilities => {
            println!(
                "panel: ppanel (JSON, HTTP Protobuf, conditional GET, device leases, online/traffic/status reporting)"
            );
            println!(
                "buffers: fixed capacity, hierarchical byte/slot budgets, atomic batch reservations (no cache)"
            );
            println!("proxy protocols: none (foundation stage)");
            println!("runtime: not implemented");
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
