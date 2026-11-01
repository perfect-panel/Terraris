// SPDX-License-Identifier: GPL-3.0-only

//! Local bootstrap configuration. Secrets are resolved only for network use.

use std::{
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::Deserialize;

use crate::panel::{Secret, ServerId, WireMode, ppanel::Options};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub panel: PanelConfig,
    #[serde(default)]
    pub node: crate::node::Settings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PanelConfig {
    base_url: String,
    server_id: i64,
    secret_env: Option<String>,
    secret_file: Option<PathBuf>,
    #[serde(default = "timeout_default")]
    timeout_seconds: u64,
    #[serde(default = "response_limit_default")]
    max_response_bytes: usize,
    #[serde(default = "request_limit_default")]
    max_request_bytes: usize,
    #[serde(default)]
    wire_format: Format,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Format {
    #[default]
    Auto,
    Json,
    Protobuf,
}

fn timeout_default() -> u64 {
    30
}
fn response_limit_default() -> usize {
    64 * 1024 * 1024
}
fn request_limit_default() -> usize {
    8 * 1024 * 1024
}

#[derive(Debug)]
pub struct Error(&'static str);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Error> {
        let body = read_bounded(path, 256 * 1024)
            .map_err(|_| Error("cannot read configuration (limit: 256 KiB)"))?;
        Self::parse(&body)
    }

    pub fn parse(body: &str) -> Result<Self, Error> {
        if body.len() > 256 * 1024 {
            return Err(Error("configuration exceeds 256 KiB"));
        }
        // Parser messages can contain the offending line, including a secret.
        let config: Self = toml::from_str(body)
            .map_err(|_| Error("invalid TOML configuration or unknown field"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), Error> {
        self.node
            .validate()
            .map_err(|_| Error("invalid node limits or timeouts"))?;
        let p = &self.panel;
        if p.secret_env.is_some() == p.secret_file.is_some() {
            return Err(Error(
                "configure exactly one of panel.secret_env and panel.secret_file",
            ));
        }
        if p.secret_env.as_ref().is_some_and(|s| {
            s.is_empty() || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }) {
            return Err(Error("invalid panel.secret_env name"));
        }
        if p.secret_file
            .as_ref()
            .is_some_and(|p| p.as_os_str().is_empty())
        {
            return Err(Error("panel.secret_file must not be empty"));
        }
        // This value is used for local validation only and never sent anywhere.
        self.options_with_secret(Secret::new("local-validation"))?
            .validate()
            .map_err(|_| Error("invalid panel URL, server ID, timeout or body limits"))
    }

    /// Relative secret files are resolved against the configuration file.
    pub fn connection_options(&self, config_path: &Path) -> Result<Options, Error> {
        self.validate()?;
        let secret = if let Some(name) = &self.panel.secret_env {
            std::env::var(name)
                .map_err(|_| Error("configured secret environment variable is unavailable"))?
        } else if let Some(path) = &self.panel.secret_file {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                config_path.parent().unwrap_or(Path::new(".")).join(path)
            };
            read_bounded(&path, 8192)
                .map_err(|_| Error("cannot read configured secret file"))?
                .trim_end_matches(['\r', '\n'])
                .to_owned()
        } else {
            return Err(Error("no secret source configured"));
        };
        let options = self.options_with_secret(Secret::new(secret))?;
        options
            .validate()
            .map_err(|_| Error("invalid panel connection settings or secret length"))?;
        Ok(options)
    }

    fn options_with_secret(&self, secret: Secret) -> Result<Options, Error> {
        let p = &self.panel;
        let id =
            ServerId::new(p.server_id).map_err(|_| Error("panel.server_id must be positive"))?;
        let mut options = Options::new(p.base_url.clone(), id, secret);
        options.timeout = Duration::from_secs(p.timeout_seconds);
        options.max_response_bytes = p.max_response_bytes;
        options.max_request_bytes = p.max_request_bytes;
        options.wire_mode = match p.wire_format {
            Format::Auto => WireMode::Auto,
            Format::Json => WireMode::Json,
            Format::Protobuf => WireMode::Protobuf,
        };
        Ok(options)
    }
}

fn read_bounded(path: &Path, limit: usize) -> Result<String, ()> {
    let mut body = String::new();
    File::open(path)
        .map_err(|_| ())?
        .take(limit as u64 + 1)
        .read_to_string(&mut body)
        .map_err(|_| ())?;
    if body.len() > limit {
        return Err(());
    }
    Ok(body)
}
