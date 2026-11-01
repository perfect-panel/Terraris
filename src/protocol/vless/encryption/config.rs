// SPDX-License-Identifier: MPL-2.0
// See THIRD_PARTY.md for protocol sources.

use super::{Error, between};
use crate::panel::ProtocolConfig;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{fmt, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Native,
    XorPub,
    Random,
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub tickets: usize,
    pub replay_keys_per_ticket: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            tickets: 1024,
            replay_keys_per_ticket: 4096,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Padding {
    rules: Vec<[u32; 3]>,
}
impl Padding {
    pub fn parse(value: &str) -> Result<Self, Error> {
        let value = if value.is_empty() {
            "100-111-1111.75-0-111.50-0-3333"
        } else {
            value
        };
        if value.len() > 4096 {
            return Err(Error::Configuration("padding length"));
        }
        let mut rules = Vec::new();
        let mut bytes = 0u32;
        let mut gaps = 0u32;
        for (index, field) in value.split('.').enumerate() {
            if index >= 64 {
                return Err(Error::Configuration("padding rules"));
            }
            let values: Vec<_> = field
                .split('-')
                .map(str::parse::<u32>)
                .collect::<Result<_, _>>()
                .map_err(|_| Error::Configuration("padding rule"))?;
            let rule: [u32; 3] = values
                .try_into()
                .map_err(|_| Error::Configuration("padding rule"))?;
            if rule[0] > 100 || (index == 0 && (rule[0] != 100 || rule[1] < 35 || rule[2] < 35)) {
                return Err(Error::Configuration("padding bounds"));
            }
            let total = if index % 2 == 0 {
                &mut bytes
            } else {
                &mut gaps
            };
            *total = total
                .checked_add(rule[1].max(rule[2]))
                .ok_or(Error::Configuration("padding overflow"))?;
            rules.push(rule);
        }
        if bytes > 65553 || gaps > 10000 {
            return Err(Error::Configuration("padding budget"));
        }
        Ok(Self { rules })
    }
    pub(crate) fn sample(&self) -> Result<(usize, Vec<(usize, Duration)>), Error> {
        let mut total = 0;
        let mut parts = Vec::new();
        for (index, rule) in self.rules.iter().enumerate() {
            let value = if rule[0] >= between(0, 100)? {
                between(rule[1], rule[2])?
            } else {
                0
            };
            if index % 2 == 0 {
                total += value as usize;
                parts.push((value as usize, Duration::ZERO));
            } else {
                parts.last_mut().expect("first padding").1 =
                    Duration::from_millis(u64::from(value));
            }
        }
        Ok((total, parts))
    }
}
#[derive(Clone)]
pub struct Config {
    pub(crate) mode: Mode,
    pub(crate) seconds: (u16, u16),
    pub(crate) padding: Padding,
    pub(crate) seeds: Vec<Zeroizing<Vec<u8>>>,
}
impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessEncryptionConfig")
            .field("mode", &self.mode)
            .field("key_count", &self.seeds.len())
            .finish_non_exhaustive()
    }
}
impl Config {
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() > 16384 {
            return Err(Error::Configuration("configuration length"));
        }
        let fields: Vec<_> = value.split('.').collect();
        if fields.len() < 4 || fields[0] != "mlkem768x25519plus" {
            return Err(Error::Configuration("method"));
        }
        let mode = match fields[1] {
            "native" => Mode::Native,
            "xorpub" => Mode::XorPub,
            "random" => Mode::Random,
            _ => return Err(Error::Configuration("appearance")),
        };
        let seconds = parse_seconds(fields[2])?;
        let mut seeds = Vec::new();
        let mut padding_fields = Vec::new();
        for field in &fields[3..] {
            let bytes = URL_SAFE_NO_PAD.decode(field).ok();
            if let Some(bytes) = bytes.filter(|b| matches!(b.len(), 32 | 64)) {
                if seeds.len() >= 8 {
                    return Err(Error::Configuration("key count"));
                }
                seeds.push(Zeroizing::new(bytes));
            } else if seeds.is_empty() {
                padding_fields.push(*field);
            } else {
                return Err(Error::Configuration("key chain"));
            }
        }
        if seeds.is_empty() {
            return Err(Error::Configuration("keys"));
        }
        let padding = Padding::parse(&padding_fields.join("."))?;
        Ok(Self {
            mode,
            seconds,
            padding,
            seeds,
        })
    }
    pub fn from_panel(value: &ProtocolConfig) -> Result<Option<Self>, Error> {
        if value.encryption_private_key.expose().len() > 16384
            || value.encryption_password.expose().len() > 16384
            || value.encryption_ticket.expose().len() > 32
            || value.encryption_mode.len() > 16
            || value.encryption_rtt.len() > 8
        {
            return Err(Error::Configuration("encryption field length"));
        }
        let method = value.encryption.trim();
        if method.is_empty() || method == "none" {
            if !value.encryption_mode.is_empty()
                || !value.encryption_rtt.is_empty()
                || !value.encryption_ticket.expose().is_empty()
                || !value.encryption_server_padding.is_empty()
                || !value.encryption_private_key.expose().is_empty()
                || !value.encryption_client_padding.is_empty()
                || !value.encryption_password.expose().is_empty()
            {
                return Err(Error::Configuration("options without encryption"));
            }
            return Ok(None);
        }
        if method != "mlkem768x25519plus" {
            return Err(Error::Configuration("method"));
        }
        if !matches!(value.encryption_rtt.as_str(), "" | "0rtt" | "1rtt") {
            return Err(Error::Configuration("client RTT"));
        }
        Padding::parse(&value.encryption_client_padding)?;
        let fields = [
            method,
            value.encryption_mode.trim(),
            value.encryption_ticket.expose().trim(),
            value.encryption_server_padding.trim(),
            value.encryption_private_key.expose().trim(),
        ];
        if fields[1].is_empty() || fields[2].is_empty() || fields[4].is_empty() {
            return Err(Error::Configuration("missing encryption field"));
        }
        let wire = Zeroizing::new(
            fields
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("."),
        );
        let config = Self::parse(&wire)?;
        if !value.encryption_password.expose().is_empty() {
            let public: Vec<_> = value.encryption_password.expose().split('.').collect();
            if public.len() != config.seeds.len() {
                return Err(Error::Configuration("client key chain"));
            }
            for (encoded, seed) in public.iter().zip(&config.seeds) {
                let decoded = URL_SAFE_NO_PAD
                    .decode(encoded)
                    .map_err(|_| Error::Configuration("client public key"))?;
                let expected = super::keys::ServerKey::from_seed(seed)?.public();
                if decoded != expected {
                    return Err(Error::Configuration("client/server key mismatch"));
                }
            }
        }
        Ok(Some(config))
    }
    pub(crate) fn cache_key(&self) -> [u8; 32] {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.push(match self.mode {
            Mode::Native => 0,
            Mode::XorPub => 1,
            Mode::Random => 2,
        });
        bytes.extend_from_slice(&self.seconds.0.to_be_bytes());
        bytes.extend_from_slice(&self.seconds.1.to_be_bytes());
        bytes.extend_from_slice(&(self.padding.rules.len() as u64).to_be_bytes());
        for rule in &self.padding.rules {
            for n in rule {
                bytes.extend_from_slice(&n.to_be_bytes());
            }
        }
        for seed in &self.seeds {
            bytes.extend_from_slice(&(seed.len() as u64).to_be_bytes());
            bytes.extend_from_slice(seed);
        }
        super::crypto::hash(&bytes)
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn client_encryption(&self, zero_rtt: bool) -> Result<String, Error> {
        let mut fields = vec![
            "mlkem768x25519plus".to_owned(),
            match self.mode {
                Mode::Native => "native",
                Mode::XorPub => "xorpub",
                Mode::Random => "random",
            }
            .into(),
            if zero_rtt { "0rtt" } else { "1rtt" }.into(),
        ];
        for seed in &self.seeds {
            fields.push(URL_SAFE_NO_PAD.encode(super::keys::ServerKey::from_seed(seed)?.public()));
        }
        Ok(fields.join("."))
    }
}
fn parse_seconds(value: &str) -> Result<(u16, u16), Error> {
    let value = value.strip_suffix('s').unwrap_or(value);
    let mut fields = value.split('-');
    let from = fields
        .next()
        .ok_or(Error::Configuration("ticket lifetime"))?
        .parse::<u16>()
        .map_err(|_| Error::Configuration("ticket lifetime"))?;
    let to = fields
        .next()
        .map(str::parse::<u16>)
        .transpose()
        .map_err(|_| Error::Configuration("ticket lifetime"))?;
    if fields.next().is_some() || to.is_some_and(|to| to < from) {
        return Err(Error::Configuration("ticket lifetime"));
    }
    Ok((from, to.unwrap_or(0)))
}
