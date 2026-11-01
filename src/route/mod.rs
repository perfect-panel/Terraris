// SPDX-License-Identifier: GPL-3.0-only
//! Immutable PPanel rule compilation. Block rules precede ordered outbound
//! rules. DNS-derived addresses are evaluated before a destination is used.
pub mod geodata;
mod selector;
use crate::panel::ServerConfig;
pub use selector::Selectors;
use std::{collections::HashSet, net::IpAddr};
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_rules: usize,
    pub max_selectors: usize,
    pub max_selector_bytes: usize,
    pub max_regex: usize,
    pub regex_bytes: usize,
    pub max_categories: usize,
    pub asset_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rules: 1024,
            max_selectors: 500_000,
            max_selector_bytes: 64 << 20,
            max_regex: 256,
            regex_bytes: 1 << 20,
            max_categories: 128,
            asset_bytes: 128 << 20,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_rules == 0
            || self.max_rules > 65536
            || self.max_selectors == 0
            || self.max_selectors > 2_000_000
            || self.max_selector_bytes == 0
            || self.max_selector_bytes > 512 << 20
            || self.max_regex > 4096
            || self.regex_bytes == 0
            || self.regex_bytes > 64 << 20
            || self.max_categories == 0
            || self.max_categories > 4096
            || self.asset_bytes == 0
            || self.asset_bytes > 512 << 20
        {
            return Err(Error::Limit("configuration"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Selector,
    Limit(&'static str),
    Asset(&'static str),
    Outbound(&'static str),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "route: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Direct,
    Block,
    Dns,
    Proxy(usize),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub target: Target,
    pub rule: Option<usize>,
}
struct Rule {
    selectors: Selectors,
    target: Target,
}
pub struct Table {
    rules: Vec<Rule>,
    has_ips: bool,
}
impl Table {
    pub fn compile(
        config: &ServerConfig,
        catalog: &mut geodata::Catalog,
        limits: &Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if config.outbounds.len().saturating_add(1) > limits.max_rules {
            return Err(Error::Limit("rules"));
        }
        let block = Selectors::compile(&config.block, catalog, limits, false)?;
        let mut rules = Vec::new();
        if !block.is_empty() {
            rules.push(Rule {
                selectors: block,
                target: Target::Block,
            });
        }
        let mut names = HashSet::new();
        for (index, outbound) in config.outbounds.iter().enumerate() {
            let target = match outbound.protocol.as_str() {
                "direct" | "freedom" => Target::Direct,
                "block" | "reject" | "blackhole" => Target::Block,
                "dns" => Target::Dns,
                "socks" | "socks5" | "http" | "vless" => Target::Proxy(index),
                _ => return Err(Error::Outbound("unsupported protocol")),
            };
            let name = outbound.name.trim();
            if name.is_empty() || name.len() > 256 || name.chars().any(char::is_control) {
                return Err(Error::Outbound("invalid name"));
            }
            if matches!(target, Target::Proxy(_))
                && (["direct", "block", "dns"]
                    .iter()
                    .any(|reserved| name.eq_ignore_ascii_case(reserved))
                    || !names.insert(name))
            {
                return Err(Error::Outbound("duplicate/reserved name"));
            }
            let selectors = Selectors::compile(&outbound.rules, catalog, limits, false)?;
            if !selectors.is_empty() {
                rules.push(Rule { selectors, target });
            }
        }
        let has_ips = rules.iter().any(|r| r.selectors.has_ip_rules());
        Ok(Self { rules, has_ips })
    }
    pub fn has_ip_rules(&self) -> bool {
        self.has_ips
    }
    pub fn decide(&self, domain: Option<&str>, ips: &[IpAddr]) -> Decision {
        let domain = domain.and_then(|name| selector::normalize(name).ok());
        for (index, rule) in self.rules.iter().enumerate() {
            if domain
                .as_deref()
                .is_some_and(|name| rule.selectors.domain_normalized(name))
                || ips.iter().any(|ip| rule.selectors.ip(*ip))
            {
                return Decision {
                    target: rule.target,
                    rule: Some(index),
                };
            }
        }
        Decision {
            target: Target::Direct,
            rule: None,
        }
    }
    pub(crate) fn ip_rules_before(&self, decision: Decision) -> bool {
        self.rules
            .iter()
            .take(decision.rule.unwrap_or(self.rules.len()))
            .any(|rule| rule.selectors.has_ip_rules())
    }
    /// A block decision retains the same first-match ordering as every action.
    pub fn blocked(&self, domain: Option<&str>, ips: &[IpAddr]) -> bool {
        self.decide(domain, ips).target == Target::Block
    }
}

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub geosite: Option<std::path::PathBuf>,
    pub geoip: Option<std::path::PathBuf>,
    pub outbound_ca_file: Option<std::path::PathBuf>,
    pub limits: Limits,
}
impl Settings {
    pub fn assets(&self) -> geodata::Assets {
        geodata::Assets {
            geosite: self.geosite.clone(),
            geoip: self.geoip.clone(),
        }
    }
}

#[cfg(test)]
mod tests;
