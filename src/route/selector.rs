// SPDX-License-Identifier: GPL-3.0-only
use super::{Error, Limits, geodata::Catalog};
use aho_corasick::AhoCorasick;
use ipnet::IpNet;
use regex::{Regex, RegexBuilder};
use std::{collections::HashSet, net::IpAddr, sync::Arc};

#[derive(Clone)]
pub(crate) enum Atom {
    Full(String),
    Suffix(String),
    Keyword(String),
    Regex(String),
    Ip(IpNet),
}
/// Sorted disjoint ranges avoid trie expansion for large IPv6 datasets.
#[derive(Default)]
struct Prefixes {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}
impl Prefixes {
    fn add(&mut self, prefix: IpNet) {
        match prefix {
            IpNet::V4(v) => self.v4.push((
                u32::from(v.network()) as u128,
                u32::from(v.broadcast()) as u128,
            )),
            IpNet::V6(v) => {
                if v.prefix_len() >= 96
                    && let Some(ip) = v.network().to_ipv4_mapped()
                {
                    self.add(
                        IpNet::new(IpAddr::V4(ip), v.prefix_len() - 96).expect("mapped prefix"),
                    );
                } else {
                    self.v6
                        .push((u128::from(v.network()), u128::from(v.broadcast())));
                }
            }
        }
    }
    fn finish(&mut self) {
        for ranges in [&mut self.v4, &mut self.v6] {
            ranges.sort_unstable();
            let mut n = 0;
            for i in 0..ranges.len() {
                let range = ranges[i];
                if n > 0 && range.0 <= ranges[n - 1].1.saturating_add(1) {
                    ranges[n - 1].1 = ranges[n - 1].1.max(range.1);
                } else {
                    ranges[n] = range;
                    n += 1;
                }
            }
            ranges.truncate(n);
        }
    }
    fn matches(&self, ip: IpAddr) -> bool {
        let (ranges, value) = match canonical_ip(ip) {
            IpAddr::V4(v) => (&self.v4, u32::from(v) as u128),
            IpAddr::V6(v) => (&self.v6, u128::from(v)),
        };
        let index = ranges.partition_point(|r| r.0 <= value);
        index > 0 && ranges[index - 1].1 >= value
    }
}
pub(crate) struct AtomSet {
    exact: HashSet<String>,
    suffix: HashSet<String>,
    keywords: Option<AhoCorasick>,
    regex: Vec<Regex>,
    prefixes: Prefixes,
    pub(crate) has_ips: bool,
    pub(crate) count: usize,
    reverse_ip: bool,
    pub(crate) bytes: usize,
    pub(crate) regex_count: usize,
}
impl AtomSet {
    pub(crate) fn compile(
        atoms: Vec<Atom>,
        limits: &Limits,
        reverse_ip: bool,
    ) -> Result<Self, Error> {
        if atoms.len() > limits.max_selectors {
            return Err(Error::Limit("selector count"));
        }
        let mut result = Self {
            exact: HashSet::new(),
            suffix: HashSet::new(),
            keywords: None,
            regex: vec![],
            prefixes: Prefixes::default(),
            has_ips: reverse_ip,
            count: atoms.len().max(usize::from(reverse_ip)),
            reverse_ip,
            bytes: 0,
            regex_count: 0,
        };
        let mut keywords = Vec::new();
        let mut bytes = 0usize;
        for atom in atoms {
            match atom {
                Atom::Full(v) => {
                    bytes += v.len();
                    result.exact.insert(normalize(&v)?);
                }
                Atom::Suffix(v) => {
                    bytes += v.len();
                    result.suffix.insert(normalize(&v)?);
                }
                Atom::Keyword(v) => {
                    bytes += v.len();
                    let v = v.trim().to_ascii_lowercase();
                    if v.is_empty() || v.len() > 1024 {
                        return Err(Error::Selector);
                    }
                    keywords.push(v);
                }
                Atom::Regex(v) => {
                    bytes += v.len();
                    if v.len() > 4096 || result.regex.len() >= limits.max_regex {
                        return Err(Error::Limit("regex count/length"));
                    }
                    result.regex.push(
                        RegexBuilder::new(&v)
                            .case_insensitive(true)
                            .size_limit(limits.regex_bytes)
                            .dfa_size_limit(limits.regex_bytes)
                            .build()
                            .map_err(|_| Error::Selector)?,
                    );
                }
                Atom::Ip(v) => {
                    bytes += 32;
                    result.prefixes.add(v);
                    result.has_ips = true;
                }
            }
            if bytes > limits.max_selector_bytes {
                return Err(Error::Limit("selector bytes"));
            }
        }
        result.prefixes.finish();
        result.bytes = bytes;
        result.regex_count = result.regex.len();
        keywords.sort();
        keywords.dedup();
        if !keywords.is_empty() {
            let matcher = AhoCorasick::new(keywords).map_err(|_| Error::Selector)?;
            if matcher.memory_usage() > limits.max_selector_bytes {
                return Err(Error::Limit("keyword automaton"));
            }
            result.keywords = Some(matcher);
        }
        Ok(result)
    }
    fn domain(&self, value: &str) -> bool {
        if self.exact.contains(value) {
            return true;
        }
        let mut suffix = value;
        loop {
            if self.suffix.contains(suffix) {
                return true;
            }
            let Some((_, rest)) = suffix.split_once('.') else {
                break;
            };
            suffix = rest;
        }
        self.keywords.as_ref().is_some_and(|k| k.is_match(value))
            || self.regex.iter().any(|r| r.is_match(value))
    }
    fn ip(&self, value: IpAddr) -> bool {
        self.has_ips && (self.prefixes.matches(value) ^ self.reverse_ip)
    }
}
#[derive(Clone, Default)]
pub struct Selectors {
    parts: Vec<Arc<AtomSet>>,
    pub(crate) has_ips: bool,
    count: usize,
}
impl Selectors {
    pub fn compile(
        values: &[String],
        catalog: &mut Catalog,
        limits: &Limits,
        domains_only: bool,
    ) -> Result<Self, Error> {
        if values.len() > limits.max_selectors {
            return Err(Error::Limit("selector count"));
        }
        let mut atoms = Vec::new();
        let mut result = Self::default();
        for raw in values {
            let value = raw.trim();
            if value.is_empty() {
                continue;
            }
            if value.len() > 4096 {
                return Err(Error::Limit("selector length"));
            }
            let lower = value.to_ascii_lowercase();
            let part = if let Some(category) = lower.strip_prefix("geosite:") {
                Some(catalog.site(category, limits)?)
            } else if let Some(category) = lower.strip_prefix("geoip:") {
                if domains_only {
                    return Err(Error::Selector);
                }
                Some(catalog.ip(category, limits)?)
            } else {
                None
            };
            if let Some(part) = part {
                if result.parts.iter().any(|old| Arc::ptr_eq(old, &part)) {
                    continue;
                }
                result.has_ips |= part.has_ips;
                result.count = result
                    .count
                    .checked_add(part.count)
                    .ok_or(Error::Limit("selector count"))?;
                result.parts.push(part);
                continue;
            }
            if let Ok(ip) = value.parse::<IpAddr>() {
                if domains_only {
                    return Err(Error::Selector);
                }
                atoms.push(Atom::Ip(IpNet::from(canonical_ip(ip))));
                continue;
            }
            if let Ok(ip) = value.parse::<IpNet>() {
                if domains_only {
                    return Err(Error::Selector);
                }
                atoms.push(Atom::Ip(ip.trunc()));
                continue;
            }
            let (kind, value) = value.split_once(':').unwrap_or(("full", value));
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Selector);
            }
            atoms.push(match kind.to_ascii_lowercase().as_str() {
                "full" => Atom::Full(value.into()),
                "domain" | "suffix" => Atom::Suffix(value.trim_start_matches('.').into()),
                "keyword" | "plain" => Atom::Keyword(value.into()),
                "regex" | "regexp" => Atom::Regex(value.into()),
                "ip" | "cidr" if !domains_only => Atom::Ip(
                    value
                        .parse::<IpNet>()
                        .or_else(|_| {
                            value
                                .parse::<IpAddr>()
                                .map(|ip| IpNet::from(canonical_ip(ip)))
                        })
                        .map_err(|_| Error::Selector)?
                        .trunc(),
                ),
                _ => return Err(Error::Selector),
            });
        }
        if !atoms.is_empty() {
            let part = Arc::new(AtomSet::compile(atoms, limits, false)?);
            catalog.charge(&part, limits)?;
            result.has_ips |= part.has_ips;
            result.count += part.count;
            result.parts.push(part);
        }
        if result.count > limits.max_selectors {
            return Err(Error::Limit("selector count"));
        }
        Ok(result)
    }
    pub fn domain(&self, domain: &str) -> bool {
        normalize(domain).is_ok_and(|domain| self.domain_normalized(&domain))
    }
    pub(crate) fn domain_normalized(&self, domain: &str) -> bool {
        self.parts.iter().any(|part| part.domain(domain))
    }
    pub fn ip(&self, ip: IpAddr) -> bool {
        self.parts.iter().any(|part| part.ip(ip))
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn has_ip_rules(&self) -> bool {
        self.has_ips
    }
}
pub(crate) fn normalize(value: &str) -> Result<String, Error> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || value.split('.').any(|s| {
            s.is_empty()
                || s.len() > 63
                || s.bytes()
                    .any(|b| !(b.is_ascii_alphanumeric() || b"-_".contains(&b)))
        })
    {
        return Err(Error::Selector);
    }
    Ok(value)
}
pub(crate) fn canonical_ip(value: IpAddr) -> IpAddr {
    match value {
        IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(value),
        _ => value,
    }
}
