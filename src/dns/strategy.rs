// SPDX-License-Identifier: GPL-3.0-only
use super::Error;
use std::net::IpAddr;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Strategy {
    Any,
    PreferV4,
    PreferV6,
    V4,
    V6,
}
impl Strategy {
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value
            .trim()
            .to_ascii_lowercase()
            .replace(['_', '-'], "")
            .as_str()
        {
            "" | "auto" | "useip" | "usesystem" => Ok(Self::Any),
            "preferipv4" | "useipv4v6" => Ok(Self::PreferV4),
            "preferipv6" | "useipv6v4" => Ok(Self::PreferV6),
            "ipv4" | "ipv4only" | "onlyipv4" | "useipv4" => Ok(Self::V4),
            "ipv6" | "ipv6only" | "onlyipv6" | "useipv6" => Ok(Self::V6),
            _ => Err(Error::Configuration("IP strategy")),
        }
    }
    pub fn select(
        self,
        addresses: impl IntoIterator<Item = IpAddr>,
        maximum: usize,
    ) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for ip in addresses {
            let ip = match ip {
                IpAddr::V6(v) => v.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
                _ => ip,
            };
            if matches!(self, Self::V4) && ip.is_ipv6()
                || matches!(self, Self::V6) && ip.is_ipv4()
                || ips.contains(&ip)
            {
                continue;
            }
            ips.push(ip);
        }
        match self {
            Self::PreferV4 => ips.sort_by_key(|v| v.is_ipv6()),
            Self::PreferV6 => ips.sort_by_key(|v| v.is_ipv4()),
            _ => {}
        }
        ips.truncate(maximum);
        ips
    }
    pub fn ipv4(self) -> bool {
        !matches!(self, Self::V6)
    }
    pub fn ipv6(self) -> bool {
        !matches!(self, Self::V4)
    }
}
