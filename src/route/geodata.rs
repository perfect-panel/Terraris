// SPDX-License-Identifier: GPL-3.0-only
//! Bounded V2Ray/Xray GeoSite/GeoIP protobuf assets, loaded only from operator paths.
use super::{
    Error, Limits,
    selector::{Atom, AtomSet},
};
use ipnet::IpNet;
use prost::Message;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Assets {
    pub geosite: Option<PathBuf>,
    pub geoip: Option<PathBuf>,
}
#[derive(Clone)]
pub struct Stamp {
    path: PathBuf,
    length: u64,
    modified: Option<SystemTime>,
    identity: (u64, u64),
    pub(crate) digest: [u8; 32],
}
impl Stamp {
    pub fn changed(&self) -> Result<bool, Error> {
        let metadata = std::fs::metadata(&self.path).map_err(|_| Error::Asset("unavailable"))?;
        Ok(metadata.len() != self.length
            || metadata.modified().ok() != self.modified
            || file_identity(&metadata) != self.identity)
    }
}
#[cfg(unix)]
fn file_identity(m: &std::fs::Metadata) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (m.dev(), m.ino())
}
#[cfg(not(unix))]
fn file_identity(_: &std::fs::Metadata) -> (u64, u64) {
    (0, 0)
}
pub struct Catalog {
    assets: Assets,
    sites: Option<BTreeMap<String, Site>>,
    ips: Option<BTreeMap<String, Vec<GeoIp>>>,
    site_cache: HashMap<String, Arc<AtomSet>>,
    ip_cache: HashMap<String, Arc<AtomSet>>,
    stamps: Vec<Stamp>,
    compiled: (usize, usize, usize),
}
impl Catalog {
    pub fn new(assets: Assets) -> Self {
        Self {
            assets,
            sites: None,
            ips: None,
            site_cache: HashMap::new(),
            ip_cache: HashMap::new(),
            stamps: vec![],
            compiled: (0, 0, 0),
        }
    }
    pub(crate) fn charge(&mut self, set: &AtomSet, limits: &Limits) -> Result<(), Error> {
        self.compiled.0 = self.compiled.0.saturating_add(set.count);
        self.compiled.1 = self.compiled.1.saturating_add(set.bytes);
        self.compiled.2 = self.compiled.2.saturating_add(set.regex_count);
        if self.compiled.0 > limits.max_selectors
            || self.compiled.1 > limits.max_selector_bytes
            || self.compiled.2 > limits.max_regex
        {
            return Err(Error::Limit("aggregate compiled selectors"));
        }
        Ok(())
    }
    pub(crate) fn record(&mut self, stamp: Stamp) -> Result<(), Error> {
        if let Some(previous) = self
            .stamps
            .iter()
            .find(|previous| previous.path == stamp.path)
        {
            if previous.digest != stamp.digest
                || previous.length != stamp.length
                || previous.modified != stamp.modified
                || previous.identity != stamp.identity
            {
                return Err(Error::Asset("changed during compilation"));
            }
        } else {
            self.stamps.push(stamp);
        }
        Ok(())
    }
    pub fn stamps(&self) -> Vec<Stamp> {
        self.stamps.clone()
    }
    pub(crate) fn site(&mut self, raw: &str, limits: &Limits) -> Result<Arc<AtomSet>, Error> {
        let mut fields = raw.split('@');
        let code = category(fields.next().unwrap_or_default())?;
        let mut attrs = fields
            .map(|a| {
                let a = a.trim().to_ascii_lowercase();
                if a.is_empty()
                    || a.len() > 64
                    || !a
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                {
                    Err(Error::Selector)
                } else {
                    Ok(a)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        attrs.sort();
        attrs.dedup();
        if attrs.len() > 16 {
            return Err(Error::Selector);
        }
        let key = format!("{code}@{}", attrs.join("@"));
        if let Some(set) = self.site_cache.get(&key) {
            return Ok(set.clone());
        }
        if self.site_cache.len() >= limits.max_categories {
            return Err(Error::Limit("geosite categories"));
        }
        if self.sites.is_none() {
            let path = self
                .assets
                .geosite
                .as_ref()
                .ok_or(Error::Asset("geosite path required"))?;
            let (bytes, stamp) = read(path, limits.asset_bytes)?;
            preflight(&bytes, true, limits)?;
            let list = SiteList::decode(bytes.as_slice())
                .map_err(|_| Error::Asset("invalid geosite protobuf"))?;
            if list.entries.len() > limits.max_selectors {
                return Err(Error::Limit("geosite entries"));
            }
            let mut sites = BTreeMap::new();
            for site in list.entries {
                let code = category(&site.code)?;
                if sites.insert(code, site).is_some() {
                    return Err(Error::Asset("duplicate geosite category"));
                }
            }
            self.sites = Some(sites);
            self.stamps.push(stamp);
        }
        let site = self
            .sites
            .as_ref()
            .expect("loaded")
            .get(&code)
            .ok_or(Error::Asset("missing geosite category"))?;
        let mut atoms = Vec::new();
        for domain in &site.domains {
            if !attrs.iter().all(|wanted| {
                domain
                    .attributes
                    .iter()
                    .any(|attr| attr.key.eq_ignore_ascii_case(wanted))
            }) {
                continue;
            }
            let atom = match domain.kind {
                0 => Atom::Keyword(domain.value.clone()),
                1 => Atom::Regex(domain.value.clone()),
                2 => Atom::Suffix(domain.value.clone()),
                3 => Atom::Full(domain.value.clone()),
                _ => return Err(Error::Asset("unknown geosite matcher")),
            };
            atoms.push(atom);
            if atoms.len() > limits.max_selectors {
                return Err(Error::Limit("geosite selectors"));
            }
        }
        let set = Arc::new(AtomSet::compile(atoms, limits, false)?);
        self.charge(&set, limits)?;
        self.site_cache.insert(key, set.clone());
        Ok(set)
    }
    pub(crate) fn ip(&mut self, raw: &str, limits: &Limits) -> Result<Arc<AtomSet>, Error> {
        let code = category(raw)?;
        if let Some(set) = self.ip_cache.get(&code) {
            return Ok(set.clone());
        }
        if self.ip_cache.len() >= limits.max_categories {
            return Err(Error::Limit("geoip categories"));
        }
        let (mut atoms, mut reverse) = (Vec::new(), false);
        if code == "PRIVATE" {
            for text in include_str!("private.txt").lines() {
                atoms.push(Atom::Ip(
                    text.parse().map_err(|_| Error::Asset("private prefixes"))?,
                ));
            }
        } else {
            if self.ips.is_none() {
                let path = self
                    .assets
                    .geoip
                    .as_ref()
                    .ok_or(Error::Asset("geoip path required"))?;
                let (bytes, stamp) = read(path, limits.asset_bytes)?;
                preflight(&bytes, false, limits)?;
                let list = IpList::decode(bytes.as_slice())
                    .map_err(|_| Error::Asset("invalid geoip protobuf"))?;
                if list.entries.len() > limits.max_selectors {
                    return Err(Error::Limit("geoip entries"));
                }
                let mut ips: BTreeMap<String, Vec<GeoIp>> = BTreeMap::new();
                for entry in list.entries {
                    ips.entry(category(&entry.code)?).or_default().push(entry);
                }
                self.ips = Some(ips);
                self.stamps.push(stamp);
            }
            let entries = self
                .ips
                .as_ref()
                .expect("loaded")
                .get(&code)
                .ok_or(Error::Asset("missing geoip category"))?;
            for (index, entry) in entries.iter().enumerate() {
                if index != 0 && entry.reverse != reverse {
                    return Err(Error::Asset("mixed geoip reverse flags"));
                }
                reverse = entry.reverse;
                for cidr in &entry.cidrs {
                    let ip = match cidr.ip.len() {
                        4 => IpAddr::V4(Ipv4Addr::from(
                            <[u8; 4]>::try_from(cidr.ip.as_slice()).expect("length"),
                        )),
                        16 => IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(cidr.ip.as_slice()).expect("length"),
                        )),
                        _ => return Err(Error::Asset("invalid geoip address")),
                    };
                    let bits = u8::try_from(cidr.prefix)
                        .map_err(|_| Error::Asset("invalid geoip prefix"))?;
                    atoms.push(Atom::Ip(
                        IpNet::new(ip, bits)
                            .map_err(|_| Error::Asset("invalid geoip prefix"))?
                            .trunc(),
                    ));
                    if atoms.len() > limits.max_selectors {
                        return Err(Error::Limit("geoip selectors"));
                    }
                }
            }
        }
        let set = Arc::new(AtomSet::compile(atoms, limits, reverse)?);
        self.charge(&set, limits)?;
        self.ip_cache.insert(code, set.clone());
        Ok(set)
    }
}
fn category(raw: &str) -> Result<String, Error> {
    let value = raw.trim().to_ascii_uppercase();
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err(Error::Selector);
    }
    Ok(value)
}
pub(crate) fn read(path: &Path, maximum: usize) -> Result<(Vec<u8>, Stamp), Error> {
    let file = File::open(path).map_err(|_| Error::Asset("unavailable"))?;
    let before = file.metadata().map_err(|_| Error::Asset("metadata"))?;
    if !before.is_file() || before.len() > maximum as u64 {
        return Err(Error::Asset("size/type"));
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Asset("read"))?;
    let after = std::fs::metadata(path).map_err(|_| Error::Asset("metadata"))?;
    if bytes.len() > maximum
        || bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || file_identity(&before) != file_identity(&after)
    {
        return Err(Error::Asset("changed during read"));
    }
    let stamp = Stamp {
        path: path.to_owned(),
        length: before.len(),
        modified: before.modified().ok(),
        identity: file_identity(&before),
        digest: Sha256::digest(&bytes).into(),
    };
    Ok((bytes, stamp))
}
#[derive(Clone, PartialEq, Message)]
struct SiteList {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<Site>,
}
#[derive(Clone, PartialEq, Message)]
struct Site {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    domains: Vec<Domain>,
}
#[derive(Clone, PartialEq, Message)]
struct Domain {
    #[prost(uint32, tag = "1")]
    kind: u32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attributes: Vec<Attribute>,
}
#[derive(Clone, PartialEq, Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
    #[prost(bool, tag = "2")]
    boolean: bool,
    #[prost(int64, tag = "3")]
    integer: i64,
}
#[derive(Clone, PartialEq, Message)]
struct IpList {
    #[prost(message, repeated, tag = "1")]
    entries: Vec<GeoIp>,
}
#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    cidrs: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    reverse: bool,
}
#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes, tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

// Preflight the repeated fields before prost allocates their object graph.
fn preflight(bytes: &[u8], site: bool, limits: &Limits) -> Result<(), Error> {
    let mut count = 0usize;
    let mut text = 0usize;
    walk(bytes, 0, site, limits, &mut count, &mut text)
}
fn varint(bytes: &[u8], at: &mut usize) -> Result<u64, Error> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *bytes.get(*at).ok_or(Error::Asset("protobuf framing"))?;
        *at += 1;
        if shift == 63 && byte > 1 {
            return Err(Error::Asset("protobuf integer"));
        }
        value |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Ok(value);
        }
    }
    Err(Error::Asset("protobuf integer"))
}
fn walk(
    bytes: &[u8],
    level: u8,
    site: bool,
    limits: &Limits,
    count: &mut usize,
    text: &mut usize,
) -> Result<(), Error> {
    let mut at = 0;
    let mut attributes = 0;
    while at < bytes.len() {
        let key = varint(bytes, &mut at)?;
        let tag = key >> 3;
        if tag == 0 {
            return Err(Error::Asset("protobuf tag"));
        }
        let length = match key & 7 {
            0 => {
                varint(bytes, &mut at)?;
                continue;
            }
            1 => 8,
            5 => 4,
            2 => usize::try_from(varint(bytes, &mut at)?)
                .map_err(|_| Error::Asset("protobuf length"))?,
            _ => return Err(Error::Asset("protobuf wire type")),
        };
        let end = at
            .checked_add(length)
            .filter(|end| *end <= bytes.len())
            .ok_or(Error::Asset("protobuf length"))?;
        if key & 7 == 2 {
            let nested = (level == 0 && tag == 1)
                || (level == 1 && tag == 2)
                || (site && level == 2 && tag == 3);
            if nested {
                *count = count.saturating_add(1);
                if *count > limits.max_selectors.saturating_mul(4) {
                    return Err(Error::Limit("asset objects"));
                }
                if level == 2 {
                    attributes += 1;
                    if attributes > 16 {
                        return Err(Error::Limit("geosite attributes"));
                    }
                }
                walk(&bytes[at..end], level + 1, site, limits, count, text)?;
            } else if (level == 1 && tag == 1)
                || (level == 2 && tag == 2 && site)
                || (level == 3 && tag == 1)
            {
                *text = text.saturating_add(length);
                if length > 4096 || *text > limits.max_selector_bytes {
                    return Err(Error::Limit("asset text"));
                }
            } else if level == 2 && !site && tag == 1 && !matches!(length, 4 | 16) {
                return Err(Error::Asset("geoip address length"));
            }
        }
        at = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::Selectors;
    #[test]
    fn protobuf_categories_attributes_reverse_sets_and_reload_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let sites = dir.path().join("geosite.dat");
        let ips = dir.path().join("geoip.dat");
        std::fs::write(
            &sites,
            SiteList {
                entries: vec![Site {
                    code: "TEST".into(),
                    domains: vec![
                        Domain {
                            kind: 2,
                            value: "example.test".into(),
                            attributes: vec![Attribute {
                                key: "ads".into(),
                                boolean: true,
                                integer: 0,
                            }],
                        },
                        Domain {
                            kind: 3,
                            value: "other.test".into(),
                            attributes: vec![],
                        },
                    ],
                }],
            }
            .encode_to_vec(),
        )
        .unwrap();
        std::fs::write(
            &ips,
            IpList {
                entries: vec![
                    GeoIp {
                        code: "INVERSE".into(),
                        reverse: true,
                        cidrs: vec![Cidr {
                            ip: vec![127, 0, 0, 0],
                            prefix: 8,
                        }],
                    },
                    GeoIp {
                        code: "EMPTY".into(),
                        reverse: true,
                        cidrs: vec![],
                    },
                ],
            }
            .encode_to_vec(),
        )
        .unwrap();
        let mut catalog = Catalog::new(Assets {
            geosite: Some(sites.clone()),
            geoip: Some(ips),
        });
        let limits = Limits::default();
        let site =
            Selectors::compile(&["geosite:test@ads".into()], &mut catalog, &limits, false).unwrap();
        assert!(site.domain("sub.example.test"));
        assert!(!site.domain("other.test"));
        let inverse =
            Selectors::compile(&["geoip:inverse".into()], &mut catalog, &limits, false).unwrap();
        assert!(!inverse.ip("127.0.0.1".parse().unwrap()));
        assert!(inverse.ip("10.0.0.1".parse().unwrap()));
        let empty =
            Selectors::compile(&["geoip:empty".into()], &mut catalog, &limits, false).unwrap();
        assert!(!empty.is_empty());
        assert!(empty.ip("::1".parse().unwrap()));
        assert!(catalog.stamps().iter().all(|s| !s.changed().unwrap()));
        std::fs::write(&sites, [0]).unwrap();
        assert!(catalog.stamps()[0].changed().unwrap());
        assert!(
            Selectors::compile(
                &["geosite:test".into()],
                &mut Catalog::new(Assets {
                    geosite: Some(sites),
                    geoip: None
                }),
                &limits,
                false
            )
            .is_err()
        );
    }
    #[test]
    fn protobuf_preflight_bounds_empty_object_amplification() {
        let input = SiteList {
            entries: vec![Site {
                code: "X".into(),
                domains: vec![
                    Domain {
                        kind: 0,
                        value: String::new(),
                        attributes: vec![]
                    };
                    100
                ],
            }],
        }
        .encode_to_vec();
        assert!(
            preflight(
                &input,
                true,
                &Limits {
                    max_selectors: 4,
                    ..Default::default()
                }
            )
            .is_err()
        );
        for bytes in [&[0x0a, 0xff][..], &[0x0a, 0x7f, 0][..], &[0][..]] {
            assert!(preflight(bytes, true, &Limits::default()).is_err());
        }
    }
}
