// SPDX-License-Identifier: GPL-3.0-only
//! Bounded startup catalogs. Registration is atomic; runtime catalogs are immutable.
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidName,
    Duplicate,
    Capacity,
    Empty,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "registry: {self:?}")
    }
}
impl std::error::Error for Error {}

pub(crate) struct Catalog<T: ?Sized> {
    entries: Vec<(String, Arc<T>)>,
    names: BTreeMap<String, usize>,
}
impl<T: ?Sized> Default for Catalog<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            names: BTreeMap::new(),
        }
    }
}
impl<T: ?Sized> Catalog<T> {
    pub fn register(
        &mut self,
        name: &str,
        aliases: &[&str],
        provider: Arc<T>,
    ) -> Result<(), Error> {
        let names = std::iter::once(name)
            .chain(aliases.iter().copied())
            .map(normalize)
            .collect::<Result<Vec<_>, _>>()?;
        if self.entries.len() >= 64 || self.names.len().saturating_add(names.len()) > 256 {
            return Err(Error::Capacity);
        }
        let mut unique = std::collections::BTreeSet::new();
        if names
            .iter()
            .any(|name| self.names.contains_key(name) || !unique.insert(name))
        {
            return Err(Error::Duplicate);
        }
        let index = self.entries.len();
        self.entries.push((names[0].clone(), provider));
        for name in names {
            self.names.insert(name, index);
        }
        Ok(())
    }
    pub fn get(&self, name: &str) -> Option<(&str, &Arc<T>)> {
        let entry = &self.entries[*self.names.get(&normalize(name).ok()?)?];
        Some((&entry.0, &entry.1))
    }
    pub fn entries(&self) -> impl Iterator<Item = (&str, &Arc<T>)> {
        self.entries
            .iter()
            .map(|(name, provider)| (name.as_str(), provider))
    }
}
fn normalize(name: &str) -> Result<String, Error> {
    let name = name.trim().to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::InvalidName);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_is_atomic_normalized_and_bounded() {
        let mut catalog = Catalog::default();
        catalog.register("TCP", &["raw"], Arc::new(1)).unwrap();
        assert_eq!(
            catalog
                .get(" RAW ")
                .map(|(name, provider)| (name, **provider)),
            Some(("tcp", 1))
        );
        assert_eq!(
            catalog.register("quic", &["udp", "RAW"], Arc::new(2)),
            Err(Error::Duplicate)
        );
        assert!(catalog.get("quic").is_none());
        assert!(catalog.get("udp").is_none());
        assert_eq!(
            catalog.register("tls", &["TLS"], Arc::new(2)),
            Err(Error::Duplicate)
        );
        assert_eq!(
            catalog.register("bad/name", &[], Arc::new(2)),
            Err(Error::InvalidName)
        );
        for i in 0..63 {
            catalog
                .register(&format!("p{i}"), &[], Arc::new(i))
                .unwrap();
        }
        assert_eq!(
            catalog.register("overflow", &[], Arc::new(0)),
            Err(Error::Capacity)
        );
        assert_eq!(catalog.entries().count(), 64);
    }
}
