// SPDX-License-Identifier: GPL-3.0-only
//! Operator-owned PEM identities. A candidate owns an immutable TLS identity;
//! file changes trigger normal generation publication rather than mutating it.
use crate::{
    panel::{CertificateFingerprint, ProtocolConfig},
    route::geodata::{self, Stamp},
    transport::Error,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub protocols: BTreeMap<String, Files>,
}
impl Settings {
    pub fn validate(&self) -> Result<(), Error> {
        if self.cert_file.is_some() != self.key_file.is_some() || self.protocols.len() > 64 {
            return Err(Error::Configuration("TLS certificate settings"));
        }
        for path in self.cert_file.iter().chain(self.key_file.iter()).chain(
            self.protocols
                .values()
                .flat_map(|f| [&f.cert_file, &f.key_file]),
        ) {
            if path.as_os_str().is_empty() {
                return Err(Error::Configuration("empty TLS file path"));
            }
        }
        for name in self.protocols.keys() {
            if crate::panel::ProtocolName::new(name)
                .map_err(|_| Error::Configuration("TLS protocol name"))?
                .as_str()
                != name
            {
                return Err(Error::Configuration("TLS protocol names must be canonical"));
            }
        }
        Ok(())
    }
    pub fn resolve_paths(&mut self, base: &Path) {
        for path in self
            .cert_file
            .iter_mut()
            .chain(self.key_file.iter_mut())
            .chain(
                self.protocols
                    .values_mut()
                    .flat_map(|f| [&mut f.cert_file, &mut f.key_file]),
            )
        {
            if path.is_relative() {
                *path = base.join(&*path);
            }
        }
    }
    pub fn prepare(&self, config: &ProtocolConfig) -> Result<Identity, Error> {
        self.validate()?;
        let (cert, key) = if let Some(files) = self.protocols.get(config.protocol.as_str()) {
            (&files.cert_file, &files.key_file)
        } else {
            (
                self.cert_file
                    .as_ref()
                    .ok_or(Error::Configuration("TLS certificate file required"))?,
                self.key_file
                    .as_ref()
                    .ok_or(Error::Configuration("TLS private key file required"))?,
            )
        };
        let (pem, cert_stamp) = geodata::read(cert, 1 << 20)
            .map_err(|_| Error::Configuration("TLS certificate file"))?;
        let (pem_key, key_stamp) = geodata::read(key, 1 << 20)
            .map_err(|_| Error::Configuration("TLS private key file"))?;
        let pem_key = zeroize::Zeroizing::new(pem_key);
        let chain = rustls_pemfile::certs(&mut pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Error::Configuration("TLS certificate PEM"))?;
        if chain.is_empty() || chain.len() > 16 {
            return Err(Error::Configuration("TLS certificate chain"));
        }
        let fingerprint =
            CertificateFingerprint::new(&format!("{:x}", Sha256::digest(chain[0].as_ref())))
                .map_err(|_| Error::Configuration("TLS fingerprint"))?;
        let mut key_reader = pem_key.as_slice();
        let mut keys = rustls_pemfile::read_all(&mut key_reader);
        let mut private_key = None;
        for item in &mut keys {
            let item = item.map_err(|_| Error::Configuration("TLS private key PEM"))?;
            let next = match item {
                rustls_pemfile::Item::Pkcs1Key(key) => {
                    Some(rustls::pki_types::PrivateKeyDer::Pkcs1(key))
                }
                rustls_pemfile::Item::Pkcs8Key(key) => {
                    Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key))
                }
                rustls_pemfile::Item::Sec1Key(key) => {
                    Some(rustls::pki_types::PrivateKeyDer::Sec1(key))
                }
                _ => None,
            };
            if next.is_some() {
                if private_key.is_some() {
                    return Err(Error::Configuration("multiple TLS private keys"));
                }
                private_key = next;
            }
        }
        let key = private_key.ok_or(Error::Configuration("TLS private key required"))?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .map_err(|_| Error::Tls)?
            .with_no_client_auth();
        let mut tls = if config.sni.is_empty() {
            builder
                .with_single_cert(chain, key)
                .map_err(|_| Error::Configuration("TLS certificate/key mismatch"))?
        } else {
            let key = rustls::sign::CertifiedKey::from_der(chain, key, &provider)
                .map_err(|_| Error::Configuration("TLS certificate/key mismatch"))?;
            let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
            resolver
                .add(&config.sni, key)
                .map_err(|_| Error::Configuration("TLS certificate/SNI mismatch"))?;
            builder.with_cert_resolver(Arc::new(resolver))
        };
        if config.alpn.len() > 16 || config.alpn.iter().any(|v| v.is_empty() || v.len() > 255) {
            return Err(Error::Configuration("TLS ALPN"));
        }
        tls.alpn_protocols = config.alpn.iter().map(|v| v.as_bytes().to_vec()).collect();
        // Do not accept replayable 0-RTT application data for proxy authentication.
        tls.max_early_data_size = 0;
        if cert_stamp
            .changed()
            .map_err(|_| Error::Configuration("TLS certificate file"))?
            || key_stamp
                .changed()
                .map_err(|_| Error::Configuration("TLS private key file"))?
        {
            return Err(Error::Configuration("TLS files changed during preparation"));
        }
        Ok(Identity {
            config: Arc::new(tls),
            fingerprint,
            stamps: [cert_stamp, key_stamp],
        })
    }
}
pub struct Identity {
    pub config: Arc<rustls::ServerConfig>,
    pub fingerprint: CertificateFingerprint,
    stamps: [Stamp; 2],
}
impl Identity {
    pub fn reload_required(&self) -> Result<bool, Error> {
        for stamp in &self.stamps {
            if stamp
                .changed()
                .map_err(|_| Error::Configuration("TLS identity unavailable"))?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
