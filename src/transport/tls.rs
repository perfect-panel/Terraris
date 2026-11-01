// SPDX-License-Identifier: GPL-3.0-only
use super::Error;
use std::sync::Arc;

pub(super) fn configure(
    config: &crate::panel::Outbound,
    roots: Arc<rustls::ClientConfig>,
) -> Result<Option<Arc<rustls::ClientConfig>>, Error> {
    match config.security.as_str() {
        "" | "none" => {
            if !config.sni.is_empty() || !config.alpn.is_empty() || config.allow_insecure {
                return Err(Error::Configuration("TLS options without TLS"));
            }
            Ok(None)
        }
        "tls" => {
            if config.alpn.len() > 16 || config.alpn.iter().any(|v| v.is_empty() || v.len() > 255) {
                return Err(Error::Configuration("ALPN"));
            }
            let mut tls = (*roots).clone();
            tls.alpn_protocols = config.alpn.iter().map(|v| v.as_bytes().to_vec()).collect();
            if config.allow_insecure {
                tls.dangerous().set_certificate_verifier(Arc::new(Insecure {
                    provider: rustls::crypto::aws_lc_rs::default_provider(),
                }));
            }
            Ok(Some(Arc::new(tls)))
        }
        _ => Err(Error::Unsupported),
    }
}

#[derive(Debug)]
struct Insecure {
    provider: rustls::crypto::CryptoProvider,
}
impl rustls::client::danger::ServerCertVerifier for Insecure {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
