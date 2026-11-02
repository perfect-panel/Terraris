// SPDX-License-Identifier: GPL-3.0-only
// SIP004/007/022/023 wire cryptography, implemented with RustCrypto/BLAKE3.
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, aead::AeadInPlace};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use sha2::{Digest, Sha256};
use std::{io, sync::Arc};
use zeroize::{Zeroize, Zeroizing};

pub const TAG: usize = 16;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    Aes128,
    Aes192,
    Aes256,
    ChaCha20,
    XChaCha20,
    Aes128_2022,
    Aes256_2022,
    ChaCha20_2022,
}
impl Method {
    pub fn parse(name: &str) -> io::Result<Self> {
        Ok(match name.trim().to_ascii_lowercase().as_str() {
            "aes-128-gcm" | "aead_aes_128_gcm" => Self::Aes128,
            "aes-192-gcm" => Self::Aes192,
            "aes-256-gcm" | "aead_aes_256_gcm" => Self::Aes256,
            "chacha20-ietf-poly1305" | "chacha20-poly1305" | "aead_chacha20_poly1305" => {
                Self::ChaCha20
            }
            "xchacha20-ietf-poly1305" => Self::XChaCha20,
            "2022-blake3-aes-128-gcm" => Self::Aes128_2022,
            "2022-blake3-aes-256-gcm" => Self::Aes256_2022,
            "2022-blake3-chacha20-poly1305" => Self::ChaCha20_2022,
            _ => return Err(bad()),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Aes128 => "aes-128-gcm",
            Self::Aes192 => "aes-192-gcm",
            Self::Aes256 => "aes-256-gcm",
            Self::ChaCha20 => "chacha20-ietf-poly1305",
            Self::XChaCha20 => "xchacha20-ietf-poly1305",
            Self::Aes128_2022 => "2022-blake3-aes-128-gcm",
            Self::Aes256_2022 => "2022-blake3-aes-256-gcm",
            Self::ChaCha20_2022 => "2022-blake3-chacha20-poly1305",
        }
    }
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes128_2022 => 16,
            Self::Aes192 => 24,
            _ => 32,
        }
    }
    pub fn modern(self) -> bool {
        matches!(
            self,
            Self::Aes128_2022 | Self::Aes256_2022 | Self::ChaCha20_2022
        )
    }
    pub fn identity(self) -> bool {
        matches!(self, Self::Aes128_2022 | Self::Aes256_2022)
    }
    pub fn nonce_len(self) -> usize {
        if self == Self::XChaCha20 { 24 } else { 12 }
    }
    pub fn record_limit(self) -> usize {
        if self.modern() { 65535 } else { 16383 }
    }
    pub fn user_key(self, credential: &str) -> io::Result<Arc<Key>> {
        if credential.is_empty() {
            return Err(bad());
        }
        let bytes = if self.modern() {
            if credential.len() < self.key_len() {
                return Err(bad());
            }
            Zeroizing::new(credential.as_bytes()[..self.key_len()].to_vec())
        } else {
            password_key(credential.as_bytes(), self.key_len())
        };
        Key::new(self, &bytes)
    }
    pub fn password(self, password: &str) -> io::Result<Vec<Arc<Key>>> {
        if password.is_empty() {
            return Err(bad());
        }
        if !self.modern() {
            return Ok(vec![Key::new(
                self,
                &password_key(password.as_bytes(), self.key_len()),
            )?]);
        }
        let parts = password.split(':').collect::<Vec<_>>();
        if parts.is_empty() || parts.len() > 8 || !self.identity() && parts.len() != 1 {
            return Err(bad());
        }
        parts
            .into_iter()
            .map(|part| {
                let raw = Zeroizing::new(
                    STANDARD
                        .decode(part)
                        .or_else(|_| STANDARD_NO_PAD.decode(part))
                        .map_err(|_| bad())?,
                );
                Key::new(self, &raw)
            })
            .collect()
    }
    pub fn subkey(self, key: &Key, salt: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut output = Zeroizing::new(vec![0; self.key_len()]);
        if self.modern() {
            let mut input = Zeroizing::new(Vec::with_capacity(key.bytes.len() + salt.len()));
            input.extend_from_slice(&key.bytes);
            input.extend_from_slice(salt);
            let derived = Zeroizing::new(blake3::derive_key(
                "shadowsocks 2022 session subkey",
                &input,
            ));
            output.copy_from_slice(&derived[..self.key_len()]);
        } else {
            hkdf::Hkdf::<sha1::Sha1>::new(Some(salt), &key.bytes)
                .expand(b"ss-subkey", &mut output)
                .map_err(|_| bad())?;
        }
        Ok(output)
    }
    pub fn session(self, key: &Key, salt: &[u8]) -> io::Result<Counter> {
        Counter::new(self, &self.subkey(key, salt)?)
    }
    pub fn cipher(self, key: &[u8]) -> io::Result<Cipher> {
        Cipher::new(self, key)
    }
    pub fn identity_cipher(
        self,
        key: &Key,
        salt: &[u8],
        block: &mut [u8; 16],
        encrypt: bool,
    ) -> io::Result<()> {
        if !self.identity() {
            return Err(bad());
        }
        let mut input = Zeroizing::new(Vec::with_capacity(key.bytes.len() + salt.len()));
        input.extend_from_slice(&key.bytes);
        input.extend_from_slice(salt);
        let output = Zeroizing::new(blake3::derive_key(
            "shadowsocks 2022 identity subkey",
            &input,
        ));
        block_cipher(&output[..self.key_len()], block, encrypt)
    }
}
pub struct Key {
    bytes: Zeroizing<Vec<u8>>,
    pub id: [u8; 32],
    pub identity: [u8; 16],
}
impl Key {
    pub fn new(method: Method, bytes: &[u8]) -> io::Result<Arc<Self>> {
        if bytes.len() != method.key_len() {
            return Err(bad());
        }
        let mut h = Sha256::new();
        h.update(method.name());
        h.update(bytes);
        let mut identity = [0; 16];
        identity.copy_from_slice(&blake3::hash(bytes).as_bytes()[..16]);
        Ok(Arc::new(Self {
            bytes: Zeroizing::new(bytes.to_vec()),
            id: h.finalize().into(),
            identity,
        }))
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn block(&self, value: &mut [u8; 16], encrypt: bool) -> io::Result<()> {
        block_cipher(&self.bytes, value, encrypt)
    }
}
fn password_key(password: &[u8], length: usize) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(length));
    let mut previous = Zeroizing::new(Vec::new());
    while output.len() < length {
        let mut hash = md5::Md5::new();
        hash.update(&previous);
        hash.update(password);
        previous.zeroize();
        *previous = hash.finalize().to_vec();
        let n = (length - output.len()).min(previous.len());
        output.extend_from_slice(&previous[..n]);
    }
    output
}
fn block_cipher(key: &[u8], value: &mut [u8; 16], encrypt: bool) -> io::Result<()> {
    use aes::cipher::generic_array::GenericArray;
    let block = GenericArray::from_mut_slice(value);
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key).map_err(|_| bad())?;
            if encrypt {
                cipher.encrypt_block(block)
            } else {
                cipher.decrypt_block(block)
            }
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key).map_err(|_| bad())?;
            if encrypt {
                cipher.encrypt_block(block)
            } else {
                cipher.decrypt_block(block)
            }
        }
        _ => return Err(bad()),
    };
    Ok(())
}
type Aes192Gcm = AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>;
pub enum Cipher {
    A128(Box<Aes128Gcm>),
    A192(Box<Aes192Gcm>),
    A256(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
    XChaCha(Box<XChaCha20Poly1305>),
}
impl Cipher {
    pub fn new(method: Method, key: &[u8]) -> io::Result<Self> {
        Ok(match method {
            Method::Aes128 | Method::Aes128_2022 => {
                Self::A128(Box::new(Aes128Gcm::new_from_slice(key).map_err(|_| bad())?))
            }
            Method::Aes192 => {
                Self::A192(Box::new(Aes192Gcm::new_from_slice(key).map_err(|_| bad())?))
            }
            Method::Aes256 | Method::Aes256_2022 => {
                Self::A256(Box::new(Aes256Gcm::new_from_slice(key).map_err(|_| bad())?))
            }
            Method::ChaCha20 | Method::ChaCha20_2022 => Self::ChaCha(Box::new(
                ChaCha20Poly1305::new_from_slice(key).map_err(|_| bad())?,
            )),
            Method::XChaCha20 => Self::XChaCha(Box::new(
                XChaCha20Poly1305::new_from_slice(key).map_err(|_| bad())?,
            )),
        })
    }
    pub fn seal(&self, nonce: &[u8], data: &mut [u8]) -> io::Result<[u8; 16]> {
        if nonce.len()
            != if matches!(self, Self::XChaCha(_)) {
                24
            } else {
                12
            }
        {
            return Err(bad());
        }
        macro_rules! seal {
            ($c:expr) => {{
                $c.encrypt_in_place_detached(nonce.into(), b"", data)
                    .map_err(|_| bad())
                    .map(Into::into)
            }};
        }
        match self {
            Self::A128(c) => seal!(c),
            Self::A192(c) => seal!(c),
            Self::A256(c) => seal!(c),
            Self::ChaCha(c) => seal!(c),
            Self::XChaCha(c) => seal!(c),
        }
    }
    pub fn open(&self, nonce: &[u8], data: &mut [u8], tag: &[u8]) -> io::Result<()> {
        if tag.len() != 16
            || nonce.len()
                != if matches!(self, Self::XChaCha(_)) {
                    24
                } else {
                    12
                }
        {
            return Err(bad());
        }
        macro_rules! open {
            ($c:expr) => {{
                $c.decrypt_in_place_detached(nonce.into(), b"", data, tag.into())
                    .map_err(|_| bad())
            }};
        }
        match self {
            Self::A128(c) => open!(c),
            Self::A192(c) => open!(c),
            Self::A256(c) => open!(c),
            Self::ChaCha(c) => open!(c),
            Self::XChaCha(c) => open!(c),
        }
    }
}
pub struct Counter {
    cipher: Cipher,
    nonce: [u8; 24],
    size: usize,
    exhausted: bool,
}
impl Counter {
    fn new(method: Method, key: &[u8]) -> io::Result<Self> {
        Ok(Self {
            cipher: Cipher::new(method, key)?,
            nonce: [0; 24],
            size: method.nonce_len(),
            exhausted: false,
        })
    }
    fn advance(&mut self) {
        for v in &mut self.nonce[..self.size] {
            let (n, overflow) = v.overflowing_add(1);
            *v = n;
            if !overflow {
                return;
            }
        }
        self.exhausted = true;
    }
    pub fn seal(&mut self, data: &mut [u8]) -> io::Result<[u8; 16]> {
        if self.exhausted {
            return Err(bad());
        }
        let tag = self.cipher.seal(&self.nonce[..self.size], data)?;
        self.advance();
        Ok(tag)
    }
    pub fn open(&mut self, data: &mut [u8], tag: &[u8]) -> io::Result<()> {
        if self.exhausted {
            return Err(bad());
        }
        self.cipher.open(&self.nonce[..self.size], data, tag)?;
        self.advance();
        Ok(())
    }
}
pub fn random(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::fill(bytes).map_err(|_| io::ErrorKind::Other.into())
}
pub fn now() -> io::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| bad())
}
pub fn timestamp(value: u64) -> io::Result<()> {
    if now()?.abs_diff(value) > 30 {
        Err(bad())
    } else {
        Ok(())
    }
}
pub fn bad() -> io::Error {
    io::ErrorKind::InvalidData.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks_exact(2)
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }
    #[test]
    fn independent_go_known_answers_cover_all_methods_and_identity_headers() {
        let values: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/interop/shadowsocks/vectors.json"
        ))
        .unwrap();
        assert_eq!(values.as_array().unwrap().len(), 8);
        for value in values.as_array().unwrap() {
            let method = Method::parse(value["cipher"].as_str().unwrap()).unwrap();
            let key = method
                .password(value["password"].as_str().unwrap())
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(key.bytes(), hex(value["master"].as_str().unwrap()));
            let salt = hex(value["salt"].as_str().unwrap());
            assert_eq!(
                method.subkey(&key, &salt).unwrap().as_slice(),
                hex(value["subkey"].as_str().unwrap())
            );
            let mut counter = method.session(&key, &salt).unwrap();
            let mut length = hex(value["length"].as_str().unwrap());
            let tag = length.split_off(2);
            counter.open(&mut length, &tag).unwrap();
            let mut payload = hex(value["payload"].as_str().unwrap());
            let tag = payload.split_off(payload.len() - TAG);
            counter.open(&mut payload, &tag).unwrap();
            assert_eq!(
                u16::from_be_bytes(length.try_into().unwrap()) as usize,
                payload.len()
            );
            assert_eq!(payload, value["plaintext"].as_str().unwrap().as_bytes());
            let mut sender = method.session(&key, &salt).unwrap();
            let mut length = (payload.len() as u16).to_be_bytes().to_vec();
            let tag = sender.seal(&mut length).unwrap();
            length.extend(tag);
            assert_eq!(length, hex(value["length"].as_str().unwrap()));
            let tag = sender.seal(&mut payload).unwrap();
            payload.extend(tag);
            assert_eq!(payload, hex(value["payload"].as_str().unwrap()));
            if method.identity() {
                let server = Key::new(method, &hex(value["server_key"].as_str().unwrap())).unwrap();
                let mut identity = key.identity;
                method
                    .identity_cipher(&server, &salt, &mut identity, true)
                    .unwrap();
                assert_eq!(
                    identity.to_vec(),
                    hex(value["identity_header"].as_str().unwrap())
                );
                method
                    .identity_cipher(&server, &salt, &mut identity, false)
                    .unwrap();
                assert_eq!(identity, key.identity);
            }
        }
    }
    #[test]
    fn key_validation_nonce_overflow_and_tag_failures_do_not_wrap() {
        for name in [
            "aes-128-gcm",
            "aes-192-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let method = Method::parse(name).unwrap();
            let raw = vec![71; method.key_len()];
            let key = Key::new(method, &raw).unwrap();
            let mut c = method.session(&key, &raw).unwrap();
            c.nonce[..c.size].fill(255);
            c.seal(&mut [0; 4]).unwrap();
            assert!(c.seal(&mut [0; 4]).is_err());
            let cipher = method.cipher(&raw).unwrap();
            assert!(cipher.seal(&[], &mut [0; 4]).is_err());
            assert!(cipher.open(&[], &mut [0; 4], &[0; 16]).is_err());
            let nonce = vec![0; method.nonce_len()];
            let mut data = [0; 4];
            let mut tag = cipher.seal(&nonce, &mut data).unwrap();
            tag[0] ^= 1;
            assert!(cipher.open(&nonce, &mut data, &tag).is_err());
            if method.modern() {
                assert!(method.password("plaintext-password").is_err());
                assert!(
                    method
                        .password(&STANDARD.encode(vec![0; method.key_len() + 1]))
                        .is_err()
                );
            }
        }
        assert!(Method::parse("aes-128-cfb").is_err());
        assert_eq!(Method::parse("AEAD_AES_128_GCM").unwrap(), Method::Aes128);
        let key = STANDARD.encode([7; 32]);
        assert!(
            Method::ChaCha20_2022
                .password(&format!("{key}:{key}"))
                .is_err()
        );
    }
}
