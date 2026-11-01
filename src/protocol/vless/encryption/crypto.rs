// SPDX-License-Identifier: MPL-2.0
// See THIRD_PARTY.md for protocol sources.

use super::{Error, blake3_reference::Hasher};
use aes::Aes256;
use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace, KeyInit},
};
use chacha20poly1305::ChaCha20Poly1305;
use ctr::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

pub(crate) fn derive(context: &[u8], key: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Hasher::new_derive_key(context);
    h.update(key);
    let mut result = Zeroizing::new([0; 32]);
    h.finalize(result.as_mut());
    result
}
pub(crate) fn hash(value: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(value);
    let mut result = [0; 32];
    h.finalize(&mut result);
    result
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}
enum Primitive {
    Aes(Box<Aes256Gcm>),
    ChaCha(Box<ChaCha20Poly1305>),
}
pub(crate) struct Aead {
    primitive: Primitive,
    pub(crate) nonce: [u8; 12],
    pub(crate) cipher: Cipher,
}
impl Aead {
    pub(crate) fn new(context: &[u8], key: &[u8], cipher: Cipher) -> Self {
        let key = derive(context, key);
        Self {
            primitive: match cipher {
                Cipher::Aes256Gcm => Primitive::Aes(Box::new(Aes256Gcm::new((&*key).into()))),
                Cipher::ChaCha20Poly1305 => {
                    Primitive::ChaCha(Box::new(ChaCha20Poly1305::new((&*key).into())))
                }
            },
            nonce: [0; 12],
            cipher,
        }
    }
    fn next(&mut self) -> [u8; 12] {
        for b in self.nonce.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        self.nonce
    }
    pub(crate) fn seal(
        &mut self,
        body: &mut [u8],
        aad: &[u8],
        explicit: Option<[u8; 12]>,
    ) -> Result<(), Error> {
        if body.len() < 16 {
            return Err(Error::InvalidRecord);
        }
        let nonce = explicit.unwrap_or_else(|| self.next());
        let at = body.len() - 16;
        let (data, tag) = body.split_at_mut(at);
        let result = match &self.primitive {
            Primitive::Aes(c) => c.encrypt_in_place_detached((&nonce).into(), aad, data),
            Primitive::ChaCha(c) => c.encrypt_in_place_detached((&nonce).into(), aad, data),
        }
        .map_err(|_| Error::Authentication)?;
        tag.copy_from_slice(&result);
        Ok(())
    }
    pub(crate) fn open(
        &mut self,
        body: &mut [u8],
        aad: &[u8],
        explicit: Option<[u8; 12]>,
    ) -> Result<usize, Error> {
        if body.len() < 16 {
            return Err(Error::InvalidRecord);
        }
        let nonce = explicit.unwrap_or_else(|| self.next());
        let at = body.len() - 16;
        let (data, tag) = body.split_at_mut(at);
        match &self.primitive {
            Primitive::Aes(c) => {
                c.decrypt_in_place_detached((&nonce).into(), aad, data, (&*tag).into())
            }
            Primitive::ChaCha(c) => {
                c.decrypt_in_place_detached((&nonce).into(), aad, data, (&*tag).into())
            }
        }
        .map_err(|_| Error::Authentication)?;
        Ok(at)
    }
}
pub(crate) struct Mask(ctr::Ctr128BE<Aes256>);
impl Mask {
    pub(crate) fn new(key: &[u8], iv: &[u8; 16]) -> Self {
        let key = derive(b"VLESS", key);
        Self(ctr::Ctr128BE::<Aes256>::new((&*key).into(), iv.into()))
    }
    pub(crate) fn apply(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.0
            .try_apply_keystream(data)
            .map_err(|_| Error::InvalidRecord)
    }
}
