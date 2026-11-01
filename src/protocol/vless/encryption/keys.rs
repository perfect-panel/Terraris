// SPDX-License-Identifier: MPL-2.0
// See THIRD_PARTY.md for protocol sources.

use super::{Error, random};
use ml_kem::{
    Decapsulate, KeyExport,
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub(crate) enum ServerKey {
    X25519(StaticSecret),
    MlKem(Box<DecapsulationKey>),
}
impl ServerKey {
    pub(crate) fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        match seed.len() {
            32 => Ok(Self::X25519(StaticSecret::from(
                <[u8; 32]>::try_from(seed).map_err(|_| Error::InvalidKey)?,
            ))),
            64 => Ok(Self::MlKem(Box::new(DecapsulationKey::from_seed(
                <[u8; 64]>::try_from(seed)
                    .map_err(|_| Error::InvalidKey)?
                    .into(),
            )))),
            _ => Err(Error::InvalidKey),
        }
    }
    pub(crate) fn public(&self) -> Vec<u8> {
        match self {
            Self::X25519(k) => PublicKey::from(k).as_bytes().to_vec(),
            Self::MlKem(k) => k.encapsulation_key().to_bytes().to_vec(),
        }
    }
    pub(crate) fn relay_len(&self) -> usize {
        match self {
            Self::X25519(_) => 32,
            Self::MlKem(_) => 1088,
        }
    }
    pub(crate) fn decapsulate(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        match self {
            Self::X25519(secret) => {
                let public: [u8; 32] = peer.try_into().map_err(|_| Error::InvalidKey)?;
                if public[31] & 0x80 != 0 {
                    return Err(Error::InvalidKey);
                }
                let shared = secret.diffie_hellman(&PublicKey::from(public));
                if !shared.was_contributory() {
                    return Err(Error::InvalidKey);
                }
                Ok(Zeroizing::new(shared.to_bytes()))
            }
            Self::MlKem(secret) => {
                let ciphertext = Ciphertext::try_from(peer).map_err(|_| Error::InvalidKey)?;
                let shared = secret.decapsulate(&ciphertext);
                Ok(Zeroizing::new(shared.into()))
            }
        }
    }
}
pub(crate) fn pfs(peer: &[u8]) -> Result<([u8; 1120], Zeroizing<[u8; 64]>), Error> {
    if peer.len() < 1216 {
        return Err(Error::InvalidKey);
    }
    let encoded =
        ml_kem::Key::<EncapsulationKey>::try_from(&peer[..1184]).map_err(|_| Error::InvalidKey)?;
    let kem = EncapsulationKey::new(&encoded).map_err(|_| Error::InvalidKey)?;
    let randomness = Zeroizing::new(random::<32>()?);
    let (ciphertext, kem_shared) = kem.encapsulate_deterministic(&(*randomness).into());
    let x = StaticSecret::from(random::<32>()?);
    let peer_x: [u8; 32] = peer[1184..1216].try_into().map_err(|_| Error::InvalidKey)?;
    if peer_x[31] & 0x80 != 0 {
        return Err(Error::InvalidKey);
    }
    let shared = x.diffie_hellman(&PublicKey::from(peer_x));
    if !shared.was_contributory() {
        return Err(Error::InvalidKey);
    }
    let mut response = [0; 1120];
    response[..1088].copy_from_slice(&ciphertext);
    response[1088..].copy_from_slice(PublicKey::from(&x).as_bytes());
    let mut key = Zeroizing::new([0; 64]);
    key[..32].copy_from_slice(&kem_shared);
    key[32..].copy_from_slice(shared.as_bytes());
    Ok((response, key))
}
