// SPDX-License-Identifier: MPL-2.0
// Xray-compatible client handshake; see THIRD_PARTY.md for the pinned peer.
use super::{
    Error, Mode, Padding,
    crypto::{Aead, Cipher, Mask, hash},
    random,
    stream::{EncryptedStream, State},
};
use crate::{
    buffer::{BufferLayout, BufferScope},
    panel::Outbound,
    time::OperationContext,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ml_kem::{
    Decapsulate, KeyExport,
    ml_kem_768::{Ciphertext, DecapsulationKey, EncapsulationKey},
};
use std::{
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;
#[derive(Clone)]
pub struct ClientConfig {
    mode: Mode,
    resume: bool,
    padding: Padding,
    keys: Vec<Vec<u8>>,
}
impl ClientConfig {
    pub fn from_panel(value: &Outbound) -> Result<Option<Self>, Error> {
        if value.encryption.is_empty() || value.encryption == "none" {
            if !value.encryption_mode.is_empty()
                || !value.encryption_rtt.is_empty()
                || !value.encryption_ticket.expose().is_empty()
                || !value.encryption_client_padding.is_empty()
                || !value.encryption_password.expose().is_empty()
            {
                return Err(Error::Configuration("options without encryption"));
            }
            return Ok(None);
        }
        if !value.encryption_ticket.expose().is_empty() {
            return Err(Error::Configuration("outbound ticket"));
        }
        if value.encryption_password.expose().len() > 16384 {
            return Err(Error::Configuration("public key chain length"));
        }
        let padding = if value.encryption_client_padding.is_empty() {
            String::new()
        } else {
            format!("{}.", value.encryption_client_padding)
        };
        Self::parse(&format!(
            "{}.{}.{}.{}{}",
            value.encryption,
            value.encryption_mode,
            value.encryption_rtt,
            padding,
            value.encryption_password.expose()
        ))
        .map(Some)
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        if value.len() > 32768 {
            return Err(Error::Configuration("client configuration length"));
        }
        let fields: Vec<_> = value.split('.').collect();
        if fields.len() < 4 || fields[0] != "mlkem768x25519plus" {
            return Err(Error::Configuration("method"));
        }
        let mode = match fields[1] {
            "native" => Mode::Native,
            "xorpub" => Mode::XorPub,
            "random" => Mode::Random,
            _ => return Err(Error::Configuration("appearance")),
        };
        let resume = match fields[2] {
            "0rtt" => true,
            "1rtt" => false,
            _ => return Err(Error::Configuration("RTT")),
        };
        let mut keys = Vec::new();
        let mut padding = Vec::new();
        for field in &fields[3..] {
            let decoded = URL_SAFE_NO_PAD.decode(field).ok();
            if let Some(key) = decoded.filter(|v| matches!(v.len(), 32 | 1184)) {
                if keys.len() >= 8 {
                    return Err(Error::Configuration("key count"));
                }
                if key.len() == 1184 {
                    let encoded = ml_kem::Key::<EncapsulationKey>::try_from(key.as_slice())
                        .map_err(|_| Error::InvalidKey)?;
                    EncapsulationKey::new(&encoded).map_err(|_| Error::InvalidKey)?;
                } else if key[31] & 128 != 0 {
                    return Err(Error::InvalidKey);
                }
                keys.push(key);
            } else if keys.is_empty() {
                padding.push(*field);
            } else {
                return Err(Error::InvalidKey);
            }
        }
        if keys.is_empty() {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            mode,
            resume,
            padding: Padding::parse(&padding.join("."))?,
            keys,
        })
    }
}
struct Ticket {
    pfs: Zeroizing<[u8; 64]>,
    ticket: [u8; 16],
    expires: Instant,
}
struct Cache {
    ticket: Mutex<Option<Ticket>>,
}
pub(crate) struct Resume {
    cache: Weak<Cache>,
    ticket: [u8; 16],
}
impl Resume {
    pub(crate) fn invalidate(&self) {
        if let Some(cache) = self.cache.upgrade() {
            let mut ticket = cache.ticket.lock().unwrap_or_else(|e| e.into_inner());
            if ticket
                .as_ref()
                .is_some_and(|value| value.ticket == self.ticket)
            {
                *ticket = None;
            }
        }
    }
}
pub struct Client {
    config: ClientConfig,
    cache: Arc<Cache>,
}
impl Client {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            cache: Arc::new(Cache {
                ticket: Mutex::new(None),
            }),
        }
    }
    pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut io: S,
        buffers: &BufferScope,
        context: &OperationContext,
    ) -> Result<EncryptedStream<S>, Error> {
        let (state, pending, resume) = context
            .run(Box::pin(self.prepare(&mut io, buffers)))
            .await
            .map_err(|_| Error::Closed)??;
        let mut stream = EncryptedStream::new(io, state, buffers)?;
        if let Some(cipher) = pending {
            stream.pending_server_iv(cipher, self.config.mode == Mode::Random);
        }
        stream.resume_guard(resume);
        Ok(stream)
    }
    async fn prepare<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: &mut S,
        buffers: &BufferScope,
    ) -> Result<(State, Option<Cipher>, Option<Resume>), Error> {
        let cipher = Cipher::Aes256Gcm;
        let iv = random::<16>()?;
        let relay_length = self
            .config
            .keys
            .iter()
            .map(|key| if key.len() == 32 { 64 } else { 1120 })
            .sum::<usize>()
            - 32;
        let mut relays = lease(buffers, relay_length)?;
        let mut relay_offset = 0;
        let mut previous: Option<Mask> = None;
        let mut nfs = Zeroizing::new([0; 32]);
        for (index, key) in self.config.keys.iter().enumerate() {
            let relay_length = if key.len() == 32 { 32 } else { 1088 };
            let relay = &mut relays.as_mut_slice()[relay_offset..relay_offset + relay_length];
            if key.len() == 32 {
                let secret = StaticSecret::from(random::<32>()?);
                relay.copy_from_slice(PublicKey::from(&secret).as_bytes());
                let peer: [u8; 32] = key.as_slice().try_into().map_err(|_| Error::InvalidKey)?;
                let shared = secret.diffie_hellman(&PublicKey::from(peer));
                if !shared.was_contributory() {
                    return Err(Error::InvalidKey);
                }
                nfs = Zeroizing::new(shared.to_bytes());
            } else {
                let encoded = ml_kem::Key::<EncapsulationKey>::try_from(key.as_slice())
                    .map_err(|_| Error::InvalidKey)?;
                let encapsulation =
                    EncapsulationKey::new(&encoded).map_err(|_| Error::InvalidKey)?;
                let randomness = Zeroizing::new(random::<32>()?);
                let (c, k) = encapsulation.encapsulate_deterministic(&(*randomness).into());
                relay.copy_from_slice(&c);
                nfs = Zeroizing::new(k.into());
            }
            if self.config.mode != Mode::Native {
                Mask::new(key, &iv).apply(relay)?;
            }
            if let Some(mask) = &mut previous {
                mask.apply(&mut relay[..32])?;
            }
            relay_offset += relay_length;
            if index + 1 < self.config.keys.len() {
                let mut digest = hash(&self.config.keys[index + 1]);
                let mut mask = Mask::new(nfs.as_ref(), &iv);
                mask.apply(&mut digest)?;
                relays.as_mut_slice()[relay_offset..relay_offset + 32].copy_from_slice(&digest);
                relay_offset += 32;
                previous = Some(mask);
            }
        }
        let mut nfs_aead = Aead::new(&iv, nfs.as_ref(), cipher);
        let cached = if self.config.resume {
            self.cache
                .ticket
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .filter(|ticket| ticket.expires > Instant::now())
                .map(|ticket| (ticket.pfs.clone(), ticket.ticket))
        } else {
            None
        };
        if let Some((pfs, ticket)) = cached {
            let mut hello = lease(buffers, 16 + relays.len() + 18 + 32)?;
            hello.as_mut_slice()[..16].copy_from_slice(&iv);
            hello.as_mut_slice()[16..16 + relays.len()].copy_from_slice(relays.as_slice());
            let at = 16 + relays.len();
            hello.as_mut_slice()[at..at + 2].copy_from_slice(&32u16.to_be_bytes());
            nfs_aead.seal(&mut hello.as_mut_slice()[at..at + 18], &[], None)?;
            hello.as_mut_slice()[at + 18..at + 34].copy_from_slice(&ticket);
            nfs_aead.seal(&mut hello.as_mut_slice()[at + 18..], &[], None)?;
            let mut key = Zeroizing::new([0; 96]);
            key[..64].copy_from_slice(pfs.as_ref());
            key[64..].copy_from_slice(nfs.as_ref());
            let write = Aead::new(&hello.as_slice()[at + 18..], key.as_ref(), cipher);
            io.write_all(hello.as_slice()).await?;
            io.flush().await?;
            let state = State {
                read: Aead::new(&[], key.as_ref(), cipher),
                write,
                read_mask: None,
                write_mask: if self.config.mode == Mode::Random {
                    Some(Mask::new(key.as_ref(), &iv))
                } else {
                    None
                },
                key,
            };
            return Ok((
                state,
                Some(cipher),
                Some(Resume {
                    cache: Arc::downgrade(&self.cache),
                    ticket,
                }),
            ));
        }
        let kem = DecapsulationKey::from_seed(random::<64>()?.into());
        let x = StaticSecret::from(random::<32>()?);
        let mut public = [0; 1216];
        public[..1184].copy_from_slice(&kem.encapsulation_key().to_bytes());
        public[1184..].copy_from_slice(PublicKey::from(&x).as_bytes());
        let (padding_length, parts) = self.config.padding.sample()?;
        let at = 16 + relays.len();
        let mut hello = lease(buffers, at + 18 + 1232 + padding_length)?;
        hello.as_mut_slice()[..16].copy_from_slice(&iv);
        hello.as_mut_slice()[16..at].copy_from_slice(relays.as_slice());
        hello.as_mut_slice()[at..at + 2].copy_from_slice(&1232u16.to_be_bytes());
        nfs_aead.seal(&mut hello.as_mut_slice()[at..at + 18], &[], None)?;
        hello.as_mut_slice()[at + 18..at + 18 + 1216].copy_from_slice(&public);
        nfs_aead.seal(
            &mut hello.as_mut_slice()[at + 18..at + 18 + 1232],
            &[],
            None,
        )?;
        let pad = at + 18 + 1232;
        hello.as_mut_slice()[pad..pad + 2]
            .copy_from_slice(&((padding_length - 18) as u16).to_be_bytes());
        nfs_aead.seal(&mut hello.as_mut_slice()[pad..pad + 18], &[], None)?;
        nfs_aead.seal(&mut hello.as_mut_slice()[pad + 18..], &[], None)?;
        let mut offset = 0;
        for (index, (length, gap)) in parts.into_iter().enumerate() {
            let length = length + if index == 0 { pad } else { 0 };
            io.write_all(&hello.as_slice()[offset..offset + length])
                .await?;
            io.flush().await?;
            offset += length;
            if !gap.is_zero() {
                tokio::time::sleep(gap).await;
            }
        }
        drop(hello);
        let mut response = [0; 1136];
        io.read_exact(&mut response).await?;
        nfs_aead.open(&mut response, &[], Some([255; 12]))?;
        let ciphertext = Ciphertext::try_from(&response[..1088]).map_err(|_| Error::InvalidKey)?;
        let kem_shared = kem.decapsulate(&ciphertext);
        let peer: [u8; 32] = response[1088..1120].try_into().expect("X25519 response");
        if peer[31] & 128 != 0 {
            return Err(Error::InvalidKey);
        }
        let x_shared = x.diffie_hellman(&PublicKey::from(peer));
        if !x_shared.was_contributory() {
            return Err(Error::InvalidKey);
        }
        let mut pfs = Zeroizing::new([0; 64]);
        pfs[..32].copy_from_slice(&kem_shared);
        pfs[32..].copy_from_slice(x_shared.as_bytes());
        let mut key = Zeroizing::new([0; 96]);
        key[..64].copy_from_slice(pfs.as_ref());
        key[64..].copy_from_slice(nfs.as_ref());
        let write = Aead::new(&public, key.as_ref(), cipher);
        let mut read = Aead::new(&response[..1120], key.as_ref(), cipher);
        let mut encrypted_ticket = [0; 32];
        io.read_exact(&mut encrypted_ticket).await?;
        read.open(&mut encrypted_ticket, &[], None)?;
        let ticket: [u8; 16] = encrypted_ticket[..16].try_into().expect("ticket");
        let lifetime = u16::from_be_bytes([ticket[0], ticket[1]]);
        if self.config.resume && lifetime > 0 {
            *self.cache.ticket.lock().unwrap_or_else(|e| e.into_inner()) = Some(Ticket {
                pfs,
                ticket,
                expires: Instant::now() + Duration::from_secs(u64::from(lifetime)),
            });
        }
        let mut length = [0; 18];
        io.read_exact(&mut length).await?;
        read.open(&mut length, &[], None)?;
        let n = u16::from_be_bytes([length[0], length[1]]) as usize;
        if n < 16 {
            return Err(Error::InvalidHandshake);
        }
        let mut padding = lease(buffers, n)?;
        io.read_exact(padding.as_mut_slice()).await?;
        read.open(padding.as_mut_slice(), &[], None)?;
        let (read_mask, write_mask) = if self.config.mode == Mode::Random {
            (
                Some(Mask::new(key.as_ref(), &ticket)),
                Some(Mask::new(key.as_ref(), &iv)),
            )
        } else {
            (None, None)
        };
        Ok((
            State {
                read,
                write,
                key,
                read_mask,
                write_mask,
            },
            None,
            None,
        ))
    }
}
fn lease(scope: &BufferScope, n: usize) -> Result<crate::buffer::BufferLease, Error> {
    let mut buffer = scope
        .try_lease(BufferLayout::new(0, n, 0).map_err(|_| Error::Resource)?)
        .map_err(|_| Error::Resource)?;
    buffer.append_zeroed(n).map_err(|_| Error::Resource)?;
    Ok(buffer)
}
