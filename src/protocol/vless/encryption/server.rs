// SPDX-License-Identifier: MPL-2.0
// See THIRD_PARTY.md for protocol sources.

use super::{
    Config, Error, Limits, Mode, between,
    crypto::{Aead, Cipher, Mask, hash},
    keys::{ServerKey, pfs},
    random,
    stream::{EncryptedStream, State},
};
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope},
    time::OperationContext,
};
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::Instant,
};
use zeroize::Zeroizing;
struct Session {
    pfs: Zeroizing<[u8; 64]>,
    seen: HashSet<[u8; 32]>,
    expires: Instant,
}
pub struct Server {
    config: Config,
    keys: Vec<ServerKey>,
    limits: Limits,
    tickets: Mutex<HashMap<[u8; 16], Session>>,
    closed: AtomicBool,
}
impl Server {
    pub fn new(config: Config, limits: Limits) -> Result<Self, Error> {
        if limits.tickets == 0 || limits.replay_keys_per_ticket == 0 {
            return Err(Error::Configuration("ticket/replay limits"));
        }
        let keys = config
            .seeds
            .iter()
            .map(|s| ServerKey::from_seed(s))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            config,
            keys,
            limits,
            tickets: Mutex::new(HashMap::new()),
            closed: AtomicBool::new(false),
        })
    }
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.tickets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
    pub fn cached_tickets(&self) -> usize {
        let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        tickets.retain(|_, s| s.expires > Instant::now());
        tickets.len()
    }
    pub async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        mut io: S,
        buffers: &BufferScope,
        context: &OperationContext,
    ) -> Result<EncryptedStream<S>, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        let state = context
            .run(self.prepare(&mut io, buffers))
            .await
            .map_err(|_| Error::Closed)??;
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        EncryptedStream::new(io, state, buffers)
    }
    async fn prepare<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: &mut S,
        buffers: &BufferScope,
    ) -> Result<State, Error> {
        let relay_length = self.keys.iter().map(|k| k.relay_len() + 32).sum::<usize>() - 32;
        let mut relays = lease(buffers, 16 + relay_length)?;
        io.read_exact(relays.as_mut_slice()).await?;
        let iv: [u8; 16] = relays.as_slice()[..16].try_into().expect("IV");
        let nfs = self.relays(&iv, &mut relays.as_mut_slice()[16..])?;
        drop(relays);
        let mut length = [0; 18];
        io.read_exact(&mut length).await?;
        let original = length;
        let mut nfs_aead = Aead::new(&iv, nfs.as_ref(), Cipher::Aes256Gcm);
        if nfs_aead.open(&mut length, &[], None).is_err() {
            length = original;
            nfs_aead = Aead::new(&iv, nfs.as_ref(), Cipher::ChaCha20Poly1305);
            nfs_aead.open(&mut length, &[], None)?;
        }
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;
        if length == 32 {
            return self.resume(io, iv, nfs, nfs_aead).await;
        }
        if length < 1232 {
            return Err(Error::InvalidHandshake);
        }
        let mut client_pfs = lease(buffers, length)?;
        io.read_exact(client_pfs.as_mut_slice()).await?;
        nfs_aead.open(client_pfs.as_mut_slice(), &[], None)?;
        let (response, pfs_key) = pfs(&client_pfs.as_slice()[..1216])?;
        let mut key = Zeroizing::new([0; 96]);
        key[..64].copy_from_slice(pfs_key.as_ref());
        key[64..].copy_from_slice(nfs.as_ref());
        let mut write = Aead::new(&response, key.as_ref(), nfs_aead.cipher);
        let read = Aead::new(
            &client_pfs.as_slice()[..1216],
            key.as_ref(),
            nfs_aead.cipher,
        );
        drop(client_pfs);
        let ticket = self.ticket(pfs_key)?;
        let (padding_length, parts) = self.config.padding.sample()?;
        let mut hello = lease(buffers, 1136 + 32 + padding_length)?;
        hello.as_mut_slice()[..1120].copy_from_slice(&response);
        nfs_aead.seal(&mut hello.as_mut_slice()[..1136], &[], Some([255; 12]))?;
        hello.as_mut_slice()[1136..1152].copy_from_slice(&ticket);
        write.seal(&mut hello.as_mut_slice()[1136..1168], &[], None)?;
        hello.as_mut_slice()[1168..1170]
            .copy_from_slice(&((padding_length - 18) as u16).to_be_bytes());
        write.seal(&mut hello.as_mut_slice()[1168..1186], &[], None)?;
        write.seal(&mut hello.as_mut_slice()[1186..], &[], None)?;
        let mut offset = 0;
        for (index, (length, gap)) in parts.into_iter().enumerate() {
            let length = length + if index == 0 { 1168 } else { 0 };
            io.write_all(&hello.as_slice()[offset..offset + length])
                .await?;
            io.flush().await?;
            offset += length;
            if !gap.is_zero() {
                tokio::time::sleep(gap).await;
            }
        }
        drop(hello);
        let mut padding_length = [0; 18];
        io.read_exact(&mut padding_length).await?;
        nfs_aead.open(&mut padding_length, &[], None)?;
        let length = u16::from_be_bytes([padding_length[0], padding_length[1]]) as usize;
        if length < 16 {
            return Err(Error::InvalidHandshake);
        }
        let mut padding = lease(buffers, length)?;
        io.read_exact(padding.as_mut_slice()).await?;
        nfs_aead.open(padding.as_mut_slice(), &[], None)?;
        let (read_mask, write_mask) = if self.config.mode == Mode::Random {
            (
                Some(Mask::new(key.as_ref(), &iv)),
                Some(Mask::new(key.as_ref(), &ticket)),
            )
        } else {
            (None, None)
        };
        Ok(State {
            read,
            write,
            key,
            read_mask,
            write_mask,
        })
    }
    fn relays(&self, iv: &[u8; 16], relays: &mut [u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let mut offset = 0;
        let mut previous: Option<Mask> = None;
        let mut secret = Zeroizing::new([0; 32]);
        for (index, key) in self.keys.iter().enumerate() {
            let length = key.relay_len();
            let relay = &mut relays[offset..offset + length];
            if let Some(mask) = &mut previous {
                mask.apply(&mut relay[..32])?;
            }
            if self.config.mode != Mode::Native {
                Mask::new(&key.public(), iv).apply(relay)?;
            }
            secret = key.decapsulate(relay)?;
            offset += length;
            if index + 1 < self.keys.len() {
                let next = &mut relays[offset..offset + 32];
                let mut mask = Mask::new(secret.as_ref(), iv);
                mask.apply(next)?;
                let expected = hash(&self.keys[index + 1].public());
                if !bool::from(next.ct_eq(&expected)) {
                    return Err(Error::Authentication);
                }
                offset += 32;
                previous = Some(mask);
            }
        }
        Ok(secret)
    }
    fn ticket(&self, pfs: Zeroizing<[u8; 64]>) -> Result<[u8; 16], Error> {
        let (from, to) = self.config.seconds;
        let mut seconds = if to != 0 {
            between(from as u32, to as u32)? as u16
        } else {
            (from as u32 * between(50, 100)? / 100) as u16
        };
        let mut ticket = random::<16>()?;
        let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
        tickets.retain(|_, s| s.expires > Instant::now());
        if tickets.len() >= self.limits.tickets || self.closed.load(Ordering::Acquire) {
            seconds = 0;
        }
        ticket[..2].copy_from_slice(&seconds.to_be_bytes());
        if seconds > 0 {
            if tickets.contains_key(&ticket) {
                return Err(Error::Random);
            }
            tickets.insert(
                ticket,
                Session {
                    pfs,
                    seen: HashSet::new(),
                    expires: Instant::now() + Duration::from_secs(u64::from(from.max(to)) + 120),
                },
            );
        }
        Ok(ticket)
    }
    async fn resume<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        io: &mut S,
        iv: [u8; 16],
        nfs: Zeroizing<[u8; 32]>,
        mut nfs_aead: Aead,
    ) -> Result<State, Error> {
        if self.config.seconds == (0, 0) {
            return Err(Error::InvalidHandshake);
        }
        let mut encrypted = [0; 32];
        io.read_exact(&mut encrypted).await?;
        let original = encrypted;
        nfs_aead.open(&mut encrypted, &[], None)?;
        let ticket: [u8; 16] = encrypted[..16].try_into().expect("ticket");
        let pfs = {
            let mut tickets = self.tickets.lock().unwrap_or_else(|e| e.into_inner());
            tickets.retain(|_, s| s.expires > Instant::now());
            if let Some(session) = tickets.get_mut(&ticket) {
                let fingerprint = hash(nfs.as_ref());
                if session.seen.contains(&fingerprint) {
                    return Err(Error::Replay);
                }
                if session.seen.len() >= self.limits.replay_keys_per_ticket {
                    // Invalidate the whole ticket: never forget a replay key
                    // while that ticket can still authenticate early data.
                    tickets.remove(&ticket);
                    None
                } else {
                    session.seen.insert(fingerprint);
                    Some(session.pfs.clone())
                }
            } else {
                None
            }
        };
        let Some(pfs) = pfs else {
            let mut noise = random::<2279>()?;
            if noise[..3] == [23, 3, 3] {
                noise[0] ^= 128;
            }
            io.write_all(&noise[..between(1279, 2279)? as usize])
                .await?;
            io.flush().await?;
            return Err(Error::ExpiredTicket);
        };
        let mut key = Zeroizing::new([0; 96]);
        key[..64].copy_from_slice(pfs.as_ref());
        key[64..].copy_from_slice(nfs.as_ref());
        let server_iv = random::<16>()?;
        io.write_all(&server_iv).await?;
        io.flush().await?;
        let read = Aead::new(&original, key.as_ref(), nfs_aead.cipher);
        let write = Aead::new(&server_iv, key.as_ref(), nfs_aead.cipher);
        let (read_mask, write_mask) = if self.config.mode == Mode::Random {
            (
                Some(Mask::new(key.as_ref(), &iv)),
                Some(Mask::new(key.as_ref(), &server_iv)),
            )
        } else {
            (None, None)
        };
        Ok(State {
            read,
            write,
            key,
            read_mask,
            write_mask,
        })
    }
}
fn lease(buffers: &BufferScope, length: usize) -> Result<BufferLease, Error> {
    let mut buffer = buffers
        .try_lease(BufferLayout::new(0, length, 0).map_err(|_| Error::Resource)?)
        .map_err(|_| Error::Resource)?;
    buffer.append_zeroed(length).map_err(|_| Error::Resource)?;
    Ok(buffer)
}
impl Drop for Server {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{Budget, Limits as ResourceLimits};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use x25519_dalek::{PublicKey, StaticSecret};
    fn config() -> Config {
        Config::parse(&format!(
            "mlkem768x25519plus.native.1-1s.100-35-35.{}",
            URL_SAFE_NO_PAD.encode([0x42; 32])
        ))
        .unwrap()
    }
    fn resume_bytes(ticket: [u8; 16], seed: u8) -> Vec<u8> {
        let server = StaticSecret::from([0x42; 32]);
        let client = StaticSecret::from([seed; 32]);
        let shared = client.diffie_hellman(&PublicKey::from(&server));
        let iv = [0x11; 16];
        let mut aead = Aead::new(&iv, shared.as_bytes(), Cipher::Aes256Gcm);
        let mut bytes = iv.to_vec();
        bytes.extend(PublicKey::from(&client).as_bytes());
        let mut length = [0; 18];
        length[..2].copy_from_slice(&32u16.to_be_bytes());
        aead.seal(&mut length, &[], None).unwrap();
        bytes.extend(length);
        let mut encrypted = [0; 32];
        encrypted[..16].copy_from_slice(&ticket);
        aead.seal(&mut encrypted, &[], None).unwrap();
        bytes.extend(encrypted);
        bytes
    }
    async fn attempt(server: &Server, bytes: &[u8]) -> Result<(), Error> {
        let budget = Budget::new(ResourceLimits::new(1 << 20, 16).unwrap());
        let buffers = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        let (mut client, io) = tokio::io::duplex(4096);
        client.write_all(bytes).await.unwrap();
        let context = OperationContext::new(
            CancellationToken::new(),
            Some(Deadline::after(Duration::from_secs(1)).unwrap()),
        );
        let result = server.handshake(io, &buffers, &context).await.map(drop);
        assert_eq!(budget.snapshot().used().bytes(), 0);
        result
    }
    use crate::{task::CancellationToken, time::Deadline};
    #[tokio::test(start_paused = true)]
    async fn cache_caps_invalidate_tickets_without_forgetting_replay_protection() {
        let server = Server::new(
            config(),
            Limits {
                tickets: 1,
                replay_keys_per_ticket: 1,
            },
        )
        .unwrap();
        let ticket = server.ticket(Zeroizing::new([0x33; 64])).unwrap();
        assert_eq!(u16::from_be_bytes(ticket[..2].try_into().unwrap()), 1);
        let overflow = server.ticket(Zeroizing::new([0x44; 64])).unwrap();
        assert_eq!(overflow[..2], [0, 0]);
        assert_eq!(server.cached_tickets(), 1);
        let bytes = resume_bytes(ticket, 11);
        attempt(&server, &bytes).await.unwrap();
        assert!(matches!(attempt(&server, &bytes).await, Err(Error::Replay)));
        assert!(matches!(
            attempt(&server, &resume_bytes(ticket, 12)).await,
            Err(Error::ExpiredTicket)
        ));
        assert_eq!(server.cached_tickets(), 0);
        assert!(matches!(
            attempt(&server, &bytes).await,
            Err(Error::ExpiredTicket)
        ));
    }
    #[tokio::test(start_paused = true)]
    async fn ticket_expiry_uses_monotonic_time_and_close_clears_cache() {
        let server = Server::new(config(), Limits::default()).unwrap();
        let ticket = server.ticket(Zeroizing::new([0x33; 64])).unwrap();
        tokio::time::advance(Duration::from_secs(122)).await;
        assert!(matches!(
            attempt(&server, &resume_bytes(ticket, 11)).await,
            Err(Error::ExpiredTicket)
        ));
        assert_eq!(server.cached_tickets(), 0);
        server.ticket(Zeroizing::new([0x33; 64])).unwrap();
        server.close();
        assert_eq!(server.cached_tickets(), 0);
    }
}
