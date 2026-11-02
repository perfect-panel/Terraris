// SPDX-License-Identifier: GPL-3.0-only
//! Stateless classic AEAD datagrams and SIP022/023 session-bound UDP packets.
use super::{
    method::{self, Key, Method, TAG, bad},
    replay::{Protection, UdpState, Window},
    stream::Keys,
};
use crate::{
    buffer::{BufferLayout, BufferLease, BufferScope},
    protocol::socksaddr::{Endpoint, Format},
    time::OperationContext,
};
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio::time::Instant;
pub const MAX_WIRE: usize = 65507;
pub struct Decoded {
    pub key: Arc<Key>,
    pub client_id: Option<[u8; 8]>,
    pub state: Option<Arc<Mutex<UdpState>>>,
    pub target: Endpoint,
    pub payload: BufferLease,
}
fn buffer(scope: &BufferScope, n: usize) -> io::Result<BufferLease> {
    scope
        .try_lease(BufferLayout::new(0, n, 0).map_err(io::Error::other)?)
        .map_err(io::Error::other)
}
fn open(
    method: Method,
    key: &Key,
    header: &[u8; 16],
    nonce: &[u8],
    encrypted: &[u8],
    scope: &BufferScope,
) -> io::Result<BufferLease> {
    if encrypted.len() < TAG {
        return Err(bad());
    }
    let mut data = buffer(scope, encrypted.len())?;
    data.append_payload(encrypted).map_err(io::Error::other)?;
    let end = data.len() - TAG;
    let mut tag = [0; TAG];
    tag.copy_from_slice(&data.as_slice()[end..]);
    let cipher = if method == Method::ChaCha20_2022 {
        Method::XChaCha20.cipher(key.bytes())?
    } else {
        method.cipher(&method.subkey(key, &header[..8])?)?
    };
    cipher.open(nonce, &mut data.as_mut_slice()[..end], &tag)?;
    data.truncate(end).map_err(io::Error::other)?;
    Ok(data)
}
fn main_header(
    data: &[u8],
    direction: u8,
    client: Option<[u8; 8]>,
) -> io::Result<(Endpoint, usize)> {
    let minimum = if direction == 0 { 11 } else { 19 };
    if data.len() < minimum || data[0] != direction {
        return Err(bad());
    }
    method::timestamp(u64::from_be_bytes(data[1..9].try_into().unwrap()))?;
    if let Some(client) = client
        && !bool::from(data[9..17].ct_eq(&client))
    {
        return Err(bad());
    }
    let padding = u16::from_be_bytes(data[minimum - 2..minimum].try_into().unwrap()) as usize;
    if padding > 900 || data.len() < minimum + padding {
        return Err(bad());
    }
    let start = minimum + padding;
    let (target, n) = Endpoint::parse(&data[start..], Format::Socks)?.ok_or_else(bad)?;
    target.address()?;
    Ok((target, start + n))
}
#[allow(clippy::too_many_arguments)]
pub async fn decode_request(
    wire: &[u8],
    method: Method,
    server: Option<&Key>,
    keys: &Keys,
    hint: Option<[u8; 32]>,
    protection: &Protection,
    scope: &BufferScope,
    context: &OperationContext,
) -> io::Result<Decoded> {
    if wire.len() > MAX_WIRE {
        return Err(bad());
    }
    let mut candidates = Vec::new();
    let mut separate = [0; 16];
    let mut offset = method.key_len();
    if method.identity() {
        offset = 16 + usize::from(server.is_some()) * 16;
        if wire.len() < offset + TAG + 11 {
            return Err(bad());
        }
        if let Some(server) = server {
            separate.copy_from_slice(&wire[..16]);
            server.block(&mut separate, false)?;
            let mut id = [0; 16];
            id.copy_from_slice(&wire[16..32]);
            server.block(&mut id, false)?;
            for (i, b) in id.iter_mut().enumerate() {
                *b ^= separate[i];
            }
            candidates.push(keys.identities.get(&id).cloned().ok_or_else(bad)?);
        }
    } else if method == Method::ChaCha20_2022 {
        offset = 24;
        if wire.len() < 24 + 16 + 11 + TAG {
            return Err(bad());
        }
    } else if wire.len() < offset + TAG + 5 {
        return Err(bad());
    }
    if candidates.is_empty() {
        if let Some(hint) = hint
            && let Some(key) = keys.all.iter().find(|k| k.id == hint)
        {
            candidates.push(key.clone());
        }
        candidates.extend(keys.all.iter().filter(|k| Some(k.id) != hint).cloned());
    }
    for (index, key) in candidates.into_iter().enumerate() {
        if index % 16 == 0 {
            context.check().map_err(|_| io::ErrorKind::Interrupted)?;
            tokio::task::yield_now().await;
        }
        if !method.modern() {
            let salt = &wire[..offset];
            let n = wire.len() - offset;
            let mut data = buffer(scope, n)?;
            data.append_payload(&wire[offset..])
                .map_err(io::Error::other)?;
            let end = n - TAG;
            let mut tag = [0; TAG];
            tag.copy_from_slice(&data.as_slice()[end..]);
            let cipher = method.cipher(&method.subkey(&key, salt)?)?;
            let nonce = [0; 24];
            if cipher
                .open(
                    &nonce[..method.nonce_len()],
                    &mut data.as_mut_slice()[..end],
                    &tag,
                )
                .is_err()
            {
                continue;
            }
            data.truncate(end).map_err(io::Error::other)?;
            let (target, n) = Endpoint::parse(data.as_slice(), Format::Socks)?.ok_or_else(bad)?;
            target.address()?;
            protection.udp_salt(key.id, salt)?;
            data.consume(n).map_err(io::Error::other)?;
            return Ok(Decoded {
                key,
                client_id: None,
                state: None,
                target,
                payload: data,
            });
        }
        let mut data = if method == Method::ChaCha20_2022 {
            match open(method, &key, &separate, &wire[..24], &wire[24..], scope) {
                Ok(v) => v,
                Err(_) => continue,
            }
        } else {
            if server.is_none() {
                separate.copy_from_slice(&wire[..16]);
                key.block(&mut separate, false)?;
            }
            match open(
                method,
                &key,
                &separate,
                &separate[4..],
                &wire[offset..],
                scope,
            ) {
                Ok(v) => v,
                Err(_) => continue,
            }
        };
        if method == Method::ChaCha20_2022 {
            if data.len() < 16 {
                return Err(bad());
            }
            separate.copy_from_slice(&data.as_slice()[..16]);
            data.consume(16).map_err(io::Error::other)?;
        }
        let client: [u8; 8] = separate[..8].try_into().unwrap();
        let packet = u64::from_be_bytes(separate[8..].try_into().unwrap());
        let (target, n) = main_header(data.as_slice(), 0, None)?;
        let state = protection.udp_packet(key.id, client, packet)?;
        data.consume(n).map_err(io::Error::other)?;
        return Ok(Decoded {
            key,
            client_id: Some(client),
            state: Some(state),
            target,
            payload: data,
        });
    }
    Err(bad())
}
fn main_bytes(
    direction: u8,
    client: Option<[u8; 8]>,
    target: &Endpoint,
    payload_len: usize,
) -> io::Result<Vec<u8>> {
    let mut b = vec![direction];
    b.extend(method::now()?.to_be_bytes());
    if let Some(client) = client {
        b.extend(client);
    }
    let padding = if target.port == 53 && payload_len < 900 {
        let mut r = [0; 1];
        method::random(&mut r)?;
        1 + usize::from(r[0]) % (900 - payload_len).min(64)
    } else {
        0
    };
    b.extend((padding as u16).to_be_bytes());
    let start = b.len();
    b.resize(start + padding, 0);
    method::random(&mut b[start..])?;
    b.extend(target.encode(Format::Socks)?);
    Ok(b)
}
#[allow(clippy::too_many_arguments)]
fn encode(
    method: Method,
    keys: &[Arc<Key>],
    direction: u8,
    session: [u8; 8],
    packet: u64,
    client: Option<[u8; 8]>,
    target: &Endpoint,
    payload: &[u8],
    scope: &BufferScope,
) -> io::Result<BufferLease> {
    let key = keys.last().ok_or_else(bad)?;
    if !method.modern() {
        let header = target.encode(Format::Socks)?;
        let size = method.key_len() + header.len() + payload.len() + TAG;
        if size > MAX_WIRE {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut out = buffer(scope, size)?;
        let salt = out
            .append_zeroed(method.key_len())
            .map_err(io::Error::other)?;
        method::random(salt)?;
        let mut counter = method.session(key, salt)?;
        out.append_payload(&header).map_err(io::Error::other)?;
        out.append_payload(payload).map_err(io::Error::other)?;
        let tag = counter.seal(&mut out.as_mut_slice()[method.key_len()..])?;
        out.append_payload(&tag).map_err(io::Error::other)?;
        return Ok(out);
    }
    let main = main_bytes(direction, client, target, payload.len())?;
    let identity = if direction == 0 && method.identity() {
        (keys.len() - 1) * 16
    } else {
        0
    };
    let overhead = if method == Method::ChaCha20_2022 {
        24 + 16
    } else {
        16 + identity
    };
    let size = overhead + main.len() + payload.len() + TAG;
    if size > MAX_WIRE {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut out = buffer(scope, size)?;
    let mut separate = [0; 16];
    separate[..8].copy_from_slice(&session);
    separate[8..].copy_from_slice(&packet.to_be_bytes());
    let start = if method == Method::ChaCha20_2022 {
        let nonce = out.append_zeroed(24).map_err(io::Error::other)?;
        method::random(nonce)?;
        out.append_payload(&separate).map_err(io::Error::other)?;
        24
    } else {
        let mut encrypted = separate;
        keys[0].block(&mut encrypted, true)?;
        out.append_payload(&encrypted).map_err(io::Error::other)?;
        if direction == 0 {
            for pair in keys.windows(2) {
                let mut id = pair[1].identity;
                for (i, b) in id.iter_mut().enumerate() {
                    *b ^= separate[i];
                }
                pair[0].block(&mut id, true)?;
                out.append_payload(&id).map_err(io::Error::other)?;
            }
        }
        16 + identity
    };
    out.append_payload(&main).map_err(io::Error::other)?;
    out.append_payload(payload).map_err(io::Error::other)?;
    let tag = if method == Method::ChaCha20_2022 {
        let mut nonce = [0; 24];
        nonce.copy_from_slice(&out.as_slice()[..24]);
        Method::XChaCha20
            .cipher(key.bytes())?
            .seal(&nonce, &mut out.as_mut_slice()[start..])?
    } else {
        method
            .cipher(&method.subkey(key, &session)?)?
            .seal(&separate[4..], &mut out.as_mut_slice()[start..])?
    };
    out.append_payload(&tag).map_err(io::Error::other)?;
    Ok(out)
}
pub fn response(
    method: Method,
    key: Arc<Key>,
    client: Option<[u8; 8]>,
    state: Option<&Arc<Mutex<UdpState>>>,
    target: &Endpoint,
    payload: &[u8],
    scope: &BufferScope,
) -> io::Result<BufferLease> {
    let (session, packet) = if let Some(state) = state {
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        let packet = state.send_id;
        state.send_id = packet.checked_add(1).ok_or_else(bad)?;
        (state.server_id, packet)
    } else {
        ([0; 8], 0)
    };
    encode(
        method,
        &[key],
        1,
        session,
        packet,
        client,
        target,
        payload,
        scope,
    )
}
struct Remote {
    window: Window,
    seen: Instant,
}
pub struct Client {
    method: Method,
    keys: Vec<Arc<Key>>,
    session: [u8; 8],
    next: u64,
    remotes: HashMap<[u8; 8], Remote>,
    protection: Arc<Protection>,
}
use std::collections::HashMap;
impl Client {
    pub fn new(
        method: Method,
        keys: Vec<Arc<Key>>,
        protection: Arc<Protection>,
    ) -> io::Result<Self> {
        let mut session = [0; 8];
        method::random(&mut session)?;
        Ok(Self {
            method,
            keys,
            session,
            next: 0,
            remotes: HashMap::new(),
            protection,
        })
    }
    pub fn encode(
        &mut self,
        target: &Endpoint,
        payload: &[u8],
        scope: &BufferScope,
    ) -> io::Result<BufferLease> {
        let packet = self.next;
        self.next = packet.checked_add(1).ok_or_else(bad)?;
        let wire = encode(
            self.method,
            &self.keys,
            0,
            self.session,
            packet,
            None,
            target,
            payload,
            scope,
        )?;
        if !self.method.modern() {
            let key = self.keys.last().ok_or_else(bad)?;
            self.protection
                .udp_salt(key.id, &wire.as_slice()[..self.method.key_len()])?;
        }
        Ok(wire)
    }
    pub fn decode(
        &mut self,
        wire: &[u8],
        scope: &BufferScope,
    ) -> io::Result<(Endpoint, BufferLease)> {
        if wire.len() > MAX_WIRE {
            return Err(bad());
        }
        let method = self.method;
        let key = self.keys.last().ok_or_else(bad)?;
        if !method.modern() {
            let offset = method.key_len();
            if wire.len() < offset + TAG + 5 {
                return Err(bad());
            }
            let mut data = buffer(scope, wire.len() - offset)?;
            data.append_payload(&wire[offset..])
                .map_err(io::Error::other)?;
            let n = data.len() - TAG;
            let mut tag = [0; TAG];
            tag.copy_from_slice(&data.as_slice()[n..]);
            let cipher = method.cipher(&method.subkey(key, &wire[..offset])?)?;
            let nonce = [0; 24];
            cipher.open(
                &nonce[..method.nonce_len()],
                &mut data.as_mut_slice()[..n],
                &tag,
            )?;
            data.truncate(n).map_err(io::Error::other)?;
            let (target, n) = Endpoint::parse(data.as_slice(), Format::Socks)?.ok_or_else(bad)?;
            target.address()?;
            self.protection.udp_salt(key.id, &wire[..offset])?;
            data.consume(n).map_err(io::Error::other)?;
            return Ok((target, data));
        }
        let mut separate = [0; 16];
        let mut data = if method == Method::ChaCha20_2022 {
            if wire.len() < 24 + 16 + 19 + TAG {
                return Err(bad());
            }
            let mut data = open(method, key, &separate, &wire[..24], &wire[24..], scope)?;
            separate.copy_from_slice(&data.as_slice()[..16]);
            data.consume(16).map_err(io::Error::other)?;
            data
        } else {
            if wire.len() < 16 + 19 + TAG {
                return Err(bad());
            }
            separate.copy_from_slice(&wire[..16]);
            key.block(&mut separate, false)?;
            open(method, key, &separate, &separate[4..], &wire[16..], scope)?
        };
        let server: [u8; 8] = separate[..8].try_into().unwrap();
        if server == self.session {
            return Err(bad());
        }
        let packet = u64::from_be_bytes(separate[8..].try_into().unwrap());
        let (target, n) = main_header(data.as_slice(), 1, Some(self.session))?;
        if !self.remotes.contains_key(&server) {
            self.remotes
                .retain(|_, v| v.seen.elapsed() < Duration::from_secs(61));
            if self.remotes.len() >= 2 {
                return Err(bad());
            }
        }
        let remote = self.remotes.entry(server).or_insert_with(|| Remote {
            window: Window::new(),
            seen: Instant::now(),
        });
        remote.window.accept(packet)?;
        remote.seen = Instant::now();
        data.consume(n).map_err(io::Error::other)?;
        Ok((target, data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        resource::{Budget, Limits},
        task::CancellationToken,
    };
    fn ctx() -> OperationContext {
        OperationContext::new(CancellationToken::new(), None)
    }
    fn target() -> Endpoint {
        Endpoint::from_address(
            &crate::network::Address::from_socket("127.0.0.1:443".parse().unwrap()).unwrap(),
        )
        .unwrap()
    }
    fn setup(
        method: Method,
    ) -> (
        Client,
        Keys,
        Option<Arc<Key>>,
        Arc<Protection>,
        Budget,
        BufferScope,
    ) {
        let user = Key::new(method, &vec![7; method.key_len()]).unwrap();
        let server = method
            .identity()
            .then(|| Key::new(method, &vec![11; method.key_len()]).unwrap());
        let mut keys = Vec::new();
        if let Some(k) = &server {
            keys.push(k.clone());
        }
        keys.push(user.clone());
        let memory = Budget::new(Limits::new(1 << 20, 64).unwrap());
        let scope = BufferScope::new(memory.root_scope(), 128 << 10).unwrap();
        (
            Client::new(method, keys, Protection::new()).unwrap(),
            Keys::new(vec![user], server.is_some()).unwrap(),
            server,
            Protection::new(),
            memory,
            scope,
        )
    }
    #[tokio::test]
    async fn replay_and_authentication_failures_all_udp_methods() {
        for method in [
            Method::Aes128,
            Method::Aes192,
            Method::Aes256,
            Method::ChaCha20,
            Method::XChaCha20,
            Method::Aes128_2022,
            Method::Aes256_2022,
            Method::ChaCha20_2022,
        ] {
            let (mut client, keys, server, protection, memory, scope) = setup(method);
            let wire = client.encode(&target(), b"packet", &scope).unwrap();
            let mut bad = wire.as_slice().to_vec();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!(
                decode_request(
                    &bad,
                    method,
                    server.as_deref(),
                    &keys,
                    None,
                    &protection,
                    &scope,
                    &ctx()
                )
                .await
                .is_err()
            );
            let packet = decode_request(
                wire.as_slice(),
                method,
                server.as_deref(),
                &keys,
                None,
                &protection,
                &scope,
                &ctx(),
            )
            .await
            .unwrap();
            assert_eq!(packet.payload.as_slice(), b"packet");
            assert!(
                decode_request(
                    wire.as_slice(),
                    method,
                    server.as_deref(),
                    &keys,
                    None,
                    &protection,
                    &scope,
                    &ctx()
                )
                .await
                .is_err()
            );
            let reply = response(
                method,
                packet.key.clone(),
                packet.client_id,
                packet.state.as_ref(),
                &target(),
                b"response",
                &scope,
            )
            .unwrap();
            let (_, payload) = client.decode(reply.as_slice(), &scope).unwrap();
            assert_eq!(payload.as_slice(), b"response");
            assert!(client.decode(reply.as_slice(), &scope).is_err());
            if !method.modern() {
                assert!(client.decode(wire.as_slice(), &scope).is_err());
            }
            drop((wire, reply, packet, payload));
            assert_eq!(memory.snapshot().used().bytes(), 0);
            assert_eq!(memory.snapshot().used().allocations(), 0);
        }
    }
    fn alter_body(
        wire: &mut [u8],
        method: Method,
        user: &Key,
        server: Option<&Key>,
        offset_in_main: usize,
    ) {
        let offset = if method == Method::ChaCha20_2022 {
            24
        } else {
            16 + usize::from(server.is_some()) * 16
        };
        let mut separate = [0; 16];
        let mut nonce = vec![
            0;
            if method == Method::ChaCha20_2022 {
                24
            } else {
                12
            }
        ];
        let cipher = if method == Method::ChaCha20_2022 {
            nonce.copy_from_slice(&wire[..24]);
            Method::XChaCha20.cipher(user.bytes()).unwrap()
        } else {
            separate.copy_from_slice(&wire[..16]);
            server.unwrap_or(user).block(&mut separate, false).unwrap();
            nonce.copy_from_slice(&separate[4..]);
            method
                .cipher(&method.subkey(user, &separate[..8]).unwrap())
                .unwrap()
        };
        let end = wire.len() - TAG;
        let mut tag = [0; TAG];
        tag.copy_from_slice(&wire[end..]);
        cipher.open(&nonce, &mut wire[offset..end], &tag).unwrap();
        let main = offset
            + if method == Method::ChaCha20_2022 {
                16
            } else {
                0
            };
        wire[main + offset_in_main] ^= 0xff;
        let tag = cipher.seal(&nonce, &mut wire[offset..end]).unwrap();
        wire[end..].copy_from_slice(&tag);
    }
    #[tokio::test]
    async fn authenticated_bad_timestamp_and_client_binding_do_not_poison_windows() {
        for method in [
            Method::Aes128_2022,
            Method::Aes256_2022,
            Method::ChaCha20_2022,
        ] {
            let (mut client, keys, server, protection, memory, scope) = setup(method);
            let user = keys.all[0].clone();
            let wire = client.encode(&target(), b"valid", &scope).unwrap();
            let mut malformed = wire.as_slice().to_vec();
            alter_body(&mut malformed, method, &user, server.as_deref(), 1);
            assert!(
                decode_request(
                    &malformed,
                    method,
                    server.as_deref(),
                    &keys,
                    None,
                    &protection,
                    &scope,
                    &ctx()
                )
                .await
                .is_err()
            );
            let packet = decode_request(
                wire.as_slice(),
                method,
                server.as_deref(),
                &keys,
                None,
                &protection,
                &scope,
                &ctx(),
            )
            .await
            .unwrap();
            let reply = response(
                method,
                user.clone(),
                packet.client_id,
                packet.state.as_ref(),
                &target(),
                b"bound",
                &scope,
            )
            .unwrap();
            let mut malformed = reply.as_slice().to_vec();
            alter_body(&mut malformed, method, &user, None, 9);
            assert!(client.decode(&malformed, &scope).is_err());
            client.decode(reply.as_slice(), &scope).unwrap();
            drop((wire, reply, packet));
            assert_eq!(memory.snapshot().used().bytes(), 0);
        }
    }
    #[tokio::test]
    async fn identical_client_session_ids_are_isolated_by_user_key() {
        let method = Method::Aes128_2022;
        let (mut one, mut keys, server, p, memory, scope) = setup(method);
        let user = Key::new(method, &[12; 16]).unwrap();
        keys.identities.insert(user.identity, user.clone());
        keys.all.push(user.clone());
        let mut two = Client::new(
            method,
            vec![server.clone().unwrap(), user],
            Protection::new(),
        )
        .unwrap();
        two.session = one.session;
        let a_wire = one.encode(&target(), b"one", &scope).unwrap();
        let b_wire = two.encode(&target(), b"two", &scope).unwrap();
        let a = decode_request(
            a_wire.as_slice(),
            method,
            server.as_deref(),
            &keys,
            None,
            &p,
            &scope,
            &ctx(),
        )
        .await
        .unwrap();
        let b = decode_request(
            b_wire.as_slice(),
            method,
            server.as_deref(),
            &keys,
            None,
            &p,
            &scope,
            &ctx(),
        )
        .await
        .unwrap();
        assert_ne!(a.key.id, b.key.id);
        assert!(!Arc::ptr_eq(
            a.state.as_ref().unwrap(),
            b.state.as_ref().unwrap()
        ));
        let reply = response(
            method,
            b.key.clone(),
            b.client_id,
            b.state.as_ref(),
            &target(),
            b"two reply",
            &scope,
        )
        .unwrap();
        assert!(one.decode(reply.as_slice(), &scope).is_err());
        two.decode(reply.as_slice(), &scope).unwrap();
        drop((a, b, reply, a_wire, b_wire));
        assert_eq!(memory.snapshot().used().bytes(), 0);
    }
}
