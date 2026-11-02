// SPDX-License-Identifier: GPL-3.0-only
//! Exact replay tracking for timestamped 2022 traffic; bounded rolling history
//! for stateless classic UDP. Authentication must precede every state mutation.
use super::method::{bad, random};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;
const CAPACITY: usize = 65536;
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Salt {
    key: [u8; 32],
    value: [u8; 32],
    len: u8,
}
struct Salts {
    map: HashMap<Salt, Instant>,
    order: VecDeque<(Salt, Instant)>,
}
impl Salts {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }
    fn insert(
        &mut self,
        key: [u8; 32],
        salt: &[u8],
        ttl: Duration,
        rolling: bool,
    ) -> io::Result<()> {
        let now = Instant::now();
        while self
            .order
            .front()
            .is_some_and(|(_, expires)| *expires <= now)
        {
            let (key, expires) = self.order.pop_front().unwrap();
            if self.map.get(&key) == Some(&expires) {
                self.map.remove(&key);
            }
        }
        if salt.len() > 32 {
            return Err(bad());
        }
        let mut value = [0; 32];
        value[..salt.len()].copy_from_slice(salt);
        let key = Salt {
            key,
            value,
            len: salt.len() as u8,
        };
        if self.map.contains_key(&key) {
            return Err(bad());
        }
        if self.map.len() >= CAPACITY {
            if !rolling {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            if let Some((old, _)) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        let expires = now + ttl;
        self.map.insert(key, expires);
        self.order.push_back((key, expires));
        Ok(())
    }
}
#[derive(Clone)]
pub struct Window {
    top: Option<u64>,
    bits: [u64; 16],
}
impl Window {
    pub fn new() -> Self {
        Self {
            top: None,
            bits: [0; 16],
        }
    }
    pub fn check(&self, id: u64) -> bool {
        match self.top {
            None => true,
            Some(top) if id > top => true,
            Some(top) => {
                let delta = top - id;
                delta < 1024 && (self.bits[(id % 1024 / 64) as usize] & (1u64 << (id % 64))) == 0
            }
        }
    }
    pub fn accept(&mut self, id: u64) -> io::Result<()> {
        if !self.check(id) {
            return Err(bad());
        }
        if let Some(top) = self.top
            && id > top
        {
            let delta = id - top;
            if delta >= 1024 {
                self.bits = [0; 16];
            } else {
                for n in 1..=delta {
                    let point = top + n;
                    self.bits[(point % 1024 / 64) as usize] &= !(1u64 << (point % 64));
                }
            }
        }
        self.top = Some(self.top.map_or(id, |top| top.max(id)));
        self.bits[(id % 1024 / 64) as usize] |= 1u64 << (id % 64);
        Ok(())
    }
}
pub struct UdpState {
    pub server_id: [u8; 8],
    pub send_id: u64,
    pub window: Window,
    pub touched: Instant,
}
impl UdpState {
    fn new(client: [u8; 8]) -> io::Result<Self> {
        let mut id = [0; 8];
        loop {
            random(&mut id)?;
            if id != client {
                break;
            }
        }
        Ok(Self {
            server_id: id,
            send_id: 0,
            window: Window::new(),
            touched: Instant::now(),
        })
    }
}
type SessionKey = ([u8; 32], [u8; 8]);
struct Sessions {
    values: HashMap<SessionKey, Arc<Mutex<UdpState>>>,
    pruned: Instant,
}

pub struct Protection {
    tcp: Mutex<Salts>,
    modern: Mutex<Salts>,
    udp: Mutex<Salts>,
    sessions: Mutex<Sessions>,
}
impl Protection {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            tcp: Mutex::new(Salts::new()),
            modern: Mutex::new(Salts::new()),
            udp: Mutex::new(Salts::new()),
            sessions: Mutex::new(Sessions {
                values: HashMap::new(),
                pruned: Instant::now(),
            }),
        })
    }
    pub fn tcp_salt(&self, key: [u8; 32], salt: &[u8], modern: bool) -> io::Result<()> {
        (if modern { &self.modern } else { &self.tcp })
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                key,
                salt,
                Duration::from_secs(if modern { 61 } else { 300 }),
                false,
            )
    }
    pub fn udp_salt(&self, key: [u8; 32], salt: &[u8]) -> io::Result<()> {
        self.udp.lock().unwrap_or_else(|e| e.into_inner()).insert(
            key,
            salt,
            Duration::from_secs(60),
            true,
        )
    }
    pub fn udp_packet(
        &self,
        key: [u8; 32],
        id: [u8; 8],
        packet: u64,
    ) -> io::Result<Arc<Mutex<UdpState>>> {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if sessions.values.len() >= CAPACITY && sessions.pruned.elapsed() >= Duration::from_secs(1)
        {
            sessions.values.retain(|_, s| {
                Arc::strong_count(s) > 1
                    || s.lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .touched
                        .elapsed()
                        < Duration::from_secs(61)
            });
            sessions.pruned = Instant::now();
        }
        let state = if let Some(s) = sessions.values.get(&(key, id)) {
            s.clone()
        } else {
            if sessions.values.len() >= CAPACITY {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let s = Arc::new(Mutex::new(UdpState::new(id)?));
            sessions.values.insert((key, id), s.clone());
            s
        };
        let mut locked = state.lock().unwrap_or_else(|e| e.into_inner());
        locked.window.accept(packet)?;
        locked.touched = Instant::now();
        drop(locked);
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sliding_window_accepts_reordering_rejects_old_and_duplicate_ids() {
        let mut w = Window::new();
        w.accept(100).unwrap();
        w.accept(102).unwrap();
        w.accept(101).unwrap();
        assert!(w.accept(101).is_err());
        w.accept(1124).unwrap();
        assert!(!w.check(100));
        assert!(w.check(1123));
        w.accept(1123).unwrap();
        w.accept(u64::MAX).unwrap();
        assert!(!w.check(0));
        assert!(!w.check(u64::MAX));
        assert!(w.check(u64::MAX - 1));
    }
    #[tokio::test(start_paused = true)]
    async fn exact_modern_salts_survive_classic_entries_and_61_seconds() {
        let p = Protection::new();
        p.tcp_salt([1; 32], &[1; 16], false).unwrap();
        p.tcp_salt([1; 32], &[2; 16], true).unwrap();
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(p.tcp_salt([1; 32], &[2; 16], true).is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        p.tcp_salt([1; 32], &[2; 16], true).unwrap();
        assert!(p.tcp_salt([1; 32], &[1; 16], false).is_err());
        let a = p.udp_packet([1; 32], [3; 8], 0).unwrap();
        let b = p.udp_packet([2; 32], [3; 8], 0).unwrap();
        assert!(!Arc::ptr_eq(&a, &b));
        assert!(p.udp_packet([1; 32], [3; 8], 0).is_err());
        let actual = p
            .udp_packet([1; 32], [3; 8], 1)
            .unwrap()
            .lock()
            .unwrap()
            .server_id;
        let expected = a.lock().unwrap().server_id;
        assert_eq!(actual, expected);
    }
}
