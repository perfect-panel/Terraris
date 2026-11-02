// SPDX-License-Identifier: GPL-3.0-only
//! Reusable client credentials and exact in-process replay state.
use super::{
    method::{Key, Method},
    packet,
    replay::Protection,
    stream,
};
use crate::{
    buffer::{BufferLease, BufferScope},
    network::Stream,
    protocol::socksaddr::Endpoint,
    time::OperationContext,
};
use std::{io, sync::Arc};
pub struct Client {
    pub(super) method: Method,
    pub(super) keys: Vec<Arc<Key>>,
    pub(super) protection: Arc<Protection>,
}
impl Client {
    pub fn new(cipher: &str, password: &str) -> io::Result<Self> {
        let method = Method::parse(cipher)?;
        Ok(Self {
            method,
            keys: method.password(password)?,
            protection: Protection::new(),
        })
    }
    pub async fn connect(
        &self,
        raw: Stream,
        target: &Endpoint,
        scope: &BufferScope,
        context: &OperationContext,
    ) -> io::Result<Stream> {
        context
            .run(stream::connect(
                raw,
                self.method,
                &self.keys,
                target,
                self.protection.clone(),
                scope,
                context,
            ))
            .await
            .map_err(|_| io::ErrorKind::Interrupted)?
    }
    pub fn datagrams(&self) -> io::Result<Datagrams> {
        Ok(Datagrams(packet::Client::new(
            self.method,
            self.keys.clone(),
            self.protection.clone(),
        )?))
    }
}
pub struct Datagrams(packet::Client);
impl Datagrams {
    pub fn encode(
        &mut self,
        target: &Endpoint,
        payload: &[u8],
        scope: &BufferScope,
    ) -> io::Result<BufferLease> {
        self.0.encode(target, payload, scope)
    }
    pub fn decode(
        &mut self,
        wire: &[u8],
        scope: &BufferScope,
    ) -> io::Result<(Endpoint, BufferLease)> {
        self.0.decode(wire, scope)
    }
}
