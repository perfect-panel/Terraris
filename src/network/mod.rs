// SPDX-License-Identifier: GPL-3.0-only

//! Unresolved destination metadata and concrete TCP/UDP I/O. DNS and routing
//! policy belong to later layers; these adapters never resolve a domain silently.

mod address;
mod io;

pub use address::{Address, AddressError, DomainName, FlowMetadata, Network, canonical_socket};
pub use io::{
    Datagram, DatagramEndpoint, DatagramTransport, Error, IoOperation, MAX_DATAGRAM_LIMIT,
    connect_tcp,
};

pub mod pipe;

pub trait StreamIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> StreamIo for T {}
pub type Stream = Box<dyn StreamIo>;
