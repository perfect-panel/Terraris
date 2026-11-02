// SPDX-License-Identifier: GPL-3.0-only
//! Shadowsocks AEAD (2017), SIP022 AEAD-2022 and SIP023 identity headers.
mod client;
mod method;
mod outbound;
mod packet;
mod replay;
mod server;
mod stream;
mod udp;
pub use client::{Client, Datagrams};
pub use method::Method;
pub(crate) use outbound::Factory as OutboundFactory;
pub use server::Factory;
pub const NAME: &str = "shadowsocks";
