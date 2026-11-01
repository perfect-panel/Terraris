// SPDX-License-Identifier: GPL-3.0-only

//! VLESS wire protocol and its Xray-compatible encryption layer.
pub mod encryption;

pub mod wire;
pub mod xudp;

mod egress;
mod ingress;
mod options;
mod server;
mod udp;
pub use options::Options;
pub use server::Factory;
