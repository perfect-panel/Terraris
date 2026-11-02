// SPDX-License-Identifier: GPL-3.0-only

//! Protocol engines compose through runtimekit and the shared flow policies.
//! The first concrete adapter is VLESS with UDP/XUDP and Encryption.
pub mod registry;
pub mod runtimekit;
pub use registry::{InboundFactory, Registry};

pub mod vless;

pub mod flow;

pub mod anytls;
pub(crate) mod ingress;
pub mod packet;
pub mod socksaddr;
pub mod stream;
pub mod trojan;
pub mod uot;

pub mod shadowsocks;
