// SPDX-License-Identifier: GPL-3.0-only

//! PPanel wire adapter. Generated Protobuf and JSON DTOs are deliberately private.

mod client;
mod convert;
mod dto_config;
mod from_proto;
mod normalize_config;

#[allow(dead_code)] // The pinned upstream schema also includes the legacy v1 config API.
mod wire {
    include!(concat!(env!("OUT_DIR"), "/ppanel.server.v1.rs"));
}

pub use client::{CertificateFingerprints, Options, PPanelConnection, PPanelProvider};
