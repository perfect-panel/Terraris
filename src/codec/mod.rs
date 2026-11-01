// SPDX-License-Identifier: GPL-3.0-only

//! Bounded primitives, the RFC 1928 destination-address representation, and
//! explicitly selected u16/u32 big-endian length frames. Protocol-specific
//! encryption, handshakes and frame layouts remain in their own adapters.

mod frame;
mod primitives;

pub use frame::{DecodeStep, FrameDecoder, LengthPrefix};
pub use primitives::{Reader, Writer};

use crate::{buffer, network::AddressError};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    LimitExceeded { requested: usize, limit: usize },
    UnexpectedEof,
    TrailingData,
    InvalidAddressType(u8),
    Address(AddressError),
    UnsupportedAddressMetadata,
    InvalidFrameLimit,
    DecoderPoisoned,
    Buffer(buffer::Error),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded { requested, limit } => {
                write!(f, "codec length {requested} exceeds limit {limit}")
            }
            Self::UnexpectedEof => f.write_str("incomplete encoded value"),
            Self::TrailingData => f.write_str("unexpected trailing encoded data"),
            Self::InvalidAddressType(kind) => write!(f, "unsupported address type {kind}"),
            Self::Address(e) => e.fmt(f),
            Self::UnsupportedAddressMetadata => {
                f.write_str("address wire format cannot preserve IPv6 scope or flow information")
            }
            Self::InvalidFrameLimit => {
                f.write_str("frame maximum does not fit prefix or buffer scope")
            }
            Self::DecoderPoisoned => {
                f.write_str("decoder failed; discard the stream or reset at a known frame boundary")
            }
            Self::Buffer(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<buffer::Error> for Error {
    fn from(error: buffer::Error) -> Self {
        Self::Buffer(error)
    }
}
impl From<AddressError> for Error {
    fn from(error: AddressError) -> Self {
        Self::Address(error)
    }
}
