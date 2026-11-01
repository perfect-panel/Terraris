// SPDX-License-Identifier: MPL-2.0
// VLESS Encryption wire semantics follow XTLS/Xray-core a4a3dff5b20c2faae567b742c172c7b95e75c083.
// See THIRD_PARTY.md and LICENSES/MPL-2.0.txt.

mod blake3_reference;
mod config;
mod crypto;
mod keys;
mod server;
mod stream;
pub use config::{Config, Limits, Mode, Padding};
pub use server::Server;
pub use stream::EncryptedStream;

use std::{fmt, io};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration(&'static str),
    Random,
    Authentication,
    InvalidKey,
    InvalidRecord,
    InvalidHandshake,
    Replay,
    ExpiredTicket,
    Closed,
    Resource,
    Io(io::ErrorKind),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VLESS encryption: {self:?}")
    }
}
impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}
impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, error)
    }
}
fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut value = [0; N];
    getrandom::fill(&mut value).map_err(|_| Error::Random)?;
    Ok(value)
}
fn between(a: u32, b: u32) -> Result<u32, Error> {
    let low = a.min(b);
    let high = a.max(b);
    let range = u64::from(high) - u64::from(low) + 1;
    let limit = u64::MAX - u64::MAX % range;
    loop {
        let value = u64::from_le_bytes(random()?);
        if value < limit {
            return Ok(low + (value % range) as u32);
        }
    }
}

#[cfg(test)]
mod tests;
