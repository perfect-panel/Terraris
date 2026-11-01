// SPDX-License-Identifier: GPL-3.0-only

//! Provider-neutral ports and models. Wire DTOs belong to their adapter.

mod error;
mod http;
mod model;
mod ports;
pub mod ppanel;

pub use error::{Endpoint, Error, ErrorKind, Result};
pub use model::*;
pub use ports::*;
