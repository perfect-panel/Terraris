// SPDX-License-Identifier: GPL-3.0-only

//! Exclusive, fixed-capacity buffers with hierarchical resource ownership.
//! No caching, implicit growth, shared views, or unbudgeted Vec escape hatches.
//!
//! ```
//! use terraris::{buffer::{BufferLayout, BufferScope}, resource::{Budget, Limits}};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let budget = Budget::new(Limits::new(1024 * 1024, 64)?);
//! let resources = budget.scope(Limits::new(128 * 1024, 4)?)?;
//! let scope = BufferScope::new(resources, 64 * 1024)?;
//! let layout = BufferLayout::new(32, 16 * 1024, 16)?;
//! let mut pair = scope.try_lease_many(&[layout, layout])?;
//! pair[0].append_payload(b"hello")?;
//! pair[0].prepend_header(b"HEAD")?;
//! pair[0].append_trailer(b"TAG")?;
//! assert_eq!(pair[0].as_slice(), b"HEADhelloTAG");
//! assert_eq!(budget.snapshot().resident().bytes(), layout.capacity() * 2);
//! drop(pair);
//! assert_eq!(budget.snapshot().used().bytes(), 0);
//! # Ok(())
//! # }
//! ```

mod error;
mod layout;
mod lease;
mod scope;

pub use error::{Error, Region};
pub use layout::BufferLayout;
pub use lease::BufferLease;
pub use scope::BufferScope;
