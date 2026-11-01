// SPDX-License-Identifier: GPL-3.0-only

//! Hierarchical memory reservations with immediate capacity checks. A short
//! mutex serializes accounting, but calls never wait for capacity. A batch is
//! charged at one linearization point; no caller holds one quota awaiting another.
//!
//! ```
//! use terraris::resource::{Budget, Limits};
//! # fn main() -> Result<(), terraris::resource::Error> {
//! let budget = Budget::new(Limits::new(1024, 8)?);
//! let connection = budget.scope(Limits::new(512, 4)?)?;
//! let reservations = connection.try_reserve_many(&[128, 128])?;
//! assert_eq!(budget.snapshot().reserved().bytes(), 256);
//! let permits: Vec<_> = reservations.into_iter().map(|r| r.commit()).collect();
//! assert_eq!(connection.snapshot().resident().bytes(), 256);
//! drop(permits);
//! assert_eq!(budget.snapshot().used().bytes(), 0);
//! # Ok(())
//! # }
//! ```

mod budget;
mod error;

pub(crate) use budget::{
    AllocationPermit, BackingRequest, BackingReservation, CachedReservation, ScopePermit,
};
pub use budget::{Budget, Limits, MAX_SCOPE_DEPTH, Permit, Reservation, Scope, Snapshot, Usage};
pub use error::{Dimension, Error};
