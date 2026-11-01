// SPDX-License-Identifier: GPL-3.0-only

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dimension {
    Bytes,
    Allocations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLimits,
    ChildLimitExceedsParent,
    ScopeDepthExceeded,
    Closed,
    SizeOverflow,
    MetadataAllocationFailed,
    ForeignBudget,
    /// Depth zero denotes the process budget. A request above `limit` cannot
    /// succeed even after all existing owners release their permits.
    Exhausted {
        dimension: Dimension,
        depth: usize,
        requested: usize,
        available: usize,
        limit: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => f.write_str("byte and allocation limits must be positive"),
            Self::ChildLimitExceedsParent => f.write_str("child limits exceed parent limits"),
            Self::ScopeDepthExceeded => f.write_str("maximum resource scope depth exceeded"),
            Self::Closed => f.write_str("resource scope is closed"),
            Self::SizeOverflow => f.write_str("reservation byte total overflows usize"),
            Self::MetadataAllocationFailed => f.write_str("cannot allocate reservation metadata"),
            Self::ForeignBudget => f.write_str("cached allocation belongs to a different budget"),
            Self::Exhausted {
                dimension,
                depth,
                requested,
                available,
                limit,
            } => write!(
                f,
                "resource {dimension:?} exhausted at depth {depth}: requested {requested}, available {available}, limit {limit}"
            ),
        }
    }
}

impl std::error::Error for Error {}
