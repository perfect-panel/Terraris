// SPDX-License-Identifier: GPL-3.0-only

use std::fmt;

use crate::resource;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Region {
    Payload,
    Headroom,
    Tailroom,
    Readable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    LayoutOverflow,
    AddressSpaceExceeded,
    InvalidAllocationLimit,
    AllocationTooLarge {
        requested: usize,
        limit: usize,
    },
    BatchTooLarge {
        requested: usize,
        limit: usize,
    },
    AllocationFailed,
    AllocationSizeMismatch,
    NotWritable,
    PayloadSealed,
    NoSpace {
        region: Region,
        requested: usize,
        available: usize,
    },
    Resource(resource::Error),
}

impl From<resource::Error> for Error {
    fn from(value: resource::Error) -> Self {
        Self::Resource(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LayoutOverflow => f.write_str("buffer layout size overflows usize"),
            Self::AddressSpaceExceeded => f.write_str("buffer layout exceeds isize::MAX"),
            Self::InvalidAllocationLimit => {
                f.write_str("maximum allocation must be positive and at most isize::MAX")
            }
            Self::AllocationTooLarge { requested, limit } => {
                write!(f, "buffer allocation {requested} exceeds limit {limit}")
            }
            Self::BatchTooLarge { requested, limit } => write!(
                f,
                "buffer batch has {requested} items, scope limit is {limit}"
            ),
            Self::AllocationFailed => f.write_str("buffer allocation failed"),
            Self::AllocationSizeMismatch => {
                f.write_str("storage size does not match reserved buffer layout")
            }
            Self::NotWritable => {
                f.write_str("clear the consumed or truncated buffer before writing new data")
            }
            Self::PayloadSealed => f.write_str("payload is sealed by trailer writing"),
            Self::NoSpace {
                region,
                requested,
                available,
            } => write!(
                f,
                "buffer {region:?}: requested {requested}, available {available}"
            ),
            Self::Resource(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resource(error) => Some(error),
            _ => None,
        }
    }
}
