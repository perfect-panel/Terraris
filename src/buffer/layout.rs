// SPDX-License-Identifier: GPL-3.0-only

use super::Error;

/// Exact logical layout. A pooled allocation may retain a larger size class,
/// but that excess space does not expand the writable payload/header limits.
/// Zero-length payloads and even entirely empty layouts are valid; an empty
/// lease still consumes one resource allocation slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferLayout {
    headroom: usize,
    payload_capacity: usize,
    tailroom: usize,
    capacity: usize,
}

impl BufferLayout {
    pub fn new(headroom: usize, payload_capacity: usize, tailroom: usize) -> Result<Self, Error> {
        let capacity = headroom
            .checked_add(payload_capacity)
            .and_then(|n| n.checked_add(tailroom))
            .ok_or(Error::LayoutOverflow)?;
        if capacity > isize::MAX as usize {
            return Err(Error::AddressSpaceExceeded);
        }
        Ok(Self {
            headroom,
            payload_capacity,
            tailroom,
            capacity,
        })
    }
    pub fn headroom(self) -> usize {
        self.headroom
    }
    pub fn payload_capacity(self) -> usize {
        self.payload_capacity
    }
    pub fn tailroom(self) -> usize {
        self.tailroom
    }
    pub fn capacity(self) -> usize {
        self.capacity
    }
    pub(super) fn payload_limit(self) -> usize {
        self.headroom + self.payload_capacity
    }
}
