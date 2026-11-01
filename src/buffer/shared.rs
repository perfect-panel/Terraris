// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    ops::{Bound, Range, RangeBounds},
    sync::Arc,
};

use bytes::Bytes;

use super::{BufferLayout, BufferLease, BufferScope, Error, storage::Owner};

/// Immutable views share one owner and retain the FULL allocation and scope
/// quota. Even an empty SharedBuffer slice retains its owner.
///
/// ```compile_fail
/// use terraris::buffer::SharedBuffer;
/// fn edit(mut view: SharedBuffer) { view.as_mut_slice()[0] = 1; }
/// ```
#[derive(Clone)]
pub struct SharedBuffer {
    pub(super) owner: Arc<Owner>,
    pub(super) range: Range<usize>,
}

impl SharedBuffer {
    pub fn len(&self) -> usize {
        self.range.end - self.range.start
    }
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.owner.storage().len()
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.owner.storage()[self.range.clone()]
    }

    pub fn slice(&self, range: impl RangeBounds<usize>) -> Result<Self, Error> {
        let start = match range.start_bound() {
            Bound::Included(&v) => v,
            Bound::Excluded(&v) => v.checked_add(1).ok_or(Error::InvalidRange)?,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&v) => v.checked_add(1).ok_or(Error::InvalidRange)?,
            Bound::Excluded(&v) => v,
            Bound::Unbounded => self.len(),
        };
        if start > end || end > self.len() {
            return Err(Error::InvalidRange);
        }
        Ok(Self {
            owner: self.owner.clone(),
            range: self.range.start + start..self.range.start + end,
        })
    }

    /// No payload copy. Bytes owns this view; nonempty Bytes slices/clones keep
    /// it alive. Bytes may discard ownership for its own empty slice operations.
    /// Converting the result to BytesMut may allocate an unbudgeted deep copy.
    pub fn into_bytes(self) -> Bytes {
        Bytes::from_owner(self)
    }

    /// Explicit copy with overlapping old/new budget. Failure leaves this view
    /// intact; this is also how a view moves into a different connection scope.
    pub fn copy_to(&self, scope: &BufferScope) -> Result<BufferLease, Error> {
        let mut lease = scope.try_lease(BufferLayout::new(0, self.len(), 0)?)?;
        lease.append_payload(self.as_slice())?;
        Ok(lease)
    }
}

impl AsRef<[u8]> for SharedBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl fmt::Debug for SharedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedBuffer")
            .field("len", &self.len())
            .field("capacity", &self.capacity())
            .finish_non_exhaustive()
    }
}
