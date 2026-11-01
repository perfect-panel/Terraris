// SPDX-License-Identifier: GPL-3.0-only

use std::{fmt, future::poll_fn, io, pin::Pin, task::Poll};

use tokio::io::{AsyncRead, ReadBuf};

use super::{BufferLayout, Error, Region};
use crate::resource::{AllocationPermit, Reservation, ScopePermit};

struct Allocation {
    // Fields drop in declaration order: storage must be freed before its
    // process capacity is made available for another allocation.
    storage: Box<[u8]>,
    _permit: AllocationPermit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Payload,
    Sealed,
    Draining,
}

/// The unique mutable owner of a fixed-capacity, budgeted allocation.
/// Readable bytes and all new header/trailer/padding bytes are initialized.
/// Debug never prints payload data.
///
/// ```compile_fail
/// use terraris::buffer::BufferLease;
/// fn duplicate(buffer: BufferLease) { let _ = buffer.clone(); }
/// ```
pub struct BufferLease {
    // End the connection lease before dropping the allocation. The process
    // charge remains owned by Allocation until AFTER its storage is freed.
    _scope_permit: ScopePermit,
    allocation: Allocation,
    layout: BufferLayout,
    start: usize,
    end: usize,
    trailer_used: usize,
    phase: Phase,
}

impl BufferLease {
    pub(super) fn from_storage(
        storage: Box<[u8]>,
        layout: BufferLayout,
        reservation: Reservation,
    ) -> Result<Self, Error> {
        if storage.len() != layout.capacity() || reservation.bytes() != storage.len() {
            drop(storage);
            drop(reservation);
            return Err(Error::AllocationSizeMismatch);
        }
        let (allocation_permit, scope_permit) = reservation.commit().into_parts();
        Ok(Self {
            _scope_permit: scope_permit,
            allocation: Allocation {
                storage,
                _permit: allocation_permit,
            },
            layout,
            start: layout.headroom(),
            end: layout.headroom(),
            trailer_used: 0,
            phase: Phase::Payload,
        })
    }

    pub fn layout(&self) -> BufferLayout {
        self.layout
    }
    pub fn capacity(&self) -> usize {
        self.allocation.storage.len()
    }
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.allocation.storage[self.start..self.end]
    }
    /// Only already-readable bytes can be edited; this cannot expand the range.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.allocation.storage[self.start..self.end]
    }
    pub fn remaining_payload(&self) -> usize {
        if self.phase == Phase::Payload {
            self.layout.payload_limit() - self.end
        } else {
            0
        }
    }
    pub fn remaining_headroom(&self) -> usize {
        if self.phase == Phase::Draining {
            0
        } else {
            self.start
        }
    }
    pub fn remaining_tailroom(&self) -> usize {
        if self.phase == Phase::Draining {
            0
        } else {
            self.layout.tailroom() - self.trailer_used
        }
    }

    pub fn append_payload(&mut self, data: &[u8]) -> Result<(), Error> {
        self.check_payload(data.len())?;
        self.allocation.storage[self.end..self.end + data.len()].copy_from_slice(data);
        self.end += data.len();
        Ok(())
    }

    /// Appends initialized padding/scratch space, never stale bytes from clear.
    pub fn append_zeroed(&mut self, length: usize) -> Result<&mut [u8], Error> {
        self.check_payload(length)?;
        let start = self.end;
        self.allocation.storage[start..start + length].fill(0);
        self.end += length;
        Ok(&mut self.allocation.storage[start..self.end])
    }

    pub fn prepend_header(&mut self, data: &[u8]) -> Result<(), Error> {
        self.check_frame()?;
        check_space(Region::Headroom, data.len(), self.start)?;
        let start = self.start - data.len();
        self.allocation.storage[start..self.start].copy_from_slice(data);
        self.start = start;
        Ok(())
    }

    /// A trailer seals payload appends, including a zero-length trailer.
    /// Additional trailers and outer headers remain allowed within the layout.
    pub fn append_trailer(&mut self, data: &[u8]) -> Result<(), Error> {
        self.check_frame()?;
        check_space(Region::Tailroom, data.len(), self.remaining_tailroom())?;
        self.allocation.storage[self.end..self.end + data.len()].copy_from_slice(data);
        self.end += data.len();
        self.trailer_used += data.len();
        self.phase = Phase::Sealed;
        Ok(())
    }

    pub fn append_trailer_zeroed(&mut self, length: usize) -> Result<&mut [u8], Error> {
        self.check_frame()?;
        check_space(Region::Tailroom, length, self.remaining_tailroom())?;
        let start = self.end;
        self.allocation.storage[start..start + length].fill(0);
        self.end += length;
        self.trailer_used += length;
        self.phase = Phase::Sealed;
        Ok(&mut self.allocation.storage[start..self.end])
    }

    /// Drops an already-written prefix without releasing its allocation budget.
    /// A nonzero consume prevents framing/appending until clear is called.
    pub fn consume(&mut self, length: usize) -> Result<(), Error> {
        check_space(Region::Readable, length, self.len())?;
        if length != 0 {
            self.start += length;
            self.phase = Phase::Draining;
        }
        Ok(())
    }

    /// Retains exactly `length` readable bytes; never exposes additional bytes.
    pub fn truncate(&mut self, length: usize) -> Result<(), Error> {
        check_space(Region::Readable, length, self.len())?;
        if length != self.len() {
            self.end = self.start + length;
            self.phase = Phase::Draining;
        }
        Ok(())
    }

    /// Restores the original layout and an empty readable range. It neither
    /// releases capacity nor promises secure erasure of the backing storage.
    pub fn clear(&mut self) {
        self.start = self.layout.headroom();
        self.end = self.start;
        self.trailer_used = 0;
        self.phase = Phase::Payload;
    }

    /// Bounded read adapter; no public spare-capacity or arbitrary set_len API.
    /// Commits only a successful poll's filled bytes. Pending, cancellation and
    /// errors leave the readable range unchanged. Full payload space is an
    /// error, not a zero-byte read which could be mistaken for EOF.
    pub async fn read_from<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        reader: &mut R,
    ) -> io::Result<usize> {
        self.check_payload(1)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        poll_fn(|cx| {
            let mut read =
                ReadBuf::new(&mut self.allocation.storage[self.end..self.layout.payload_limit()]);
            match Pin::new(&mut *reader).poll_read(cx, &mut read) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let count = read.filled().len();
                    self.end += count;
                    Poll::Ready(Ok(count))
                }
            }
        })
        .await
    }

    fn check_payload(&self, length: usize) -> Result<(), Error> {
        match self.phase {
            Phase::Draining => Err(Error::NotWritable),
            Phase::Sealed => Err(Error::PayloadSealed),
            Phase::Payload => check_space(Region::Payload, length, self.remaining_payload()),
        }
    }

    fn check_frame(&self) -> Result<(), Error> {
        if self.phase == Phase::Draining {
            Err(Error::NotWritable)
        } else {
            Ok(())
        }
    }
}

impl AsRef<[u8]> for BufferLease {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for BufferLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferLease")
            .field("layout", &self.layout)
            .field("len", &self.len())
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

fn check_space(region: Region, requested: usize, available: usize) -> Result<(), Error> {
    if requested > available {
        Err(Error::NoSpace {
            region,
            requested,
            available,
        })
    } else {
        Ok(())
    }
}
