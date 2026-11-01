// SPDX-License-Identifier: GPL-3.0-only

use std::{fmt, sync::Weak};

use super::{BufferLayout, BufferLease, Error, pool::PoolInner, storage::allocate_zeroed};
use crate::resource::{Limits, Scope, Snapshot};

/// Allocates against one resource scope; all clones share its quotas. new()
/// uses exact allocations; BufferPool::scope() opts into bounded class caching.
#[derive(Clone)]
pub struct BufferScope {
    pub(super) resources: Scope,
    pub(super) max_allocation: usize,
    pub(super) pool: Option<Weak<PoolInner>>,
}

impl BufferScope {
    pub(crate) fn capacity_changed(&self) -> &tokio::sync::Notify {
        self.resources.capacity_changed()
    }
    /// Internal I/O backpressure. The owning operation supplies cancellation
    /// and a deadline; dropping this future leaves no pending reservation.
    pub(crate) async fn lease_when_available(
        &self,
        layout: BufferLayout,
    ) -> Result<BufferLease, Error> {
        loop {
            let changed = self.capacity_changed().notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            match self.try_lease(layout) {
                Err(Error::Resource(crate::resource::Error::Exhausted {
                    requested,
                    limit,
                    ..
                })) if requested <= limit => changed.await,
                result => return result,
            }
        }
    }
    pub fn new(resources: Scope, max_allocation: usize) -> Result<Self, Error> {
        if max_allocation == 0 || max_allocation > isize::MAX as usize {
            return Err(Error::InvalidAllocationLimit);
        }
        Ok(Self {
            resources,
            max_allocation,
            pool: None,
        })
    }

    pub fn child(&self, limits: Limits) -> Result<Self, Error> {
        Ok(Self {
            resources: self.resources.child(limits)?,
            max_allocation: self.max_allocation,
            pool: self.pool.clone(),
        })
    }
    pub fn snapshot(&self) -> Snapshot {
        self.resources.snapshot()
    }
    pub fn max_allocation(&self) -> usize {
        self.max_allocation
    }
    pub fn close(&self) {
        self.resources.close();
    }

    pub fn try_lease(&self, layout: BufferLayout) -> Result<BufferLease, Error> {
        if let Some(pool) = &self.pool {
            let pool = pool.upgrade().ok_or(Error::PoolClosed)?;
            let mut leases = pool.lease_many(&self.resources, self.max_allocation, &[layout])?;
            return Ok(leases.pop().expect("single checked-out buffer"));
        }
        self.validate(layout)?;
        let reservation = self.resources.try_reserve(layout.capacity())?;
        let storage = allocate_zeroed(layout.capacity())?;
        BufferLease::from_storage(storage, layout, reservation)
    }

    /// Reserves all layouts atomically BEFORE allocating any payload storage.
    /// If a later allocation fails, earlier buffers and unused reservations
    /// are dropped: no partial batch is ever handed to the caller.
    pub fn try_lease_many(&self, layouts: &[BufferLayout]) -> Result<Vec<BufferLease>, Error> {
        if let Some(pool) = &self.pool {
            return pool.upgrade().ok_or(Error::PoolClosed)?.lease_many(
                &self.resources,
                self.max_allocation,
                layouts,
            );
        }
        self.lease_many_with(layouts, allocate_zeroed)
    }

    fn lease_many_with(
        &self,
        layouts: &[BufferLayout],
        mut allocate: impl FnMut(usize) -> Result<Box<[u8]>, Error>,
    ) -> Result<Vec<BufferLease>, Error> {
        if layouts.len() > self.resources.limits().allocations() {
            return Err(Error::BatchTooLarge {
                requested: layouts.len(),
                limit: self.resources.limits().allocations(),
            });
        }
        for &layout in layouts {
            self.validate(layout)?;
        }
        let mut sizes = Vec::new();
        sizes
            .try_reserve_exact(layouts.len())
            .map_err(|_| Error::AllocationFailed)?;
        sizes.extend(layouts.iter().map(|layout| layout.capacity()));
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(layouts.len())
            .map_err(|_| Error::AllocationFailed)?;
        let reservations = self.resources.try_reserve_many(&sizes)?;
        for (&layout, reservation) in layouts.iter().zip(reservations) {
            let storage = allocate(layout.capacity())?;
            leases.push(BufferLease::from_storage(storage, layout, reservation)?);
        }
        Ok(leases)
    }

    fn validate(&self, layout: BufferLayout) -> Result<(), Error> {
        if layout.capacity() > self.max_allocation {
            return Err(Error::AllocationTooLarge {
                requested: layout.capacity(),
                limit: self.max_allocation,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for BufferScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferScope")
            .field("max_allocation", &self.max_allocation)
            .field("resources", &self.resources)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::Budget;

    #[test]
    fn later_allocation_failure_rolls_back_resident_and_reserved_capacity() {
        for fail_at in 0..3 {
            let budget = Budget::new(Limits::new(128, 8).unwrap());
            let scope = BufferScope::new(budget.root_scope(), 64).unwrap();
            let layout = BufferLayout::new(4, 12, 4).unwrap();
            let mut calls = 0;
            let result = scope.lease_many_with(&[layout; 3], |size| {
                let snapshot = budget.snapshot();
                assert_eq!(snapshot.used().bytes(), 60);
                assert_eq!(snapshot.resident().bytes(), calls * 20);
                assert_eq!(snapshot.reserved().bytes(), (3 - calls) * 20);
                if calls == fail_at {
                    return Err(Error::AllocationFailed);
                }
                calls += 1;
                allocate_zeroed(size)
            });
            assert!(matches!(result, Err(Error::AllocationFailed)));
            assert_eq!(budget.snapshot().used().bytes(), 0);
            assert_eq!(budget.snapshot().used().allocations(), 0);
        }
    }

    #[test]
    fn invalid_allocator_output_cannot_undercharge_a_buffer() {
        let budget = Budget::new(Limits::new(64, 4).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 64).unwrap();
        let result = scope.lease_many_with(&[BufferLayout::new(0, 8, 0).unwrap()], |_| {
            Ok(vec![0; 9].into_boxed_slice())
        });
        assert!(matches!(result, Err(Error::AllocationSizeMismatch)));
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }

    #[test]
    fn preflight_failure_does_not_allocate_any_payload_storage() {
        let budget = Budget::new(Limits::new(32, 4).unwrap());
        let scope = BufferScope::new(budget.root_scope(), 16).unwrap();
        let small = BufferLayout::new(0, 8, 0).unwrap();
        let large = BufferLayout::new(0, 17, 0).unwrap();
        assert!(
            scope
                .lease_many_with(&[small, large], |_| panic!("must not allocate"))
                .is_err()
        );
        assert!(
            scope
                .lease_many_with(&[BufferLayout::new(0, 16, 0).unwrap(); 3], |_| panic!(
                    "must not allocate"
                ))
                .is_err()
        );
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }

    #[test]
    fn allocator_unwind_releases_partial_batch_in_every_scope() {
        let budget = Budget::new(Limits::new(128, 8).unwrap());
        let parent = budget.scope(Limits::new(100, 6).unwrap()).unwrap();
        let scope =
            BufferScope::new(parent.child(Limits::new(80, 4).unwrap()).unwrap(), 64).unwrap();
        let layout = BufferLayout::new(4, 12, 4).unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut calls = 0;
            scope.lease_many_with(&[layout; 3], |size| {
                calls += 1;
                assert!(calls != 2, "synthetic allocator panic");
                allocate_zeroed(size)
            })
        }));
        assert!(result.is_err());
        for snapshot in [budget.snapshot(), parent.snapshot(), scope.snapshot()] {
            assert_eq!(snapshot.used().bytes(), 0);
            assert_eq!(snapshot.used().allocations(), 0);
        }
        // The allocator callback never held the accounting lock.
        drop(scope.try_lease_many(&[layout; 3]).unwrap());
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}
