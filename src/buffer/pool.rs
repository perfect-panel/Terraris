// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    sync::{Arc, Mutex, MutexGuard, Weak},
};

use super::{
    BufferLayout, BufferLease, BufferScope, Error,
    storage::{Allocation, Owner, allocate_zeroed},
};
use crate::resource::{self, BackingRequest, BackingReservation, Budget, Scope};

const MAX_CLASSES: usize = 32;

#[derive(Clone, Debug)]
pub struct PoolConfig {
    classes: Vec<usize>,
    max_idle_bytes: usize,
    max_idle_allocations: usize,
    max_idle_per_class: usize,
}

impl PoolConfig {
    /// Classes must be strictly increasing, nonzero and at most isize::MAX.
    /// Zero idle limits disable retention. Larger-than-class allocations remain
    /// budgeted but are never cached. Metadata is outside the byte budget.
    pub fn new(
        classes: Vec<usize>,
        max_idle_bytes: usize,
        max_idle_allocations: usize,
        max_idle_per_class: usize,
    ) -> Result<Self, Error> {
        if classes.len() > MAX_CLASSES
            || classes.iter().any(|&n| n == 0 || n > isize::MAX as usize)
            || classes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(Error::InvalidPoolConfig);
        }
        Ok(Self {
            classes,
            max_idle_bytes,
            max_idle_allocations,
            max_idle_per_class,
        })
    }
    pub fn standard(
        max_idle_bytes: usize,
        max_idle_allocations: usize,
        max_idle_per_class: usize,
    ) -> Self {
        Self {
            classes: vec![4096, 16384, 32768, 65536],
            max_idle_bytes,
            max_idle_allocations,
            max_idle_per_class,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PoolSnapshot {
    pub idle_bytes: usize,
    pub idle_allocations: usize,
    pub pending_bytes: usize,
    pub pending_allocations: usize,
    pub leased_bytes: usize,
    pub leased_allocations: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub rejected: u64,
    pub closed: bool,
}

/// All clones are owners of one cache. Buffer scopes and checked-out buffers
/// hold only weak references; dropping the last pool owner frees idle storage.
///
/// ```
/// use terraris::{buffer::{BufferPool, PoolConfig, BufferLayout}, resource::{Budget, Limits}};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let budget = Budget::new(Limits::new(1024 * 1024, 64)?);
/// let pool = BufferPool::new(budget.clone(), PoolConfig::standard(256 * 1024, 16, 4))?;
/// let scope = pool.scope(budget.scope(Limits::new(128 * 1024, 8)?)?, 64 * 1024)?;
/// let mut lease = scope.try_lease(BufferLayout::new(32, 1024, 16)?)?;
/// lease.append_payload(b"hello")?;
/// let bytes = lease.freeze().slice(0..1)?.into_bytes();
/// assert_eq!(scope.snapshot().resident().bytes(), 4096);
/// drop(bytes);
/// assert_eq!(scope.snapshot().used().bytes(), 0);
/// assert_eq!(pool.snapshot().idle_bytes, 4096);
/// pool.close();
/// assert_eq!(budget.snapshot().used().bytes(), 0);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<PoolInner>,
}

pub(super) struct PoolInner {
    budget: Budget,
    config: PoolConfig,
    state: Mutex<State>,
}
struct State {
    buckets: Vec<Vec<Allocation>>,
    stats: PoolSnapshot,
}

impl BufferPool {
    pub fn new(budget: Budget, config: PoolConfig) -> Result<Self, Error> {
        let limits = budget.snapshot().limits();
        if budget.snapshot().is_closed() {
            return Err(resource::Error::Closed.into());
        }
        let mut buckets = Vec::new();
        buckets
            .try_reserve_exact(config.classes.len())
            .map_err(|_| Error::AllocationFailed)?;
        for &size in &config.classes {
            // Reserve cache metadata up front so returning a buffer never grows
            // a bucket or allocates its slot storage while holding the pool lock.
            let count = config
                .max_idle_per_class
                .min(config.max_idle_allocations)
                .min(config.max_idle_bytes / size)
                .min(limits.allocations())
                .min(limits.bytes() / size);
            let mut bucket = Vec::new();
            bucket
                .try_reserve_exact(count)
                .map_err(|_| Error::AllocationFailed)?;
            buckets.push(bucket);
        }
        Ok(Self {
            inner: Arc::new(PoolInner {
                budget,
                config,
                state: Mutex::new(State {
                    buckets,
                    stats: PoolSnapshot::default(),
                }),
            }),
        })
    }

    /// A pool may serve multiple branches, but never a different process budget.
    pub fn scope(&self, resources: Scope, max_allocation: usize) -> Result<BufferScope, Error> {
        if !self.inner.budget.owns(&resources) {
            return Err(resource::Error::ForeignBudget.into());
        }
        if self.inner.lock().stats.closed {
            return Err(Error::PoolClosed);
        }
        let mut scope = BufferScope::new(resources, max_allocation)?;
        scope.pool = Some(Arc::downgrade(&self.inner));
        Ok(scope)
    }

    pub fn snapshot(&self) -> PoolSnapshot {
        let mut stats = self.inner.lock().stats;
        stats.closed |= self.inner.budget.snapshot().is_closed();
        stats
    }

    /// Releases all idle allocations at the linearization point of the drain.
    /// Active leases remain valid and may subsequently return to an open pool.
    pub fn trim(&self) -> Result<(), Error> {
        let mut victims = Vec::new();
        victims
            .try_reserve_exact(
                self.inner
                    .config
                    .max_idle_allocations
                    .min(self.inner.budget.snapshot().limits().allocations()),
            )
            .map_err(|_| Error::AllocationFailed)?;
        {
            let mut state = self.inner.lock();
            for bucket in &mut state.buckets {
                victims.append(bucket);
            }
            state.stats.evictions = state
                .stats
                .evictions
                .saturating_add(state.stats.idle_allocations as u64);
            state.stats.idle_bytes = 0;
            state.stats.idle_allocations = 0;
        }
        drop(victims);
        Ok(())
    }

    /// Rejects new checkouts and frees idle blocks. Granted batches and views
    /// remain valid; their final owners free storage instead of caching it.
    pub fn close(&self) {
        let victims = {
            let mut state = self.inner.lock();
            state.stats.closed = true;
            state.stats.evictions = state
                .stats
                .evictions
                .saturating_add(state.stats.idle_allocations as u64);
            state.stats.idle_bytes = 0;
            state.stats.idle_allocations = 0;
            std::mem::take(&mut state.buckets)
        };
        drop(victims);
    }
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot().fmt(f)
    }
}

#[derive(Clone, Copy)]
struct Plan {
    capacity: usize,
    class: Option<usize>,
    cached_index: Option<usize>,
}

enum PreparedBacking {
    // Drop the scope reservation before potentially freeing cached storage.
    Cached {
        grant: resource::CachedReservation,
        allocation: Allocation,
    },
    // Free allocated memory before releasing its process reservation.
    New {
        storage: Option<Box<[u8]>>,
        grant: resource::Reservation,
    },
}

struct Prepared {
    // Stop observing the checkout as pending before its backing/grants drop.
    ticket: PoolTicket,
    backing: PreparedBacking,
    layout: BufferLayout,
}

impl PoolInner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn plan(&self, scope: &Scope, max: usize, layout: BufferLayout) -> Result<Plan, Error> {
        let required = layout.capacity();
        if required > max {
            return Err(Error::AllocationTooLarge {
                requested: required,
                limit: max,
            });
        }
        // Don't round beyond an explicit single-block or permanent scope limit.
        let class = if required == 0 {
            None
        } else {
            self.config
                .classes
                .iter()
                .position(|&n| n >= required && n <= max && n <= scope.limits().bytes())
        };
        Ok(Plan {
            capacity: class.map_or(required, |c| self.config.classes[c]),
            class,
            cached_index: None,
        })
    }

    pub(super) fn lease_many(
        self: &Arc<Self>,
        scope: &Scope,
        max: usize,
        layouts: &[BufferLayout],
    ) -> Result<Vec<BufferLease>, Error> {
        self.lease_many_with(scope, max, layouts, allocate_zeroed)
    }

    fn lease_many_with(
        self: &Arc<Self>,
        scope: &Scope,
        max: usize,
        layouts: &[BufferLayout],
        mut allocate: impl FnMut(usize) -> Result<Box<[u8]>, Error>,
    ) -> Result<Vec<BufferLease>, Error> {
        if layouts.len() > scope.limits().allocations() {
            return Err(Error::BatchTooLarge {
                requested: layouts.len(),
                limit: scope.limits().allocations(),
            });
        }
        let mut plans = Vec::new();
        plans
            .try_reserve_exact(layouts.len())
            .map_err(|_| Error::AllocationFailed)?;
        for &layout in layouts {
            plans.push(self.plan(scope, max, layout)?);
        }
        let mut prepared = Vec::new();
        prepared
            .try_reserve_exact(layouts.len())
            .map_err(|_| Error::AllocationFailed)?;
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(layouts.len())
            .map_err(|_| Error::AllocationFailed)?;
        let mut evictions = 0;
        loop {
            let mut requests = Vec::new();
            requests
                .try_reserve_exact(plans.len())
                .map_err(|_| Error::AllocationFailed)?;
            let mut state = self.lock();
            if state.stats.closed {
                return Err(Error::PoolClosed);
            }
            let mut selected = [0usize; MAX_CLASSES];
            for plan in &mut plans {
                plan.cached_index = plan.class.and_then(|class| {
                    let len = state.buckets[class].len();
                    if len > selected[class] {
                        selected[class] += 1;
                        Some(len - selected[class])
                    } else {
                        None
                    }
                });
                requests.push(match (plan.class, plan.cached_index) {
                    (Some(class), Some(index)) => {
                        BackingRequest::Cached(&state.buckets[class][index].permit)
                    }
                    _ => BackingRequest::New(plan.capacity),
                });
            }
            let grants = scope.try_reserve_backings(&requests);
            drop(requests);
            let grants = match grants {
                Ok(grants) => grants,
                Err(error) => {
                    // Free only idle entries not needed by this batch, and only
                    // on process pressure. Retry count is bounded despite races.
                    let victim_class = if matches!(error, resource::Error::Exhausted { depth: 0, requested, limit, .. } if requested <= limit)
                        && evictions < self.config.max_idle_allocations
                    {
                        state
                            .buckets
                            .iter()
                            .enumerate()
                            .rev()
                            .find(|(i, b)| b.len() > selected[*i])
                            .map(|(i, _)| i)
                    } else {
                        None
                    };
                    if let Some(class) = victim_class {
                        let victim = state.buckets[class].pop().expect("selected victim");
                        state.stats.idle_bytes -= victim.storage.len();
                        state.stats.idle_allocations -= 1;
                        state.stats.evictions = state.stats.evictions.saturating_add(1);
                        evictions += 1;
                        drop(state);
                        drop(victim);
                        continue;
                    }
                    state.stats.rejected = state.stats.rejected.saturating_add(1);
                    return Err(error.into());
                }
            };
            for ((plan, grant), &layout) in plans.iter().zip(grants).zip(layouts) {
                let backing = match grant {
                    BackingReservation::Cached(grant) => {
                        let allocation = state.buckets[plan.class.expect("cached class")]
                            .pop()
                            .expect("planned cache entry");
                        state.stats.idle_bytes -= plan.capacity;
                        state.stats.idle_allocations -= 1;
                        state.stats.hits = state.stats.hits.saturating_add(1);
                        PreparedBacking::Cached { grant, allocation }
                    }
                    BackingReservation::New(grant) => {
                        state.stats.misses = state.stats.misses.saturating_add(1);
                        PreparedBacking::New {
                            storage: None,
                            grant,
                        }
                    }
                };
                state.stats.pending_bytes += plan.capacity;
                state.stats.pending_allocations += 1;
                prepared.push(Prepared {
                    backing,
                    ticket: PoolTicket {
                        pool: Arc::downgrade(self),
                        capacity: plan.capacity,
                        class: plan.class,
                        phase: Some(TicketPhase::Pending),
                    },
                    layout,
                });
            }
            drop(state);
            break;
        }
        // All fallible storage preparation happens before any lease is returned
        // or activated. On failure, Prepared's field order unwinds both sorts of
        // reservations; selected cached blocks may be evicted during rollback.
        for entry in &mut prepared {
            match &mut entry.backing {
                PreparedBacking::Cached { allocation, .. } => allocation.storage.fill(0),
                PreparedBacking::New { storage, .. } => {
                    let allocated = allocate(entry.ticket.capacity)?;
                    if allocated.len() != entry.ticket.capacity {
                        drop(allocated);
                        return Err(Error::AllocationSizeMismatch);
                    }
                    *storage = Some(allocated);
                }
            }
        }
        for entry in prepared {
            let (allocation, scope_permit) = match entry.backing {
                PreparedBacking::Cached { grant, allocation } => (allocation, grant.commit()),
                PreparedBacking::New { storage, grant } => {
                    let (permit, scope_permit) = grant.commit().into_parts();
                    (
                        Allocation {
                            storage: storage.expect("prepared allocation"),
                            permit,
                        },
                        scope_permit,
                    )
                }
            };
            let mut ticket = entry.ticket;
            ticket.activate();
            leases.push(BufferLease::from_owner(
                Owner::new(allocation, scope_permit, Some(ticket)),
                entry.layout,
            ));
        }
        Ok(leases)
    }
}

#[derive(Clone, Copy)]
enum TicketPhase {
    Pending,
    Active,
}

pub(super) struct PoolTicket {
    pool: Weak<PoolInner>,
    capacity: usize,
    class: Option<usize>,
    phase: Option<TicketPhase>,
}

impl PoolTicket {
    fn activate(&mut self) {
        if let Some(pool) = self.pool.upgrade() {
            let mut state = pool.lock();
            state.stats.pending_bytes -= self.capacity;
            state.stats.pending_allocations -= 1;
            state.stats.leased_bytes += self.capacity;
            state.stats.leased_allocations += 1;
        }
        self.phase = Some(TicketPhase::Active);
    }

    fn finish(&mut self, stats: &mut PoolSnapshot) {
        match self.phase.take() {
            Some(TicketPhase::Pending) => {
                stats.pending_bytes -= self.capacity;
                stats.pending_allocations -= 1;
            }
            Some(TicketPhase::Active) => {
                stats.leased_bytes -= self.capacity;
                stats.leased_allocations -= 1;
            }
            None => {}
        }
    }

    pub(super) fn recycle(mut self, allocation: Allocation) {
        let mut allocation = Some(allocation);
        if let Some(pool) = self.pool.upgrade() {
            let mut state = pool.lock();
            self.finish(&mut state.stats);
            if !state.stats.closed
                && !allocation
                    .as_ref()
                    .expect("owned allocation")
                    .permit
                    .is_closed()
                && let Some(class) = self.class
                && state.stats.idle_allocations < pool.config.max_idle_allocations
                && self.capacity
                    <= pool
                        .config
                        .max_idle_bytes
                        .saturating_sub(state.stats.idle_bytes)
                && state.buckets[class].len() < pool.config.max_idle_per_class
                && state.buckets[class].len() < state.buckets[class].capacity()
            {
                state.buckets[class].push(allocation.take().expect("owned allocation"));
                state.stats.idle_bytes += self.capacity;
                state.stats.idle_allocations += 1;
            }
        }
        // Never free payload storage or invoke the resource permit Drop under
        // the cache mutex. Scope permits have already been released by Owner.
        drop(allocation);
    }
}

impl Drop for PoolTicket {
    fn drop(&mut self) {
        if self.phase.is_some()
            && let Some(pool) = self.pool.upgrade()
        {
            self.finish(&mut pool.lock().stats);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::Limits;

    #[test]
    fn mixed_batch_allocation_failure_releases_cached_and_fresh_grants() {
        for panic_in_allocator in [false, true] {
            let budget = Budget::new(Limits::new(64, 8).unwrap());
            let pool = BufferPool::new(
                budget.clone(),
                PoolConfig::new(vec![8, 16, 32], 64, 8, 8).unwrap(),
            )
            .unwrap();
            let parent = budget.scope(Limits::new(64, 8).unwrap()).unwrap();
            let resources = parent.child(Limits::new(48, 4).unwrap()).unwrap();
            let scope = pool.scope(resources.clone(), 32).unwrap();
            drop(
                scope
                    .try_lease(BufferLayout::new(0, 8, 0).unwrap())
                    .unwrap(),
            );
            let layouts = [
                BufferLayout::new(0, 8, 0).unwrap(),
                BufferLayout::new(0, 16, 0).unwrap(),
                BufferLayout::new(0, 16, 0).unwrap(),
            ];
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut calls = 0;
                pool.inner
                    .lease_many_with(&resources, 32, &layouts, |size| {
                        assert_eq!(budget.snapshot().used().bytes(), 40);
                        assert_eq!(resources.snapshot().reserved().bytes(), 40);
                        assert_eq!(pool.snapshot().pending_bytes, 40);
                        calls += 1;
                        if calls == 2 {
                            assert!(!panic_in_allocator, "synthetic allocation unwind");
                            return Err(Error::AllocationFailed);
                        }
                        allocate_zeroed(size)
                    })
            }));
            if panic_in_allocator {
                assert!(result.is_err());
            } else {
                assert!(matches!(result.unwrap(), Err(Error::AllocationFailed)));
            }
            for snapshot in [budget.snapshot(), parent.snapshot(), resources.snapshot()] {
                assert_eq!(snapshot.used().bytes(), 0);
                assert_eq!(snapshot.used().allocations(), 0);
            }
            assert_eq!(pool.snapshot().pending_allocations, 0);
            assert_eq!(pool.snapshot().leased_allocations, 0);
            assert_eq!(pool.snapshot().idle_allocations, 0);
            drop(scope.try_lease_many(&layouts).unwrap());
            pool.close();
            assert_eq!(budget.snapshot().used().bytes(), 0);
        }
    }

    #[test]
    fn close_during_granted_preparation_keeps_lease_valid_but_prevents_recaching() {
        let budget = Budget::new(Limits::new(32, 4).unwrap());
        let pool = BufferPool::new(
            budget.clone(),
            PoolConfig::new(vec![8, 16], 32, 4, 4).unwrap(),
        )
        .unwrap();
        let resources = budget.scope(Limits::new(32, 4).unwrap()).unwrap();
        let leases = pool
            .inner
            .lease_many_with(
                &resources,
                16,
                &[BufferLayout::new(0, 8, 0).unwrap()],
                |size| {
                    pool.close();
                    allocate_zeroed(size)
                },
            )
            .unwrap();
        assert_eq!(pool.snapshot().leased_bytes, 8);
        assert_eq!(resources.snapshot().resident().bytes(), 8);
        drop(leases);
        assert_eq!(pool.snapshot().leased_bytes, 0);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}
