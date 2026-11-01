// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fmt,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use super::{Dimension, Error};

/// Bound both ancestry traversal and recursive Arc destruction.
pub const MAX_SCOPE_DEPTH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    bytes: usize,
    allocations: usize,
}

impl Limits {
    pub fn new(bytes: usize, allocations: usize) -> Result<Self, Error> {
        if bytes == 0 || allocations == 0 {
            return Err(Error::InvalidLimits);
        }
        Ok(Self { bytes, allocations })
    }
    pub fn bytes(self) -> usize {
        self.bytes
    }
    pub fn allocations(self) -> usize {
        self.allocations
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    bytes: usize,
    allocations: usize,
}

impl Usage {
    pub fn bytes(self) -> usize {
        self.bytes
    }
    pub fn allocations(self) -> usize {
        self.allocations
    }

    fn plus(self, other: Self) -> Self {
        // Only used for totals already bounded by a validated Limits value.
        Self {
            bytes: self.bytes + other.bytes,
            allocations: self.allocations + other.allocations,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    limits: Limits,
    reserved: Usage,
    resident: Usage,
    closed: bool,
}

impl Snapshot {
    pub fn limits(self) -> Limits {
        self.limits
    }
    pub fn reserved(self) -> Usage {
        self.reserved
    }
    pub fn resident(self) -> Usage {
        self.resident
    }
    pub fn used(self) -> Usage {
        self.reserved.plus(self.resident)
    }
    pub fn is_closed(self) -> bool {
        self.closed
    }
}

#[derive(Clone)]
pub struct Budget {
    inner: Arc<Inner>,
}

struct Inner {
    limits: Limits,
    state: Mutex<State>,
    changed: tokio::sync::Notify,
}

#[derive(Default)]
struct State {
    reserved: Usage,
    resident: Usage,
    closed: bool,
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                state: Mutex::default(),
                changed: tokio::sync::Notify::new(),
            }),
        }
    }
    pub fn root_scope(&self) -> Scope {
        Scope {
            inner: self.inner.clone(),
            node: None,
        }
    }
    pub fn scope(&self, limits: Limits) -> Result<Scope, Error> {
        self.root_scope().child(limits)
    }
    pub fn snapshot(&self) -> Snapshot {
        self.root_scope().snapshot()
    }
    pub(crate) fn owns(&self, scope: &Scope) -> bool {
        Arc::ptr_eq(&self.inner, &scope.inner)
    }
    /// Stops new reservations, including in descendants. Previously granted
    /// reservations and resident permits remain valid until their owners drop.
    pub fn close(&self) {
        self.root_scope().close();
    }
}

impl fmt::Debug for Budget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.snapshot().fmt(f)
    }
}

#[derive(Clone)]
pub struct Scope {
    inner: Arc<Inner>,
    node: Option<Arc<Node>>,
}

struct Node {
    parent: Option<Arc<Node>>,
    depth: usize,
    limits: Limits,
    // These atomics provide safe shared storage, not independent lock-free
    // accounting. ALL reads and mutations occur under Inner.state's lock.
    reserved_bytes: AtomicUsize,
    reserved_allocations: AtomicUsize,
    resident_bytes: AtomicUsize,
    resident_allocations: AtomicUsize,
    closed: AtomicBool,
}

impl Node {
    fn reserved(&self) -> Usage {
        Usage {
            bytes: self.reserved_bytes.load(Ordering::Relaxed),
            allocations: self.reserved_allocations.load(Ordering::Relaxed),
        }
    }
    fn resident(&self) -> Usage {
        Usage {
            bytes: self.resident_bytes.load(Ordering::Relaxed),
            allocations: self.resident_allocations.load(Ordering::Relaxed),
        }
    }
    fn set_usage(&self, reserved: Usage, resident: Usage) {
        self.reserved_bytes.store(reserved.bytes, Ordering::Relaxed);
        self.reserved_allocations
            .store(reserved.allocations, Ordering::Relaxed);
        self.resident_bytes.store(resident.bytes, Ordering::Relaxed);
        self.resident_allocations
            .store(resident.allocations, Ordering::Relaxed);
    }
}

impl Scope {
    /// Register before checking capacity so a concurrent release cannot be lost.
    pub(crate) fn capacity_changed(&self) -> &tokio::sync::Notify {
        &self.inner.changed
    }
    pub fn limits(&self) -> Limits {
        self.node.as_ref().map_or(self.inner.limits, |n| n.limits)
    }
    pub fn depth(&self) -> usize {
        self.node.as_ref().map_or(0, |n| n.depth)
    }

    pub fn child(&self, limits: Limits) -> Result<Self, Error> {
        let parent = self.limits();
        if limits.bytes > parent.bytes || limits.allocations > parent.allocations {
            return Err(Error::ChildLimitExceedsParent);
        }
        if self.depth() == MAX_SCOPE_DEPTH {
            return Err(Error::ScopeDepthExceeded);
        }
        // Allocate the metadata outside the budget lock, then linearize creation
        // against close. Creating a scope itself reserves no buffer capacity.
        let node = Arc::new(Node {
            parent: self.node.clone(),
            depth: self.depth() + 1,
            limits,
            reserved_bytes: AtomicUsize::new(0),
            reserved_allocations: AtomicUsize::new(0),
            resident_bytes: AtomicUsize::new(0),
            resident_allocations: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        });
        let state = self.inner.lock();
        self.check_open(&state)?;
        Ok(Self {
            inner: self.inner.clone(),
            node: Some(node),
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.inner.lock();
        let (reserved, resident) = self
            .node
            .as_ref()
            .map_or((state.reserved, state.resident), |n| {
                (n.reserved(), n.resident())
            });
        Snapshot {
            limits: self.limits(),
            reserved,
            resident,
            closed: self.check_open(&state).is_err(),
        }
    }

    /// Idempotently prevents new grants in this branch. Existing owners are not
    /// revoked; closing a child does not close its parent or siblings.
    pub fn close(&self) {
        let mut state = self.inner.lock();
        if let Some(node) = &self.node {
            node.closed.store(true, Ordering::Relaxed);
        } else {
            state.closed = true;
        }
        drop(state);
        self.inner.changed.notify_waiters();
    }

    /// A zero-byte request still occupies one allocation slot.
    pub fn try_reserve(&self, bytes: usize) -> Result<Reservation, Error> {
        let cost = Usage {
            bytes,
            allocations: 1,
        };
        let mut state = self.inner.lock();
        self.check(&state, cost)?;
        self.add_reserved(&mut state, cost);
        Ok(self.reservation(bytes))
    }

    /// All requests target this scope. The returned non-cloneable reservations
    /// can subsequently be committed or dropped independently. Failure does
    /// not change usage in the root, ancestors, or this scope.
    pub fn try_reserve_many(&self, sizes: &[usize]) -> Result<Vec<Reservation>, Error> {
        let bytes = sizes
            .iter()
            .try_fold(0usize, |sum, &n| sum.checked_add(n))
            .ok_or(Error::SizeOverflow)?;
        let cost = Usage {
            bytes,
            allocations: sizes.len(),
        };
        {
            let state = self.inner.lock();
            self.check(&state, cost)?;
        }
        let mut reservations = Vec::new();
        reservations
            .try_reserve_exact(sizes.len())
            .map_err(|_| Error::MetadataAllocationFailed)?;
        let mut state = self.inner.lock();
        self.check(&state, cost)?;
        self.add_reserved(&mut state, cost);
        // Capacity is already allocated; pushes and Arc clones do not allocate.
        for &bytes in sizes {
            reservations.push(self.reservation(bytes));
        }
        Ok(reservations)
    }

    /// Pool checkout transaction: cached allocations already own process
    /// capacity, while BOTH cached and fresh entries need new scope capacity.
    pub(crate) fn try_reserve_backings(
        &self,
        requests: &[BackingRequest<'_>],
    ) -> Result<Vec<BackingReservation>, Error> {
        let mut global = Usage::default();
        let mut scoped = Usage::default();
        for request in requests {
            let bytes = match request {
                BackingRequest::New(bytes) => {
                    global.bytes = global
                        .bytes
                        .checked_add(*bytes)
                        .ok_or(Error::SizeOverflow)?;
                    global.allocations += 1;
                    *bytes
                }
                BackingRequest::Cached(permit) => {
                    if !Arc::ptr_eq(&self.inner, &permit._charge.scope.inner) {
                        return Err(Error::ForeignBudget);
                    }
                    permit._charge.cost.bytes
                }
            };
            scoped.bytes = scoped.bytes.checked_add(bytes).ok_or(Error::SizeOverflow)?;
            scoped.allocations += 1;
        }
        let mut grants = Vec::new();
        grants
            .try_reserve_exact(requests.len())
            .map_err(|_| Error::MetadataAllocationFailed)?;
        let mut state = self.inner.lock();
        self.check_open(&state)?;
        // Impossible batches must not evict caches while retrying pressure.
        check_limit(self.inner.limits, Usage::default(), scoped, 0)?;
        for node in self.nodes() {
            check_limit(node.limits, Usage::default(), scoped, node.depth)?;
        }
        check_limit(
            self.inner.limits,
            state.reserved.plus(state.resident),
            global,
            0,
        )?;
        for node in self.nodes() {
            check_limit(
                node.limits,
                node.reserved().plus(node.resident()),
                scoped,
                node.depth,
            )?;
        }
        state.reserved = state.reserved.plus(global);
        for node in self.nodes() {
            node.set_usage(node.reserved().plus(scoped), node.resident());
        }
        for request in requests {
            grants.push(match request {
                BackingRequest::New(bytes) => BackingReservation::New(self.reservation(*bytes)),
                BackingRequest::Cached(permit) => BackingReservation::Cached(CachedReservation {
                    charge: Charge {
                        scope: self.clone(),
                        cost: permit._charge.cost,
                        phase: Phase::Reserved,
                        target: Target::Scopes,
                    },
                }),
            });
        }
        Ok(grants)
    }

    fn reservation(&self, bytes: usize) -> Reservation {
        Reservation {
            charge: Charge {
                scope: self.clone(),
                cost: Usage {
                    bytes,
                    allocations: 1,
                },
                phase: Phase::Reserved,
                target: Target::All,
            },
        }
    }

    fn nodes(&self) -> impl Iterator<Item = &Node> {
        std::iter::successors(self.node.as_deref(), |node| node.parent.as_deref())
    }

    fn check_open(&self, state: &State) -> Result<(), Error> {
        if state.closed || self.nodes().any(|n| n.closed.load(Ordering::Relaxed)) {
            return Err(Error::Closed);
        }
        Ok(())
    }

    fn check(&self, state: &State, cost: Usage) -> Result<(), Error> {
        self.check_open(state)?;
        check_limit(
            self.inner.limits,
            state.reserved.plus(state.resident),
            cost,
            0,
        )?;
        for node in self.nodes() {
            check_limit(
                node.limits,
                node.reserved().plus(node.resident()),
                cost,
                node.depth,
            )?;
        }
        Ok(())
    }

    fn add_reserved(&self, state: &mut State, cost: Usage) {
        state.reserved = state.reserved.plus(cost);
        for node in self.nodes() {
            node.set_usage(node.reserved().plus(cost), node.resident());
        }
    }
}

impl fmt::Debug for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scope")
            .field("depth", &self.depth())
            .field("usage", &self.snapshot())
            .finish()
    }
}

fn check_limit(limits: Limits, used: Usage, cost: Usage, depth: usize) -> Result<(), Error> {
    for (dimension, limit, used, requested) in [
        (Dimension::Bytes, limits.bytes, used.bytes, cost.bytes),
        (
            Dimension::Allocations,
            limits.allocations,
            used.allocations,
            cost.allocations,
        ),
    ] {
        let available = limit - used;
        if requested > available {
            return Err(Error::Exhausted {
                dimension,
                depth,
                requested,
                available,
                limit,
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Phase {
    Reserved,
    Resident,
}
#[derive(Clone, Copy)]
enum Target {
    All,
    Global,
    Scopes,
}

struct Charge {
    scope: Scope,
    cost: Usage,
    phase: Phase,
    target: Target,
}

impl Charge {
    fn commit(&mut self) {
        let mut state = self.scope.inner.lock();
        if matches!(self.target, Target::All | Target::Global) {
            subtract(&mut state.reserved, self.cost);
            state.resident = state.resident.plus(self.cost);
        }
        if matches!(self.target, Target::All | Target::Scopes) {
            for node in self.scope.nodes() {
                let mut reserved = node.reserved();
                subtract(&mut reserved, self.cost);
                node.set_usage(reserved, node.resident().plus(self.cost));
            }
        }
        self.phase = Phase::Resident;
    }
}

impl Drop for Charge {
    fn drop(&mut self) {
        let mut state = self.scope.inner.lock();
        if matches!(self.target, Target::All | Target::Global) {
            subtract(
                match self.phase {
                    Phase::Reserved => &mut state.reserved,
                    Phase::Resident => &mut state.resident,
                },
                self.cost,
            );
        }
        if matches!(self.target, Target::All | Target::Scopes) {
            for node in self.scope.nodes() {
                let (mut reserved, mut resident) = (node.reserved(), node.resident());
                subtract(
                    match self.phase {
                        Phase::Reserved => &mut reserved,
                        Phase::Resident => &mut resident,
                    },
                    self.cost,
                );
                node.set_usage(reserved, resident);
            }
        }
        drop(state);
        self.scope.inner.changed.notify_waiters();
    }
}

fn subtract(usage: &mut Usage, cost: Usage) {
    usage.bytes -= cost.bytes;
    usage.allocations -= cost.allocations;
}

/// Capacity is already charged, including while the backing allocation is
/// being constructed. Dropping this object rolls back its reservation.
#[must_use = "dropping the reservation immediately returns its budget"]
pub struct Reservation {
    charge: Charge,
}

impl Reservation {
    pub fn bytes(&self) -> usize {
        self.charge.cost.bytes
    }
    /// Marks storage resident without acquiring more capacity. A grant made
    /// before close remains valid, so this operation cannot fail on close.
    pub fn commit(mut self) -> Permit {
        self.charge.commit();
        Permit {
            charge: self.charge,
        }
    }
}

impl fmt::Debug for Reservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reservation")
            .field("bytes", &self.bytes())
            .finish()
    }
}

/// Keep this owner for the entire lifetime of the allocation it accounts for.
#[must_use = "dropping the permit returns its resident capacity"]
pub struct Permit {
    charge: Charge,
}

impl Permit {
    pub fn bytes(&self) -> usize {
        self.charge.cost.bytes
    }

    // Buffer owns these separately so a future cache may retain the process
    // charge after a connection lease ends. No external API can detach either
    // permit from a BufferLease's storage.
    pub(crate) fn into_parts(mut self) -> (AllocationPermit, ScopePermit) {
        self.charge.target = Target::Scopes;
        let global = Charge {
            scope: Scope {
                inner: self.charge.scope.inner.clone(),
                node: None,
            },
            cost: self.charge.cost,
            phase: Phase::Resident,
            target: Target::Global,
        };
        (
            AllocationPermit { _charge: global },
            ScopePermit {
                _charge: self.charge,
            },
        )
    }
}

impl fmt::Debug for Permit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Permit")
            .field("bytes", &self.bytes())
            .finish()
    }
}

pub(crate) struct AllocationPermit {
    _charge: Charge,
}
pub(crate) struct ScopePermit {
    _charge: Charge,
}

impl AllocationPermit {
    pub(crate) fn is_closed(&self) -> bool {
        self._charge.scope.inner.lock().closed
    }
}

pub(crate) enum BackingRequest<'a> {
    New(usize),
    Cached(&'a AllocationPermit),
}
pub(crate) enum BackingReservation {
    New(Reservation),
    Cached(CachedReservation),
}

pub(crate) struct CachedReservation {
    charge: Charge,
}
impl CachedReservation {
    pub(crate) fn commit(mut self) -> ScopePermit {
        self.charge.commit();
        ScopePermit {
            _charge: self.charge,
        }
    }
}
