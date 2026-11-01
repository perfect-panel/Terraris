// SPDX-License-Identifier: GPL-3.0-only

use super::{Error, pool::PoolTicket};
use crate::resource::{AllocationPermit, ScopePermit};

pub(super) struct Allocation {
    // Free memory before releasing its process capacity.
    pub storage: Box<[u8]>,
    pub permit: AllocationPermit,
}

pub(super) struct Owner {
    // The connection stops retaining memory before it can become idle cache.
    _scope: ScopePermit,
    backing: Recyclable,
}

impl Owner {
    pub fn new(allocation: Allocation, scope: ScopePermit, ticket: Option<PoolTicket>) -> Self {
        Self {
            _scope: scope,
            backing: Recyclable {
                allocation: Some(allocation),
                ticket,
            },
        }
    }
    pub fn storage(&self) -> &[u8] {
        &self
            .backing
            .allocation
            .as_ref()
            .expect("live allocation")
            .storage
    }
    pub fn storage_mut(&mut self) -> &mut [u8] {
        &mut self
            .backing
            .allocation
            .as_mut()
            .expect("live allocation")
            .storage
    }
}

struct Recyclable {
    allocation: Option<Allocation>,
    ticket: Option<PoolTicket>,
}
impl Drop for Recyclable {
    fn drop(&mut self) {
        let Some(allocation) = self.allocation.take() else {
            return;
        };
        if let Some(ticket) = self.ticket.take() {
            ticket.recycle(allocation);
        } else {
            drop(allocation);
        }
    }
}

pub(super) fn allocate_zeroed(capacity: usize) -> Result<Box<[u8]>, Error> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(capacity)
        .map_err(|_| Error::AllocationFailed)?;
    storage.resize(capacity, 0);
    Ok(storage.into_boxed_slice())
}
