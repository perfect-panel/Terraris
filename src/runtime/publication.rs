// SPDX-License-Identifier: GPL-3.0-only

use crate::time::Revocation;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Shared by all stores and admission gates in one supervisor. No network I/O
/// or await is permitted while holding a publication permit.
#[derive(Clone, Default)]
pub struct Publication {
    inner: Arc<RwLock<()>>,
}
pub struct ReadPermit<'a> {
    _guard: RwLockReadGuard<'a, ()>,
    owner: &'a RwLock<()>,
}
pub struct WritePermit<'a> {
    guard: Option<RwLockWriteGuard<'a, ()>>,
    owner: &'a RwLock<()>,
    notifications: Vec<Arc<[Revocation]>>,
}
impl Publication {
    pub fn read(&self) -> ReadPermit<'_> {
        ReadPermit {
            _guard: self.inner.read().unwrap_or_else(|e| e.into_inner()),
            owner: &self.inner,
        }
    }
    /// Metadata is allocated before locking. The coordinator supplies the
    /// maximum number of stores it may revoke in this transaction.
    pub(crate) fn write(&self, batches: usize) -> WritePermit<'_> {
        let notifications = Vec::with_capacity(batches);
        WritePermit {
            guard: Some(self.inner.write().unwrap_or_else(|e| e.into_inner())),
            owner: &self.inner,
            notifications,
        }
    }
    pub fn owns_read(&self, permit: &ReadPermit<'_>) -> bool {
        std::ptr::eq(self.inner.as_ref(), permit.owner)
    }
    pub fn owns_write(&self, permit: &WritePermit<'_>) -> bool {
        std::ptr::eq(self.inner.as_ref(), permit.owner)
    }
    pub fn same_domain(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl WritePermit<'_> {
    pub(crate) fn revoke(&mut self, signals: Arc<[Revocation]>) {
        if signals.is_empty() {
            return;
        }
        assert!(
            self.notifications.len() < self.notifications.capacity(),
            "publication notification capacity prepared in advance"
        );
        for signal in signals.iter() {
            signal.mark();
        }
        self.notifications.push(signals);
    }
}
impl Drop for WritePermit<'_> {
    fn drop(&mut self) {
        drop(self.guard.take());
        for batch in &self.notifications {
            for signal in batch.iter() {
                signal.notify();
            }
        }
    }
}
