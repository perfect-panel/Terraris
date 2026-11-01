// SPDX-License-Identifier: GPL-3.0-only
//! Bounded, explicitly joined transport work owned by a connector or server.
use super::Error;
use crate::{
    task::{CancellationToken, TaskFailure, TaskGroup},
    telemetry::Metrics,
};
use std::{
    future::{Future, poll_fn},
    sync::Mutex,
};
pub(super) struct Jobs {
    pub cancel: CancellationToken,
    group: Mutex<TaskGroup>,
}
impl Jobs {
    pub fn new(limit: usize) -> Result<Self, Error> {
        let cancel = CancellationToken::new();
        let group = TaskGroup::new(&cancel, limit, Metrics::default())
            .map_err(|_| Error::Configuration("transport task limit"))?;
        Ok(Self {
            cancel,
            group: Mutex::new(group),
        })
    }
    pub fn spawn<F, Fut>(&self, name: &'static str, job: F) -> Result<(), Error>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskFailure>> + Send + 'static,
    {
        let mut group = self.group.lock().unwrap_or_else(|e| e.into_inner());
        while group.try_join_next().is_some() {}
        group
            .spawn(name, job)
            .map_err(|_| Error::Io(std::io::ErrorKind::WouldBlock))?;
        Ok(())
    }
    pub fn abort(&self) {
        self.cancel.cancel();
        self.group
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .abort_all();
    }
    pub fn idle(&self) -> bool {
        let mut group = self.group.lock().unwrap_or_else(|e| e.into_inner());
        while group.try_join_next().is_some() {}
        group.is_empty()
    }
    pub async fn close(&self) {
        self.abort();
        while poll_fn(|cx| {
            self.group
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .poll_join_next(cx)
        })
        .await
        .is_some()
        {}
    }
}
impl Drop for Jobs {
    fn drop(&mut self) {
        self.abort();
    }
}
