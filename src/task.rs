// SPDX-License-Identifier: GPL-3.0-only

//! Bounded ownership of cooperative Tokio tasks, including completed but
//! unjoined tasks. Explicit shutdown retains handles until they are joined;
//! Drop is an abort fallback and cannot confirm asynchronous cleanup.

use crate::{
    telemetry::{Counter, Gauge, Metrics},
    time::{Deadline, StopReason},
};
use std::{collections::HashMap, fmt, future::Future};
use tokio::task::{Id, JoinError, JoinSet};
pub use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SpawnError {
    InvalidLimit,
    InvalidName,
    Closed,
    AtCapacity,
    NoRuntime,
    AllocationFailed,
}
impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "task limit must be positive",
            Self::InvalidName => "task name must contain 1..64 ASCII identifier characters",
            Self::Closed => "task group is closed",
            Self::AtCapacity => "task group is at its tracked-task limit",
            Self::NoRuntime => "spawning requires a Tokio runtime",
            Self::AllocationFailed => "task metadata allocation failed",
        })
    }
}
impl std::error::Error for SpawnError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskFailure {
    Cancelled,
    TimedOut,
    Failed(&'static str),
}
impl From<StopReason> for TaskFailure {
    fn from(reason: StopReason) -> Self {
        match reason {
            StopReason::Cancelled => Self::Cancelled,
            StopReason::DeadlineExceeded => Self::TimedOut,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskOutcome {
    Completed,
    Failed(TaskFailure),
    Panicked,
    Aborted,
}
#[derive(Clone, Debug)]
pub struct TaskReport {
    pub id: Id,
    pub name: &'static str,
    pub outcome: TaskOutcome,
}
#[derive(Debug)]
pub struct ShutdownReport {
    pub tasks: Vec<TaskReport>,
    pub abort_requested: bool,
}

/// ```
/// use terraris::{task::{TaskGroup, CancellationToken}, telemetry::Metrics, time::Deadline};
/// use std::time::Duration;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let parent = CancellationToken::new();
/// let mut tasks = TaskGroup::new(&parent, 8, Metrics::default())?;
/// tasks.spawn("worker", |cancel| async move { cancel.cancelled().await; Ok(()) })?;
/// let report = tasks.shutdown(Deadline::after(Duration::from_secs(1))?).await;
/// assert_eq!(report.tasks.len(), 1);
/// assert!(tasks.is_empty());
/// assert!(!parent.is_cancelled());
/// # Ok(())
/// # }
/// ```
pub struct TaskGroup {
    tasks: JoinSet<Result<(), TaskFailure>>,
    names: HashMap<Id, &'static str>,
    cancellation: CancellationToken,
    limit: usize,
    closed: bool,
    metrics: Metrics,
}

impl TaskGroup {
    pub fn new(
        parent: &CancellationToken,
        limit: usize,
        metrics: Metrics,
    ) -> Result<Self, SpawnError> {
        if limit == 0 {
            return Err(SpawnError::InvalidLimit);
        }
        Ok(Self {
            tasks: JoinSet::new(),
            names: HashMap::new(),
            cancellation: parent.child_token(),
            limit,
            closed: false,
            metrics,
        })
    }
    pub fn len(&self) -> usize {
        self.tasks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }
    pub fn is_closed(&self) -> bool {
        self.closed || self.cancellation.is_cancelled()
    }
    pub fn close(&mut self) {
        self.closed = true;
    }
    pub fn cancel(&mut self) {
        self.close();
        self.cancellation.cancel();
    }

    /// The factory runs inside the tracked task, so even factory panics are
    /// joined. Each task receives a child token: cancelling it cannot cancel
    /// the group, its siblings, or the parent operation.
    pub fn spawn<F, Fut>(&mut self, name: &'static str, factory: F) -> Result<Id, SpawnError>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskFailure>> + Send + 'static,
    {
        if self.is_closed() {
            return Err(SpawnError::Closed);
        }
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-./".contains(&b))
        {
            return Err(SpawnError::InvalidName);
        }
        if self.tasks.len() >= self.limit {
            return Err(SpawnError::AtCapacity);
        }
        tokio::runtime::Handle::try_current().map_err(|_| SpawnError::NoRuntime)?;
        self.names
            .try_reserve(1)
            .map_err(|_| SpawnError::AllocationFailed)?;
        let token = self.cancellation.child_token();
        let metrics = self.metrics.clone();
        let handle = self.tasks.spawn(async move {
            let _active = metrics.guard(Gauge::ActiveTasks);
            if token.is_cancelled() {
                return Err(TaskFailure::Cancelled);
            }
            factory(token).await
        });
        let id = handle.id();
        self.names.insert(id, name);
        self.metrics.increment(Counter::TasksSpawned);
        Ok(id)
    }

    pub async fn join_next(&mut self) -> Option<TaskReport> {
        let result = self.tasks.join_next_with_id().await?;
        Some(self.report(result))
    }
    pub fn try_join_next(&mut self) -> Option<TaskReport> {
        let result = self.tasks.try_join_next_with_id()?;
        Some(self.report(result))
    }
    pub fn abort_all(&mut self) {
        self.cancel();
        self.tasks.abort_all();
    }
    /// Lets an owning coordinator poll under a short mutex without holding it
    /// across await. Handles remain in this group if the waiter is cancelled.
    pub fn poll_join_next(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<TaskReport>> {
        self.tasks
            .poll_join_next_with_id(cx)
            .map(|result| result.map(|result| self.report(result)))
    }

    /// Cancel, wait until the deadline, then abort and JOIN every remaining task.
    /// Tokio cannot preempt a blocking/non-yielding future; this API deliberately
    /// does not pretend such work has been stopped when it has not been joined.
    /// Cancelling this shutdown future leaves the handles owned by this group.
    pub async fn shutdown(&mut self, deadline: Deadline) -> ShutdownReport {
        self.cancel();
        let mut reports = Vec::with_capacity(self.tasks.len());
        let mut abort_requested = false;
        while !self.tasks.is_empty() {
            tokio::select! {biased;
                _=deadline.wait()=>{abort_requested=true;self.tasks.abort_all();break;}
                result=self.tasks.join_next_with_id()=>{if let Some(result)=result{reports.push(self.report(result));}}
            }
        }
        while let Some(result) = self.tasks.join_next_with_id().await {
            reports.push(self.report(result));
        }
        ShutdownReport {
            tasks: reports,
            abort_requested,
        }
    }

    fn report(&mut self, result: Result<(Id, Result<(), TaskFailure>), JoinError>) -> TaskReport {
        let (id, outcome) = match result {
            Ok((id, Ok(()))) => (id, TaskOutcome::Completed),
            Ok((id, Err(error))) => (id, TaskOutcome::Failed(error)),
            Err(error) => {
                let id = error.id();
                (
                    id,
                    if error.is_cancelled() {
                        TaskOutcome::Aborted
                    } else {
                        TaskOutcome::Panicked
                    },
                )
            }
        };
        let counter = match outcome {
            TaskOutcome::Completed => Counter::TasksCompleted,
            TaskOutcome::Failed(TaskFailure::Cancelled) => Counter::TasksCancelled,
            TaskOutcome::Failed(_) => Counter::TasksFailed,
            TaskOutcome::Panicked => Counter::TasksPanicked,
            TaskOutcome::Aborted => Counter::TasksAborted,
        };
        self.metrics.increment(counter);
        TaskReport {
            id,
            name: self.names.remove(&id).expect("tracked task name"),
            outcome,
        }
    }
}
impl Drop for TaskGroup {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.tasks.abort_all();
    }
}
