// SPDX-License-Identifier: GPL-3.0-only

//! Bounded structured concurrency for maintenance futures. No per-job detached
//! task, no overlapping execution of one job, and no unbounded event backlog.

use crate::time::{Deadline, OperationContext, StopReason};
use async_trait::async_trait;
use futures_util::{FutureExt, StreamExt, future::BoxFuture, stream::FuturesUnordered};
use std::{
    fmt,
    future::Future,
    panic::AssertUnwindSafe,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Critical,
    Normal,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobFailure {
    Failed(&'static str),
    Stopped(StopReason),
    Panicked,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLimits,
    InvalidSchedule,
    InvalidName,
    DuplicateName,
    TooManyJobs,
    AlreadyRunning,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "scheduler: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_jobs: usize,
    pub concurrency: usize,
    pub critical_reserve: usize,
}
#[derive(Clone, Copy, Debug)]
pub struct Schedule {
    interval: Duration,
    timeout: Duration,
    max_backoff: Duration,
    initial_delay: Duration,
}
impl Schedule {
    pub fn new(
        interval: Duration,
        timeout: Duration,
        max_backoff: Duration,
    ) -> Result<Self, Error> {
        if interval.is_zero()
            || timeout.is_zero()
            || max_backoff < interval
            || Deadline::after(max_backoff).is_err()
            || Deadline::after(timeout).is_err()
        {
            return Err(Error::InvalidSchedule);
        }
        Ok(Self {
            interval,
            timeout,
            max_backoff,
            initial_delay: Duration::ZERO,
        })
    }
    pub fn initial_delay(mut self, delay: Duration) -> Result<Self, Error> {
        if Deadline::after(delay).is_err() {
            return Err(Error::InvalidSchedule);
        }
        self.initial_delay = delay;
        Ok(self)
    }
    fn delay(self, failures: u32) -> Duration {
        if failures == 0 {
            self.interval
        } else {
            self.interval
                .saturating_mul(1u32.checked_shl(failures.min(31)).unwrap_or(u32::MAX))
                .min(self.max_backoff)
        }
    }
}
#[async_trait]
pub trait Job: Send + Sync {
    async fn execute(&self, context: &OperationContext) -> Result<(), JobFailure>;
}
struct FunctionJob<F>(F);
#[async_trait]
impl<F, Fut> Job for FunctionJob<F>
where
    F: Fn(OperationContext) -> Fut + Send + Sync,
    Fut: Future<Output = Result<(), JobFailure>> + Send,
{
    async fn execute(&self, context: &OperationContext) -> Result<(), JobFailure> {
        (self.0)(context.clone()).await
    }
}
pub fn job<F, Fut>(function: F) -> Arc<dyn Job>
where
    F: Fn(OperationContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), JobFailure>> + Send + 'static,
{
    Arc::new(FunctionJob(function))
}
#[derive(Clone)]
pub struct JobSpec {
    pub name: String,
    pub lane: Lane,
    pub schedule: Schedule,
    pub job: Arc<dyn Job>,
}
impl JobSpec {
    pub fn new(name: impl Into<String>, lane: Lane, schedule: Schedule, job: Arc<dyn Job>) -> Self {
        Self {
            name: name.into(),
            lane,
            schedule,
            job,
        }
    }
}
#[derive(Clone, Debug)]
pub struct JobSnapshot {
    pub name: String,
    pub running: bool,
    pub runs: u64,
    pub failures: u32,
    pub last: Option<Result<(), JobFailure>>,
}
struct Shared {
    running: AtomicBool,
    jobs: Mutex<Vec<JobSnapshot>>,
}
type JobCompletion = BoxFuture<'static, (usize, Result<(), JobFailure>, Instant)>;

pub struct Scheduler {
    limits: Limits,
    jobs: Vec<JobSpec>,
    shared: Arc<Shared>,
}
impl Scheduler {
    pub fn new(limits: Limits, jobs: Vec<JobSpec>) -> Result<Self, Error> {
        if limits.max_jobs == 0
            || limits.concurrency == 0
            || limits.critical_reserve >= limits.concurrency
        {
            return Err(Error::InvalidLimits);
        }
        if jobs.len() > limits.max_jobs {
            return Err(Error::TooManyJobs);
        }
        let mut names = std::collections::HashSet::new();
        for spec in &jobs {
            if spec.name.is_empty()
                || spec.name.len() > 128
                || !spec
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-/.:".contains(&b))
            {
                return Err(Error::InvalidName);
            }
            if !names.insert(spec.name.as_str()) {
                return Err(Error::DuplicateName);
            }
        }
        let snapshots = jobs
            .iter()
            .map(|j| JobSnapshot {
                name: j.name.clone(),
                running: false,
                runs: 0,
                failures: 0,
                last: None,
            })
            .collect();
        Ok(Self {
            limits,
            jobs,
            shared: Arc::new(Shared {
                running: AtomicBool::new(false),
                jobs: Mutex::new(snapshots),
            }),
        })
    }
    pub fn snapshot(&self) -> Vec<JobSnapshot> {
        self.shared
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn is_running(&self) -> bool {
        self.shared.running.load(Ordering::Acquire)
    }
    pub async fn run(&self, context: &OperationContext) -> Result<(), Error> {
        if self
            .shared
            .running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::AlreadyRunning);
        }
        let _guard = RunGuard(self.shared.clone());
        let mut inflight: FuturesUnordered<JobCompletion> = FuturesUnordered::new();
        let mut running = vec![false; self.jobs.len()];
        let mut failures = vec![0u32; self.jobs.len()];
        let mut due: Vec<_> = self
            .jobs
            .iter()
            .map(|j| {
                Instant::now()
                    .checked_add(j.schedule.initial_delay)
                    .ok_or(Error::InvalidSchedule)
            })
            .collect::<Result<_, _>>()?;
        let mut cursor = 0;
        let mut normal = 0;
        loop {
            if context.check().is_err() {
                return Ok(());
            }
            for offset in 0..self.jobs.len() {
                let index = (cursor + offset) % self.jobs.len();
                let spec = &self.jobs[index];
                if inflight.len() >= self.limits.concurrency {
                    break;
                }
                if running[index]
                    || due[index] > Instant::now()
                    || (spec.lane == Lane::Normal
                        && normal >= self.limits.concurrency - self.limits.critical_reserve)
                {
                    continue;
                }
                running[index] = true;
                if spec.lane == Lane::Normal {
                    normal += 1;
                }
                self.shared.jobs.lock().unwrap_or_else(|e| e.into_inner())[index].running = true;
                let operation = context.child_with_deadline(
                    Deadline::after(spec.schedule.timeout).map_err(|_| Error::InvalidSchedule)?,
                );
                let work = spec.job.clone();
                inflight.push(
                    async move {
                        let outcome = AssertUnwindSafe(operation.run(work.execute(&operation)))
                            .catch_unwind()
                            .await;
                        let result = match outcome {
                            Ok(Ok(value)) => value,
                            Ok(Err(reason)) => Err(JobFailure::Stopped(reason)),
                            Err(_) => Err(JobFailure::Panicked),
                        };
                        (index, result, Instant::now())
                    }
                    .boxed(),
                );
            }
            if !self.jobs.is_empty() {
                cursor = (cursor + 1) % self.jobs.len();
            }
            // Exclude jobs which cannot be dispatched; otherwise an already-due
            // timer could busy-loop while the eligible lanes are at capacity.
            let next = if inflight.len() >= self.limits.concurrency {
                None
            } else {
                self.jobs
                    .iter()
                    .enumerate()
                    .filter(|(i, j)| {
                        !running[*i]
                            && (j.lane == Lane::Critical
                                || normal < self.limits.concurrency - self.limits.critical_reserve)
                    })
                    .map(|(i, _)| due[i])
                    .min()
            };
            tokio::select! {biased;
                _=context.run(std::future::pending::<()>())=>return Ok(()),
                Some((index,result,finished))=inflight.next(),if !inflight.is_empty()=>{
                    running[index]=false;if self.jobs[index].lane==Lane::Normal{normal-=1;}
                    failures[index]=if result.is_ok(){0}else{failures[index].saturating_add(1)};
                    due[index]=finished.checked_add(self.jobs[index].schedule.delay(failures[index])).ok_or(Error::InvalidSchedule)?;
                    let mut stats=self.shared.jobs.lock().unwrap_or_else(|e|e.into_inner());let stat=&mut stats[index];stat.running=false;stat.runs=stat.runs.saturating_add(1);stat.failures=failures[index];stat.last=Some(result);
                }
                _=wait_until(next)=>{}
            }
        }
    }
}
async fn wait_until(deadline: Option<Instant>) {
    if let Some(at) = deadline {
        tokio::time::sleep_until(at).await;
    } else {
        std::future::pending::<()>().await;
    }
}
struct RunGuard(Arc<Shared>);
impl Drop for RunGuard {
    fn drop(&mut self) {
        for job in self
            .0
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
        {
            job.running = false;
        }
        self.0.running.store(false, Ordering::Release);
    }
}
