// SPDX-License-Identifier: GPL-3.0-only

//! Budgeted stream copying. No background tasks, hidden relay buffers, routing,
//! authentication, rate policy, or panel calls are created here.

use crate::{
    buffer::{self, BufferLayout, BufferLease, BufferScope},
    telemetry::{Counter, Direction, Gauge, Metrics, TransferObserver},
    time::{Deadline, OperationContext, StopReason},
};
use std::{
    fmt,
    future::Future,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    time::Instant,
};

#[derive(Clone, Copy, Debug)]
pub struct TransferConfig {
    buffer_size: usize,
    idle_timeout: Option<Duration>,
}
impl TransferConfig {
    pub fn new(
        buffer_size: usize,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, TransferFailure> {
        if buffer_size == 0
            || buffer_size > isize::MAX as usize
            || idle_timeout.is_some_and(|d| d.is_zero() || Deadline::after(d).is_err())
        {
            return Err(TransferFailure::InvalidConfig);
        }
        Ok(Self {
            buffer_size,
            idle_timeout,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoOperation {
    Read,
    Write,
    Flush,
    Shutdown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferFailure {
    InvalidConfig,
    Buffer(buffer::Error),
    Stopped(StopReason),
    IdleTimeout,
    Io {
        operation: IoOperation,
        kind: io::ErrorKind,
    },
}
impl fmt::Display for TransferFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("invalid stream buffer capacity or idle timeout"),
            Self::Buffer(e) => e.fmt(f),
            Self::Stopped(e) => e.fmt(f),
            Self::IdleTimeout => f.write_str("stream idle timeout"),
            Self::Io { operation, kind } => write!(f, "stream {operation:?} failed: {kind:?}"),
        }
    }
}
impl std::error::Error for TransferFailure {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TransferReport {
    pub upload: u64,
    pub download: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferError {
    pub cause: TransferFailure,
    pub progress: TransferReport,
}
impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl std::error::Error for TransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[derive(Clone)]
/// ```
/// use terraris::{buffer::BufferScope, resource::{Budget, Limits}, dataplane::{DataPlane, TransferConfig}, telemetry::{Direction, Metrics}, task::CancellationToken, time::OperationContext};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let budget = Budget::new(Limits::new(1024, 8)?);
/// let scope = BufferScope::new(budget.root_scope(), 512)?;
/// let plane = DataPlane::new(scope, TransferConfig::new(128, None)?, Metrics::default())?;
/// let context = OperationContext::new(CancellationToken::new(), None);
/// let result = plane.copy_stream(&b"hello"[..], tokio::io::sink(), Direction::Upload, &context).await?;
/// assert_eq!(result.upload, 5);
/// assert_eq!(budget.snapshot().used().bytes(), 0);
/// # Ok(())
/// # }
/// ```
pub struct DataPlane {
    scope: BufferScope,
    config: TransferConfig,
    metrics: Metrics,
    observer: Option<Arc<dyn TransferObserver>>,
}
impl DataPlane {
    pub fn new(
        scope: BufferScope,
        config: TransferConfig,
        metrics: Metrics,
    ) -> Result<Self, TransferFailure> {
        if config.buffer_size > scope.max_allocation() {
            return Err(TransferFailure::InvalidConfig);
        }
        Ok(Self {
            scope,
            config,
            metrics,
            observer: None,
        })
    }
    /// Additional product accounting hook. Metrics are always recorded once by
    /// DataPlane itself; the observer should record only its own domain state.
    pub fn with_observer(mut self, observer: Arc<dyn TransferObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Owns both handles for the duration of the relay. Clean EOF flushes and
    /// half-closes only that direction. Any error stops the sibling direction;
    /// actual owned sockets are dropped before this operation returns. A caller
    /// supplying borrowed/shared wrappers remains responsible for their owners.
    pub async fn relay_tcp<A, B>(
        &self,
        client: A,
        upstream: B,
        context: &OperationContext,
    ) -> Result<TransferReport, TransferError>
    where
        A: AsyncRead + AsyncWrite + Unpin + Send,
        B: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let _active = self.metrics.guard(Gauge::ActiveRelays);
        let mut progress = TransferReport::default();
        let result = async {
            context.check().map_err(TransferFailure::Stopped)?;
            let layout = BufferLayout::new(0, self.config.buffer_size, 0)
                .map_err(TransferFailure::Buffer)?;
            let pair = self
                .scope
                .try_lease_many(&[layout; 2])
                .map_err(TransferFailure::Buffer)?;
            let mut pair = pair.into_iter();
            let upload = pair.next().expect("reserved upload buffer");
            let download = pair.next().expect("reserved download buffer");
            let (read_client, write_client) = tokio::io::split(client);
            let (read_upstream, write_upstream) = tokio::io::split(upstream);
            let local = context.child();
            let activity = Activity::new(self.config.idle_timeout);
            let (up, down) = tokio::join!(
                async {
                    let result = self
                        .copy_direction(
                            read_client,
                            write_upstream,
                            upload,
                            &local,
                            &activity,
                            Direction::Upload,
                            &mut progress.upload,
                        )
                        .await;
                    if result.is_err() {
                        local.cancellation().cancel();
                    }
                    result
                },
                async {
                    let result = self
                        .copy_direction(
                            read_upstream,
                            write_client,
                            download,
                            &local,
                            &activity,
                            Direction::Download,
                            &mut progress.download,
                        )
                        .await;
                    if result.is_err() {
                        local.cancellation().cancel();
                    }
                    result
                },
            );
            // Preserve the initiating failure, rather than its sibling's
            // cancellation. A clean EOF never cancels a healthy other half.
            match (up, down) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(TransferFailure::Stopped(StopReason::Cancelled)), Err(other)) => Err(other),
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        }
        .await;
        match result {
            Ok(()) => {
                self.metrics.increment(Counter::TcpRelaysCompleted);
                Ok(progress)
            }
            Err(cause) => {
                self.record_failure(cause);
                Err(TransferError { cause, progress })
            }
        }
    }

    /// One direction with a retained per-write offset. On failure, progress
    /// includes every successful write, even when the final flush fails.
    pub async fn copy_stream<R, W>(
        &self,
        reader: R,
        writer: W,
        direction: Direction,
        context: &OperationContext,
    ) -> Result<TransferReport, TransferError>
    where
        R: AsyncRead + Unpin + Send,
        W: AsyncWrite + Unpin + Send,
    {
        let _active = self.metrics.guard(Gauge::ActiveRelays);
        let mut progress = TransferReport::default();
        let result = async {
            context.check().map_err(TransferFailure::Stopped)?;
            let buffer = self
                .scope
                .try_lease(
                    BufferLayout::new(0, self.config.buffer_size, 0)
                        .map_err(TransferFailure::Buffer)?,
                )
                .map_err(TransferFailure::Buffer)?;
            let activity = Activity::new(self.config.idle_timeout);
            let count = match direction {
                Direction::Upload => &mut progress.upload,
                Direction::Download => &mut progress.download,
            };
            self.copy_direction(reader, writer, buffer, context, &activity, direction, count)
                .await
        }
        .await;
        match result {
            Ok(()) => Ok(progress),
            Err(cause) => {
                self.record_failure(cause);
                Err(TransferError { cause, progress })
            }
        }
    }

    #[allow(clippy::too_many_arguments)] // These are per-direction borrowed state, not an owning service context.
    async fn copy_direction<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        mut buffer: BufferLease,
        context: &OperationContext,
        activity: &Activity,
        direction: Direction,
        count: &mut u64,
    ) -> Result<(), TransferFailure>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            buffer.clear();
            let read = activity
                .io(context, buffer.read_from(&mut reader), IoOperation::Read)
                .await?;
            if read == 0 {
                activity
                    .io(context, writer.flush(), IoOperation::Flush)
                    .await?;
                activity
                    .io(context, writer.shutdown(), IoOperation::Shutdown)
                    .await?;
                return Ok(());
            }
            activity.touch();
            while !buffer.is_empty() {
                let written = activity
                    .io(context, writer.write(buffer.as_slice()), IoOperation::Write)
                    .await?;
                if written == 0 {
                    return Err(TransferFailure::Io {
                        operation: IoOperation::Write,
                        kind: io::ErrorKind::WriteZero,
                    });
                }
                if written > buffer.len() {
                    return Err(TransferFailure::Io {
                        operation: IoOperation::Write,
                        kind: io::ErrorKind::InvalidData,
                    });
                }
                buffer.consume(written).map_err(TransferFailure::Buffer)?;
                *count = count.saturating_add(written as u64);
                self.metrics.record_transfer(direction, written);
                if let Some(observer) = &self.observer {
                    observer.written(direction, written);
                }
                activity.touch();
            }
        }
    }

    fn record_failure(&self, cause: TransferFailure) {
        self.metrics.increment(match cause {
            TransferFailure::Buffer(_) => Counter::BufferRejected,
            TransferFailure::InvalidConfig => Counter::InvalidInputs,
            TransferFailure::Stopped(StopReason::Cancelled) => Counter::OperationCancelled,
            TransferFailure::Stopped(StopReason::DeadlineExceeded)
            | TransferFailure::IdleTimeout => Counter::OperationTimeouts,
            _ => Counter::IoErrors,
        });
    }
}

struct Activity {
    last: Mutex<Instant>,
    timeout: Option<Duration>,
}
impl Activity {
    fn new(timeout: Option<Duration>) -> Self {
        Self {
            last: Mutex::new(Instant::now()),
            timeout,
        }
    }
    fn touch(&self) {
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
    }
    fn deadline(&self) -> Result<Option<Deadline>, TransferFailure> {
        let last = *self.last.lock().unwrap_or_else(|e| e.into_inner());
        self.timeout
            .map(|timeout| {
                last.checked_add(timeout)
                    .map(Deadline::at)
                    .ok_or(TransferFailure::InvalidConfig)
            })
            .transpose()
    }
    async fn io<T, F: Future<Output = io::Result<T>>>(
        &self,
        context: &OperationContext,
        future: F,
        operation: IoOperation,
    ) -> Result<T, TransferFailure> {
        context.run(async{
            tokio::pin!(future);
            loop{
                if let Some(deadline)=self.deadline()?{
                    tokio::select!{biased;
                        _=deadline.wait()=>{
                            // Progress in the opposite direction may have moved
                            // the idle deadline. No extra timer task is needed.
                            if self.deadline()?.is_some_and(Deadline::is_elapsed){return Err(TransferFailure::IdleTimeout);}
                        }
                        result=&mut future=>return result.map_err(|error|TransferFailure::Io{operation,kind:error.kind()}),
                    }
                }else{return future.await.map_err(|error|TransferFailure::Io{operation,kind:error.kind()});}
            }
        }).await.map_err(TransferFailure::Stopped)?
    }
}
