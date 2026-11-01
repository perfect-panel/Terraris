// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    panel::{self, Fetch, ProtocolClient, SubscriptionId},
    protocol::runtimekit::Core,
    reports,
    scheduler::{self, JobSpec, Lane, Schedule},
    time::{OperationContext, StopReason},
    users::{self, AuthUpdater, PreparedUpdate, Reconciler},
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    NotOwner,
    InvalidOptions,
    Panel(panel::Error),
    Users(users::Error),
    Reports(reports::Error),
    Stopped(StopReason),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "controller: {self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub pull_interval: Duration,
    pub push_interval: Duration,
    pub timeout: Duration,
    pub traffic_threshold: u64,
}
pub struct Controller {
    core: Core,
    client: Arc<dyn ProtocolClient>,
    updater: Arc<dyn AuthUpdater>,
    options: Options,
    alive: Mutex<BTreeMap<SubscriptionId, u64>>,
    last_error: Mutex<Option<Error>>,
}
impl Controller {
    pub fn new(
        core: Core,
        client: Arc<dyn ProtocolClient>,
        updater: Arc<dyn AuthUpdater>,
        options: Options,
    ) -> Result<Self, Error> {
        if client.protocol() != core.protocol()
            || options.pull_interval.is_zero()
            || options.push_interval.is_zero()
            || options.timeout.is_zero()
            || client.policy().max_online_entries == 0
            || !client.policy().report_active_and_unconfirmed
        {
            return Err(Error::InvalidOptions);
        }
        Ok(Self {
            core,
            client,
            updater,
            options,
            alive: Mutex::new(BTreeMap::new()),
            last_error: Mutex::new(None),
        })
    }
    pub fn core(&self) -> &Core {
        &self.core
    }
    pub fn last_error(&self) -> Option<Error> {
        self.last_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    pub fn alive(&self) -> BTreeMap<SubscriptionId, u64> {
        self.alive.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    pub async fn prepare(&self, context: &OperationContext) -> Result<PreparedUpdate, Error> {
        let source = self.core.users().view();
        let result = context
            .run(self.client.get_users(source.validator.as_ref()))
            .await
            .map_err(Error::Stopped)?
            .map_err(Error::Panel)?;
        let (users, validator) = match result {
            Fetch::Changed { value, validator } => (value, validator),
            Fetch::Unchanged { validator } => {
                if source.confirmed_at.is_none() {
                    return Err(Error::Users(users::Error::MissingSnapshot));
                }
                (source.snapshot.users().cloned().collect(), validator)
            }
        };
        let candidate = self
            .core
            .users()
            .candidate(source, users, Some(validator))
            .map_err(Error::Users)?;
        PreparedUpdate::prepare(candidate, self.updater.as_ref(), true, context)
            .await
            .map_err(Error::Users)
    }
    fn current(&self) -> Result<(), Error> {
        if self.core.is_current() {
            Ok(())
        } else {
            Err(Error::NotOwner)
        }
    }
    pub async fn sync_users(&self, context: &OperationContext) -> Result<(), Error> {
        self.current()?;
        let source = self.core.users().view();
        let result = async {
            let result = context
                .run(self.client.get_users(source.validator.as_ref()))
                .await
                .map_err(Error::Stopped)?
                .map_err(Error::Panel)?;
            self.current()?;
            context.check().map_err(Error::Stopped)?;
            match result {
                Fetch::Changed { value, validator } => {
                    Reconciler::new(self.core.users().clone(), self.updater.clone())
                        .apply(source, value, validator, self.core.generation(), context)
                        .await
                        .map_err(Error::Users)?;
                }
                Fetch::Unchanged { validator } => {
                    self.core
                        .users()
                        .confirm(&source, self.core.generation(), validator)
                        .map_err(Error::Users)?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(error) = &result
            && matches!(
                error,
                Error::Panel(panel::Error {
                    http_status: Some(401 | 403),
                    ..
                })
            )
        {
            self.core.users().suspend(self.core.generation(), false);
        }
        *self.last_error.lock().unwrap_or_else(|e| e.into_inner()) = result.as_ref().err().cloned();
        result
    }
    pub async fn sync_alive(&self, context: &OperationContext) -> Result<(), Error> {
        self.current()?;
        let alive = context
            .run(self.client.get_alive())
            .await
            .map_err(Error::Stopped)?
            .map_err(Error::Panel)?;
        self.current()?;
        *self.alive.lock().unwrap_or_else(|e| e.into_inner()) = alive;
        Ok(())
    }
    pub async fn report_traffic(&self, context: &OperationContext) -> Result<(), Error> {
        self.current()?;
        self.flush_traffic(context, self.options.traffic_threshold)
            .await
    }
    pub async fn flush_traffic(
        &self,
        context: &OperationContext,
        threshold: u64,
    ) -> Result<(), Error> {
        flush_reports(
            self.core.reports(),
            self.client.as_ref(),
            threshold,
            context,
        )
        .await
    }
    pub async fn report_online(&self, context: &OperationContext) -> Result<(), Error> {
        self.current()?;
        let Some(mut batch) = self.core.reports().online_batch().map_err(Error::Reports)? else {
            return Ok(());
        };
        while batch.remaining() > 0 {
            self.current()?;
            let chunk = batch.next_chunk(self.client.policy().max_online_entries.min(10_000));
            context
                .run(self.client.report_online(&chunk))
                .await
                .map_err(Error::Stopped)?
                .map_err(Error::Panel)?;
            batch.acknowledge_chunk(chunk.len());
        }
        Ok(())
    }
    pub fn expire(&self) -> Result<(), Error> {
        self.current()?;
        self.core.users().suspend(self.core.generation(), true);
        self.core.reap_tasks();
        Ok(())
    }
    pub fn jobs(self: &Arc<Self>) -> Result<Vec<JobSpec>, scheduler::Error> {
        let make = |interval: Duration| {
            Schedule::new(interval, self.options.timeout, interval.saturating_mul(8))?
                .initial_delay(interval)
        };
        let prefix = self.core.protocol().as_str();
        let mut jobs = Vec::new();
        let owned = self.clone();
        jobs.push(JobSpec::new(
            format!("{prefix}.users"),
            Lane::Critical,
            make(self.options.pull_interval)?,
            scheduler::job(move |ctx| {
                let owned = owned.clone();
                async move {
                    owned
                        .sync_users(&ctx)
                        .await
                        .map_err(|_| scheduler::JobFailure::Failed("users"))
                }
            }),
        ));
        let owned = self.clone();
        jobs.push(JobSpec::new(
            format!("{prefix}.alive"),
            Lane::Normal,
            make(self.options.pull_interval)?,
            scheduler::job(move |ctx| {
                let owned = owned.clone();
                async move {
                    owned
                        .sync_alive(&ctx)
                        .await
                        .map_err(|_| scheduler::JobFailure::Failed("alive"))
                }
            }),
        ));
        let owned = self.clone();
        jobs.push(JobSpec::new(
            format!("{prefix}.traffic"),
            Lane::Normal,
            make(self.options.push_interval)?,
            scheduler::job(move |ctx| {
                let owned = owned.clone();
                async move {
                    owned
                        .report_traffic(&ctx)
                        .await
                        .map_err(|_| scheduler::JobFailure::Failed("traffic"))
                }
            }),
        ));
        let owned = self.clone();
        jobs.push(JobSpec::new(
            format!("{prefix}.online"),
            Lane::Critical,
            make(self.options.push_interval.min(Duration::from_secs(60)))?,
            scheduler::job(move |ctx| {
                let owned = owned.clone();
                async move {
                    owned
                        .report_online(&ctx)
                        .await
                        .map_err(|_| scheduler::JobFailure::Failed("online"))
                }
            }),
        ));
        let owned = self.clone();
        jobs.push(JobSpec::new(
            format!("{prefix}.validity"),
            Lane::Critical,
            make(self.options.pull_interval.min(Duration::from_secs(1)))?,
            scheduler::job(move |_| {
                let owned = owned.clone();
                async move {
                    owned
                        .expire()
                        .map_err(|_| scheduler::JobFailure::Failed("validity"))
                }
            }),
        ));
        Ok(jobs)
    }
}

pub(crate) async fn flush_reports(
    reports: &reports::Reports,
    client: &dyn ProtocolClient,
    threshold: u64,
    context: &OperationContext,
) -> Result<(), Error> {
    let Some(mut batch) = reports
        .traffic_batch(threshold, reports.capacity())
        .map_err(Error::Reports)?
    else {
        return Ok(());
    };
    while !batch.values().is_empty() {
        let count = batch.values().len().min(1000);
        context
            .run(client.report_traffic(&batch.values()[..count]))
            .await
            .map_err(Error::Stopped)?
            .map_err(Error::Panel)?;
        batch.acknowledge_chunk(count);
    }
    Ok(())
}

/// Final/retired reporting does not require an active generation owner.
pub(crate) async fn flush_online(
    reports: &reports::Reports,
    client: &dyn ProtocolClient,
    context: &OperationContext,
) -> Result<(), Error> {
    let maximum = client.policy().max_online_entries.min(10_000);
    if maximum == 0 {
        return Err(Error::InvalidOptions);
    }
    let Some(mut batch) = reports.online_batch().map_err(Error::Reports)? else {
        return Ok(());
    };
    while batch.remaining() > 0 {
        let chunk = batch.next_chunk(maximum);
        context
            .run(client.report_online(&chunk))
            .await
            .map_err(Error::Stopped)?
            .map_err(Error::Panel)?;
        batch.acknowledge_chunk(chunk.len());
    }
    Ok(())
}
