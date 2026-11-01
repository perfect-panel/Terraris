// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    panel::{Secret, SubscriptionId, User, Validator},
    runtime::{GenerationId, Publication, ReadPermit, WritePermit},
    task::CancellationToken,
    time::{Deadline, OperationContext, Revocation, StopReason},
};
use async_trait::async_trait;
use std::{
    borrow::Borrow,
    collections::{BTreeMap, HashMap},
    fmt,
    hash::{Hash, Hasher},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLimits,
    TooManyUsers,
    InvalidUser,
    DuplicateId,
    DuplicateCredential,
    ForeignSnapshot,
    StaleCandidate,
    NotOwner,
    MissingSnapshot,
    Revoked,
    StaleUsers,
    SessionLimit,
    RevisionOverflow,
    Apply(&'static str),
    Stopped(StopReason),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "users: {self:?}")
    }
}
impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_users: usize,
    pub max_sessions: usize,
    pub max_age: Duration,
}
impl Limits {
    pub fn validate(self) -> Result<Self, Error> {
        if self.max_users == 0
            || self.max_sessions == 0
            || self.max_age.is_zero()
            || Deadline::after(self.max_age).is_err()
        {
            Err(Error::InvalidLimits)
        } else {
            Ok(self)
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Credential(Secret);
impl Hash for Credential {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.expose().hash(state)
    }
}
impl Borrow<str> for Credential {
    fn borrow(&self) -> &str {
        self.0.expose()
    }
}
struct Entry {
    user: User,
    epoch: u64,
    revoked: Revocation,
}

pub struct Snapshot {
    owner: Arc<()>,
    entries: BTreeMap<SubscriptionId, Entry>,
    credentials: HashMap<Credential, SubscriptionId>,
    signals: Arc<[Revocation]>,
}
impl Snapshot {
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn users(&self) -> impl Iterator<Item = &User> {
        self.entries.values().map(|e| &e.user)
    }
    pub fn user(&self, id: SubscriptionId) -> Option<&User> {
        self.entries.get(&id).map(|e| &e.user)
    }
    /// Protocol adapters may attach this identity only after authenticating the
    /// corresponding user. Core revalidates it against the current store.
    pub fn identity(&self, id: SubscriptionId) -> Option<Identity> {
        self.entries
            .get(&id)
            .filter(|e| !e.revoked.is_revoked())
            .map(|e| Identity {
                owner: self.owner.clone(),
                id,
                epoch: e.epoch,
            })
    }
    pub fn authenticate(&self, credential: &str) -> Option<Identity> {
        self.identity(*self.credentials.get(credential)?)
    }
}
impl fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserSnapshot")
            .field("count", &self.len())
            .finish()
    }
}
#[derive(Clone)]
pub struct Identity {
    owner: Arc<()>,
    id: SubscriptionId,
    epoch: u64,
}
impl Identity {
    pub fn id(&self) -> SubscriptionId {
        self.id
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserIdentity")
            .field("id", &self.id)
            .field("epoch", &self.epoch)
            .finish()
    }
}

#[derive(Clone)]
pub struct View {
    owner: Arc<()>,
    pub snapshot: Arc<Snapshot>,
    pub revision: u64,
    pub validator: Option<Validator>,
    pub writer: Option<GenerationId>,
    pub confirmed_at: Option<Instant>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Diff {
    pub added: Vec<SubscriptionId>,
    pub removed: Vec<SubscriptionId>,
    pub credentials_changed: Vec<SubscriptionId>,
    pub limits_changed: Vec<SubscriptionId>,
}
impl Diff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.credentials_changed.is_empty()
            && self.limits_changed.is_empty()
    }
}
pub struct Candidate {
    source: View,
    next: Arc<Snapshot>,
    next_revision: u64,
    validator: Option<Validator>,
    confirmed_at: Instant,
    revocations: Arc<[Revocation]>,
    pub diff: Diff,
}
impl Candidate {
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.next.clone()
    }
    pub fn source_revision(&self) -> u64 {
        self.source.revision
    }
}

struct State {
    snapshot: Arc<Snapshot>,
    revision: u64,
    validator: Option<Validator>,
    writer: Option<GenerationId>,
    confirmed_at: Option<Instant>,
    sessions: usize,
}
struct Inner {
    publication: Publication,
    owner: Arc<()>,
    limits: Limits,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}
impl Store {
    pub fn new(publication: Publication, limits: Limits) -> Result<Self, Error> {
        let limits = limits.validate()?;
        let owner = Arc::new(());
        let snapshot = Arc::new(Snapshot {
            owner: owner.clone(),
            entries: BTreeMap::new(),
            credentials: HashMap::new(),
            signals: Arc::from([]),
        });
        Ok(Self {
            inner: Arc::new(Inner {
                publication,
                owner,
                limits,
                state: Mutex::new(State {
                    snapshot,
                    revision: 0,
                    validator: None,
                    writer: None,
                    confirmed_at: None,
                    sessions: 0,
                }),
            }),
        })
    }
    pub fn publication(&self) -> &Publication {
        &self.inner.publication
    }
    pub fn view(&self) -> View {
        let _guard = self.inner.publication.read();
        self.view_inner()
    }
    fn view_inner(&self) -> View {
        let s = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        View {
            owner: self.inner.owner.clone(),
            snapshot: s.snapshot.clone(),
            revision: s.revision,
            validator: s.validator.clone(),
            writer: s.writer,
            confirmed_at: s.confirmed_at,
        }
    }
    pub fn active_sessions(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
    }
    pub fn is_owner(&self, writer: GenerationId) -> bool {
        self.view().writer == Some(writer)
    }
    pub(crate) fn fresh_with(&self, permit: &ReadPermit<'_>) -> bool {
        assert!(self.publication().owns_read(permit));
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .confirmed_at
            .is_some_and(|at| at.elapsed() < self.inner.limits.max_age)
    }
    pub fn max_age(&self) -> Duration {
        self.inner.limits.max_age
    }

    pub fn candidate(
        &self,
        source: View,
        users: Vec<User>,
        validator: Option<Validator>,
    ) -> Result<Candidate, Error> {
        if !Arc::ptr_eq(&source.owner, &self.inner.owner) {
            return Err(Error::ForeignSnapshot);
        }
        if users.len() > self.inner.limits.max_users {
            return Err(Error::TooManyUsers);
        }
        let next_revision = source
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionOverflow)?;
        let mut entries = BTreeMap::new();
        let mut credentials = HashMap::with_capacity(users.len());
        let mut signals = Vec::with_capacity(users.len());
        let mut revoked = Vec::new();
        let mut diff = Diff::default();
        for user in users {
            if user.credential.expose().is_empty()
                || user.credential.expose().len() > 4096
                || user.speed_limit_mbps.checked_mul(125_000).is_none()
                || user.device_limit > i64::MAX as u64
            {
                return Err(Error::InvalidUser);
            }
            if entries.contains_key(&user.id) {
                return Err(Error::DuplicateId);
            }
            if credentials
                .insert(Credential(user.credential.clone()), user.id)
                .is_some()
            {
                return Err(Error::DuplicateCredential);
            }
            let (epoch, signal) = match source.snapshot.entries.get(&user.id) {
                Some(old)
                    if old.user.credential == user.credential && !old.revoked.is_revoked() =>
                {
                    if old.user.speed_limit_mbps != user.speed_limit_mbps
                        || old.user.device_limit != user.device_limit
                    {
                        diff.limits_changed.push(user.id);
                    }
                    (old.epoch, old.revoked.clone())
                }
                Some(old) => {
                    diff.credentials_changed.push(user.id);
                    revoked.push(old.revoked.clone());
                    (next_revision, Revocation::default())
                }
                None => {
                    diff.added.push(user.id);
                    (next_revision, Revocation::default())
                }
            };
            signals.push(signal.clone());
            entries.insert(
                user.id,
                Entry {
                    user,
                    epoch,
                    revoked: signal,
                },
            );
        }
        for (&id, old) in &source.snapshot.entries {
            if !entries.contains_key(&id) {
                diff.removed.push(id);
                revoked.push(old.revoked.clone());
            }
        }
        diff.added.sort();
        diff.credentials_changed.sort();
        diff.limits_changed.sort();
        let next = if diff.is_empty() {
            source.snapshot.clone()
        } else {
            Arc::new(Snapshot {
                owner: self.inner.owner.clone(),
                entries,
                credentials,
                signals: signals.into(),
            })
        };
        Ok(Candidate {
            source,
            next,
            next_revision,
            validator,
            confirmed_at: Instant::now(),
            revocations: revoked.into(),
            diff,
        })
    }

    pub(crate) fn validate_candidate(
        &self,
        permit: &WritePermit<'_>,
        candidate: &Candidate,
    ) -> Result<(), Error> {
        if !self.publication().owns_write(permit)
            || !Arc::ptr_eq(&candidate.source.owner, &self.inner.owner)
        {
            return Err(Error::ForeignSnapshot);
        }
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.revision != candidate.source.revision || state.writer != candidate.source.writer {
            return Err(Error::StaleCandidate);
        }
        Ok(())
    }
    /// Caller validates all participants first. No fallible work remains here.
    pub(crate) fn publish(
        &self,
        permit: &mut WritePermit<'_>,
        candidate: Candidate,
        writer: Option<GenerationId>,
    ) {
        assert!(self.publication().owns_write(permit));
        permit.revoke(candidate.revocations);
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.snapshot = candidate.next;
        state.revision = candidate.next_revision;
        state.validator = candidate.validator;
        state.writer = writer;
        state.confirmed_at = Some(candidate.confirmed_at);
    }
    pub fn suspend(&self, writer: GenerationId, only_if_stale: bool) -> bool {
        let mut permit = self.publication().write(1);
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.writer != Some(writer) || state.confirmed_at.is_none() {
            return false;
        }
        if only_if_stale
            && state
                .confirmed_at
                .is_some_and(|at| at.elapsed() < self.inner.limits.max_age)
        {
            return false;
        }
        permit.revoke(state.snapshot.signals.clone());
        state.validator = None;
        state.confirmed_at = None;
        // At revision exhaustion, keep the store suspended forever rather than wrap.
        state.revision = state.revision.saturating_add(1);
        true
    }
    pub fn confirm(
        &self,
        source: &View,
        writer: GenerationId,
        validator: Validator,
    ) -> Result<(), Error> {
        let _permit = self.publication().write(0);
        let mut s = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if !Arc::ptr_eq(&source.owner, &self.inner.owner) {
            return Err(Error::ForeignSnapshot);
        }
        if s.writer != Some(writer) {
            return Err(Error::NotOwner);
        }
        if s.revision != source.revision {
            return Err(Error::StaleCandidate);
        }
        if s.confirmed_at.is_none() {
            return Err(Error::MissingSnapshot);
        }
        s.revision = s.revision.checked_add(1).ok_or(Error::RevisionOverflow)?;
        s.validator = Some(validator);
        s.confirmed_at = Some(Instant::now());
        Ok(())
    }

    pub(crate) fn acquire(
        &self,
        permit: &ReadPermit<'_>,
        writer: GenerationId,
        identity: &Identity,
        parent: &CancellationToken,
    ) -> Result<SessionLease, Error> {
        if !self.publication().owns_read(permit) || !Arc::ptr_eq(&identity.owner, &self.inner.owner)
        {
            return Err(Error::ForeignSnapshot);
        }
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.writer != Some(writer) {
            return Err(Error::NotOwner);
        }
        let entry = self.resolve(&state, identity)?;
        let signal = entry.revoked.clone();
        if parent.is_cancelled() {
            return Err(Error::Stopped(StopReason::Cancelled));
        }
        if state.sessions >= self.inner.limits.max_sessions {
            return Err(Error::SessionLimit);
        }
        state.sessions += 1;
        Ok(SessionLease {
            store: self.clone(),
            identity: identity.clone(),
            cancellation: parent.child_token(),
            revocation: signal,
        })
    }
    fn resolve<'a>(&self, state: &'a State, identity: &Identity) -> Result<&'a Entry, Error> {
        if !Arc::ptr_eq(&identity.owner, &self.inner.owner) {
            return Err(Error::ForeignSnapshot);
        }
        if state
            .confirmed_at
            .is_none_or(|at| at.elapsed() >= self.inner.limits.max_age)
        {
            return Err(Error::StaleUsers);
        }
        let entry = state
            .snapshot
            .entries
            .get(&identity.id)
            .ok_or(Error::Revoked)?;
        if entry.epoch != identity.epoch || entry.revoked.is_revoked() {
            return Err(Error::Revoked);
        }
        Ok(entry)
    }
}

pub struct SessionLease {
    store: Store,
    identity: Identity,
    cancellation: CancellationToken,
    revocation: Revocation,
}
impl SessionLease {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    pub fn context(&self, deadline: Option<Deadline>) -> OperationContext {
        OperationContext::new(self.cancellation.clone(), deadline)
            .with_revocation(self.revocation.clone())
            .expect("fresh session context")
    }
    pub fn current_user(&self) -> Result<User, Error> {
        let _guard = self.store.publication().read();
        let s = self
            .store
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Ok(self.store.resolve(&s, &self.identity)?.user.clone())
    }
}
impl Drop for SessionLease {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.store
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions -= 1;
    }
}

pub trait PreparedAuth: Send {
    /// Local, atomic publication. Err MUST leave the previous auth state intact.
    /// Do not reenter publication APIs, await, perform I/O, or panic here.
    fn commit(&mut self, permit: &WritePermit<'_>) -> Result<(), Error>;
    fn abort(&mut self);
}
#[async_trait]
pub trait AuthUpdater: Send + Sync {
    async fn prepare_users(
        &self,
        snapshot: Arc<Snapshot>,
        context: &OperationContext,
    ) -> Result<Box<dyn PreparedAuth>, Error>;
}
pub struct PreparedUpdate {
    candidate: Option<Candidate>,
    auth: Option<Box<dyn PreparedAuth>>,
    committed: bool,
}
impl PreparedUpdate {
    pub async fn prepare(
        candidate: Candidate,
        updater: &dyn AuthUpdater,
        force: bool,
        context: &OperationContext,
    ) -> Result<Self, Error> {
        let mut prepared = Self {
            candidate: Some(candidate),
            auth: None,
            committed: false,
        };
        if force
            || !prepared
                .candidate
                .as_ref()
                .expect("candidate")
                .diff
                .is_empty()
        {
            prepared.auth = Some(
                context
                    .run(updater.prepare_users(prepared.snapshot(), context))
                    .await
                    .map_err(Error::Stopped)??,
            );
        }
        context.check().map_err(Error::Stopped)?;
        Ok(prepared)
    }
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.candidate
            .as_ref()
            .expect("unpublished candidate")
            .snapshot()
    }
    pub(crate) fn validate(&self, store: &Store, permit: &WritePermit<'_>) -> Result<(), Error> {
        store.validate_candidate(
            permit,
            self.candidate.as_ref().ok_or(Error::StaleCandidate)?,
        )
    }
    pub(crate) fn commit_auth(&mut self, permit: &WritePermit<'_>) -> Result<(), Error> {
        if !self.committed {
            if let Some(auth) = &mut self.auth {
                auth.commit(permit)?;
            }
            self.committed = true;
        }
        Ok(())
    }
    pub(crate) fn publish(
        &mut self,
        store: &Store,
        permit: &mut WritePermit<'_>,
        writer: Option<GenerationId>,
    ) {
        assert!(self.committed);
        store.publish(
            permit,
            self.candidate.take().expect("single publication"),
            writer,
        );
    }
}
impl Drop for PreparedUpdate {
    fn drop(&mut self) {
        if !self.committed
            && let Some(auth) = &mut self.auth
        {
            auth.abort();
        }
    }
}

pub struct Reconciler {
    store: Store,
    updater: Arc<dyn AuthUpdater>,
}
impl Reconciler {
    pub fn new(store: Store, updater: Arc<dyn AuthUpdater>) -> Self {
        Self { store, updater }
    }
    pub async fn apply(
        &self,
        source: View,
        users: Vec<User>,
        validator: Validator,
        writer: GenerationId,
        context: &OperationContext,
    ) -> Result<Diff, Error> {
        if source.writer != Some(writer) {
            return Err(Error::NotOwner);
        }
        let candidate = self.store.candidate(source, users, Some(validator))?;
        let diff = candidate.diff.clone();
        let mut prepared =
            PreparedUpdate::prepare(candidate, self.updater.as_ref(), false, context).await?;
        let mut permit = self.store.publication().write(1);
        context.check().map_err(Error::Stopped)?;
        prepared.validate(&self.store, &permit)?;
        prepared.commit_auth(&permit)?;
        prepared.publish(&self.store, &mut permit, Some(writer));
        Ok(diff)
    }
}
