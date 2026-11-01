// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    buffer::{BufferLayout, BufferScope},
    panel::{self, *},
    protocol::runtimekit::{Core, Runtime},
    resource::{Budget, Limits},
    runtime::{
        self, PreparedListener, ProtocolDriver, RuntimeFactory, SharedServices, WritePermit,
    },
    supervisor::{self, Supervisor},
    task::CancellationToken,
    telemetry::Metrics,
    time::{Deadline, OperationContext},
    users::{self, AuthUpdater, PreparedAuth},
};
use async_trait::async_trait;
use std::result::Result;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

fn ctx() -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(300)).unwrap()),
    )
}
fn name(value: &str) -> ProtocolName {
    ProtocolName::new(value).unwrap()
}
fn user(id: i64, key: &str) -> User {
    User {
        id: SubscriptionId::new(id).unwrap(),
        credential: Secret::new(key),
        speed_limit_mbps: 0,
        device_limit: 0,
    }
}
fn validator(endpoint: Endpoint, version: u8) -> Validator {
    Validator {
        owner: Arc::new(()),
        endpoint,
        protocol: None,
        encoding: Encoding::Json,
        etag: Some(version.to_string()),
        digest: [version; 32],
    }
}
fn config(protocols: &[&str], version: u64) -> ServerConfig {
    ServerConfig {
        pull_interval: Duration::from_secs(60),
        push_interval: Duration::from_secs(60),
        traffic_report_threshold: 1024,
        ip_strategy: String::new(),
        dns: vec![],
        block: vec![],
        outbounds: vec![],
        protocols: protocols
            .iter()
            .enumerate()
            .map(|(i, p)| protocol(p, 10000 + i as u16, version))
            .collect(),
        extensions: BTreeMap::new(),
    }
}
fn protocol(name_: &str, port: u16, version: u64) -> ProtocolConfig {
    ProtocolConfig {
        protocol: name(name_),
        port,
        version,
        mode: String::new(),
        enabled: true,
        security: String::new(),
        network: String::new(),
        sni: String::new(),
        alpn: vec![],
        allow_insecure: false,
        fingerprint: String::new(),
        reality_server_addr: String::new(),
        reality_server_port: 0,
        reality_private_key: Secret::new(""),
        reality_public_key: String::new(),
        reality_short_id: String::new(),
        transport: String::new(),
        host: String::new(),
        path: String::new(),
        service_name: String::new(),
        cipher: String::new(),
        server_key: Secret::new(""),
        plugin: String::new(),
        plugin_options: ConfigValue::Null,
        flow: String::new(),
        uot: false,
        uot_version: 0,
        accept_proxy_protocol: false,
        hop_ports: String::new(),
        hop_interval: 0,
        obfs_password: Secret::new(""),
        disable_sni: false,
        reduce_rtt: false,
        heartbeat: 0,
        udp_relay_mode: String::new(),
        congestion_controller: String::new(),
        quic_congestion_control: String::new(),
        multiplex: String::new(),
        padding_scheme: String::new(),
        traffic_pattern: String::new(),
        user_hint_is_mandatory: false,
        up_mbps: 0,
        down_mbps: 0,
        obfs: String::new(),
        ssr_protocol: String::new(),
        protocol_param: String::new(),
        obfs_param: String::new(),
        obfs_host: String::new(),
        obfs_path: String::new(),
        xhttp_mode: String::new(),
        xhttp_extra: String::new(),
        encryption: String::new(),
        encryption_mode: String::new(),
        encryption_rtt: String::new(),
        encryption_ticket: Secret::new(""),
        encryption_server_padding: String::new(),
        encryption_private_key: Secret::new(""),
        encryption_client_padding: String::new(),
        encryption_password: Secret::new(""),
        ech_enable: false,
        ech_server_name: String::new(),
        ratio: 1.0,
        cert_mode: String::new(),
        cert_dns_provider: String::new(),
        cert_dns_env: Secret::new(""),
        extensions: BTreeMap::new(),
    }
}

#[derive(Default)]
struct Block {
    entered: Notify,
    release: Notify,
}
struct PanelState {
    config: Mutex<ServerConfig>,
    users: Mutex<Vec<User>>,
    version: AtomicUsize,
    unchanged: AtomicBool,
    error: Mutex<Option<panel::Error>>,
    users_block: Mutex<Option<Arc<Block>>>,
    traffic: Mutex<Vec<Vec<Traffic>>>,
    online: Mutex<Vec<Vec<OnlineUser>>>,
    status: AtomicUsize,
}
impl PanelState {
    fn new(config: ServerConfig) -> Arc<Self> {
        Arc::new(Self {
            config: Mutex::new(config),
            users: Mutex::new(vec![user(1, "first")]),
            version: AtomicUsize::new(1),
            unchanged: AtomicBool::new(false),
            error: Mutex::new(None),
            users_block: Mutex::new(None),
            traffic: Mutex::new(vec![]),
            online: Mutex::new(vec![]),
            status: AtomicUsize::new(0),
        })
    }
    fn config(&self, value: ServerConfig) {
        *self.config.lock().unwrap() = value;
        self.version.fetch_add(1, Ordering::SeqCst);
    }
    fn users(&self, value: Vec<User>) {
        *self.users.lock().unwrap() = value;
        self.version.fetch_add(1, Ordering::SeqCst);
    }
}
struct Client {
    panel: Arc<PanelState>,
    name: ProtocolName,
}
#[async_trait]
impl ServerClient for PanelState {
    async fn get_config(&self, _: Option<&Validator>) -> panel::Result<Fetch<ServerConfig>> {
        let validator = validator(Endpoint::Config, self.version.load(Ordering::SeqCst) as u8);
        if self.unchanged.load(Ordering::SeqCst) {
            Ok(Fetch::Unchanged { validator })
        } else {
            Ok(Fetch::Changed {
                value: self.config.lock().unwrap().clone(),
                validator,
            })
        }
    }
}
#[async_trait]
impl ProtocolClient for Client {
    fn protocol(&self) -> &ProtocolName {
        &self.name
    }
    fn policy(&self) -> ProtocolPolicy {
        ProtocolPolicy {
            devices: DevicePolicy::AtomicPanelLease,
            report_active_and_unconfirmed: true,
            max_online_entries: 2,
        }
    }
    async fn get_users(&self, _: Option<&Validator>) -> panel::Result<Fetch<Vec<User>>> {
        if let Some(error) = self.panel.error.lock().unwrap().clone() {
            return Err(error);
        }
        let users = self.panel.users.lock().unwrap().clone();
        let version = self.panel.version.load(Ordering::SeqCst) as u8;
        let block = self.panel.users_block.lock().unwrap().take();
        if let Some(block) = block {
            block.entered.notify_one();
            block.release.notified().await;
        }
        let validator = validator(Endpoint::Users, version);
        if self.panel.unchanged.load(Ordering::SeqCst) {
            Ok(Fetch::Unchanged { validator })
        } else {
            Ok(Fetch::Changed {
                value: users,
                validator,
            })
        }
    }
    async fn get_alive(&self) -> panel::Result<BTreeMap<SubscriptionId, u64>> {
        Ok(BTreeMap::new())
    }
    async fn claim_device(
        &self,
        _: SubscriptionId,
        _: std::net::IpAddr,
    ) -> panel::Result<DeviceClaim> {
        panic!("B4 never claims device slots")
    }
    async fn report_online(&self, users: &[OnlineUser]) -> panel::Result<()> {
        self.panel.online.lock().unwrap().push(users.to_vec());
        Ok(())
    }
    async fn report_traffic(&self, traffic: &[Traffic]) -> panel::Result<()> {
        self.panel.traffic.lock().unwrap().push(traffic.to_vec());
        Ok(())
    }
}
#[async_trait]
impl StatusClient for PanelState {
    async fn report_status(&self, _: NodeStatus) -> panel::Result<()> {
        self.status.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
struct ConnectionMock(Arc<PanelState>);
impl Connection for ConnectionMock {
    fn server(&self) -> Arc<dyn ServerClient> {
        self.0.clone()
    }
    fn protocol(&self, protocol: &str) -> panel::Result<Arc<dyn ProtocolClient>> {
        Ok(Arc::new(Client {
            panel: self.0.clone(),
            name: name(protocol),
        }))
    }
    fn status(&self, _: &str) -> panel::Result<Arc<dyn StatusClient>> {
        Ok(self.0.clone())
    }
}
#[derive(Default)]
struct FactoryState {
    drivers: Mutex<Vec<Arc<Driver>>>,
    shared_prepared: AtomicUsize,
    shared_closed: AtomicUsize,
    auth_failure: Mutex<Option<ProtocolName>>,
    listener_failure: Mutex<Option<ProtocolName>>,
    listener_prepare_failure: AtomicBool,
    auth_aborts: AtomicUsize,
    prepare_block: Mutex<Option<Arc<Block>>>,
}
struct Shared(Arc<FactoryState>);
#[async_trait]
impl SharedServices for Shared {
    fn abort(&self) {}
    async fn close(&self, _: &OperationContext) -> Result<(), runtime::Error> {
        self.0.shared_closed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
struct Driver {
    state: Weak<FactoryState>,
    core: Core,
    auth: Arc<Mutex<Option<Arc<users::Snapshot>>>>,
    aborted: AtomicBool,
    listener_aborted: Arc<AtomicBool>,
}
struct Auth {
    state: Arc<FactoryState>,
    name: ProtocolName,
    auth: Arc<Mutex<Option<Arc<users::Snapshot>>>>,
    next: Arc<users::Snapshot>,
}
impl PreparedAuth for Auth {
    fn commit(&mut self, _: &WritePermit<'_>) -> Result<(), users::Error> {
        if self.state.auth_failure.lock().unwrap().as_ref() == Some(&self.name) {
            return Err(users::Error::Apply("injected auth"));
        }
        *self.auth.lock().unwrap() = Some(self.next.clone());
        Ok(())
    }
    fn abort(&mut self) {
        self.state.auth_aborts.fetch_add(1, Ordering::SeqCst);
    }
}
#[async_trait]
impl AuthUpdater for Driver {
    async fn prepare_users(
        &self,
        snapshot: Arc<users::Snapshot>,
        _: &OperationContext,
    ) -> Result<Box<dyn PreparedAuth>, users::Error> {
        Ok(Box::new(Auth {
            state: self.state.upgrade().expect("factory still owns driver"),
            name: self.core.protocol().clone(),
            auth: self.auth.clone(),
            next: snapshot,
        }))
    }
}
struct Listener {
    state: Arc<FactoryState>,
    core: Core,
    aborted: Arc<AtomicBool>,
}
impl PreparedListener for Listener {
    fn commit(&mut self) -> Result<(), runtime::Error> {
        assert!(!self.core.gate().is_open());
        if self.state.listener_failure.lock().unwrap().as_ref() == Some(self.core.protocol()) {
            return Err(runtime::Error::Commit("injected listener"));
        }
        Ok(())
    }
    fn stop_accepting(&mut self) -> Result<(), runtime::Error> {
        Ok(())
    }
    fn abort(&mut self) {
        self.aborted.store(true, Ordering::SeqCst);
    }
}
#[async_trait]
impl ProtocolDriver for Driver {
    async fn prepare_listener(
        &self,
        _: &OperationContext,
    ) -> Result<Box<dyn PreparedListener>, runtime::Error> {
        let state = self.state.upgrade().expect("factory still owns driver");
        let block = state.prepare_block.lock().unwrap().take();
        if let Some(block) = block {
            block.entered.notify_one();
            block.release.notified().await;
        }
        if state.listener_prepare_failure.load(Ordering::SeqCst) {
            return Err(runtime::Error::Preparation("listener"));
        }
        Ok(Box::new(Listener {
            state: state.clone(),
            core: self.core.clone(),
            aborted: self.listener_aborted.clone(),
        }))
    }
    fn certificate(&self) -> Option<CertificateFingerprint> {
        Some(
            CertificateFingerprint::new(&format!("{:064x}", self.core.generation().get())).unwrap(),
        )
    }
    fn abort(&self) {
        self.aborted.store(true, Ordering::SeqCst);
    }
    async fn close(&self, _: &OperationContext) -> Result<(), runtime::Error> {
        Ok(())
    }
}
struct Factory(Arc<FactoryState>);
#[async_trait]
impl RuntimeFactory for Factory {
    type Shared = Shared;
    fn supports(&self, protocol: &ProtocolName) -> bool {
        protocol.as_str() != "unknown"
    }
    async fn prepare_shared(
        &self,
        _: Arc<ServerConfig>,
        _: BufferScope,
        _: &OperationContext,
    ) -> Result<Shared, runtime::Error> {
        self.0.shared_prepared.fetch_add(1, Ordering::SeqCst);
        Ok(Shared(self.0.clone()))
    }
    async fn prepare_protocol(
        &self,
        _: ProtocolConfig,
        _: Arc<Shared>,
        core: Core,
        _: &OperationContext,
    ) -> Result<Arc<dyn ProtocolDriver>, runtime::Error> {
        let driver = Arc::new(Driver {
            state: Arc::downgrade(&self.0),
            core,
            auth: Arc::new(Mutex::new(None)),
            aborted: AtomicBool::new(false),
            listener_aborted: Arc::new(AtomicBool::new(false)),
        });
        self.0.drivers.lock().unwrap().push(driver.clone());
        Ok(driver)
    }
}
#[derive(Default)]
struct Fingerprints(Mutex<BTreeMap<ProtocolName, CertificateFingerprint>>);
impl supervisor::FingerprintSink for Fingerprints {
    fn replace(&self, values: BTreeMap<ProtocolName, CertificateFingerprint>) {
        *self.0.lock().unwrap() = values;
    }
}
struct Harness {
    panel: Arc<PanelState>,
    factory: Arc<FactoryState>,
    supervisor: Arc<Supervisor<Factory>>,
    fingerprints: Arc<Fingerprints>,
    budget: Budget,
}
impl Harness {
    fn new(protocols: &[&str]) -> Self {
        Self::with_options(protocols, supervisor::Options::default())
    }
    fn with_options(protocols: &[&str], options: supervisor::Options) -> Self {
        Self::with_sampler(protocols, options, None)
    }
    fn with_sampler(
        protocols: &[&str],
        options: supervisor::Options,
        sampler: Option<Arc<dyn supervisor::StatusSampler>>,
    ) -> Self {
        let panel = PanelState::new(config(protocols, 1));
        let factory = Arc::new(FactoryState::default());
        let budget = Budget::new(Limits::new(4096, 16).unwrap());
        let buffers = BufferScope::new(budget.root_scope(), 1024).unwrap();
        let fingerprints = Arc::new(Fingerprints::default());
        let supervisor = Arc::new(
            Supervisor::new(
                Arc::new(ConnectionMock(panel.clone())),
                Arc::new(Factory(factory.clone())),
                buffers,
                options,
                Metrics::default(),
                fingerprints.clone(),
                sampler,
            )
            .unwrap(),
        );
        Self {
            panel,
            factory,
            supervisor,
            fingerprints,
            budget,
        }
    }
    async fn sync(&self) {
        self.supervisor.sync_config(&ctx()).await.unwrap();
    }
    fn runtime(&self, protocol: &str) -> Arc<Runtime> {
        self.supervisor.runtime(&name(protocol)).unwrap()
    }
}

#[tokio::test(start_paused = true)]
async fn all_protocols_publish_together_and_share_one_egress() {
    let h = Harness::new(&["shadowsocks", "trojan"]);
    h.sync().await;
    assert!(h.supervisor.snapshot().ready);
    assert_eq!(h.factory.shared_prepared.load(Ordering::SeqCst), 1);
    assert_eq!(h.supervisor.snapshot().protocols.len(), 2);
    assert_eq!(h.fingerprints.0.lock().unwrap().len(), 2);
    let runtime = h.runtime("trojan");
    let identity = runtime
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    let lease = runtime.core().admit(&identity).unwrap();
    assert_eq!(lease.current_user().unwrap().id.get(), 1);
    drop(lease);
    h.supervisor.close(&ctx()).await.unwrap();
    assert!(!h.supervisor.snapshot().ready);
    assert!(h.fingerprints.0.lock().unwrap().is_empty());
}
#[tokio::test(start_paused = true)]
async fn failure_in_later_protocol_does_not_publish_any_candidate_or_fingerprint() {
    for auth_failure in [false, true] {
        let h = Harness::new(&["alpha", "zeta"]);
        h.sync().await;
        let before = h.supervisor.snapshot().generation;
        let runtime = h.runtime("alpha");
        let view = runtime.core().users().view();
        let fingerprints = h.fingerprints.0.lock().unwrap().clone();
        h.panel.config(config(&["alpha", "zeta"], 2));
        h.panel.users(vec![user(2, "new")]);
        let failure = if auth_failure {
            &h.factory.auth_failure
        } else {
            &h.factory.listener_failure
        };
        *failure.lock().unwrap() = Some(name("zeta"));
        assert!(h.supervisor.sync_config(&ctx()).await.is_err());
        assert_eq!(h.supervisor.snapshot().generation, before);
        assert_eq!(*h.fingerprints.0.lock().unwrap(), fingerprints);
        assert_eq!(runtime.core().users().view().revision, view.revision);
        assert!(
            runtime
                .core()
                .admit(&view.snapshot.authenticate("first").unwrap())
                .is_ok()
        );
        for driver in h.factory.drivers.lock().unwrap().iter().skip(2) {
            assert!(!driver.core.gate().is_open());
            assert!(driver.aborted.load(Ordering::SeqCst));
        }
        assert_eq!(h.factory.shared_closed.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test(start_paused = true)]
async fn failed_listener_preparation_is_retryable_without_committing_config_validator() {
    let h = Harness::new(&["trojan"]);
    h.factory
        .listener_prepare_failure
        .store(true, Ordering::SeqCst);
    assert!(h.supervisor.sync_config(&ctx()).await.is_err());
    assert!(!h.supervisor.snapshot().ready);
    h.factory
        .listener_prepare_failure
        .store(false, Ordering::SeqCst);
    h.sync().await;
    assert!(h.supervisor.snapshot().ready);
    assert_eq!(h.factory.shared_prepared.load(Ordering::SeqCst), 2);
    h.sync().await;
    assert_eq!(h.factory.shared_prepared.load(Ordering::SeqCst), 2);
}
#[tokio::test(start_paused = true)]
async fn old_sessions_see_new_limits_then_revocation_across_reload() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let old = h.runtime("trojan");
    let id = old
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    let lease = old.core().admit(&id).unwrap();
    let mut limited = user(1, "first");
    limited.speed_limit_mbps = 20;
    limited.device_limit = 3;
    h.panel.users(vec![limited]);
    h.panel.config(config(&["trojan"], 2));
    h.sync().await;
    assert_eq!(lease.current_user().unwrap().speed_limit_mbps, 20);
    assert!(old.core().admit(&id).is_err());
    assert!(lease.context(None).check().is_ok());
    let current = h.runtime("trojan");
    h.panel.users(vec![user(1, "changed")]);
    current.controller.sync_users(&ctx()).await.unwrap();
    assert!(lease.context(None).check().is_err());
    assert!(current.core().admit(&id).is_err());
    drop(lease);
    h.supervisor.reap_retired(&ctx()).await.unwrap();
    assert_eq!(h.supervisor.snapshot().retired, 0);
    assert!(!current.core().is_closed());
}
#[tokio::test(start_paused = true)]
async fn late_old_generation_response_cannot_restore_revoked_user() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let old = h.runtime("trojan");
    let block = Arc::new(Block::default());
    *h.panel.users_block.lock().unwrap() = Some(block.clone());
    let controller = old.controller.clone();
    let pending = tokio::spawn(async move { controller.sync_users(&ctx()).await });
    block.entered.notified().await;
    h.panel.users(vec![]);
    h.panel.config(config(&["trojan"], 2));
    h.sync().await;
    block.release.notify_one();
    assert!(pending.await.unwrap().is_err());
    assert!(
        h.runtime("trojan")
            .core()
            .users()
            .view()
            .snapshot
            .is_empty()
    );
}
#[tokio::test(start_paused = true)]
async fn candidate_prepared_before_user_update_fails_revision_cas() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let old = h.runtime("trojan");
    let before = h.supervisor.snapshot().generation;
    h.panel.config(config(&["trojan"], 2));
    let block = Arc::new(Block::default());
    *h.factory.prepare_block.lock().unwrap() = Some(block.clone());
    let supervisor = h.supervisor.clone();
    let pending = tokio::spawn(async move { supervisor.sync_config(&ctx()).await });
    block.entered.notified().await;
    h.panel.users(vec![]);
    old.controller.sync_users(&ctx()).await.unwrap();
    block.release.notify_one();
    assert!(pending.await.unwrap().is_err());
    assert_eq!(h.supervisor.snapshot().generation, before);
    assert!(old.core().users().view().snapshot.is_empty());
    h.sync().await;
}
#[tokio::test(start_paused = true)]
async fn removal_revokes_sessions_and_preserves_reports_for_final_ack() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let old = h.runtime("trojan");
    let id = old
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    let lease = old.core().admit(&id).unwrap();
    old.core()
        .reports()
        .record_traffic(Traffic {
            id: id.id(),
            upload: 10,
            download: 7,
        })
        .unwrap();
    h.panel.config(config(&[], 2));
    h.sync().await;
    assert!(!h.supervisor.snapshot().ready);
    assert!(lease.context(None).check().is_err());
    assert_eq!(
        h.supervisor
            .reports(&name("trojan"))
            .unwrap()
            .snapshot()
            .pending_bytes,
        17
    );
    drop(lease);
    h.supervisor.reap_retired(&ctx()).await.unwrap();
    h.supervisor.flush_reports(&ctx()).await.unwrap();
    assert_eq!(h.panel.traffic.lock().unwrap()[0][0].upload, 10);
    assert_eq!(
        h.supervisor
            .reports(&name("trojan"))
            .unwrap()
            .snapshot()
            .pending_bytes,
        0
    );
}
#[tokio::test(start_paused = true)]
async fn cancellation_during_prepare_leaves_active_runtime_alive() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let old = h.runtime("trojan");
    h.panel.config(config(&["trojan"], 2));
    let block = Arc::new(Block::default());
    *h.factory.prepare_block.lock().unwrap() = Some(block.clone());
    let supervisor = h.supervisor.clone();
    let pending = tokio::spawn(async move { supervisor.sync_config(&ctx()).await });
    block.entered.notified().await;
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    assert!(old.core().is_current());
    assert!(
        h.factory.drivers.lock().unwrap()[1]
            .aborted
            .load(Ordering::SeqCst)
    );
    h.sync().await;
}
#[tokio::test(start_paused = true)]
async fn shutdown_joins_runtime_tasks_and_returns_their_buffers() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let runtime = h.runtime("trojan");
    let buffer = runtime
        .core()
        .buffers()
        .try_lease(BufferLayout::new(0, 512, 0).unwrap())
        .unwrap();
    let started = Arc::new(Notify::new());
    let signal = started.clone();
    runtime
        .core()
        .spawn("held-buffer", move |_| async move {
            let _buffer = buffer;
            signal.notify_one();
            std::future::pending::<()>().await;
            Ok(())
        })
        .unwrap();
    started.notified().await;
    assert_eq!(h.budget.snapshot().used().bytes(), 512);
    h.supervisor.close(&ctx()).await.unwrap();
    assert_eq!(h.budget.snapshot().used().bytes(), 0);
    assert!(runtime.core().is_closed());
}
#[tokio::test(start_paused = true)]
async fn unsupported_required_protocol_is_rejected_but_empty_config_disables_node() {
    let options = supervisor::Options {
        required_protocols: BTreeSet::from([name("trojan")]),
        ..Default::default()
    };
    let h = Harness::with_options(&["unknown"], options);
    assert!(matches!(
        h.supervisor.sync_config(&ctx()).await,
        Err(supervisor::Error::RequiredProtocol)
    ));
    h.panel.config(config(&[], 2));
    h.sync().await;
    assert!(!h.supervisor.snapshot().ready);
}
#[tokio::test(start_paused = true)]
async fn user_commit_failure_does_not_advance_revision_or_cancel_sessions() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let runtime = h.runtime("trojan");
    let view = runtime.core().users().view();
    let lease = runtime
        .core()
        .admit(&view.snapshot.authenticate("first").unwrap())
        .unwrap();
    h.panel.users(vec![]);
    *h.factory.auth_failure.lock().unwrap() = Some(name("trojan"));
    assert!(runtime.controller.sync_users(&ctx()).await.is_err());
    assert_eq!(runtime.core().users().view().revision, view.revision);
    assert!(lease.context(None).check().is_ok());
    assert_eq!(h.factory.auth_aborts.load(Ordering::SeqCst), 1);
    *h.factory.auth_failure.lock().unwrap() = None;
    runtime.controller.sync_users(&ctx()).await.unwrap();
    assert!(lease.context(None).check().is_err());
}
#[tokio::test(start_paused = true)]
async fn successful_304_refreshes_age_and_suspension_requires_full_snapshot() {
    let options = supervisor::Options {
        users: users::Limits {
            max_users: 10,
            max_sessions: 2,
            max_age: Duration::from_secs(5),
        },
        ..Default::default()
    };
    let h = Harness::with_options(&["trojan"], options);
    h.sync().await;
    let runtime = h.runtime("trojan");
    let view = runtime.core().users().view();
    let id = view.snapshot.authenticate("first").unwrap();
    let lease = runtime.core().admit(&id).unwrap();
    tokio::time::advance(Duration::from_secs(3)).await;
    h.panel.unchanged.store(true, Ordering::SeqCst);
    runtime.controller.sync_users(&ctx()).await.unwrap();
    assert!(runtime.core().users().view().revision > view.revision);
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(lease.current_user().is_ok());
    runtime
        .core()
        .users()
        .suspend(runtime.core().generation(), false);
    assert!(lease.context(None).check().is_err());
    assert!(runtime.controller.sync_users(&ctx()).await.is_err());
    h.panel.unchanged.store(false, Ordering::SeqCst);
    runtime.controller.sync_users(&ctx()).await.unwrap();
    assert!(runtime.core().admit(&id).is_err());
    let fresh = runtime
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    assert!(runtime.core().admit(&fresh).is_ok());
}
#[tokio::test(start_paused = true)]
async fn user_validation_and_session_capacity_are_enforced() {
    let options = supervisor::Options {
        users: users::Limits {
            max_users: 2,
            max_sessions: 1,
            max_age: Duration::from_secs(300),
        },
        ..Default::default()
    };
    let h = Harness::with_options(&["trojan"], options);
    h.sync().await;
    let runtime = h.runtime("trojan");
    let core = runtime.core();
    let store = core.users();
    let view = store.view();
    assert!(matches!(
        store.candidate(view.clone(), vec![user(1, "a"), user(1, "b")], None),
        Err(users::Error::DuplicateId)
    ));
    assert!(matches!(
        store.candidate(view.clone(), vec![user(1, "a"), user(2, "a")], None),
        Err(users::Error::DuplicateCredential)
    ));
    assert!(matches!(
        store.candidate(
            view.clone(),
            vec![user(1, "a"), user(2, "b"), user(3, "c")],
            None
        ),
        Err(users::Error::TooManyUsers)
    ));
    let id = view.snapshot.authenticate("first").unwrap();
    let lease = core.admit(&id).unwrap();
    assert!(matches!(
        core.admit(&id),
        Err(runtime::Error::Users(users::Error::SessionLimit))
    ));
    drop(lease);
    assert!(core.admit(&id).is_ok());
}

#[tokio::test(start_paused = true)]
async fn auth_rejection_suspends_users_but_transient_errors_retain_snapshot() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let runtime = h.runtime("trojan");
    let id = runtime
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    let lease = runtime.core().admit(&id).unwrap();
    *h.panel.error.lock().unwrap() = Some(panel::Error::http(Endpoint::Users, 503));
    assert!(runtime.controller.sync_users(&ctx()).await.is_err());
    assert!(lease.context(None).check().is_ok());
    assert!(h.supervisor.snapshot().ready);
    *h.panel.error.lock().unwrap() = Some(panel::Error::http(Endpoint::Users, 403));
    assert!(runtime.controller.sync_users(&ctx()).await.is_err());
    assert!(lease.context(None).check().is_err());
    assert!(!h.supervisor.snapshot().ready);
    *h.panel.error.lock().unwrap() = None;
    runtime.controller.sync_users(&ctx()).await.unwrap();
    assert!(h.supervisor.snapshot().ready);
}
#[tokio::test(start_paused = true)]
async fn expired_snapshot_refuses_admission_even_before_validity_tick() {
    let options = supervisor::Options {
        users: users::Limits {
            max_users: 2,
            max_sessions: 2,
            max_age: Duration::from_secs(2),
        },
        ..Default::default()
    };
    let h = Harness::with_options(&["trojan"], options);
    h.sync().await;
    let runtime = h.runtime("trojan");
    let id = runtime
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert!(runtime.core().admit(&id).is_err());
    assert!(!h.supervisor.snapshot().ready);
    runtime.controller.expire().unwrap();
    assert!(runtime.core().users().view().confirmed_at.is_none());
}
#[tokio::test(start_paused = true)]
async fn retirement_retry_preserves_original_drain_deadline() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let runtime = h.runtime("trojan");
    let id = runtime
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    let lease = runtime.core().admit(&id).unwrap();
    h.panel.config(config(&["trojan"], 2));
    h.sync().await;
    let cleanup_context = ctx();
    let pending = h.supervisor.reap_retired(&cleanup_context);
    assert!(
        tokio::time::timeout(Duration::from_secs(20), pending)
            .await
            .is_err()
    );
    assert_eq!(h.supervisor.snapshot().retired, 1);
    let started = tokio::time::Instant::now();
    h.supervisor.reap_retired(&ctx()).await.unwrap();
    assert_eq!(started.elapsed(), Duration::from_secs(10));
    assert!(lease.context(None).check().is_err());
    assert_eq!(h.supervisor.snapshot().retired, 0);
}
#[tokio::test(start_paused = true)]
async fn retired_capacity_is_recovered_by_explicit_reaping() {
    let options = supervisor::Options {
        max_retired: 1,
        ..Default::default()
    };
    let h = Harness::with_options(&["trojan"], options);
    h.sync().await;
    h.panel.config(config(&["trojan"], 2));
    h.sync().await;
    h.panel.config(config(&["trojan"], 3));
    assert!(matches!(
        h.supervisor.sync_config(&ctx()).await,
        Err(supervisor::Error::Capacity)
    ));
    h.supervisor.reap_retired(&ctx()).await.unwrap();
    h.sync().await;
}
#[tokio::test(start_paused = true)]
async fn controller_chunks_online_reports_and_does_not_renew_acked_short_connections() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let runtime = h.runtime("trojan");
    for index in 1..=5 {
        drop(
            runtime
                .core()
                .reports()
                .online(
                    SubscriptionId::new(index).unwrap(),
                    "127.0.0.1".parse().unwrap(),
                )
                .unwrap(),
        );
    }
    runtime.controller.report_online(&ctx()).await.unwrap();
    let batches = h.panel.online.lock().unwrap().clone();
    assert_eq!(
        batches.iter().map(Vec::len).collect::<Vec<_>>(),
        vec![2, 2, 1]
    );
    runtime.controller.report_online(&ctx()).await.unwrap();
    assert_eq!(h.panel.online.lock().unwrap().len(), 3);
}
#[tokio::test(start_paused = true)]
async fn run_drives_configuration_changes_and_retired_cleanup() {
    let options = supervisor::Options {
        config_interval: Duration::from_secs(1),
        ..Default::default()
    };
    let h = Harness::with_options(&["trojan"], options);
    let token = CancellationToken::new();
    let context = OperationContext::new(token.clone(), None);
    let supervisor = h.supervisor.clone();
    let running = tokio::spawn(async move { supervisor.run(&context).await });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(h.supervisor.snapshot().ready);
    let initial = h.supervisor.snapshot().generation;
    h.panel.config(config(&["trojan"], 2));
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_ne!(h.supervisor.snapshot().generation, initial);
    tokio::time::advance(Duration::from_secs(2)).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(h.supervisor.snapshot().retired, 0);
    token.cancel();
    running.await.unwrap().unwrap();
    h.supervisor.close(&ctx()).await.unwrap();
}

struct Sampler(AtomicUsize);
#[async_trait]
impl supervisor::StatusSampler for Sampler {
    async fn sample(&self, _: &OperationContext) -> Result<NodeStatus, runtime::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(NodeStatus {
            cpu_percent: 1.0,
            memory_percent: 2.0,
            disk_percent: 3.0,
            updated_at_millis: 1,
        })
    }
}
#[tokio::test(start_paused = true)]
async fn one_generation_status_sample_is_reused_for_all_protocols() {
    let sampler = Arc::new(Sampler(AtomicUsize::new(0)));
    let h = Harness::with_sampler(
        &["alpha", "beta"],
        supervisor::Options::default(),
        Some(sampler.clone()),
    );
    h.sync().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(sampler.0.load(Ordering::SeqCst), 1);
    assert_eq!(h.panel.status.load(Ordering::SeqCst), 2);
    h.panel.config(config(&["alpha", "beta"], 2));
    h.sync().await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert_eq!(sampler.0.load(Ordering::SeqCst), 2);
    assert_eq!(h.panel.status.load(Ordering::SeqCst), 4);
}
#[tokio::test(start_paused = true)]
async fn final_flush_drains_more_than_one_panel_limit_and_short_online_sessions() {
    let h = Harness::new(&["trojan"]);
    h.sync().await;
    let runtime = h.runtime("trojan");
    runtime
        .core()
        .reports()
        .record_traffic(Traffic {
            id: SubscriptionId::new(1).unwrap(),
            upload: (10 << 40) + 7,
            download: 8,
        })
        .unwrap();
    drop(
        runtime
            .core()
            .reports()
            .online(
                SubscriptionId::new(1).unwrap(),
                "127.0.0.1".parse().unwrap(),
            )
            .unwrap(),
    );
    h.supervisor.close(&ctx()).await.unwrap();
    assert_eq!(runtime.core().reports().snapshot().pending_bytes, 0);
    assert_eq!(h.panel.traffic.lock().unwrap().len(), 2);
    assert_eq!(h.panel.online.lock().unwrap().len(), 1);
    assert_eq!(runtime.core().reports().snapshot().online_ips, 0);
}
#[tokio::test(start_paused = true)]
async fn aborting_run_stops_admission_and_later_close_can_join_remaining_tasks() {
    let h = Harness::new(&["trojan"]);
    let supervisor = h.supervisor.clone();
    let run = tokio::spawn(async move {
        supervisor
            .run(&OperationContext::new(CancellationToken::new(), None))
            .await
    });
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    let runtime = h.runtime("trojan");
    run.abort();
    assert!(run.await.unwrap_err().is_cancelled());
    assert!(!h.supervisor.snapshot().ready);
    assert!(runtime.core().is_closed());
    h.supervisor.close(&ctx()).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn flow_limits_are_shared_by_upload_download_and_survive_generation_switch() {
    use crate::protocol::flow::{Options as PolicyOptions, Policies};
    let h = Harness::new(&["trojan"]);
    let mut limited = user(1, "first");
    limited.speed_limit_mbps = 1;
    h.panel.users(vec![limited]);
    h.sync().await;
    let policies = Policies::new(PolicyOptions::default()).unwrap();
    let core = h.runtime("trojan").core();
    let id = core.users().view().snapshot.authenticate("first").unwrap();
    let client: Arc<dyn ProtocolClient> = Arc::new(Client {
        panel: h.panel.clone(),
        name: name("trojan"),
    });
    let first = policies
        .admit(&core, &id, "127.0.0.1".parse().unwrap(), client.clone())
        .await
        .unwrap();
    h.panel.config(config(&["trojan"], 2));
    h.sync().await;
    let next = h.runtime("trojan").core();
    let second = policies
        .admit(&next, &id, "127.0.0.2".parse().unwrap(), client)
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let upload = async {
        let mut permit = first.quota(62500).await.unwrap();
        permit.commit(62500);
    };
    let download = async {
        let mut permit = second.quota(62500).await.unwrap();
        permit.commit(62500);
    };
    tokio::join!(upload, download);
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    let permit = first.quota(8192).await.unwrap();
    drop(permit);
    let started = tokio::time::Instant::now();
    let mut refunded = second.quota(8192).await.unwrap();
    refunded.commit(8192);
    assert_eq!(started.elapsed(), Duration::ZERO);
}
struct DeviceClient {
    calls: AtomicUsize,
    response: Mutex<panel::Result<DeviceClaim>>,
    block: Mutex<Option<Arc<Block>>>,
    name: ProtocolName,
}
#[async_trait]
impl ProtocolClient for DeviceClient {
    fn protocol(&self) -> &ProtocolName {
        &self.name
    }
    fn policy(&self) -> ProtocolPolicy {
        ProtocolPolicy {
            devices: DevicePolicy::AtomicPanelLease,
            report_active_and_unconfirmed: true,
            max_online_entries: 10000,
        }
    }
    async fn claim_device(
        &self,
        _: SubscriptionId,
        _: std::net::IpAddr,
    ) -> panel::Result<DeviceClaim> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let block = self.block.lock().unwrap().take();
        if let Some(block) = block {
            block.entered.notify_one();
            block.release.notified().await;
        }
        self.response.lock().unwrap().clone()
    }
    async fn get_users(&self, _: Option<&Validator>) -> panel::Result<Fetch<Vec<User>>> {
        panic!("unexpected device client users")
    }
    async fn get_alive(&self) -> panel::Result<BTreeMap<SubscriptionId, u64>> {
        panic!("unexpected device client alive")
    }
    async fn report_online(&self, _: &[OnlineUser]) -> panel::Result<()> {
        panic!("unexpected device client online")
    }
    async fn report_traffic(&self, _: &[Traffic]) -> panel::Result<()> {
        panic!("unexpected device client traffic")
    }
}
#[tokio::test(start_paused = true)]
async fn device_claims_coalesce_canonical_ips_across_protocol_scopes() {
    use crate::protocol::flow::{Options as PolicyOptions, Policies};
    let h = Harness::new(&["alpha", "beta"]);
    let mut limited = user(1, "first");
    limited.device_limit = 1;
    h.panel.users(vec![limited]);
    h.sync().await;
    let policies = Arc::new(Policies::new(PolicyOptions::default()).unwrap());
    let block = Arc::new(Block::default());
    let client = Arc::new(DeviceClient {
        calls: AtomicUsize::new(0),
        response: Mutex::new(Ok(DeviceClaim {
            allowed: true,
            ttl: Duration::from_secs(60),
        })),
        block: Mutex::new(Some(block.clone())),
        name: name("alpha"),
    });
    let owned = policies.clone();
    let port = client.clone();
    let core = h.runtime("alpha").core();
    let id = core.users().view().snapshot.authenticate("first").unwrap();
    let first = tokio::spawn(async move {
        owned
            .admit(&core, &id, "127.0.0.1".parse().unwrap(), port)
            .await
    });
    block.entered.notified().await;
    let owned = policies.clone();
    let port = client.clone();
    let core = h.runtime("beta").core();
    let id = core.users().view().snapshot.authenticate("first").unwrap();
    let second = tokio::spawn(async move {
        owned
            .admit(&core, &id, "::ffff:127.0.0.1".parse().unwrap(), port)
            .await
    });
    tokio::task::yield_now().await;
    block.release.notify_one();
    let first = first.await.unwrap().unwrap();
    let second = second.await.unwrap().unwrap();
    assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    assert!(first.check().is_ok());
    assert!(second.check().is_ok());
}
#[tokio::test(start_paused = true)]
async fn failed_device_renewal_stops_pending_io_at_the_confirmed_ttl() {
    use crate::protocol::flow::{Error as PolicyError, Options as PolicyOptions, Policies};
    let h = Harness::new(&["trojan"]);
    let mut limited = user(1, "first");
    limited.device_limit = 1;
    h.panel.users(vec![limited]);
    h.sync().await;
    let policies = Policies::new(PolicyOptions::default()).unwrap();
    let client = Arc::new(DeviceClient {
        calls: AtomicUsize::new(0),
        response: Mutex::new(Ok(DeviceClaim {
            allowed: true,
            ttl: Duration::from_secs(3),
        })),
        block: Mutex::new(None),
        name: name("trojan"),
    });
    let core = h.runtime("trojan").core();
    let id = core.users().view().snapshot.authenticate("first").unwrap();
    let session = policies
        .admit(&core, &id, "127.0.0.1".parse().unwrap(), client.clone())
        .await
        .unwrap();
    *client.response.lock().unwrap() = Err(panel::Error::http(Endpoint::Device, 503));
    let started = tokio::time::Instant::now();
    let maintenance = session.maintain();
    let blocked = session.run(std::future::pending::<()>());
    tokio::pin!(maintenance, blocked);
    tokio::select! {result=&mut blocked=>assert!(matches!(result,Err(PolicyError::DeviceExpired))),result=&mut maintenance=>assert!(result.is_err())};
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    assert!(session.check().is_err());
}
#[tokio::test(start_paused = true)]
async fn denied_device_never_registers_online_or_leaves_counter_slots() {
    use crate::protocol::flow::{Options as PolicyOptions, Policies};
    let h = Harness::new(&["trojan"]);
    let mut limited = user(1, "first");
    limited.device_limit = 1;
    h.panel.users(vec![limited]);
    h.sync().await;
    let core = h.runtime("trojan").core();
    let id = core.users().view().snapshot.authenticate("first").unwrap();
    let policies = Policies::new(PolicyOptions::default()).unwrap();
    let client = Arc::new(DeviceClient {
        calls: AtomicUsize::new(0),
        response: Mutex::new(Ok(DeviceClaim {
            allowed: false,
            ttl: Duration::from_secs(60),
        })),
        block: Mutex::new(None),
        name: name("trojan"),
    });
    assert!(
        policies
            .admit(&core, &id, "127.0.0.1".parse().unwrap(), client)
            .await
            .is_err()
    );
    assert_eq!(core.active_sessions(), 0);
    assert_eq!(core.reports().snapshot().traffic_users, 0);
    assert_eq!(core.reports().snapshot().online_ips, 0);
}

#[tokio::test(start_paused = true)]
async fn identity_hashes_include_store_scope_and_authentication_epoch() {
    let h = Harness::new(&["alpha", "beta"]);
    h.sync().await;
    let first = h
        .runtime("alpha")
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    let second = h
        .runtime("beta")
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("first")
        .unwrap();
    assert_ne!(first, second);
    let mut identities = std::collections::HashSet::from([first.clone(), second]);
    assert_eq!(identities.len(), 2);
    h.panel.users(vec![user(1, "changed")]);
    h.runtime("alpha")
        .controller
        .sync_users(&ctx())
        .await
        .unwrap();
    let next = h
        .runtime("alpha")
        .core()
        .users()
        .view()
        .snapshot
        .authenticate("changed")
        .unwrap();
    assert_ne!(first, next);
    identities.insert(next);
    assert_eq!(identities.len(), 3);
}

struct RegisteredProvider {
    state: Arc<FactoryState>,
    prepares: Mutex<Vec<(ProtocolName, [u8; 32])>>,
    publications: AtomicUsize,
    aborts: AtomicUsize,
    closes: AtomicUsize,
    fail_close: bool,
}
impl RegisteredProvider {
    fn new(fail_close: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Arc::new(FactoryState::default()),
            prepares: Mutex::new(Vec::new()),
            publications: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            fail_close,
        })
    }
}
#[async_trait]
impl crate::protocol::InboundFactory for RegisteredProvider {
    fn abort(&self) {
        self.aborts.fetch_add(1, Ordering::SeqCst);
    }
    async fn close(&self, _: &OperationContext) -> Result<(), runtime::Error> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        if self.fail_close {
            Err(runtime::Error::Preparation("injected close"))
        } else {
            Ok(())
        }
    }
    fn published(&self, _: &crate::egress::Handle) {
        self.publications.fetch_add(1, Ordering::SeqCst);
    }
    async fn prepare(
        &self,
        config: ProtocolConfig,
        shared: Arc<crate::egress::Handle>,
        core: Core,
        context: &OperationContext,
    ) -> Result<Arc<dyn ProtocolDriver>, runtime::Error> {
        assert_eq!(core.protocol(), &config.protocol);
        self.prepares
            .lock()
            .unwrap()
            .push((config.protocol.clone(), shared.migration_scope()));
        Factory(self.state.clone())
            .prepare_protocol(config, Arc::new(Shared(self.state.clone())), core, context)
            .await
    }
}
fn registry_egress() -> Arc<crate::egress::Registry> {
    crate::egress::Registry::new(
        crate::dns::Settings::default(),
        crate::route::Settings::default(),
        16,
    )
    .unwrap()
}
#[tokio::test]
async fn protocol_registry_dispatches_aliases_and_rolls_back_all_providers() {
    let alpha = RegisteredProvider::new(false);
    let zeta = RegisteredProvider::new(false);
    let mut builder = crate::protocol::Registry::builder(registry_egress(), Metrics::default());
    builder
        .register("Alpha", &["first"], alpha.clone())
        .unwrap();
    assert!(matches!(
        builder.register("new", &["FIRST"], zeta.clone()),
        Err(crate::registry::Error::Duplicate)
    ));
    builder.register("zeta", &[], zeta.clone()).unwrap();
    let registry = Arc::new(builder.build().unwrap());
    assert_eq!(registry.names().collect::<Vec<_>>(), ["alpha", "zeta"]);
    assert!(!registry.supports(&name("new")));
    let panel = PanelState::new(config(&["first", "zeta", "unknown"], 1));
    let budget = Budget::new(Limits::new(16 << 20, 1024).unwrap());
    let buffers = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
    let supervisor = Arc::new(
        Supervisor::new(
            Arc::new(ConnectionMock(panel.clone())),
            registry.clone(),
            buffers,
            supervisor::Options::default(),
            Metrics::default(),
            Arc::new(Fingerprints::default()),
            None,
        )
        .unwrap(),
    );
    supervisor.sync_config(&ctx()).await.unwrap();
    assert_eq!(supervisor.snapshot().protocols.len(), 2);
    assert!(supervisor.snapshot().ready);
    let ap = alpha.prepares.lock().unwrap()[0].clone();
    let zp = zeta.prepares.lock().unwrap()[0].clone();
    assert_eq!(ap.0, name("first"));
    assert_eq!(zp.0, name("zeta"));
    assert_eq!(ap.1, zp.1);
    assert_eq!(alpha.publications.load(Ordering::SeqCst), 1);
    let before = supervisor.snapshot().generation;
    let old = supervisor.runtime(&name("first")).unwrap();
    *zeta.state.listener_failure.lock().unwrap() = Some(name("zeta"));
    panel.config(config(&["first", "zeta"], 2));
    assert!(supervisor.sync_config(&ctx()).await.is_err());
    assert_eq!(supervisor.snapshot().generation, before);
    assert!(old.core().is_current());
    assert_eq!(alpha.publications.load(Ordering::SeqCst), 1);
    for provider in [&alpha, &zeta] {
        let drivers = provider.state.drivers.lock().unwrap();
        assert!(drivers[1].aborted.load(Ordering::SeqCst));
        assert!(!drivers[0].aborted.load(Ordering::SeqCst));
    }
    *zeta.state.listener_failure.lock().unwrap() = None;
    let mut invalid = config(&["first", "zeta"], 3);
    invalid.ip_strategy = "invalid-strategy".into();
    panel.config(invalid);
    assert!(supervisor.sync_config(&ctx()).await.is_err());
    assert_eq!(supervisor.snapshot().generation, before);
    // A cancelled candidate must preserve both old runtimes as well.
    panel.config(config(&["first", "zeta"], 4));
    let block = Arc::new(Block::default());
    *zeta.state.prepare_block.lock().unwrap() = Some(block.clone());
    let cancel = CancellationToken::new();
    let operation = OperationContext::new(cancel.clone(), None);
    let sync = supervisor.sync_config(&operation);
    tokio::pin!(sync);
    tokio::select! { result = &mut sync => panic!("unexpected: {result:?}"), _ = block.entered.notified() => {} }
    cancel.cancel();
    assert!(sync.await.is_err());
    assert_eq!(supervisor.snapshot().generation, before);
    assert!(old.core().is_current());
    panel.config(config(&["unknown"], 5));
    assert!(supervisor.sync_config(&ctx()).await.is_err());
    assert_eq!(supervisor.snapshot().generation, before);
    panel.config(config(&["first", "zeta"], 6));
    supervisor.sync_config(&ctx()).await.unwrap();
    assert_ne!(supervisor.snapshot().generation, before);
    supervisor.close(&ctx()).await.unwrap();
    assert!(alpha.aborts.load(Ordering::SeqCst) > 0);
    assert!(zeta.aborts.load(Ordering::SeqCst) > 0);
    assert!(alpha.closes.load(Ordering::SeqCst) > 0);
    assert!(zeta.closes.load(Ordering::SeqCst) > 0);
}
#[tokio::test]
async fn protocol_registry_closes_remaining_providers_and_shared_services_after_failure() {
    let alpha = RegisteredProvider::new(true);
    let zeta = RegisteredProvider::new(false);
    let egress = registry_egress();
    let mut builder = crate::protocol::Registry::builder(egress.clone(), Metrics::default());
    builder
        .register("alpha", &["alias"], alpha.clone())
        .unwrap();
    builder.register("zeta", &[], zeta.clone()).unwrap();
    let registry = builder.build().unwrap();
    assert!(registry.close(&ctx()).await.is_err());
    assert_eq!(alpha.closes.load(Ordering::SeqCst), 1);
    assert_eq!(zeta.closes.load(Ordering::SeqCst), 1);
    assert_eq!(alpha.aborts.load(Ordering::SeqCst), 1); // alias is not a second owner
    let budget = Budget::new(Limits::new(16 << 20, 1024).unwrap());
    let buffers = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
    assert!(matches!(
        egress
            .open(&config(&["alpha"], 0), buffers, Metrics::default(), &ctx())
            .await,
        Err(crate::egress::Error::Closed)
    ));
}

#[test]
fn transport_registry_validates_aliases_conflicts_and_tcp_security_before_binding() {
    use crate::transport::{Error, Registry, Tcp};
    let mut builder = Registry::builtin_builder();
    builder.register("other", &[], Arc::new(Tcp)).unwrap();
    let registry = builder.build();
    let mut config = protocol("vless", 12345, 0);
    assert!(registry.inbound(&config).is_ok());
    config.network = "tcp".into();
    config.transport = "raw".into();
    assert!(registry.inbound(&config).is_ok());
    config.transport = "other".into();
    assert!(matches!(
        registry.inbound(&config),
        Err(Error::Configuration("conflicting transport selections"))
    ));
    config.transport = "unregistered".into();
    assert!(matches!(registry.inbound(&config), Err(Error::Unsupported)));
    config.transport = "tcp".into();
    config.security = "tls".into();
    assert!(matches!(registry.inbound(&config), Err(Error::Unsupported)));
    config.security.clear();
    config.host = "unused-host".into();
    assert!(matches!(registry.inbound(&config), Err(Error::Unsupported)));
    config.host.clear();
    config.accept_proxy_protocol = true;
    assert!(matches!(registry.inbound(&config), Err(Error::Unsupported)));
    config.accept_proxy_protocol = false;
    config.cert_mode = "file".into();
    assert!(matches!(registry.inbound(&config), Err(Error::Unsupported)));
}
