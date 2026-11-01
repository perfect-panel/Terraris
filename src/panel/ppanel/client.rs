// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use prost::Message;
use reqwest::Method;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{convert, wire};
use crate::panel::{
    self,
    http::{Http, Request, Response},
    *,
};

const MAX_TRAFFIC: u64 = 10 << 40;

/// Update only after the corresponding certificate/runtime has been committed.
#[derive(Default)]
pub struct CertificateFingerprints(RwLock<BTreeMap<ProtocolName, CertificateFingerprint>>);

impl CertificateFingerprints {
    pub fn publish(
        &self,
        protocol: &str,
        fingerprint: Option<CertificateFingerprint>,
    ) -> Result<()> {
        let name = ProtocolName::new(protocol)?;
        let mut values = self.0.write().unwrap_or_else(|e| e.into_inner());
        if let Some(value) = fingerprint {
            values.insert(name, value);
        } else {
            values.remove(&name);
        }
        Ok(())
    }

    fn get(&self, protocol: &ProtocolName) -> Option<CertificateFingerprint> {
        self.0
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(protocol)
            .cloned()
    }
}

#[derive(Clone)]
pub struct Options {
    pub base_url: String,
    pub server_id: ServerId,
    pub secret_key: Secret,
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub max_request_bytes: usize,
    pub wire_mode: WireMode,
    pub fingerprints: Arc<CertificateFingerprints>,
}

impl Options {
    pub fn new(base_url: impl Into<String>, server_id: ServerId, secret_key: Secret) -> Self {
        Self {
            base_url: base_url.into(),
            server_id,
            secret_key,
            timeout: Duration::from_secs(30),
            max_response_bytes: 64 * 1024 * 1024,
            max_request_bytes: 8 * 1024 * 1024,
            wire_mode: WireMode::Auto,
            fingerprints: Arc::default(),
        }
    }

    /// Validates locally; does not build a client or contact the panel.
    pub fn validate(&self) -> Result<()> {
        panel::http::validate_url(&self.base_url)?;
        if self.secret_key.expose().is_empty() || self.secret_key.expose().len() > 4096 {
            return Err(Error::input(
                Endpoint::Connection,
                "secret key must contain 1..4096 bytes",
            ));
        }
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(300) {
            return Err(Error::input(
                Endpoint::Connection,
                "request timeout must be positive and at most 300 seconds",
            ));
        }
        if self.max_response_bytes == 0
            || self.max_response_bytes > 128 * 1024 * 1024
            || self.max_request_bytes == 0
            || self.max_request_bytes > 128 * 1024 * 1024
        {
            return Err(Error::input(
                Endpoint::Connection,
                "body limits must be between 1 byte and 128 MiB",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PPanelOptions")
            .field("server_id", &self.server_id)
            .field("wire_mode", &self.wire_mode)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

pub struct PPanelProvider;

impl Provider for PPanelProvider {
    type Options = Options;
    fn open(&self, options: Options) -> Result<Arc<dyn Connection>> {
        Ok(Arc::new(PPanelConnection::new(options)?))
    }
}

#[derive(Clone)]
pub struct PPanelConnection {
    shared: Arc<Shared>,
}

impl PPanelConnection {
    pub fn new(options: Options) -> Result<Self> {
        options.validate()?;
        let http = Http::new(
            panel::http::validate_url(&options.base_url)?,
            options.secret_key,
            options.timeout,
            options.max_response_bytes,
        )?;
        Ok(Self {
            shared: Arc::new(Shared {
                http,
                server_id: options.server_id,
                mode: options.wire_mode,
                json_negotiated: AtomicBool::new(options.wire_mode == WireMode::Json),
                owner: Arc::new(()),
                max_request_bytes: options.max_request_bytes,
                fingerprints: options.fingerprints,
            }),
        })
    }
}

impl Connection for PPanelConnection {
    fn server(&self) -> Arc<dyn ServerClient> {
        Arc::new(ServerPort(self.shared.clone()))
    }
    fn protocol(&self, name: &str) -> Result<Arc<dyn ProtocolClient>> {
        Ok(Arc::new(ProtocolPort {
            shared: self.shared.clone(),
            name: ProtocolName::new(name)?,
        }))
    }
    fn status(&self, name: &str) -> Result<Arc<dyn StatusClient>> {
        Ok(Arc::new(ProtocolPort {
            shared: self.shared.clone(),
            name: ProtocolName::new(name)?,
        }))
    }
}

struct Shared {
    http: Http,
    server_id: ServerId,
    mode: WireMode,
    json_negotiated: AtomicBool,
    owner: Arc<()>,
    max_request_bytes: usize,
    fingerprints: Arc<CertificateFingerprints>,
}

enum Pull {
    Payload {
        body: Vec<u8>,
        validator: Validator,
        same_body: bool,
    },
    Unchanged(Validator),
}

impl Shared {
    fn encoding(&self) -> Encoding {
        match self.mode {
            WireMode::Json => Encoding::Json,
            WireMode::Protobuf => Encoding::Protobuf,
            WireMode::Auto => {
                if self.json_negotiated.load(Ordering::Relaxed) {
                    Encoding::Json
                } else {
                    Encoding::Protobuf
                }
            }
        }
    }

    fn remember(&self, encoding: Encoding) {
        if self.mode == WireMode::Auto {
            self.json_negotiated
                .store(encoding == Encoding::Json, Ordering::Relaxed);
        }
    }

    fn response_encoding(&self, endpoint: Endpoint, response: &Response) -> Result<Encoding> {
        if response.status != 200 {
            return Err(Error::http(endpoint, response.status));
        }
        let encoding = response.encoding.ok_or_else(|| {
            Error::new(
                endpoint,
                ErrorKind::UnsupportedContentType,
                "unsupported response Content-Type",
            )
        })?;
        if matches!(
            (self.mode, encoding),
            (WireMode::Json, Encoding::Protobuf) | (WireMode::Protobuf, Encoding::Json)
        ) {
            return Err(Error::new(
                endpoint,
                ErrorKind::UnsupportedContentType,
                "response differs from forced wire format",
            ));
        }
        Ok(encoding)
    }

    async fn request(
        &self,
        endpoint: Endpoint,
        name: Option<&ProtocolName>,
        method: Method,
        encoding: Encoding,
        etag: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<Response> {
        if body
            .as_ref()
            .is_some_and(|b| b.len() > self.max_request_bytes)
        {
            return Err(Error::input(
                endpoint,
                "request exceeds configured body limit",
            ));
        }
        let path = if endpoint == Endpoint::Config {
            format!("/v2/server/{}", self.server_id.get())
        } else {
            endpoint.path().to_owned()
        };
        let query = name
            .map(|n| {
                vec![
                    ("server_id", self.server_id.get().to_string()),
                    ("protocol", n.as_str().to_owned()),
                ]
            })
            .unwrap_or_default();
        let fingerprint = name.and_then(|n| self.fingerprints.get(n));
        self.http
            .send(Request {
                endpoint,
                path: &path,
                method,
                query: &query,
                encoding,
                etag,
                body,
                fingerprint: fingerprint.as_ref().map(CertificateFingerprint::as_str),
            })
            .await
    }

    async fn pull(
        &self,
        endpoint: Endpoint,
        name: Option<&ProtocolName>,
        previous: Option<&Validator>,
    ) -> Result<Pull> {
        if let Some(v) = previous
            && (!Arc::ptr_eq(&v.owner, &self.owner)
                || v.endpoint != endpoint
                || v.protocol.as_ref() != name)
        {
            return Err(Error::new(
                endpoint,
                ErrorKind::ValidatorScope,
                "validator belongs to another resource or connection",
            ));
        }
        let mut encoding = self.encoding();
        let mut retried_not_modified = false;
        let mut tried_json = false;
        loop {
            let etag = previous
                .filter(|v| v.encoding == encoding && !retried_not_modified)
                .and_then(|v| v.etag.as_deref());
            let response = self
                .request(endpoint, name, Method::GET, encoding, etag, None)
                .await?;
            if matches!(response.status, 406 | 415)
                && self.mode == WireMode::Auto
                && encoding == Encoding::Protobuf
                && !tried_json
            {
                encoding = Encoding::Json;
                tried_json = true;
                continue;
            }
            if response.status == 304 {
                if etag.is_some()
                    && response.encoding.is_none_or(|e| e == encoding)
                    && let Some(previous) = previous
                {
                    let mut validator = previous.clone();
                    if response.etag.is_some() {
                        validator.etag = response.etag;
                    }
                    self.remember(encoding);
                    return Ok(Pull::Unchanged(validator));
                }
                if !retried_not_modified {
                    retried_not_modified = true;
                    continue;
                }
                return Err(Error::new(
                    endpoint,
                    ErrorKind::UnexpectedNotModified,
                    "304 without a matching cached representation",
                ));
            }
            let actual_encoding = self.response_encoding(endpoint, &response)?;
            let digest: [u8; 32] = Sha256::digest(&response.body).into();
            let same_body =
                previous.is_some_and(|v| v.encoding == actual_encoding && v.digest == digest);
            let validator = Validator {
                owner: self.owner.clone(),
                endpoint,
                protocol: name.cloned(),
                encoding: actual_encoding,
                etag: response.etag,
                digest,
            };
            return Ok(Pull::Payload {
                body: response.body,
                validator,
                same_body,
            });
        }
    }

    async fn post(
        &self,
        endpoint: Endpoint,
        name: &ProtocolName,
        encoding: Encoding,
        body: Vec<u8>,
    ) -> Result<(Vec<u8>, Encoding)> {
        // Never retry or change encoding for a POST: acceptance may be ambiguous.
        let response = self
            .request(
                endpoint,
                Some(name),
                Method::POST,
                encoding,
                None,
                Some(body),
            )
            .await?;
        let encoding = self.response_encoding(endpoint, &response)?;
        Ok((response.body, encoding))
    }
}

struct ServerPort(Arc<Shared>);

#[async_trait]
impl ServerClient for ServerPort {
    async fn get_config(&self, validator: Option<&Validator>) -> Result<Fetch<ServerConfig>> {
        match self.0.pull(Endpoint::Config, None, validator).await? {
            Pull::Unchanged(validator) => Ok(Fetch::Unchanged { validator }),
            Pull::Payload {
                body,
                validator,
                same_body,
            } => {
                let value = convert::config(&body, validator.encoding)?;
                self.0.remember(validator.encoding);
                if same_body {
                    Ok(Fetch::Unchanged { validator })
                } else {
                    Ok(Fetch::Changed { value, validator })
                }
            }
        }
    }
}

struct ProtocolPort {
    shared: Arc<Shared>,
    name: ProtocolName,
}

#[async_trait]
impl ProtocolClient for ProtocolPort {
    fn protocol(&self) -> &ProtocolName {
        &self.name
    }

    fn policy(&self) -> ProtocolPolicy {
        ProtocolPolicy {
            devices: DevicePolicy::AtomicPanelLease,
            report_active_and_unconfirmed: true,
            max_online_entries: 10_000,
        }
    }

    async fn get_users(&self, validator: Option<&Validator>) -> Result<Fetch<Vec<User>>> {
        match self
            .shared
            .pull(Endpoint::Users, Some(&self.name), validator)
            .await?
        {
            Pull::Unchanged(validator) => Ok(Fetch::Unchanged { validator }),
            Pull::Payload {
                body,
                validator,
                same_body,
            } => {
                let value = convert::users(&body, validator.encoding)?;
                self.shared.remember(validator.encoding);
                if same_body {
                    Ok(Fetch::Unchanged { validator })
                } else {
                    Ok(Fetch::Changed { value, validator })
                }
            }
        }
    }

    async fn get_alive(&self) -> Result<BTreeMap<SubscriptionId, u64>> {
        let response = self
            .shared
            .request(
                Endpoint::Alive,
                Some(&self.name),
                Method::GET,
                self.shared.encoding(),
                None,
                None,
            )
            .await?;
        let encoding = self.shared.response_encoding(Endpoint::Alive, &response)?;
        convert::alive(&response.body, encoding)
    }

    async fn claim_device(&self, user: SubscriptionId, source: IpAddr) -> Result<DeviceClaim> {
        if !valid_source(source) {
            return Err(Error::input(Endpoint::Device, "invalid source address"));
        }
        let source = canonical_ip(source).to_string();
        let encoding = self.shared.encoding();
        let body = match encoding {
            Encoding::Json => encode_json(
                Endpoint::Device,
                &json!({ "uid": user.get(), "ip": source }),
            )?,
            Encoding::Protobuf => wire::ClaimServerDeviceRequest {
                user_id: user.get(),
                ip: source,
            }
            .encode_to_vec(),
        };
        let (body, encoding) = self
            .shared
            .post(Endpoint::Device, &self.name, encoding, body)
            .await?;
        convert::claim(&body, encoding)
    }

    async fn report_online(&self, users: &[OnlineUser]) -> Result<()> {
        if users.is_empty() {
            return Ok(());
        }
        if users.len() > 10_000 {
            return Err(Error::input(
                Endpoint::Online,
                "online batch exceeds 10000 entries",
            ));
        }
        if users.iter().any(|u| !valid_source(u.ip)) {
            return Err(Error::input(Endpoint::Online, "invalid source address"));
        }
        let encoding = self.shared.encoding();
        let body = match encoding {
            Encoding::Json => encode_json(
                Endpoint::Online,
                &json!({ "users": users.iter().map(|u| json!({ "uid": u.id.get(), "ip": canonical_ip(u.ip).to_string() })).collect::<Vec<_>>() }),
            )?,
            Encoding::Protobuf => wire::PushOnlineUsersRequest {
                users: users
                    .iter()
                    .map(|u| wire::OnlineUser {
                        user_id: u.id.get(),
                        ip: canonical_ip(u.ip).to_string(),
                    })
                    .collect(),
            }
            .encode_to_vec(),
        };
        let (body, encoding) = self
            .shared
            .post(Endpoint::Online, &self.name, encoding, body)
            .await?;
        convert::report(Endpoint::Online, &body, encoding)
    }

    async fn report_traffic(&self, traffic: &[Traffic]) -> Result<()> {
        if traffic.is_empty() {
            return Ok(());
        }
        let mut totals = BTreeMap::<SubscriptionId, u64>::new();
        for item in traffic {
            let total = totals.entry(item.id).or_default();
            *total = item
                .upload
                .checked_add(item.download)
                .and_then(|n| total.checked_add(n))
                .filter(|n| *n <= MAX_TRAFFIC)
                .ok_or_else(|| {
                    Error::input(Endpoint::Traffic, "traffic per subscription exceeds 10 TiB")
                })?;
        }
        let encoding = self.shared.encoding();
        let body = match encoding {
            Encoding::Json => encode_json(
                Endpoint::Traffic,
                &json!({ "traffic": traffic.iter().map(|t| json!({ "uid": t.id.get(), "upload": t.upload, "download": t.download })).collect::<Vec<_>>() }),
            )?,
            Encoding::Protobuf => wire::PushUserTrafficRequest {
                traffic: traffic
                    .iter()
                    .map(|t| wire::UserTraffic {
                        user_id: t.id.get(),
                        upload: t.upload as i64,
                        download: t.download as i64,
                    })
                    .collect(),
            }
            .encode_to_vec(),
        };
        let (body, encoding) = self
            .shared
            .post(Endpoint::Traffic, &self.name, encoding, body)
            .await?;
        convert::report(Endpoint::Traffic, &body, encoding)
    }
}

#[async_trait]
impl StatusClient for ProtocolPort {
    async fn report_status(&self, status: NodeStatus) -> Result<()> {
        if [
            status.cpu_percent,
            status.memory_percent,
            status.disk_percent,
        ]
        .iter()
        .any(|v| !v.is_finite() || !(0.0..=100.0).contains(v))
            || status.updated_at_millis <= 0
        {
            return Err(Error::input(
                Endpoint::Status,
                "status requires finite percentages and a positive millisecond timestamp",
            ));
        }
        let encoding = self.shared.encoding();
        let body = match encoding {
            Encoding::Json => encode_json(
                Endpoint::Status,
                &json!({ "cpu": status.cpu_percent, "mem": status.memory_percent, "disk": status.disk_percent, "updated_at": status.updated_at_millis }),
            )?,
            Encoding::Protobuf => wire::PushServerStatusRequest {
                cpu: status.cpu_percent,
                mem: status.memory_percent,
                disk: status.disk_percent,
                updated_at: status.updated_at_millis,
            }
            .encode_to_vec(),
        };
        let (body, encoding) = self
            .shared
            .post(Endpoint::Status, &self.name, encoding, body)
            .await?;
        convert::report(Endpoint::Status, &body, encoding)
    }
}

fn encode_json(endpoint: Endpoint, value: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| Error::input(endpoint, "request cannot be encoded"))
}

impl crate::supervisor::FingerprintSink for CertificateFingerprints {
    fn replace(&self, values: BTreeMap<ProtocolName, CertificateFingerprint>) {
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = values;
    }
}
