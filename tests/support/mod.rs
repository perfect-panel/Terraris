// SPDX-License-Identifier: GPL-3.0-only

#![allow(dead_code)]

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request, Response},
    routing::any,
};
use prost::Message;
use serde_json::{Value, json};
use terraris::panel::{Secret, ServerId, ppanel::Options};
use tokio::{net::TcpListener, task::JoinHandle};

pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/ppanel.server.v1.rs"));
}

pub const SECRET: &str = "fixture-secret +/&?=測試";
pub const USER_ID: i64 = 9_007_199_254_740_993;

#[derive(Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

pub struct Reply {
    pub status: u16,
    pub content_type: Option<&'static str>,
    pub etag: Option<&'static str>,
    pub location: Option<String>,
    pub body: Vec<u8>,
    pub delay: Duration,
}

impl Reply {
    pub fn json(value: Value) -> Self {
        Self::raw(
            200,
            Some("application/json; charset=utf-8"),
            serde_json::to_vec(&value).unwrap(),
        )
    }
    pub fn proto(message: impl Message) -> Self {
        Self::raw(200, Some("application/protobuf"), message.encode_to_vec())
    }
    pub fn raw(status: u16, content_type: Option<&'static str>, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type,
            etag: None,
            location: None,
            body: body.into(),
            delay: Duration::ZERO,
        }
    }
    pub fn etag(mut self, value: &'static str) -> Self {
        self.etag = Some(value);
        self
    }
}

#[derive(Clone)]
struct ServerState {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

pub struct MockPanel {
    pub url: String,
    state: ServerState,
    task: JoinHandle<()>,
}

impl MockPanel {
    pub async fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = ServerState {
            replies: Arc::new(Mutex::new(replies.into())),
            requests: Arc::default(),
        };
        let app = Router::new()
            .fallback(any(handle))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, state, task }
    }
    pub fn options(&self) -> Options {
        Options::new(
            format!("{}/panel/api", self.url),
            ServerId::new(7).unwrap(),
            Secret::new(SECRET),
        )
    }
    pub fn requests(&self) -> Vec<Recorded> {
        self.state.requests.lock().unwrap().clone()
    }
    pub fn remaining(&self) -> usize {
        self.state.replies.lock().unwrap().len()
    }
}

impl Drop for MockPanel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(State(state): State<ServerState>, request: Request<Body>) -> Response<Body> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 16 * 1024 * 1024).await.unwrap().to_vec();
    state.requests.lock().unwrap().push(Recorded {
        method: parts.method.to_string(),
        path: parts.uri.path().to_owned(),
        query: url::form_urlencoded::parse(parts.uri.query().unwrap_or("").as_bytes())
            .into_owned()
            .collect(),
        headers: parts.headers,
        body,
    });
    let reply = state
        .replies
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or_else(|| Reply::raw(500, Some("text/plain"), b"unexpected request".to_vec()));
    if !reply.delay.is_zero() {
        tokio::time::sleep(reply.delay).await;
    }
    let mut response = Response::builder().status(reply.status);
    if let Some(v) = reply.content_type {
        response = response.header("content-type", v);
    }
    if let Some(v) = reply.etag {
        response = response.header("etag", v);
    }
    if let Some(v) = reply.location {
        response = response.header("location", v);
    }
    response.body(Body::from(reply.body)).unwrap()
}

pub fn config_json() -> Value {
    json!({ "code": 200, "msg": "success", "data": {
        "traffic_report_threshold": 1024, "pull_interval": 30, "push_interval": 60,
        "ip_strategy": "prefer_ipv4", "dns": [{"proto":"udp", "address":"127.0.0.1:53", "server_name":"", "domains":null}],
        "block": ["full:blocked.example.com"],
        "outbound": [{"name":"relay", "protocol":"shadowsocks", "address":"relay.example.com", "port":443,
            "password":"outbound-secret", "uuid":"outbound-user", "cipher":"aes-256-gcm", "plugin":"v2ray-plugin",
            "plugin_opts":"tls;host=relay.example.com", "rules":["suffix:example.com"], "uot":true, "uot_version":2,
            "encryption_password":"encryption-secret", "stream_settings":"{\"transport\":\"tcp\"}"}],
        "protocols":[{"type":"shadowsocks", "enable":true, "port":8388, "cipher":"2022-blake3-aes-128-gcm",
            "server_key":"server-secret", "plugin":"v2ray-plugin", "plugin_opts":{"mode":"websocket", "tls":true, "port":443},
            "network":"tcp,udp", "ratio":1.5, "accept_proxy_protocol":true, "uot":true, "uot_version":2,
            "cert_mode":"dns", "cert_dns_provider":"fixture", "cert_dns_env":"API_TOKEN=secret"}],
        "total":1
    }})
}

pub fn config_proto() -> wire::QueryServerProtocolConfigResponse {
    use prost_types::{Struct, Value as ProtoValue, value::Kind};
    let option = |kind| ProtoValue { kind: Some(kind) };
    wire::QueryServerProtocolConfigResponse {
        code: 200,
        message: "success".into(),
        data: Some(wire::QueryServerProtocolConfigData {
            traffic_report_threshold: 1024,
            pull_interval: 30,
            push_interval: 60,
            ip_strategy: "prefer_ipv4".into(),
            dns: vec![wire::DnsResolver {
                proto: "udp".into(),
                address: "127.0.0.1:53".into(),
                server_name: String::new(),
                domains: vec![],
            }],
            block: vec!["full:blocked.example.com".into()],
            outbound: vec![wire::Outbound {
                name: "relay".into(),
                protocol: "shadowsocks".into(),
                address: "relay.example.com".into(),
                port: 443,
                password: "outbound-secret".into(),
                uuid: "outbound-user".into(),
                cipher: "aes-256-gcm".into(),
                plugin: "v2ray-plugin".into(),
                plugin_options: Some(option(Kind::StringValue(
                    "tls;host=relay.example.com".into(),
                ))),
                rules: vec!["suffix:example.com".into()],
                uot: true,
                uot_version: 2,
                encryption_password: "encryption-secret".into(),
                stream_settings: "{\"transport\":\"tcp\"}".into(),
                ..Default::default()
            }],
            protocols: vec![wire::ServerProtocol {
                r#type: "shadowsocks".into(),
                enable: true,
                port: 8388,
                cipher: "2022-blake3-aes-128-gcm".into(),
                server_key: "server-secret".into(),
                plugin: "v2ray-plugin".into(),
                plugin_options: Some(option(Kind::StructValue(Struct {
                    fields: BTreeMap::from([
                        ("mode".into(), option(Kind::StringValue("websocket".into()))),
                        ("tls".into(), option(Kind::BoolValue(true))),
                        ("port".into(), option(Kind::NumberValue(443.0))),
                    ]),
                }))),
                network: "tcp,udp".into(),
                ratio: 1.5,
                accept_proxy_protocol: true,
                uot: true,
                uot_version: 2,
                cert_mode: "dns".into(),
                cert_dns_provider: "fixture".into(),
                cert_dns_env: "API_TOKEN=secret".into(),
                ..Default::default()
            }],
            total: 1,
        }),
    }
}

pub fn users_json() -> Value {
    json!({"users":[{"id":USER_ID, "uuid":"fixture-user-credential", "speed_limit":100, "device_limit":2}]})
}

pub fn users_proto() -> wire::GetServerUserListResponse {
    wire::GetServerUserListResponse {
        code: 200,
        message: "success".into(),
        data: Some(wire::ServerUserListData {
            users: vec![wire::ServerUser {
                id: USER_ID,
                uuid: "fixture-user-credential".into(),
                speed_limit: 100,
                device_limit: 2,
            }],
        }),
    }
}
