// SPDX-License-Identifier: GPL-3.0-only

mod support;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use prost::Message;
use serde_json::json;
use support::*;
use terraris::{
    app,
    panel::{
        ppanel::{CertificateFingerprints, PPanelConnection},
        *,
    },
};

fn changed<T>(result: Fetch<T>) -> (T, Validator) {
    match result {
        Fetch::Changed { value, validator } => (value, validator),
        Fetch::Unchanged { .. } => panic!("expected changed data"),
    }
}

#[tokio::test]
async fn json_and_protobuf_preserve_config_and_subscription_semantics() {
    let json_panel =
        MockPanel::start(vec![Reply::json(config_json()), Reply::json(users_json())]).await;
    let proto_panel = MockPanel::start(vec![
        Reply::proto(config_proto()),
        Reply::proto(users_proto()),
    ])
    .await;
    let json_conn = PPanelConnection::new(json_panel.options()).unwrap();
    let proto_conn = PPanelConnection::new(proto_panel.options()).unwrap();
    let (json_config, _) = changed(json_conn.server().get_config(None).await.unwrap());
    let (proto_config, _) = changed(proto_conn.server().get_config(None).await.unwrap());
    assert_eq!(json_config, proto_config);
    assert_eq!(
        json_config.protocols[0].server_key.expose(),
        "server-secret"
    );
    assert_eq!(
        json_config.protocols[0].cert_dns_env.expose(),
        "API_TOKEN=secret"
    );
    assert_eq!(json_config.protocols[0].uot_version, 2);
    assert!(json_config.protocols[0].accept_proxy_protocol);
    assert_eq!(
        json_config.outbounds[0].password.expose(),
        "outbound-secret"
    );
    assert_eq!(json_config.dns[0].domains.len(), 0);
    assert_eq!(
        json_config.protocols[0].plugin_options,
        ConfigValue::Object(BTreeMap::from([
            ("mode".into(), ConfigValue::String("websocket".into())),
            ("tls".into(), ConfigValue::Bool(true)),
            ("port".into(), ConfigValue::Integer(443))
        ]))
    );
    let (json_users, _) = changed(
        json_conn
            .protocol("shadowsocks")
            .unwrap()
            .get_users(None)
            .await
            .unwrap(),
    );
    let (proto_users, _) = changed(
        proto_conn
            .protocol("shadowsocks")
            .unwrap()
            .get_users(None)
            .await
            .unwrap(),
    );
    assert_eq!(json_users, proto_users);
    assert_eq!(json_users[0].id.get(), USER_ID);
    assert_eq!(json_users[0].speed_limit_mbps, 100);
    assert_eq!(
        json_panel.requests()[1].headers["accept"],
        "application/json"
    );
    assert_eq!(
        proto_panel.requests()[1].headers["accept"],
        "application/protobuf"
    );
    let debug = format!("{json_config:?} {json_users:?} {:?}", json_config.protocols);
    for secret in [
        "server-secret",
        "outbound-secret",
        "API_TOKEN=secret",
        "fixture-user-credential",
    ] {
        assert!(!debug.contains(secret));
    }
}

#[tokio::test]
async fn json_reporting_matches_backend_paths_query_names_units_and_scoped_pins() {
    let panel = MockPanel::start(vec![
        Reply::json(config_json()),
        Reply::json(json!({"alive":{USER_ID.to_string():2}})),
        Reply::json(json!({"allowed":true,"ttl_seconds":300})),
        Reply::json(json!({"code":200,"msg":"success"})),
        Reply::json(json!({"code":200})),
        Reply::json(json!({"code":200})),
        Reply::json(json!({"code":200})),
    ])
    .await;
    let fingerprints = Arc::new(CertificateFingerprints::default());
    let mut options = panel.options();
    options.fingerprints = fingerprints.clone();
    let conn = PPanelConnection::new(options).unwrap();
    conn.server().get_config(None).await.unwrap();
    let protocol = conn.protocol(" Hysteria2 ").unwrap();
    assert_eq!(protocol.protocol().as_str(), "hysteria");
    assert_eq!(protocol.policy().devices, DevicePolicy::AtomicPanelLease);
    let id = SubscriptionId::new(USER_ID).unwrap();
    assert_eq!(protocol.get_alive().await.unwrap()[&id], 2);
    let ip = "::ffff:127.0.0.1".parse().unwrap();
    assert_eq!(
        protocol.claim_device(id, ip).await.unwrap(),
        DeviceClaim {
            allowed: true,
            ttl: Duration::from_secs(300)
        }
    );
    protocol
        .report_online(&[OnlineUser { id, ip }])
        .await
        .unwrap();
    protocol
        .report_traffic(&[Traffic {
            id,
            upload: 123,
            download: 456,
        }])
        .await
        .unwrap();
    let status = conn.status("hysteria2").unwrap();
    fingerprints
        .publish(
            "hysteria",
            Some(CertificateFingerprint::new(&"A".repeat(64)).unwrap()),
        )
        .unwrap();
    let sample = NodeStatus {
        cpu_percent: 12.5,
        memory_percent: 25.0,
        disk_percent: 50.0,
        updated_at_millis: 1_800_000_000_123,
    };
    status.report_status(sample).await.unwrap();
    conn.status("shadowsocks")
        .unwrap()
        .report_status(sample)
        .await
        .unwrap();
    let requests = panel.requests();
    assert_eq!(
        requests.iter().map(|r| r.path.as_str()).collect::<Vec<_>>(),
        [
            "/panel/api/v2/server/7",
            "/panel/api/v1/server/alivelist",
            "/panel/api/v1/server/device",
            "/panel/api/v1/server/online",
            "/panel/api/v1/server/push",
            "/panel/api/v1/server/status",
            "/panel/api/v1/server/status"
        ]
    );
    for (index, request) in requests.iter().enumerate() {
        assert_eq!(request.query["secret_key"], SECRET);
        if index == 0 {
            assert!(!request.query.contains_key("protocol"));
        } else {
            assert_eq!(request.query["server_id"], "7");
        }
    }
    assert_eq!(requests[2].query["protocol"], "hysteria");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[2].body).unwrap(),
        json!({"uid":USER_ID,"ip":"127.0.0.1"})
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[3].body).unwrap(),
        json!({"users":[{"uid":USER_ID,"ip":"127.0.0.1"}]})
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[4].body).unwrap(),
        json!({"traffic":[{"uid":USER_ID,"upload":123,"download":456}]})
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[5].body).unwrap()["updated_at"],
        sample.updated_at_millis
    );
    assert_eq!(
        requests[5].headers["x-node-certificate-sha256"],
        "a".repeat(64)
    );
    assert!(
        !requests[6]
            .headers
            .contains_key("x-node-certificate-sha256")
    );
    assert!(!requests[1].headers.contains_key("if-none-match"));
    assert_eq!(panel.remaining(), 0);
}

#[tokio::test]
async fn protobuf_reporting_uses_binary_bodies_and_ack_envelopes() {
    let ack = || {
        Reply::proto(wire::Result {
            code: 200,
            message: "success".into(),
        })
    };
    let panel = MockPanel::start(vec![
        Reply::proto(config_proto()),
        Reply::proto(wire::GetServerAliveListResponse {
            code: 200,
            message: String::new(),
            data: Some(wire::ServerAliveListData {
                alive: BTreeMap::from([(USER_ID, 2)]),
            }),
        }),
        Reply::proto(wire::ClaimServerDeviceResponse {
            code: 200,
            message: String::new(),
            data: Some(wire::ServerDeviceClaimData {
                allowed: false,
                ttl_seconds: 300,
            }),
        }),
        ack(),
        ack(),
        ack(),
    ])
    .await;
    let conn = PPanelConnection::new(panel.options()).unwrap();
    conn.server().get_config(None).await.unwrap();
    let p = conn.protocol("vless").unwrap();
    let id = SubscriptionId::new(USER_ID).unwrap();
    assert_eq!(p.get_alive().await.unwrap()[&id], 2);
    assert!(
        !p.claim_device(id, "127.0.0.1".parse().unwrap())
            .await
            .unwrap()
            .allowed
    );
    p.report_online(&[OnlineUser {
        id,
        ip: "127.0.0.1".parse().unwrap(),
    }])
    .await
    .unwrap();
    p.report_traffic(&[Traffic {
        id,
        upload: 19,
        download: 23,
    }])
    .await
    .unwrap();
    conn.status("vless")
        .unwrap()
        .report_status(NodeStatus {
            cpu_percent: 1.0,
            memory_percent: 2.0,
            disk_percent: 3.0,
            updated_at_millis: 1_800_000_000_000,
        })
        .await
        .unwrap();
    let requests = panel.requests();
    for r in &requests[2..] {
        assert_eq!(r.headers["content-type"], "application/protobuf");
    }
    let claim = wire::ClaimServerDeviceRequest::decode(requests[2].body.as_slice()).unwrap();
    assert_eq!(claim.user_id, USER_ID);
    assert_eq!(claim.ip, "127.0.0.1");
    let online = wire::PushOnlineUsersRequest::decode(requests[3].body.as_slice()).unwrap();
    assert_eq!(online.users[0].user_id, USER_ID);
    let traffic = wire::PushUserTrafficRequest::decode(requests[4].body.as_slice()).unwrap();
    assert_eq!(
        (
            traffic.traffic[0].user_id,
            traffic.traffic[0].upload,
            traffic.traffic[0].download
        ),
        (USER_ID, 19, 23)
    );
    let status = wire::PushServerStatusRequest::decode(requests[5].body.as_slice()).unwrap();
    assert_eq!(status.updated_at, 1_800_000_000_000);
}

#[tokio::test]
async fn validators_are_caller_owned_scoped_and_advance_only_on_valid_responses() {
    let panel = MockPanel::start(vec![
        Reply::json(users_json()).etag("\"u1\""),
        Reply::raw(304, None, vec![]),
        Reply::json(json!({"users":[]})).etag("\"u2\""),
        Reply::json(json!({"users":[{"id":0,"uuid":"bad","speed_limit":0,"device_limit":0}]}))
            .etag("\"bad\""),
        Reply::raw(304, None, vec![]),
    ])
    .await;
    let conn = PPanelConnection::new(panel.options()).unwrap();
    let p = conn.protocol("vless").unwrap();
    let (_, v1) = changed(p.get_users(None).await.unwrap());
    assert!(matches!(
        p.get_users(Some(&v1)).await.unwrap(),
        Fetch::Unchanged { .. }
    ));
    let (empty, v2) = changed(p.get_users(Some(&v1)).await.unwrap());
    assert!(empty.is_empty());
    assert_eq!(
        p.get_users(Some(&v2)).await.unwrap_err().kind,
        ErrorKind::Schema
    );
    assert!(matches!(
        p.get_users(Some(&v2)).await.unwrap(),
        Fetch::Unchanged { .. }
    ));
    assert_eq!(
        conn.protocol("trojan")
            .unwrap()
            .get_users(Some(&v2))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::ValidatorScope
    );
    assert_eq!(
        conn.server().get_config(Some(&v2)).await.unwrap_err().kind,
        ErrorKind::ValidatorScope
    );
    let other = PPanelConnection::new(panel.options()).unwrap();
    assert_eq!(
        other
            .protocol("vless")
            .unwrap()
            .get_users(Some(&v2))
            .await
            .unwrap_err()
            .kind,
        ErrorKind::ValidatorScope
    );
    let reqs = panel.requests();
    assert_eq!(reqs.len(), 5);
    assert_eq!(reqs[1].headers["if-none-match"], "\"u1\"");
    assert_eq!(reqs[4].headers["if-none-match"], "\"u2\"");
}

#[tokio::test]
async fn unchanged_body_can_clear_an_old_etag_without_replacing_users() {
    let panel = MockPanel::start(vec![
        Reply::json(users_json()).etag("\"first\""),
        Reply::json(users_json()),
        Reply::json(users_json()),
    ])
    .await;
    let p = PPanelConnection::new(panel.options())
        .unwrap()
        .protocol("vless")
        .unwrap();
    let (_, v1) = changed(p.get_users(None).await.unwrap());
    let Fetch::Unchanged { validator: v2 } = p.get_users(Some(&v1)).await.unwrap() else {
        panic!("body unchanged");
    };
    assert!(!v2.has_etag());
    p.get_users(Some(&v2)).await.unwrap();
    assert!(!panel.requests()[2].headers.contains_key("if-none-match"));
}

#[tokio::test]
async fn bootstrap_304_is_retried_without_a_validator_and_then_rejected_if_repeated() {
    let panel = MockPanel::start(vec![
        Reply::raw(304, None, vec![]),
        Reply::json(users_json()),
        Reply::raw(304, None, vec![]),
        Reply::raw(304, None, vec![]),
    ])
    .await;
    let p = PPanelConnection::new(panel.options())
        .unwrap()
        .protocol("vless")
        .unwrap();
    assert_eq!(changed(p.get_users(None).await.unwrap()).0.len(), 1);
    assert_eq!(
        p.get_users(None).await.unwrap_err().kind,
        ErrorKind::UnexpectedNotModified
    );
    assert_eq!(panel.requests().len(), 4);
}

#[tokio::test]
async fn format_change_does_not_send_an_etag_from_another_representation() {
    let panel = MockPanel::start(vec![
        Reply::proto(users_proto()).etag("\"binary\""),
        Reply::json(config_json()),
        Reply::json(users_json()).etag("\"json\""),
    ])
    .await;
    let conn = PPanelConnection::new(panel.options()).unwrap();
    let p = conn.protocol("vless").unwrap();
    let (_, validator) = changed(p.get_users(None).await.unwrap());
    conn.server().get_config(None).await.unwrap();
    let (_, next) = changed(p.get_users(Some(&validator)).await.unwrap());
    assert_eq!(next.encoding(), Encoding::Json);
    assert!(!panel.requests()[2].headers.contains_key("if-none-match"));
}

#[tokio::test]
async fn empty_config_and_empty_users_have_explicit_success_semantics() {
    for proto in [false, true] {
        let config = if proto {
            let mut c = config_proto();
            let d = c.data.as_mut().unwrap();
            d.protocols.clear();
            d.total = 0;
            Reply::proto(c)
        } else {
            let mut c = config_json();
            c["data"]["protocols"] = json!(null);
            c["data"]["total"] = json!(0);
            Reply::json(c)
        };
        let users = if proto {
            Reply::proto(wire::GetServerUserListResponse {
                code: 200,
                message: String::new(),
                data: Some(wire::ServerUserListData { users: vec![] }),
            })
        } else {
            Reply::json(json!({"users":[]}))
        };
        let panel = MockPanel::start(vec![config, users]).await;
        let conn = PPanelConnection::new(panel.options()).unwrap();
        assert!(
            changed(conn.server().get_config(None).await.unwrap())
                .0
                .protocols
                .is_empty()
        );
        assert!(
            changed(
                conn.protocol("vless")
                    .unwrap()
                    .get_users(None)
                    .await
                    .unwrap()
            )
            .0
            .is_empty()
        );
    }
}

#[tokio::test]
async fn invalid_or_duplicate_users_never_become_an_empty_valid_snapshot() {
    let valid = json!({"id":1,"uuid":"credential","speed_limit":0,"device_limit":0});
    for body in [
        json!({}),
        json!({"users":null}),
        json!({"users":[valid.clone(),valid.clone()]}),
        json!({"users":[valid.clone(),{"id":2,"uuid":"credential","speed_limit":0,"device_limit":0}]}),
        json!({"users":[{"id":1,"uuid":"credential","speed_limit":-1,"device_limit":0}]}),
    ] {
        let panel = MockPanel::start(vec![Reply::json(body)]).await;
        assert!(
            PPanelConnection::new(panel.options())
                .unwrap()
                .protocol("vless")
                .unwrap()
                .get_users(None)
                .await
                .is_err()
        );
    }
    let panel = MockPanel::start(vec![Reply::json(json!({"users":[valid]}))]).await;
    assert_eq!(
        changed(
            PPanelConnection::new(panel.options())
                .unwrap()
                .protocol("vless")
                .unwrap()
                .get_users(None)
                .await
                .unwrap()
        )
        .0[0]
            .id
            .get(),
        1
    );
}

#[tokio::test]
async fn read_only_panel_check_only_issues_gets_and_does_not_claim_readiness() {
    let panel = MockPanel::start(vec![
        Reply::json(config_json()),
        Reply::json(users_json()),
        Reply::json(json!({"alive":{}})),
    ])
    .await;
    assert_eq!(
        app::check_panel(panel.options()).await.unwrap(),
        app::PanelSummary {
            protocols: 1,
            user_records: 1,
            alive_records: 0
        }
    );
    assert!(
        panel
            .requests()
            .iter()
            .all(|r| r.method == "GET" && r.body.is_empty())
    );
    assert_eq!(panel.requests().len(), 3);
}

#[tokio::test]
async fn invalid_reports_are_rejected_before_any_request() {
    let panel = MockPanel::start(vec![]).await;
    let conn = PPanelConnection::new(panel.options()).unwrap();
    let p = conn.protocol("vless").unwrap();
    let id = SubscriptionId::new(1).unwrap();
    let user = OnlineUser {
        id,
        ip: "127.0.0.1".parse().unwrap(),
    };
    p.report_online(&[]).await.unwrap();
    p.report_traffic(&[]).await.unwrap();
    assert!(p.report_online(&vec![user; 10_001]).await.is_err());
    assert!(
        p.report_traffic(&[
            Traffic {
                id,
                upload: 10 << 40,
                download: 0
            },
            Traffic {
                id,
                upload: 1,
                download: 0
            }
        ])
        .await
        .is_err()
    );
    assert!(
        p.report_traffic(&[Traffic {
            id,
            upload: u64::MAX,
            download: 1
        }])
        .await
        .is_err()
    );
    assert!(
        p.claim_device(id, "::ffff:0.0.0.0".parse().unwrap())
            .await
            .is_err()
    );
    assert!(
        conn.status("vless")
            .unwrap()
            .report_status(NodeStatus {
                cpu_percent: f64::NAN,
                memory_percent: 0.0,
                disk_percent: 0.0,
                updated_at_millis: 1
            })
            .await
            .is_err()
    );
    assert!(panel.requests().is_empty());
}

#[tokio::test]
async fn go_encoded_backend_fixtures_are_interoperable_in_both_directions() {
    let binary = |bytes: &'static [u8]| Reply::raw(200, Some("application/protobuf"), bytes);
    let panel = MockPanel::start(vec![
        binary(include_bytes!("fixtures/config.pb")),
        binary(include_bytes!("fixtures/users.pb")),
        binary(include_bytes!("fixtures/alive.pb")),
        binary(include_bytes!("fixtures/device.pb")),
        binary(include_bytes!("fixtures/ack.pb")),
        binary(include_bytes!("fixtures/ack.pb")),
        binary(include_bytes!("fixtures/ack.pb")),
    ])
    .await;
    let conn = PPanelConnection::new(panel.options()).unwrap();
    let (config, _) = changed(conn.server().get_config(None).await.unwrap());
    assert_eq!(
        config.protocols[0].server_key.expose(),
        "fixture-server-key"
    );
    let p = conn.protocol("shadowsocks").unwrap();
    let (users, _) = changed(p.get_users(None).await.unwrap());
    let id = users[0].id;
    assert_eq!(id.get(), USER_ID);
    assert_eq!(p.get_alive().await.unwrap()[&id], 2);
    assert!(
        p.claim_device(id, "127.0.0.1".parse().unwrap())
            .await
            .unwrap()
            .allowed
    );
    p.report_online(&[OnlineUser {
        id,
        ip: "127.0.0.1".parse().unwrap(),
    }])
    .await
    .unwrap();
    p.report_traffic(&[Traffic {
        id,
        upload: 19,
        download: 23,
    }])
    .await
    .unwrap();
    conn.status("shadowsocks")
        .unwrap()
        .report_status(NodeStatus {
            cpu_percent: 1.0,
            memory_percent: 2.0,
            disk_percent: 3.0,
            updated_at_millis: 1_800_000_000_000,
        })
        .await
        .unwrap();
    let requests = panel.requests();
    assert_eq!(
        requests[3].body,
        include_bytes!("fixtures/device-request.pb")
    );
    assert_eq!(
        requests[4].body,
        include_bytes!("fixtures/online-request.pb")
    );
    assert_eq!(
        requests[5].body,
        include_bytes!("fixtures/traffic-request.pb")
    );
    assert_eq!(
        requests[6].body,
        include_bytes!("fixtures/status-request.pb")
    );
}

#[tokio::test]
async fn config_aliases_unknown_features_and_semantic_validation_are_preserved() {
    let mut cfg = config_json();
    cfg["data"]["protocols"][0]["type"] = json!("hysteria2");
    cfg["data"]["protocols"][0]["protocol"] = json!("auth_aes128_md5");
    cfg["data"]["protocols"][0]["future_security"] = json!({"required": true});
    cfg["data"]["pull_interval"] = json!(0);
    let panel = MockPanel::start(vec![Reply::json(cfg)]).await;
    let (config, _) = changed(
        PPanelConnection::new(panel.options())
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap(),
    );
    assert_eq!(config.protocols[0].protocol.as_str(), "hysteria");
    assert_eq!(config.protocols[0].ssr_protocol, "auth_aes128_md5");
    assert!(
        config.protocols[0]
            .extensions
            .contains_key("future_security")
    );
    assert_eq!(config.pull_interval, Duration::from_secs(60));

    for mutation in [
        "missing protocols",
        "duplicate",
        "port",
        "negative parameter",
        "plugin type",
    ] {
        let mut cfg = config_json();
        match mutation {
            "missing protocols" => {
                cfg["data"].as_object_mut().unwrap().remove("protocols");
            }
            "duplicate" => {
                let p = cfg["data"]["protocols"][0].clone();
                cfg["data"]["protocols"].as_array_mut().unwrap().push(p);
                cfg["data"]["total"] = json!(2);
            }
            "port" => cfg["data"]["protocols"][0]["port"] = json!(65536),
            "negative parameter" => cfg["data"]["protocols"][0]["uot_version"] = json!(-1),
            _ => cfg["data"]["protocols"][0]["plugin_opts"] = json!(["unsupported"]),
        }
        let panel = MockPanel::start(vec![Reply::json(cfg)]).await;
        assert!(
            PPanelConnection::new(panel.options())
                .unwrap()
                .server()
                .get_config(None)
                .await
                .is_err(),
            "{mutation}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_panel_check_resolves_env_secret_and_only_uses_read_endpoints() {
    let panel = MockPanel::start(vec![
        Reply::json(config_json()),
        Reply::json(users_json()),
        Reply::json(json!({"alive": {}})),
    ])
    .await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.toml");
    std::fs::write(&path, format!("[panel]\nbase_url = '{}/panel/api'\nserver_id = 7\nsecret_env = 'TERRARIS_CLI_TEST_SECRET'\n",panel.url)).unwrap();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_terraris"))
            .args(["check", "--panel", "--config"])
            .arg(path)
            .env("TERRARIS_CLI_TEST_SECRET", SECRET)
            .output()
            .unwrap()
    })
    .await
    .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("1 enabled protocols, 1 user records, 0 alive records"));
    assert!(!stdout.contains(SECRET) && !stderr.contains(SECRET));
    for request in panel.requests() {
        assert_eq!(request.method, "GET");
        assert_eq!(request.query["secret_key"], SECRET);
    }
}
