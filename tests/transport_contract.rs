// SPDX-License-Identifier: GPL-3.0-only

mod support;

use std::{error::Error as _, time::Duration};

use serde_json::json;
use support::*;
use terraris::panel::{ppanel::PPanelConnection, *};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn auto_negotiates_json_only_on_a_valid_response_or_explicit_get_rejection() {
    let panel = MockPanel::start(vec![
        Reply::raw(406, None, vec![]),
        Reply::json(config_json()),
        Reply::json(users_json()),
    ])
    .await;
    let conn = PPanelConnection::new(panel.options()).unwrap();
    conn.server().get_config(None).await.unwrap();
    conn.protocol("vless")
        .unwrap()
        .get_users(None)
        .await
        .unwrap();
    let requests = panel.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].headers["accept"], "application/protobuf");
    assert_eq!(requests[1].headers["accept"], "application/json");
    assert_eq!(requests[2].headers["accept"], "application/json");
    for status in [401, 403, 500] {
        let panel = MockPanel::start(vec![Reply::raw(status, Some("text/plain"), SECRET)]).await;
        let error = PPanelConnection::new(panel.options())
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap_err();
        assert_eq!(error.http_status, Some(status));
        assert_eq!(panel.requests().len(), 1);
    }
}

#[tokio::test]
async fn forced_formats_reject_downgrades_and_mislabeled_payloads() {
    let panel = MockPanel::start(vec![Reply::json(config_json())]).await;
    let mut options = panel.options();
    options.wire_mode = WireMode::Protobuf;
    assert_eq!(
        PPanelConnection::new(options)
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::UnsupportedContentType
    );
    let panel = MockPanel::start(vec![Reply::raw(
        200,
        Some("application/protobuf"),
        serde_json::to_vec(&config_json()).unwrap(),
    )])
    .await;
    assert_eq!(
        PPanelConnection::new(panel.options())
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Decode
    );
    assert_eq!(panel.requests().len(), 1);
}

#[tokio::test]
async fn redirects_are_not_followed_even_to_another_local_server() {
    let target = MockPanel::start(vec![Reply::json(config_json())]).await;
    let mut redirect = Reply::raw(302, None, vec![]);
    redirect.location = Some(format!("{}/stolen", target.url));
    let panel = MockPanel::start(vec![redirect]).await;
    assert_eq!(
        PPanelConnection::new(panel.options())
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap_err()
            .http_status,
        Some(302)
    );
    assert_eq!(panel.requests().len(), 1);
    assert!(target.requests().is_empty());
}

#[tokio::test]
async fn error_display_debug_and_sources_do_not_retain_credentials_or_body() {
    let echoes = [
        Reply::raw(
            500,
            Some("text/plain"),
            format!("{SECRET} http://credentials:password@host/path?secret_key={SECRET}"),
        ),
        Reply::json(json!({"code":403,"msg":SECRET})),
        Reply::raw(200, Some("application/json"), format!("{{{SECRET}")),
    ];
    for reply in echoes {
        let panel = MockPanel::start(vec![reply]).await;
        let error = PPanelConnection::new(panel.options())
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap_err();
        for text in [error.to_string(), format!("{error:?}")] {
            for forbidden in [
                SECRET,
                "credentials",
                "password@host",
                "secret_key=",
                "fixture-secret",
            ] {
                assert!(!text.contains(forbidden));
            }
        }
        assert!(error.source().is_none());
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let options =
        terraris::panel::ppanel::Options::new(url, ServerId::new(1).unwrap(), Secret::new(SECRET));
    let error = PPanelConnection::new(options)
        .unwrap()
        .server()
        .get_config(None)
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Transport);
    assert!(!format!("{error:?}").contains(SECRET));
    assert!(error.source().is_none());
}

#[tokio::test]
async fn timeout_and_cancellation_are_bounded_and_do_not_retry() {
    let mut delayed = Reply::json(config_json());
    delayed.delay = Duration::from_secs(1);
    let panel = MockPanel::start(vec![delayed]).await;
    let mut options = panel.options();
    options.timeout = Duration::from_millis(100);
    assert_eq!(
        PPanelConnection::new(options)
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::Timeout
    );
    assert_eq!(panel.requests().len(), 1);

    let mut delayed = Reply::json(users_json());
    delayed.delay = Duration::from_secs(1);
    let panel = MockPanel::start(vec![delayed, Reply::json(users_json())]).await;
    let p = PPanelConnection::new(panel.options())
        .unwrap()
        .protocol("vless")
        .unwrap();
    let task_client = p.clone();
    let request = tokio::spawn(async move { task_client.get_users(None).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while panel.requests().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    assert!(matches!(
        p.get_users(None).await.unwrap(),
        Fetch::Changed { .. }
    ));
    assert_eq!(panel.requests().len(), 2);
}

#[tokio::test]
async fn body_limit_applies_to_content_length_and_chunked_responses() {
    let panel = MockPanel::start(vec![Reply::json(config_json())]).await;
    let mut options = panel.options();
    options.max_response_bytes = 32;
    assert_eq!(
        PPanelConnection::new(options)
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::ResponseTooLarge
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            request.push(byte[0]);
        }
        let _=stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n10\r\n0123456789abcdef\r\n10\r\n0123456789abcdef\r\n10\r\n0123456789abcdef\r\n0\r\n\r\n").await;
    });
    let mut options =
        terraris::panel::ppanel::Options::new(url, ServerId::new(1).unwrap(), Secret::new(SECRET));
    options.max_response_bytes = 32;
    assert_eq!(
        PPanelConnection::new(options)
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap_err()
            .kind,
        ErrorKind::ResponseTooLarge
    );
    task.await.unwrap();
}

#[tokio::test]
async fn post_failures_are_never_retried_or_reencoded() {
    let cases = [
        Reply::raw(415, None, vec![]),
        Reply::raw(500, None, vec![]),
        Reply::json(json!({"code":400,"msg":SECRET})),
        Reply::proto(wire::Result {
            code: 500,
            message: SECRET.into(),
        }),
        Reply::raw(200, Some("application/json"), b"broken".to_vec()),
    ];
    for reply in cases {
        let panel = MockPanel::start(vec![reply]).await;
        let p = PPanelConnection::new(panel.options())
            .unwrap()
            .protocol("vless")
            .unwrap();
        assert!(
            p.report_traffic(&[Traffic {
                id: SubscriptionId::new(1).unwrap(),
                upload: 4,
                download: 5
            }])
            .await
            .is_err()
        );
        assert_eq!(panel.requests().len(), 1);
        assert_eq!(
            panel.requests()[0].headers["content-type"],
            "application/protobuf"
        );
    }
}

#[tokio::test]
async fn successful_http_status_does_not_hide_business_errors_on_bare_endpoints() {
    for protobuf in [false, true] {
        let error = || {
            if protobuf {
                Reply::proto(wire::Result {
                    code: 403,
                    message: SECRET.into(),
                })
            } else {
                Reply::json(json!({"code":403,"msg":SECRET}))
            }
        };
        let panel = MockPanel::start(vec![error(), error(), error()]).await;
        let p = PPanelConnection::new(panel.options())
            .unwrap()
            .protocol("vless")
            .unwrap();
        let user_error = p.get_users(None).await.unwrap_err();
        let alive_error = p.get_alive().await.unwrap_err();
        let claim_error = p
            .claim_device(
                SubscriptionId::new(1).unwrap(),
                "127.0.0.1".parse().unwrap(),
            )
            .await
            .unwrap_err();
        for error in [user_error, alive_error, claim_error] {
            assert_eq!(error.kind, ErrorKind::Business);
            assert_eq!(error.business_code, Some(403));
        }
    }
}

#[tokio::test]
async fn request_limit_is_enforced_before_sending() {
    let panel = MockPanel::start(vec![]).await;
    let mut options = panel.options();
    options.max_request_bytes = 1;
    let p = PPanelConnection::new(options)
        .unwrap()
        .protocol("vless")
        .unwrap();
    assert_eq!(
        p.report_traffic(&[Traffic {
            id: SubscriptionId::new(1).unwrap(),
            upload: 1,
            download: 0
        }])
        .await
        .unwrap_err()
        .kind,
        ErrorKind::InvalidInput
    );
    assert!(panel.requests().is_empty());
}

#[tokio::test]
async fn conditional_json_fallback_retains_negotiated_format_for_reports() {
    let panel = MockPanel::start(vec![
        Reply::json(users_json()).etag("\"json-users\""),
        Reply::proto(config_proto()),
        Reply::raw(406, None, vec![]),
        Reply::raw(304, None, vec![]),
        Reply::json(json!({"code":200})),
    ])
    .await;
    let conn = PPanelConnection::new(panel.options()).unwrap();
    let p = conn.protocol("vless").unwrap();
    let Fetch::Changed { validator, .. } = p.get_users(None).await.unwrap() else {
        panic!("initial snapshot");
    };
    conn.server().get_config(None).await.unwrap();
    assert!(matches!(
        p.get_users(Some(&validator)).await.unwrap(),
        Fetch::Unchanged { .. }
    ));
    p.report_traffic(&[Traffic {
        id: SubscriptionId::new(1).unwrap(),
        upload: 1,
        download: 0,
    }])
    .await
    .unwrap();
    let requests = panel.requests();
    assert!(!requests[2].headers.contains_key("if-none-match"));
    assert_eq!(requests[3].headers["if-none-match"], "\"json-users\"");
    assert_eq!(requests[4].headers["content-type"], "application/json");
}

#[tokio::test]
async fn encoded_api_prefix_is_preserved_with_or_without_trailing_slash() {
    for suffix in ["/tenant%20one/api", "/tenant%20one/api/"] {
        let panel = MockPanel::start(vec![Reply::json(config_json())]).await;
        let mut options = panel.options();
        options.base_url = format!("{}{suffix}", panel.url);
        PPanelConnection::new(options)
            .unwrap()
            .server()
            .get_config(None)
            .await
            .unwrap();
        assert_eq!(panel.requests()[0].path, "/tenant%20one/api/v2/server/7");
    }
}
