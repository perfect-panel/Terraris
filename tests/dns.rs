// SPDX-License-Identifier: GPL-3.0-only
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, SOA},
    },
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use terraris::{
    buffer::BufferScope,
    dns::{Resolver, Settings, Strategy, wire},
    panel::DnsResolver,
    resource::{Budget, Limits},
    route::{
        Limits as RouteLimits,
        geodata::{Assets, Catalog},
    },
    task::CancellationToken,
    telemetry::Metrics,
    time::{Deadline, OperationContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Notify,
};
fn ctx() -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(3)).unwrap()),
    )
}
fn item(proto: &str, address: String) -> DnsResolver {
    DnsResolver {
        transport: proto.into(),
        address,
        server_name: String::new(),
        domains: vec![],
        extensions: BTreeMap::new(),
    }
}
fn resolver(items: Vec<DnsResolver>, settings: Settings) -> (Budget, Arc<Resolver>) {
    let budget = Budget::new(Limits::new(16 << 20, 256).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
    let resolver = Resolver::new(
        &items,
        &mut Catalog::new(Assets::default()),
        &RouteLimits::default(),
        settings,
        scope,
        Metrics::default(),
    )
    .unwrap();
    (budget, Arc::new(resolver))
}
fn query(name: &str, id: u16) -> Vec<u8> {
    let mut message = wire::address_query(name, RecordType::A).unwrap();
    message.metadata.id = id;
    message.to_vec().unwrap()
}
fn answer(query: &Message, ttl: u32) -> Message {
    let mut response = wire::error_response(query, ResponseCode::NoError);
    response.answers.push(Record::from_rdata(
        query.queries[0].name.clone(),
        ttl,
        RData::A(A(Ipv4Addr::new(127, 0, 0, 9))),
    ));
    response
}

#[tokio::test]
async fn udp_matching_and_cache_restore_id_and_expire_by_ttl() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let query = wire::query(&buffer[..n]).unwrap();
            let response = answer(&query, 1);
            let mut wrong = response.clone();
            wrong.metadata.id ^= 1;
            socket
                .send_to(&wrong.to_vec().unwrap(), peer)
                .await
                .unwrap();
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let (budget, resolver) = resolver(vec![item("udp", address.to_string())], Settings::default());
    let first = resolver
        .exchange(&query("example.test", 11), false, &ctx())
        .await
        .unwrap();
    assert_eq!(wire::parse(first.as_slice()).unwrap().metadata.id, 11);
    let second = resolver
        .exchange(&query("EXAMPLE.TEST", 22), false, &ctx())
        .await
        .unwrap();
    assert_eq!(wire::parse(second.as_slice()).unwrap().metadata.id, 22);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(first);
    drop(second);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let third = resolver
        .exchange(&query("example.test", 33), false, &ctx())
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(third);
    resolver.close(&ctx()).await.unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn identical_queries_coalesce_and_one_cancelled_waiter_does_not_cancel_others() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let signal = entered.clone();
    let hold = release.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let query = wire::query(&buffer[..n]).unwrap();
            signal.notify_one();
            hold.notified().await;
            socket
                .send_to(&answer(&query, 60).to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let (_, resolver) = resolver(vec![item("udp", address.to_string())], Settings::default());
    let cancel = CancellationToken::new();
    let context = OperationContext::new(cancel.clone(), None);
    let owned = resolver.clone();
    let first =
        tokio::spawn(async move { owned.lookup("example.test", Strategy::V4, &context).await });
    entered.notified().await;
    let mut others = Vec::new();
    for _ in 0..10 {
        let owned = resolver.clone();
        others.push(tokio::spawn(async move {
            owned.lookup("example.test", Strategy::V4, &ctx()).await
        }));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while resolver.snapshot().coalesced < 10 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    assert!(first.await.unwrap().is_err());
    release.notify_one();
    for other in others {
        assert_eq!(
            other.await.unwrap().unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9))]
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    resolver.close(&ctx()).await.unwrap();
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn udp_truncation_retries_over_tcp() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(address).await.unwrap();
    let udp_task = tokio::spawn(async move {
        let mut buf = [0; 4096];
        let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
        let request = wire::query(&buf[..n]).unwrap();
        let mut response = wire::error_response(&request, ResponseCode::NoError);
        response.metadata.truncation = true;
        udp.send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let len = stream.read_u16().await.unwrap() as usize;
        let mut body = vec![0; len];
        stream.read_exact(&mut body).await.unwrap();
        let request = wire::query(&body).unwrap();
        let response = answer(&request, 60).to_vec().unwrap();
        stream
            .write_all(&(response.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&response).await.unwrap();
    });
    let (_, resolver) = resolver(vec![item("udp", address.to_string())], Settings::default());
    assert_eq!(
        resolver
            .lookup("example.test", Strategy::V4, &ctx())
            .await
            .unwrap()
            .len(),
        1
    );
    resolver.close(&ctx()).await.unwrap();
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
}
#[tokio::test]
async fn negative_cache_uses_soa_and_transient_failures_are_not_cached() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        let mut data = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut data).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let q = wire::query(&data[..n]).unwrap();
            let mut response = wire::error_response(
                &q,
                if q.queries[0].name.to_ascii().starts_with("missing") {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::ServFail
                },
            );
            if response.metadata.response_code == ResponseCode::NXDomain {
                response.authorities.push(Record::from_rdata(
                    Name::from_ascii("test.").unwrap(),
                    30,
                    RData::SOA(SOA::new(
                        Name::from_ascii("ns.test.").unwrap(),
                        Name::from_ascii("hostmaster.test.").unwrap(),
                        1,
                        60,
                        60,
                        600,
                        5,
                    )),
                ));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let (_, resolver) = resolver(vec![item("udp", address.to_string())], Settings::default());
    for _ in 0..2 {
        let response = resolver
            .exchange(&query("missing.test", 1), false, &ctx())
            .await
            .unwrap();
        assert_eq!(
            wire::parse(response.as_slice())
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    for _ in 0..2 {
        assert!(
            resolver
                .exchange(&query("failure.test", 2), false, &ctx())
                .await
                .is_err()
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    resolver.close(&ctx()).await.unwrap();
    task.abort();
    task.await.ok();
}
fn certificate() -> (tempfile::TempDir, Arc<rustls::ServerConfig>) {
    let key = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("ca.pem"), key.cert.pem()).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![key.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
    )
    .unwrap();
    (dir, Arc::new(config))
}
#[tokio::test]
async fn dot_requires_certificate_name_and_preserves_dns_framing() {
    let (dir, tls) = certificate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(tls);
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut tls) = acceptor.accept(stream).await else {
                continue;
            };
            let n = match tls.read_u16().await {
                Ok(n) => n,
                Err(_) => continue,
            };
            let mut bytes = vec![0; n as usize];
            tls.read_exact(&mut bytes).await.unwrap();
            let q = wire::query(&bytes).unwrap();
            let bytes = answer(&q, 60).to_vec().unwrap();
            tls.write_all(&(bytes.len() as u16).to_be_bytes())
                .await
                .unwrap();
            tls.write_all(&bytes).await.unwrap();
        }
    });
    let settings = Settings {
        ca_file: Some(dir.path().join("ca.pem")),
        ..Default::default()
    };
    let mut upstream = item("dot", address.to_string());
    upstream.server_name = "wrong.test".into();
    let (_, wrong) = resolver(vec![upstream.clone()], settings.clone());
    assert!(
        wrong
            .lookup("example.test", Strategy::V4, &ctx())
            .await
            .is_err()
    );
    wrong.close(&ctx()).await.unwrap();
    upstream.server_name = "dns.test".into();
    let (_, correct) = resolver(vec![upstream], settings);
    assert_eq!(
        correct
            .lookup("example.test", Strategy::V4, &ctx())
            .await
            .unwrap()
            .len(),
        1
    );
    correct.close(&ctx()).await.unwrap();
    task.await.unwrap();
}
#[tokio::test]
async fn doh_post_checks_tls_content_type_and_http_age() {
    let (dir, tls) = certificate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(tls)
            .accept(stream)
            .await
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
            assert!(header.len() < 16384);
        }
        let text = String::from_utf8(header).unwrap();
        assert!(text.starts_with("POST /dns-query "));
        assert!(
            text.to_ascii_lowercase()
                .contains("content-type: application/dns-message")
        );
        let length = text
            .lines()
            .find_map(|l| {
                l.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|v| v.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await.unwrap();
        let q = wire::query(&bytes).unwrap();
        assert_eq!(q.metadata.id, 0);
        let bytes = answer(&q, 60).to_vec().unwrap();
        stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nAge: 10\r\nConnection: close\r\n\r\n",bytes.len()).as_bytes()).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let settings = Settings {
        ca_file: Some(dir.path().join("ca.pem")),
        ..Default::default()
    };
    let mut upstream = item("doh", format!("https://{address}/dns-query"));
    upstream.server_name = "dns.test".into();
    let (_, resolver) = resolver(vec![upstream], settings);
    let response = resolver
        .exchange(&query("example.test", 42), false, &ctx())
        .await
        .unwrap();
    let response = wire::parse(response.as_slice()).unwrap();
    assert_eq!(response.metadata.id, 42);
    assert_eq!(response.answers[0].ttl, 50);
    resolver.close(&ctx()).await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn scoped_servers_are_ordered_and_failure_does_not_fall_back() {
    let scope = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let default = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut scoped = item("udp", scope.local_addr().unwrap().to_string());
    scoped.domains = vec!["domain:private.test".into()];
    let fallback = item("udp", default.local_addr().unwrap().to_string());
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (n, peer) = scope.recv_from(&mut bytes).await.unwrap();
        let q = wire::query(&bytes[..n]).unwrap();
        assert_eq!(q.queries[0].name.to_ascii(), "x.private.test.");
        scope
            .send_to(
                &wire::error_response(&q, ResponseCode::ServFail)
                    .to_vec()
                    .unwrap(),
                peer,
            )
            .await
            .unwrap();
    });
    let (_, resolver) = resolver(vec![fallback, scoped], Settings::default());
    assert!(
        resolver
            .lookup("x.private.test", Strategy::V4, &ctx())
            .await
            .is_err()
    );
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), default.recv_from(&mut byte))
            .await
            .is_err()
    );
    resolver.close(&ctx()).await.unwrap();
    task.await.unwrap();
}
#[tokio::test]
async fn cname_queries_follow_only_the_chain_and_reject_cycles() {
    use hickory_proto::rr::rdata::CNAME;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let q = wire::query(&bytes[..n]).unwrap();
            let name = q.queries[0].name.to_ascii();
            let mut response = wire::error_response(&q, ResponseCode::NoError);
            let alias = match name.as_str() {
                "alias.test." => Some("final.test."),
                "cycle.test." => Some("cycle2.test."),
                "cycle2.test." => Some("cycle.test."),
                _ => None,
            };
            if let Some(alias) = alias {
                response.answers.push(Record::from_rdata(
                    q.queries[0].name.clone(),
                    60,
                    RData::CNAME(CNAME(Name::from_ascii(alias).unwrap())),
                ));
                response.answers.push(Record::from_rdata(
                    Name::from_ascii("unrelated.test.").unwrap(),
                    60,
                    RData::A(A(Ipv4Addr::new(127, 0, 0, 99))),
                ));
            } else {
                response = answer(&q, 60);
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let (_, resolver) = resolver(vec![item("udp", address.to_string())], Settings::default());
    assert_eq!(
        resolver
            .lookup("alias.test", Strategy::V4, &ctx())
            .await
            .unwrap(),
        vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9))]
    );
    assert!(matches!(
        resolver.lookup("cycle.test", Strategy::V4, &ctx()).await,
        Err(terraris::dns::Error::InvalidResponse)
    ));
    resolver.close(&ctx()).await.unwrap();
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn dnssec_flags_have_separate_cache_keys_and_cache_capacity_is_bounded() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            count.fetch_add(1, Ordering::SeqCst);
            let q = wire::query(&bytes[..n]).unwrap();
            socket
                .send_to(&answer(&q, 60).to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let (budget, resolver) = resolver(
        vec![item("udp", address.to_string())],
        Settings {
            cache_entries: 2,
            cache_bytes: 512,
            ..Default::default()
        },
    );
    let q = wire::address_query("flags.test", RecordType::A).unwrap();
    resolver
        .exchange(&q.to_vec().unwrap(), false, &ctx())
        .await
        .unwrap();
    let mut flagged = q.clone();
    flagged.metadata.checking_disabled = true;
    resolver
        .exchange(&flagged.to_vec().unwrap(), false, &ctx())
        .await
        .unwrap();
    resolver
        .exchange(&q.to_vec().unwrap(), false, &ctx())
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    for index in 0..10 {
        resolver
            .exchange(&query(&format!("n{index}.test"), index), false, &ctx())
            .await
            .unwrap();
        assert!(resolver.snapshot().entries <= 2);
        assert!(resolver.snapshot().bytes <= 512);
    }
    resolver.close(&ctx()).await.unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn query_and_waiter_limits_fail_without_unowned_work_and_close_wakes_waiters() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (budget, resolver) = resolver(
        vec![item("udp", address.to_string())],
        Settings {
            concurrency: 1,
            max_waiters: 1,
            ..Default::default()
        },
    );
    let owned = resolver.clone();
    let task =
        tokio::spawn(async move { owned.lookup("pending.test", Strategy::V4, &ctx()).await });
    let mut bytes = [0; 4096];
    socket.recv_from(&mut bytes).await.unwrap();
    assert!(matches!(
        resolver.lookup("pending.test", Strategy::V4, &ctx()).await,
        Err(terraris::dns::Error::Capacity)
    ));
    assert!(matches!(
        resolver.lookup("other.test", Strategy::V4, &ctx()).await,
        Err(terraris::dns::Error::Capacity)
    ));
    resolver.close(&ctx()).await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(resolver.snapshot().in_flight, 0);
}
#[tokio::test]
async fn doh_rejects_redirect_wrong_type_oversize_and_invalid_age() {
    let (dir, tls) = certificate();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for headers in [
            "302 Found\r\nLocation: https://dns.test/other\r\nContent-Length: 0",
            "200 OK\r\nContent-Type: application/json\r\nContent-Length: 0",
            "200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 65536",
            "200 OK\r\nContent-Type: application/dns-message\r\nAge: invalid\r\nContent-Length: 0",
        ] {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(tls.clone())
                .accept(stream)
                .await
                .unwrap();
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                header.push(stream.read_u8().await.unwrap());
            }
            let text = String::from_utf8(header).unwrap();
            let length = text
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).await.unwrap();
            stream
                .write_all(format!("HTTP/1.1 {headers}\r\nConnection: close\r\n\r\n").as_bytes())
                .await
                .unwrap();
        }
    });
    let mut server = item("doh", format!("https://{address}/dns-query"));
    server.server_name = "dns.test".into();
    let (_, resolver) = resolver(
        vec![server],
        Settings {
            ca_file: Some(dir.path().join("ca.pem")),
            ..Default::default()
        },
    );
    for index in 0..4 {
        assert!(
            resolver
                .exchange(&query(&format!("q{index}.test"), index), false, &ctx())
                .await
                .is_err()
        );
    }
    assert_eq!(resolver.snapshot().entries, 0);
    resolver.close(&ctx()).await.unwrap();
    task.await.unwrap();
}
