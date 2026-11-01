// SPDX-License-Identifier: GPL-3.0-only
mod support;
use hickory_proto::{
    op::ResponseCode,
    rr::{RData, Record, RecordType, rdata::A},
};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use terraris::{
    buffer::BufferScope,
    dns::{self, wire},
    egress::{Error, Handle, Registry},
    network::{Address, Network},
    panel::{Connection, Fetch, ServerConfig, WireMode, ppanel::PPanelConnection},
    resource::{Budget, Limits},
    route::{
        Table, Target,
        geodata::{Assets, Catalog},
    },
    runtime::SharedServices,
    task::CancellationToken,
    telemetry::Metrics,
    time::{Deadline, OperationContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
fn ctx() -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(5)).unwrap()),
    )
}
async fn config(extra: Value) -> ServerConfig {
    let mut value = json!({"pull_interval":300,"push_interval":300,"traffic_report_threshold":1024,"dns":[],"block":[],"outbound":[],"total":1,"ip_strategy":"ipv4_only","protocols":[{"type":"vless","enable":true,"port":12345,"network":"tcp","security":"none"}]});
    for (k, v) in extra.as_object().unwrap() {
        value[k] = v.clone();
    }
    for outbound in value["outbound"].as_array_mut().unwrap() {
        let outbound = outbound.as_object_mut().unwrap();
        outbound.entry("address").or_insert(json!(""));
        outbound.entry("port").or_insert(json!(0));
    }
    let mock =
        support::MockPanel::start(vec![support::Reply::json(json!({"code":200,"data":value}))])
            .await;
    let mut options = mock.options();
    options.wire_mode = WireMode::Json;
    let connection = PPanelConnection::new(options).unwrap();
    let Fetch::Changed { value, .. } = connection.server().get_config(None).await.unwrap() else {
        panic!("config")
    };
    value
}
fn resources() -> (Budget, BufferScope) {
    let budget = Budget::new(Limits::new(16 << 20, 1024).unwrap());
    let buffers = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
    (budget, buffers)
}
async fn engine(config: &ServerConfig) -> (Arc<Registry>, Handle, Budget, BufferScope) {
    let (budget, scope) = resources();
    let registry = Registry::new(
        dns::Settings::default(),
        terraris::route::Settings::default(),
        64,
    )
    .unwrap();
    let handle = registry
        .open(config, scope.clone(), Metrics::default(), &ctx())
        .await
        .unwrap();
    (registry, handle, budget, scope)
}
async fn dns_server(
    ips: Vec<Ipv4Addr>,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            calls.fetch_add(1, Ordering::SeqCst);
            let query = wire::query(&bytes[..n]).unwrap();
            let mut response = wire::error_response(&query, ResponseCode::NoError);
            for ip in &ips {
                response.answers.push(Record::from_rdata(
                    query.queries[0].name.clone(),
                    60,
                    RData::A(A(*ip)),
                ));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    (address, count, task)
}
#[tokio::test]
async fn rule_order_and_blacklist_precedence_cover_domains_and_resolved_ips() {
    let config=config(json!({"block":["full:deny.test"],"outbound":[{"name":"allowed","protocol":"direct","rules":["127.0.0.0/8"]},{"name":"denied","protocol":"block","rules":["domain:test"]}]})).await;
    let table = Table::compile(
        &config,
        &mut Catalog::new(Assets::default()),
        &terraris::route::Limits::default(),
    )
    .unwrap();
    assert_eq!(
        table
            .decide(Some("x.test"), &["127.0.0.1".parse().unwrap()])
            .target,
        Target::Direct
    );
    assert_eq!(
        table
            .decide(Some("x.test"), &["10.0.0.1".parse().unwrap()])
            .target,
        Target::Block
    );
    assert_eq!(
        table
            .decide(Some("deny.test"), &["127.0.0.1".parse().unwrap()])
            .target,
        Target::Block
    );
    assert_eq!(table.decide(Some("other.example"), &[]).rule, None);
}
#[tokio::test]
async fn dns_resolution_honors_earlier_ip_rule_and_never_dials_a_later_blocked_address() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (dns, _, task) = dns_server(vec![Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::LOCALHOST]).await;
    let config=config(json!({"dns":[{"proto":"udp","address":dns.to_string()}],"outbound":[{"name":"allowed","protocol":"direct","rules":["127.0.0.1"]},{"name":"blocked","protocol":"block","rules":["domain:test"]}]})).await;
    let (registry, handle, _, scope) = engine(&config).await;
    let target = Address::from_domain("x.test", port).unwrap();
    let plan = handle.plan(&target, Network::Tcp, &ctx()).await.unwrap();
    assert_eq!(
        plan.address.socket_addr().unwrap().ip(),
        Ipv4Addr::LOCALHOST
    );
    let stream = handle.connect(&target, &ctx(), scope).await.unwrap();
    let (peer, _) = listener.accept().await.unwrap();
    drop(stream);
    drop(peer);
    drop(plan);
    drop(handle);
    registry.close(&ctx()).await.unwrap();
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn dns_outbound_udp_tcp_share_cache_preserve_source_and_apply_block_policy() {
    let (dns, count, task) = dns_server(vec![Ipv4Addr::LOCALHOST]).await;
    let config = config(
        json!({"dns":[{"proto":"udp","address":dns.to_string()}],"block":["domain:blocked.test","10.0.0.0/8"]}),
    )
    .await;
    let (registry, handle, budget, scope) = engine(&config).await;
    let target = Address::from_socket("127.0.0.9:53".parse().unwrap()).unwrap();
    let plan = handle.plan(&target, Network::Udp, &ctx()).await.unwrap();
    assert_eq!(plan.decision.target, Target::Dns);
    let packet_scope = scope.child(Limits::new(1 << 20, 128).unwrap()).unwrap();
    let packet = handle
        .packet(&plan, packet_scope.clone(), &ctx())
        .await
        .unwrap();
    let query = wire::address_query("allowed.test", RecordType::A)
        .unwrap()
        .to_vec()
        .unwrap();
    packet.send(&plan.address, &query, &ctx()).await.unwrap();
    let answer = packet.recv(&ctx()).await.unwrap();
    assert_eq!(answer.source, target);
    assert!(packet_scope.snapshot().used().bytes() >= answer.payload.len());
    assert_eq!(
        wire::parse(answer.payload.as_slice())
            .unwrap()
            .answers
            .len(),
        1
    );
    drop(answer);
    let mut tcp = handle.connect(&target, &ctx(), scope).await.unwrap();
    tcp.write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    tcp.write_all(&query).await.unwrap();
    let n = tcp.read_u16().await.unwrap();
    let mut response = vec![0; n as usize];
    tcp.read_exact(&mut response).await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let blocked = wire::address_query("blocked.test", RecordType::A)
        .unwrap()
        .to_vec()
        .unwrap();
    packet.send(&target, &blocked, &ctx()).await.unwrap();
    let reply = packet.recv(&ctx()).await.unwrap();
    assert_eq!(
        wire::parse(reply.payload.as_slice())
            .unwrap()
            .metadata
            .response_code,
        ResponseCode::Refused
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    drop(reply);
    drop(tcp);
    drop(packet);
    drop(plan);
    handle.close(&ctx()).await.unwrap();
    registry.close(&ctx()).await.unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn http_connect_uses_remote_domain_auth_and_does_not_consume_tunnel_payload() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut io, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(io.read_u8().await.unwrap());
        }
        let text = String::from_utf8(header).unwrap();
        assert!(text.starts_with("CONNECT unresolved.test:443 HTTP/1.1\r\n"));
        assert!(text.contains("Proxy-Authorization: Basic dTpw\r\n"));
        io.write_all(b"HTTP/1.1 200 Connection established\r\n\r\nearly")
            .await
            .unwrap();
        let mut b = [0; 4];
        io.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"ping");
        io.write_all(b"pong").await.unwrap();
    });
    let config=config(json!({"outbound":[{"name":"proxy","protocol":"http","address":"127.0.0.1","port":proxy.port(),"user":"u","password":"p","rules":["domain:test"]}]})).await;
    let (registry, handle, _, scope) = engine(&config).await;
    let target = Address::from_domain("unresolved.test", 443).unwrap();
    let mut io = handle.connect(&target, &ctx(), scope).await.unwrap();
    let mut early = [0; 5];
    io.read_exact(&mut early).await.unwrap();
    assert_eq!(&early, b"early");
    io.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    io.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"pong");
    assert!(handle.plan(&target, Network::Udp, &ctx()).await.is_err());
    drop(io);
    drop(handle);
    registry.close(&ctx()).await.unwrap();
    task.await.unwrap();
}
#[tokio::test]
async fn proxy_failure_never_opens_a_direct_destination() {
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = Address::from_socket(destination.local_addr().unwrap()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut io, _) = listener.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(io.read_u8().await.unwrap());
        }
        io.write_all(b"HTTP/1.1 407 Denied\r\n\r\n").await.unwrap();
    });
    let config=config(json!({"outbound":[{"name":"proxy","protocol":"http","address":"127.0.0.1","port":proxy.port(),"rules":["127.0.0.0/8"]}]})).await;
    let (registry, handle, _, scope) = engine(&config).await;
    assert!(matches!(
        handle.connect(&target, &ctx(), scope).await,
        Err(Error::Outbound(_))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), destination.accept())
            .await
            .is_err()
    );
    drop(handle);
    registry.close(&ctx()).await.unwrap();
    task.await.unwrap();
}
async fn socks_auth(io: &mut tokio::net::TcpStream) {
    let mut greet = [0; 3];
    io.read_exact(&mut greet).await.unwrap();
    assert_eq!(greet, [5, 1, 2]);
    io.write_all(&[5, 2]).await.unwrap();
    let mut auth = [0; 5];
    io.read_exact(&mut auth).await.unwrap();
    assert_eq!(&auth, &[1, 1, b'u', 1, b'p']);
    io.write_all(&[1, 0]).await.unwrap();
}
#[tokio::test]
async fn socks5_tcp_and_udp_keep_remote_domains_and_control_lifetime() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = relay.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        socks_auth(&mut tcp).await;
        let mut prefix = [0; 5];
        tcp.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[..4], &[5, 1, 0, 3]);
        let mut host = vec![0; prefix[4] as usize];
        tcp.read_exact(&mut host).await.unwrap();
        assert_eq!(&host, b"unresolved.test");
        assert_eq!(tcp.read_u16().await.unwrap(), 443);
        tcp.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        tcp.write_all(b"ok").await.unwrap();
        let (mut control, _) = listener.accept().await.unwrap();
        socks_auth(&mut control).await;
        let mut request = [0; 10];
        control.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
        let mut response = vec![5, 0, 0, 1, 0, 0, 0, 0];
        response.extend(port.to_be_bytes());
        control.write_all(&response).await.unwrap();
        let mut buffer = [0; 1024];
        let (n, peer) = relay.recv_from(&mut buffer).await.unwrap();
        assert_eq!(&buffer[..5], &[0, 0, 0, 3, 15]);
        assert_eq!(&buffer[5..20], b"unresolved.test");
        assert_eq!(&buffer[n - 4..n], b"ping");
        relay.send_to(&buffer[..n], peer).await.unwrap();
        let mut eof = [0];
        assert!(matches!(control.read(&mut eof).await, Ok(0) | Err(_)));
    });
    let config=config(json!({"outbound":[{"name":"proxy","protocol":"socks5","address":"127.0.0.1","port":proxy.port(),"user":"u","password":"p","rules":["domain:test"]}]})).await;
    let (registry, handle, budget, scope) = engine(&config).await;
    let target = Address::from_domain("unresolved.test", 443).unwrap();
    let mut tcp = handle
        .connect(&target, &ctx(), scope.clone())
        .await
        .unwrap();
    let mut reply = [0; 2];
    tcp.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ok");
    drop(tcp);
    let plan = handle.plan(&target, Network::Udp, &ctx()).await.unwrap();
    let packet = handle.packet(&plan, scope, &ctx()).await.unwrap();
    packet.send(&plan.address, b"ping", &ctx()).await.unwrap();
    let reply = packet.recv(&ctx()).await.unwrap();
    assert_eq!(reply.source, target);
    assert_eq!(reply.payload.as_slice(), b"ping");
    drop(reply);
    drop(packet);
    drop(plan);
    drop(handle);
    registry.close(&ctx()).await.unwrap();
    task.await.unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
#[tokio::test]
async fn compatible_generations_reuse_dns_cache_and_policy_changes_isolate_it() {
    let (dns, count, task) = dns_server(vec![Ipv4Addr::LOCALHOST]).await;
    let config = config(json!({"dns":[{"proto":"udp","address":dns.to_string()}]})).await;
    let (registry, handle, budget, scope) = engine(&config).await;
    let address = Address::from_domain("cache.test", 80).unwrap();
    drop(handle.plan(&address, Network::Tcp, &ctx()).await.unwrap());
    let second = registry
        .open(&config, scope.clone(), Metrics::default(), &ctx())
        .await
        .unwrap();
    assert_eq!(handle.migration_scope(), second.migration_scope());
    drop(second.plan(&address, Network::Tcp, &ctx()).await.unwrap());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let mut changed = config.clone();
    changed.block.push("other.test".into());
    let third = registry
        .open(&changed, scope, Metrics::default(), &ctx())
        .await
        .unwrap();
    assert_ne!(third.migration_scope(), second.migration_scope());
    drop(third.plan(&address, Network::Tcp, &ctx()).await.unwrap());
    assert_eq!(count.load(Ordering::SeqCst), 2);
    drop(third);
    drop(second);
    drop(handle);
    registry.close(&ctx()).await.unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
    task.abort();
    task.await.ok();
}

#[tokio::test]
#[ignore = "requires TERRARIS_XRAY pinned to the documented Xray commit"]
async fn native_vless_outbound_interoperates_with_xray_tcp_xudp_and_encryption() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use terraris::protocol::vless::encryption::Config;
    let binary = std::env::var("TERRARIS_XRAY").expect("Xray binary");
    let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811";
    for mode in ["none", "native", "xorpub", "random"] {
        for zero in [false, true] {
            let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = reservation.local_addr().unwrap();
            drop(reservation);
            let private = [
                URL_SAFE_NO_PAD.encode([0x42; 32]),
                URL_SAFE_NO_PAD.encode([0x38; 64]),
                URL_SAFE_NO_PAD.encode([0x52; 32]),
            ]
            .join(".");
            let decryption = if mode == "none" {
                "none".into()
            } else {
                format!("mlkem768x25519plus.{mode}.600s.100-35-35.{private}")
            };
            let client = if mode == "none" {
                "none".into()
            } else {
                Config::parse(&decryption)
                    .unwrap()
                    .client_encryption(zero)
                    .unwrap()
            };
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("xray.json");
            let log = dir.path().join("xray.log");
            std::fs::write(&path,serde_json::to_vec(&json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":address.port(),"protocol":"vless","settings":{"clients":[{"id":uuid}],"decryption":decryption},"streamSettings":{"network":"tcp","security":"none"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]})).unwrap()).unwrap();
            let mut child = tokio::process::Command::new(&binary)
                .args(["run", "-config"])
                .arg(&path)
                .stdout(std::fs::File::create(&log).unwrap())
                .stderr(std::fs::OpenOptions::new().append(true).open(&log).unwrap())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
            let start = tokio::time::Instant::now();
            loop {
                if tokio::net::TcpStream::connect(address).await.is_ok() {
                    break;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(5) && child.try_wait().unwrap().is_none(),
                    "Xray: {}",
                    std::fs::read_to_string(&log).unwrap()
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tcp_target = Address::from_socket(tcp.local_addr().unwrap()).unwrap();
            let echo = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    let mut bytes = vec![0; 65536];
                    stream.read_exact(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                }
            });
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_target = Address::from_socket(udp.local_addr().unwrap()).unwrap();
            let udp_echo = tokio::spawn(async move {
                let mut bytes = [0; 65535];
                for _ in 0..3 {
                    let (n, peer) = udp.recv_from(&mut bytes).await.unwrap();
                    udp.send_to(&bytes[..n], peer).await.unwrap();
                }
            });
            let mut outbound = json!({"name":"vless-peer","protocol":"vless","address":"127.0.0.1","port":address.port(),"uuid":uuid,"rules":["127.0.0.0/8"]});
            if mode != "none" {
                let parts: Vec<_> = client.split('.').collect();
                outbound["encryption"] = json!(parts[0]);
                outbound["encryption_mode"] = json!(parts[1]);
                outbound["encryption_rtt"] = json!(parts[2]);
                outbound["encryption_password"] = json!(parts[3..].join("."));
            }
            let config = config(json!({"outbound":[outbound]})).await;
            let (registry, handle, budget, scope) = engine(&config).await;
            for _ in 0..2 {
                let mut stream = handle
                    .connect(&tcp_target, &ctx(), scope.clone())
                    .await
                    .unwrap();
                let payload = vec![0x91; 65536];
                ctx()
                    .run(async {
                        stream.write_all(&payload).await.unwrap();
                        stream.flush().await.unwrap();
                        let mut received = vec![0; payload.len()];
                        stream.read_exact(&mut received).await.unwrap();
                        assert_eq!(payload, received);
                    })
                    .await
                    .unwrap_or_else(|error| {
                        panic!(
                            "mode={mode} zero={zero}: {error:?}; Xray: {}",
                            std::fs::read_to_string(&log).unwrap()
                        )
                    });
            }
            let plan = handle
                .plan(&udp_target, Network::Udp, &ctx())
                .await
                .unwrap();
            let packet = handle.packet(&plan, scope, &ctx()).await.unwrap();
            // The pinned Xray peer drops zero-length UDP buffers; native loopback tests cover them.
            for payload in [&b"one"[..], &b"two"[..], &vec![0x72; 4096][..]] {
                packet.send(&plan.address, payload, &ctx()).await.unwrap();
                let reply = packet.recv(&ctx()).await.unwrap_or_else(|error| {
                    panic!(
                        "mode={mode} zero={zero} udp={} {error:?}; Xray: {}",
                        payload.len(),
                        std::fs::read_to_string(&log).unwrap()
                    )
                });
                assert_eq!(reply.source, udp_target);
                assert_eq!(reply.payload.as_slice(), payload);
            }
            drop(packet);
            drop(plan);
            drop(handle);
            registry.close(&ctx()).await.unwrap();
            assert_eq!(budget.snapshot().used().bytes(), 0);
            echo.await.unwrap();
            udp_echo.await.unwrap();
            child.kill().await.ok();
            child.wait().await.ok();
        }
    }
}

#[tokio::test]
async fn https_proxy_checks_trust_and_name_unless_explicitly_overridden() {
    let certificate = rcgen::generate_simple_self_signed(vec!["proxy.test".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, certificate.cert.pem()).unwrap();
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..4 {
            let (socket, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = acceptor.accept(socket).await else {
                continue;
            };
            let mut header = Vec::new();
            while let Ok(byte) = stream.read_u8().await {
                header.push(byte);
                if header.ends_with(b"\r\n\r\n") {
                    stream
                        .write_all(b"HTTP/1.1 200 OK\r\n\r\nsecure")
                        .await
                        .unwrap();
                    break;
                }
            }
        }
    });
    for (trust, name, insecure, success) in [
        (false, "proxy.test", false, false),
        (true, "wrong.test", false, false),
        (true, "proxy.test", false, true),
        (false, "wrong.test", true, true),
    ] {
        let config=config(json!({"outbound":[{"name":"proxy","protocol":"http","address":"127.0.0.1","port":address.port(),"security":"tls","sni":name,"allow_insecure":insecure,"rules":["domain:test"]}]})).await;
        let (budget, scope) = resources();
        let registry = Registry::new(
            dns::Settings::default(),
            terraris::route::Settings {
                outbound_ca_file: trust.then(|| ca.clone()),
                ..Default::default()
            },
            32,
        )
        .unwrap();
        let handle = registry
            .open(&config, scope.clone(), Metrics::default(), &ctx())
            .await
            .unwrap();
        let target = Address::from_domain("target.test", 443).unwrap();
        let result = handle.connect(&target, &ctx(), scope).await;
        if success {
            let mut stream = result.unwrap();
            let mut bytes = [0; 6];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"secure");
        } else {
            assert!(matches!(
                result,
                Err(Error::Outbound(terraris::outbound::Error::Tls))
            ));
        }
        drop(handle);
        registry.close(&ctx()).await.unwrap();
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    task.await.unwrap();
}

#[tokio::test]
async fn registry_shutdown_cancels_a_retained_packet_port() {
    let config = config(json!({})).await;
    let (registry, handle, budget, scope) = engine(&config).await;
    let target = Address::from_socket("127.0.0.1:11111".parse().unwrap()).unwrap();
    let plan = handle.plan(&target, Network::Udp, &ctx()).await.unwrap();
    let port = handle.packet(&plan, scope, &ctx()).await.unwrap();
    let reader = port.clone();
    let task = tokio::spawn(async move { reader.recv(&ctx()).await });
    tokio::task::yield_now().await;
    registry.close(&ctx()).await.unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(terraris::outbound::Error::Closed)
    ));
    assert!(matches!(
        port.send(&target, b"closed", &ctx()).await,
        Err(terraris::outbound::Error::Closed)
    ));
    drop(port);
    drop(plan);
    drop(handle);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

struct RegisteredOutbound {
    address: SocketAddr,
    compiled: Arc<AtomicUsize>,
    connected: Arc<AtomicUsize>,
}
impl terraris::outbound::registry::Factory for RegisteredOutbound {
    fn kind(&self) -> terraris::outbound::registry::Kind {
        terraris::outbound::registry::Kind::Proxy
    }
    fn compile(
        &self,
        config: &terraris::panel::Outbound,
        _: &terraris::outbound::registry::Context,
    ) -> Result<Option<Arc<dyn terraris::outbound::Connector>>, terraris::outbound::Error> {
        assert_eq!(config.protocol.as_str(), "registered");
        self.compiled.fetch_add(1, Ordering::SeqCst);
        Ok(Some(Arc::new(RegisteredConnector {
            address: self.address,
            connected: self.connected.clone(),
        })))
    }
}
struct RegisteredConnector {
    address: SocketAddr,
    connected: Arc<AtomicUsize>,
}
#[async_trait::async_trait]
impl terraris::outbound::Connector for RegisteredConnector {
    fn supports(&self, network: Network) -> bool {
        network == Network::Tcp
    }
    async fn connect(
        &self,
        target: &Address,
        _: &BufferScope,
        context: &OperationContext,
    ) -> Result<terraris::network::Stream, terraris::outbound::Error> {
        assert_eq!(target.to_string(), "unresolved.test:443");
        self.connected.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(
            context
                .run(tokio::net::TcpStream::connect(self.address))
                .await
                .map_err(terraris::outbound::Error::Stopped)??,
        ))
    }
    async fn packet(
        &self,
        _: BufferScope,
        _: &OperationContext,
    ) -> Result<Arc<dyn terraris::outbound::PacketPort>, terraris::outbound::Error> {
        panic!("UDP must be rejected before opening the connector")
    }
}
#[tokio::test]
async fn registered_outbound_alias_drives_routing_and_network_capability_without_builtin_dispatch()
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut io, _) = listener.accept().await.unwrap();
        io.write_all(b"custom").await.unwrap();
    });
    let compiled = Arc::new(AtomicUsize::new(0));
    let connected = Arc::new(AtomicUsize::new(0));
    let mut outbounds = terraris::outbound::Registry::builtin_builder();
    outbounds
        .register(
            "registered",
            &["custom-alias"],
            Arc::new(RegisteredOutbound {
                address,
                compiled: compiled.clone(),
                connected: connected.clone(),
            }),
        )
        .unwrap();
    let config = config(
        json!({"protocols":[{"type":"custom-inbound","enable":true,"port":12345}],
        "outbound":[{"name":"custom-proxy","protocol":"custom-alias","rules":["domain:test"]}]}),
    )
    .await;
    let registry = Registry::with_providers(
        dns::Settings::default(),
        terraris::route::Settings::default(),
        16,
        Arc::new(outbounds.build()),
        Arc::new(terraris::transport::Registry::builtin()),
    )
    .unwrap();
    let (budget, scope) = resources();
    let handle = registry
        .open(&config, scope.clone(), Metrics::default(), &ctx())
        .await
        .unwrap();
    let target = Address::from_domain("unresolved.test", 443).unwrap();
    let plan = handle.plan(&target, Network::Tcp, &ctx()).await.unwrap();
    assert_eq!(plan.decision.target, Target::Proxy(0));
    assert!(matches!(
        handle.plan(&target, Network::Udp, &ctx()).await,
        Err(Error::Outbound(terraris::outbound::Error::Unsupported))
    ));
    let mut stream = handle.connect(&target, &ctx(), scope).await.unwrap();
    let mut bytes = [0; 6];
    ctx()
        .run(stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"custom");
    assert_eq!(compiled.load(Ordering::SeqCst), 1);
    assert_eq!(connected.load(Ordering::SeqCst), 1);
    drop(stream);
    handle.close(&ctx()).await.unwrap();
    registry.close(&ctx()).await.unwrap();
    task.await.unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
struct PrefaceTransport;
impl terraris::transport::Factory for PrefaceTransport {
    fn inbound(
        &self,
        _: &terraris::panel::ProtocolConfig,
    ) -> Result<Arc<dyn terraris::transport::Inbound>, terraris::transport::Error> {
        Err(terraris::transport::Error::Unsupported)
    }
    fn outbound(
        &self,
        _: &terraris::panel::Outbound,
        _: Arc<rustls::ClientConfig>,
    ) -> Result<Arc<dyn terraris::transport::Outbound>, terraris::transport::Error> {
        Ok(Arc::new(PrefaceTransport))
    }
}
#[async_trait::async_trait]
impl terraris::transport::Outbound for PrefaceTransport {
    async fn connect(
        &self,
        addresses: &[SocketAddr],
        _: &BufferScope,
        context: &OperationContext,
    ) -> Result<(terraris::network::Stream, SocketAddr), terraris::transport::Error> {
        let mut stream = context
            .run(tokio::net::TcpStream::connect(addresses))
            .await
            .map_err(terraris::transport::Error::Stopped)??;
        let peer = stream.peer_addr()?;
        context
            .run(stream.write_all(b"marker\n"))
            .await
            .map_err(terraris::transport::Error::Stopped)??;
        Ok((Box::new(stream), peer))
    }
}
#[tokio::test]
async fn builtin_http_proxy_uses_registered_outbound_transport() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut io, _) = listener.accept().await.unwrap();
        let mut preface = [0; 7];
        io.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, b"marker\n");
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(io.read_u8().await.unwrap());
        }
        assert!(request.starts_with(b"CONNECT unresolved.test:443 HTTP/1.1\r\n"));
        io.write_all(b"HTTP/1.1 200 OK\r\n\r\ntransport")
            .await
            .unwrap();
    });
    let mut transports = terraris::transport::Registry::builtin_builder();
    transports
        .register("preface", &["marked"], Arc::new(PrefaceTransport))
        .unwrap();
    let config = config(json!({"outbound":[{"name":"proxy","protocol":"http","address":"127.0.0.1","port":address.port(),"transport":"marked","rules":["domain:test"]}]})).await;
    let registry = Registry::with_providers(
        dns::Settings::default(),
        terraris::route::Settings::default(),
        16,
        Arc::new(terraris::outbound::Registry::builtin()),
        Arc::new(transports.build()),
    )
    .unwrap();
    let (_, scope) = resources();
    let handle = registry
        .open(&config, scope.clone(), Metrics::default(), &ctx())
        .await
        .unwrap();
    let mut stream = handle
        .connect(
            &Address::from_domain("unresolved.test", 443).unwrap(),
            &ctx(),
            scope,
        )
        .await
        .unwrap();
    let mut bytes = [0; 9];
    ctx()
        .run(stream.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"transport");
    drop(stream);
    handle.close(&ctx()).await.unwrap();
    registry.close(&ctx()).await.unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn transport_rejects_unknown_tls_and_unused_options_without_fallback() {
    for extra in [
        json!({"transport":"ws"}),
        json!({"security":"reality"}),
        json!({"sni":"unused.test"}),
        json!({"allow_insecure":true}),
        json!({"host":"unused.test"}),
        json!({"path":"/unused"}),
        json!({"security":"tls","sni":"invalid/name"}),
        json!({"security":"tls","alpn":["h2"]}), // HTTP supports HTTP/1.1 only
    ] {
        let mut proxy = json!({"name":"proxy","protocol":"http","address":"127.0.0.1","port":12345,"rules":["domain:test"]});
        for (key, value) in extra.as_object().unwrap() {
            proxy[key] = value.clone();
        }
        let config = config(json!({"outbound":[proxy]})).await;
        let registry = Registry::new(
            dns::Settings::default(),
            terraris::route::Settings::default(),
            16,
        )
        .unwrap();
        let (_, scope) = resources();
        assert!(
            registry
                .open(&config, scope, Metrics::default(), &ctx())
                .await
                .is_err()
        );
        registry.close(&ctx()).await.unwrap();
    }
}
#[tokio::test]
async fn tls_transport_cancellation_drops_unfinished_handshake_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let config = config(json!({"outbound":[{"name":"proxy","protocol":"http","address":"127.0.0.1","port":address.port(),"security":"tls"}]})).await;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let transport = terraris::transport::Registry::builtin()
        .outbound(&config.outbounds[0], Arc::new(tls))
        .unwrap();
    let (_, scope) = resources();
    let cancel = CancellationToken::new();
    let operation = OperationContext::new(cancel.clone(), None);
    let addresses = [address];
    let connect = transport.connect(&addresses, &scope, &operation);
    tokio::pin!(connect);
    let mut peer = tokio::select! {
        result = &mut connect => panic!("unexpected result: {:?}", result.err()),
        accepted = listener.accept() => accepted.unwrap().0,
    };
    cancel.cancel();
    assert!(matches!(
        connect.await,
        Err(terraris::transport::Error::Stopped(
            terraris::time::StopReason::Cancelled
        ))
    ));
    let result = ctx().run(peer.read_to_end(&mut Vec::new())).await.unwrap();
    assert!(result.is_ok() || result.unwrap_err().kind() == std::io::ErrorKind::ConnectionReset);
}
