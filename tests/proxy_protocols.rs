// SPDX-License-Identifier: GPL-3.0-only
mod support;
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use support::{MockPanel, Reply};
use terraris::{
    buffer::BufferScope,
    network::{Address, Stream},
    panel::{Connection, ProtocolName, WireMode, ppanel::PPanelConnection},
    protocol::{
        self, flow,
        packet::{self, Codec},
        socksaddr::{Endpoint, Format, Host},
        trojan,
        uot::Version,
    },
    resource::{Budget, Limits},
    supervisor::Supervisor,
    task::CancellationToken,
    telemetry::Metrics,
    time::{Deadline, OperationContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
const PASSWORD: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
fn ctx() -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(5)).unwrap()),
    )
}
fn resources() -> (Budget, BufferScope) {
    let budget = Budget::new(Limits::new(32 << 20, 4096).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
    (budget, scope)
}
fn users() -> Value {
    json!({"users":[{"id":1,"uuid":PASSWORD,"speed_limit":0,"device_limit":0}]})
}
fn config(name: &str, address: SocketAddr) -> Value {
    json!({"code":200,"data":{"pull_interval":300,"push_interval":300,"traffic_report_threshold":1024,"ip_strategy":"prefer_ipv4","dns":[],"block":[],"outbound":[],"protocols":[{"type":name,"enable":true,"port":address.port(),"network":"tcp","security":"tls","sni":"localhost","cert_mode":"file","uot":true}],"total":1}})
}
fn web_config(name: &str, address: SocketAddr, transport: &str) -> Value {
    let mut value = config(name, address);
    let p = &mut value["data"]["protocols"][0];
    p["network"] = json!(transport);
    if transport != "tcp" {
        p["host"] = json!("localhost");
        if transport == "grpc" {
            p["service_name"] = json!("terraris");
        } else {
            p["path"] = json!("/relay");
        }
    }
    value
}
struct Harness {
    panel: MockPanel,
    supervisor: Arc<Supervisor<protocol::Registry>>,
    address: SocketAddr,
    files: tempfile::TempDir,
    cert: rustls::pki_types::CertificateDer<'static>,
    budget: Budget,
    name: &'static str,
}
impl Harness {
    async fn new(name: &'static str) -> Self {
        Self::with_transport(name, "tcp").await
    }
    async fn with_transport(name: &'static str, transport: &str) -> Self {
        Self::with_security(name, transport, true).await
    }
    async fn with_security(name: &'static str, transport: &str, secure: bool) -> Self {
        Self::with_xhttp_options(name, transport, secure, None).await
    }
    async fn with_xhttp_options(
        name: &'static str,
        transport: &str,
        secure: bool,
        xhttp: Option<(&str, &str, Value)>,
    ) -> Self {
        let quic = xhttp.as_ref().is_some_and(|(_, alpn, _)| *alpn == "h3");
        let address = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let files = tempfile::tempdir().unwrap();
        let cert = write_identity(files.path());
        let mut value = web_config(name, address, transport);
        if !secure {
            let p = &mut value["data"]["protocols"][0];
            p["security"] = json!("none");
            p["sni"] = json!("");
            p["cert_mode"] = json!("");
        }
        if let Some((mode, alpn, extra)) = xhttp {
            let p = &mut value["data"]["protocols"][0];
            p["xhttp_mode"] = json!(mode);
            p["xhttp_extra"] = json!(extra.to_string());
            if !alpn.is_empty() {
                p["alpn"] = json!([alpn]);
            }
        }
        let panel = MockPanel::start(vec![
            Reply::json(value).etag("\"proxy-config\""),
            Reply::json(users()),
        ])
        .await;
        let mut options = panel.options();
        options.wire_mode = WireMode::Json;
        let pins = options.fingerprints.clone();
        let connection: Arc<dyn Connection> = Arc::new(PPanelConnection::new(options).unwrap());
        let factory = protocol::Registry::with_tls(
            connection.clone(),
            protocol::vless::Options {
                listen: Ipv4Addr::LOCALHOST.into(),
                ..Default::default()
            },
            flow::Options::default(),
            terraris::dns::Settings::default(),
            terraris::route::Settings::default(),
            terraris::certificate::Settings {
                cert_file: Some(files.path().join("cert.pem")),
                key_file: Some(files.path().join("key.pem")),
                ..Default::default()
            },
            Metrics::default(),
        )
        .unwrap();
        let (budget, scope) = resources();
        let supervisor = Arc::new(
            Supervisor::new(
                connection,
                Arc::new(factory),
                scope,
                terraris::supervisor::Options {
                    // A killed UDP peer cannot send QUIC CONNECTION_CLOSE. Exercise
                    // the bounded forced-drain path without a 30-second fixture wait.
                    drain_timeout: if quic {
                        Duration::from_millis(100)
                    } else {
                        Duration::from_secs(30)
                    },
                    close_timeout: Duration::from_secs(if quic { 3 } else { 1 }),
                    ..Default::default()
                },
                Metrics::default(),
                pins,
                None,
            )
            .unwrap(),
        );
        supervisor.sync_config(&ctx()).await.unwrap();
        Self {
            panel,
            supervisor,
            address,
            files,
            cert,
            budget,
            name,
        }
    }
    async fn tls(&self) -> Stream {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(self.cert.clone()).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let socket = TcpStream::connect(self.address).await.unwrap();
        Box::new(
            ctx()
                .run(
                    tokio_rustls::TlsConnector::from(Arc::new(tls))
                        .connect("localhost".try_into().unwrap(), socket),
                )
                .await
                .unwrap()
                .unwrap(),
        )
    }
    async fn tcp(&self, target: SocketAddr) -> Stream {
        let mut stream = self.tls().await;
        trojan::write_request(
            &mut stream,
            PASSWORD,
            1,
            &Endpoint::from_address(&Address::from_socket(target).unwrap()).unwrap(),
        )
        .await
        .unwrap();
        stream
    }
    async fn close(&self) {
        self.panel.push(Reply::json(json!({"code":200})));
        self.panel.push(Reply::json(json!({"code":200})));
        self.supervisor.close(&ctx()).await.unwrap();
        assert_eq!(self.budget.snapshot().used().bytes(), 0);
    }
}
fn write_identity(path: &std::path::Path) -> rustls::pki_types::CertificateDer<'static> {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(path.join("cert.pem"), certificate.cert.pem()).unwrap();
    std::fs::write(
        path.join("key.pem"),
        certificate.signing_key.serialize_pem(),
    )
    .unwrap();
    certificate.cert.der().clone()
}
async fn echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {accepted=listener.accept()=>{let(mut s,_)=accepted.unwrap();tasks.spawn(async move{let(mut r,mut w)=s.split();let _=tokio::io::copy(&mut r,&mut w).await;});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
    });
    (address, task)
}
async fn exchange(stream: &mut Stream, data: &[u8]) {
    ctx().run(stream.write_all(data)).await.unwrap().unwrap();
    let mut reply = vec![0; data.len()];
    ctx()
        .run(stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, data);
}
#[tokio::test]
async fn trojan_tls_tcp_authentication_accounting_and_user_revocation() {
    let h = Harness::new("trojan").await;
    let (target, task) = echo().await;
    let mut stream = h.tcp(target).await;
    exchange(&mut stream, b"hello").await;
    let runtime = h
        .supervisor
        .runtime(&ProtocolName::new("trojan").unwrap())
        .unwrap();
    let batch = runtime
        .core()
        .reports()
        .traffic_batch(0, 10)
        .unwrap()
        .unwrap();
    assert_eq!(batch.values()[0].upload, 5);
    assert_eq!(batch.values()[0].download, 5);
    drop(batch);
    let mut invalid = h.tls().await;
    trojan::write_request(
        &mut invalid,
        "wrong",
        1,
        &Endpoint::from_address(&Address::from_socket(target).unwrap()).unwrap(),
    )
    .await
    .unwrap();
    let result = ctx().run(invalid.read_u8()).await.unwrap();
    assert!(result.is_err());
    drop(invalid);
    h.panel.push(Reply::json(json!({"users":[]})));
    runtime.controller.sync_users(&ctx()).await.unwrap();
    assert!(ctx().run(stream.read_u8()).await.unwrap().is_err());
    drop(stream);
    h.close().await;
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn pem_reload_is_transactional_and_keeps_established_tls_streams() {
    let mut h = Harness::new("trojan").await;
    let (target, task) = echo().await;
    let mut old = h.tcp(target).await;
    exchange(&mut old, b"old").await;
    let name = ProtocolName::new(h.name).unwrap();
    let fingerprint = h.supervisor.runtime(&name).unwrap().certificate().unwrap();
    let generation = h.supervisor.snapshot().generation;
    let key = std::fs::read(h.files.path().join("key.pem")).unwrap();
    std::fs::write(h.files.path().join("key.pem"), b"invalid").unwrap();
    h.panel.push(Reply::json(config(h.name, h.address)));
    assert!(h.supervisor.sync_config(&ctx()).await.is_err());
    assert_eq!(h.supervisor.snapshot().generation, generation);
    assert_eq!(
        h.supervisor.runtime(&name).unwrap().certificate(),
        Some(fingerprint.clone())
    );
    exchange(&mut old, b"retained").await;
    let other = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(
        h.files.path().join("key.pem"),
        other.signing_key.serialize_pem(),
    )
    .unwrap();
    h.panel.push(Reply::json(config(h.name, h.address)));
    assert!(h.supervisor.sync_config(&ctx()).await.is_err());
    assert_eq!(h.supervisor.snapshot().generation, generation);
    exchange(&mut old, b"mismatched key retained").await;
    std::fs::write(h.files.path().join("key.pem"), key).unwrap();
    h.cert = write_identity(h.files.path());
    h.panel.push(Reply::raw(304, None, Vec::new()));
    h.panel.push(Reply::json(users()));
    h.supervisor.sync_config(&ctx()).await.unwrap();
    assert_ne!(h.supervisor.snapshot().generation, generation);
    assert_ne!(
        h.supervisor.runtime(&name).unwrap().certificate(),
        Some(fingerprint)
    );
    let mut new = h.tcp(target).await;
    exchange(&mut new, b"new").await;
    exchange(&mut old, b"still old").await;
    drop(new);
    drop(old);
    h.close().await;
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn trojan_udp_and_uot_versions_preserve_empty_datagrams_and_multiple_targets() {
    let h = Harness::new("trojan").await;
    let mut addresses = Vec::new();
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        addresses.push(Address::from_socket(socket.local_addr().unwrap()).unwrap());
        tasks.push(tokio::spawn(async move {
            let mut b = [0; 65535];
            loop {
                let (n, peer) = socket.recv_from(&mut b).await.unwrap();
                socket.send_to(&b[..n], peer).await.unwrap();
            }
        }));
    }
    let address = addresses[0].clone();
    for mode in 0..4 {
        let mut stream = h.tls().await;
        let codec = if mode == 0 {
            trojan::write_request(
                &mut stream,
                PASSWORD,
                3,
                &Endpoint {
                    host: Host::Ip(Ipv4Addr::UNSPECIFIED.into()),
                    port: 0,
                },
            )
            .await
            .unwrap();
            Codec::Trojan
        } else {
            let version = if mode == 1 { Version::V1 } else { Version::V2 };
            trojan::write_request(&mut stream, PASSWORD, 1, &version.endpoint())
                .await
                .unwrap();
            version
                .write(&mut stream, if mode == 3 { Some(&address) } else { None })
                .await
                .unwrap()
        };
        let (_, scope) = resources();
        let (read, mut write) = tokio::io::split(stream);
        let mut reader = packet::Reader::new(read, codec.clone(), scope);
        let targets = if mode == 3 {
            &addresses[..1]
        } else {
            &addresses[..]
        };
        for address in targets {
            for data in [&b""[..], &b"udp"[..], &[7; 8192][..]] {
                packet::write(&mut write, &codec, address, data)
                    .await
                    .unwrap();
                let packet = ctx().run(reader.next()).await.unwrap().unwrap().unwrap();
                assert_eq!(&packet.address, address);
                assert_eq!(packet.payload.as_slice(), data);
            }
        }
        drop(reader);
        drop(write);
    }
    h.close().await;
    for task in tasks {
        task.abort();
        task.await.ok();
    }
}
#[tokio::test]
async fn packet_parsers_resume_after_cancel_and_reject_malformed_trailers() {
    let (_, scope) = resources();
    let (target, mut feed) = tokio::io::duplex(1024);
    let address = Address::from_socket("127.0.0.1:53".parse().unwrap()).unwrap();
    let mut header = Endpoint::from_address(&address)
        .unwrap()
        .encode(Format::Socks)
        .unwrap();
    header.extend([0, 3]);
    header.extend(b"\r\n");
    header.extend(b"abc");
    let mut reader = packet::Reader::new(target, Codec::Trojan, scope);
    for byte in header.iter().take(header.len() - 1) {
        feed.write_u8(*byte).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(1), reader.next())
                .await
                .is_err()
        );
    }
    feed.write_u8(*header.last().unwrap()).await.unwrap();
    let result = reader.next().await.unwrap().unwrap();
    assert_eq!(result.payload.as_slice(), b"abc");
    let mut bad = header;
    let n = bad.len();
    bad[n - 4] = 0;
    feed.write_all(&bad).await.unwrap();
    assert!(reader.next().await.is_err());
    assert!(reader.next().await.is_err());
}

use sha2::{Digest, Sha256};
use terraris::protocol::anytls::wire as aw;
struct AnyClient {
    read: aw::Reader<tokio::io::ReadHalf<Stream>>,
    write: tokio::io::WriteHalf<Stream>,
}
impl AnyClient {
    async fn new(h: &Harness, version: u8) -> Self {
        let mut stream = h.tls().await;
        stream
            .write_all(&Sha256::digest(PASSWORD.as_bytes()))
            .await
            .unwrap();
        stream.write_u16(30).await.unwrap();
        stream.write_all(&[0; 30]).await.unwrap();
        let (read, write) = tokio::io::split(stream);
        let (_, scope) = resources();
        let mut client = Self {
            read: aw::Reader::new(read, scope),
            write,
        };
        client
            .send(
                aw::SETTINGS,
                0,
                format!("v={version}\nclient=terraris/test\npadding-md5=none").as_bytes(),
            )
            .await;
        let padding = client.next().await;
        assert_eq!(padding.command, aw::PADDING);
        assert_eq!(
            padding.data.as_slice(),
            terraris::protocol::anytls::padding::DEFAULT.as_bytes()
        );
        if version == 2 {
            let settings = client.next().await;
            assert_eq!(settings.command, aw::SERVER_SETTINGS);
            assert_eq!(settings.data.as_slice(), b"v=2");
        }
        client
    }
    async fn send(&mut self, command: u8, id: u32, data: &[u8]) {
        let mut frame = vec![command];
        frame.extend(id.to_be_bytes());
        frame.extend((data.len() as u16).to_be_bytes());
        frame.extend(data);
        ctx()
            .run(self.write.write_all(&frame))
            .await
            .unwrap()
            .unwrap();
        self.write.flush().await.unwrap();
    }
    async fn next(&mut self) -> aw::Frame {
        ctx().run(self.read.next()).await.unwrap().unwrap().unwrap()
    }
    async fn open(&mut self, id: u32, endpoint: &Endpoint) {
        self.send(aw::SYN, id, &[]).await;
        self.send(aw::PSH, id, &endpoint.encode(Format::Socks).unwrap())
            .await;
    }
    async fn ack(&mut self, id: u32) {
        let frame = self.next().await;
        assert_eq!(frame.command, aw::SYNACK);
        assert_eq!(frame.id, id);
        assert!(frame.data.is_empty());
    }
}
#[tokio::test]
async fn anytls_versions_multiplex_reuse_sessions_and_answer_heartbeat() {
    let h = Harness::new("anytls").await;
    let (target, task) = echo().await;
    let endpoint = Endpoint::from_address(&Address::from_socket(target).unwrap()).unwrap();
    for version in [1, 2] {
        let mut client = AnyClient::new(&h, version).await;
        client.open(1, &endpoint).await;
        if version == 2 {
            client.ack(1).await;
        }
        client.open(2, &endpoint).await;
        if version == 2 {
            client.ack(2).await;
        }
        client.send(aw::PSH, 1, b"first").await;
        client.send(aw::PSH, 2, b"second").await;
        let mut replies = std::collections::BTreeMap::new();
        for _ in 0..2 {
            let frame = client.next().await;
            assert_eq!(frame.command, aw::PSH);
            replies.insert(frame.id, frame.data.as_slice().to_vec());
        }
        assert_eq!(replies[&1], b"first");
        assert_eq!(replies[&2], b"second");
        client.send(aw::FIN, 1, b"").await;
        client.send(aw::FIN, 2, b"").await;
        client.open(3, &endpoint).await;
        if version == 2 {
            client.ack(3).await;
        }
        client.send(aw::PSH, 3, b"reused").await;
        let frame = client.next().await;
        assert_eq!(frame.command, aw::PSH);
        assert_eq!(frame.id, 3);
        assert_eq!(frame.data.as_slice(), b"reused");
        if version == 2 {
            client.send(aw::HEART_REQUEST, 77, b"").await;
            let frame = client.next().await;
            assert_eq!(frame.command, aw::HEART_RESPONSE);
            assert_eq!(frame.id, 77);
        }
        drop(client);
    }
    h.close().await;
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn anytls_udp_v2_supports_split_destination_headers_and_empty_packets() {
    let h = Harness::new("anytls").await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = Address::from_socket(socket.local_addr().unwrap()).unwrap();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(&bytes[..n], peer).await.unwrap();
        }
    });
    let mut client = AnyClient::new(&h, 2).await;
    client.send(aw::SYN, 1, b"").await;
    let target = Version::V2.endpoint().encode(Format::Socks).unwrap();
    for bytes in target.chunks(3) {
        client.send(aw::PSH, 1, bytes).await;
    }
    let mut request = vec![0];
    request.extend(
        Endpoint {
            host: Host::Ip(Ipv4Addr::UNSPECIFIED.into()),
            port: 0,
        }
        .encode(Format::Socks)
        .unwrap(),
    );
    client.send(aw::PSH, 1, &request).await;
    client.ack(1).await;
    for data in [&b""[..], &b"datagram"[..]] {
        let mut frame = Endpoint::from_address(&address)
            .unwrap()
            .encode(Format::Uot)
            .unwrap();
        frame.extend((data.len() as u16).to_be_bytes());
        frame.extend(data);
        client.send(aw::PSH, 1, &frame).await;
        // UoT writes its address/length and payload separately; collect stream PSH
        // fragments until the complete UDP frame is available.
        let mut response = Vec::<u8>::new();
        while response.len() < frame.len() {
            let reply = client.next().await;
            assert_eq!(reply.command, aw::PSH);
            assert_eq!(reply.id, 1);
            response.extend(reply.data.as_slice());
        }
        assert_eq!(response, frame);
    }
    drop(client);
    h.close().await;
    task.abort();
    task.await.ok();
}
#[tokio::test]
async fn anytls_requires_settings_and_rejects_reused_stream_ids() {
    let h = Harness::new("anytls").await;
    let mut stream = h.tls().await;
    stream
        .write_all(&Sha256::digest(PASSWORD.as_bytes()))
        .await
        .unwrap();
    stream.write_u16(0).await.unwrap();
    let (read, write) = tokio::io::split(stream);
    let (_, scope) = resources();
    let mut client = AnyClient {
        read: aw::Reader::new(read, scope),
        write,
    };
    client.send(aw::SYN, 1, b"").await;
    assert_eq!(client.next().await.command, aw::ALERT);
    drop(client);
    let mut client = AnyClient::new(&h, 2).await;
    client.send(aw::SYN, 1, b"").await;
    client.send(aw::SYN, 1, b"").await;
    let result = ctx().run(client.read.next()).await.unwrap();
    assert!(result.is_err() || result.unwrap().is_none());
    drop(client);
    h.close().await;
}

#[tokio::test]
#[ignore = "requires TERRARIS_PROXY_CLIENT built from tests/interop/proxy"]
async fn official_anytls_client_interoperates_and_reuses_one_tls_session() {
    let h = Harness::new("anytls").await;
    let (target, tcp) = echo().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = socket.local_addr().unwrap();
    let udp = tokio::spawn(async move {
        let mut b = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut b).await.unwrap();
            socket.send_to(&b[..n], peer).await.unwrap();
        }
    });
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(std::env::var("TERRARIS_PROXY_CLIENT").expect("Go helper"))
            .args([
                "--server",
                &h.address.to_string(),
                "--tcp",
                &target.to_string(),
                "--udp",
                &udp_address.to_string(),
                "--password",
                PASSWORD,
                "--ca",
            ])
            .arg(h.files.path().join("cert.pem"))
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("session reuse passed"));
    h.close().await;
    tcp.abort();
    tcp.await.ok();
    udp.abort();
    udp.await.ok();
}

#[tokio::test]
async fn anytls_stream_capacity_recovery_and_user_revocation() {
    let h = Harness::new("anytls").await;
    let mut client = AnyClient::new(&h, 2).await;
    for id in 1..=33 {
        client.send(aw::SYN, id, b"").await;
    }
    let rejected = client.next().await;
    assert_eq!(rejected.command, aw::SYNACK);
    assert_eq!(rejected.id, 33);
    assert!(!rejected.data.is_empty());
    let fin = client.next().await;
    assert_eq!(fin.command, aw::FIN);
    assert_eq!(fin.id, 33);
    client.send(aw::HEART_REQUEST, 9, b"").await;
    assert_eq!(client.next().await.command, aw::HEART_RESPONSE);
    for id in 1..=32 {
        client.send(aw::FIN, id, b"").await;
    }
    let runtime = h
        .supervisor
        .runtime(&ProtocolName::new("anytls").unwrap())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while runtime.core().active_sessions() > 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (target, task) = echo().await;
    client
        .open(
            34,
            &Endpoint::from_address(&Address::from_socket(target).unwrap()).unwrap(),
        )
        .await;
    client.ack(34).await;
    client.send(aw::PSH, 34, b"still usable").await;
    assert_eq!(client.next().await.data.as_slice(), b"still usable");
    h.panel.push(Reply::json(json!({"users":[]})));
    runtime.controller.sync_users(&ctx()).await.unwrap();
    let closed = ctx().run(client.read.next()).await.unwrap();
    assert!(closed.is_err() || closed.unwrap().is_none());
    drop(client);
    h.close().await;
    task.abort();
    task.await.ok();
}
async fn socks_connect(address: SocketAddr, command: u8, target: SocketAddr) -> (Stream, Endpoint) {
    let mut stream: Stream = Box::new(TcpStream::connect(address).await.unwrap());
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut auth = [0; 2];
    stream.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [5, 0]);
    let mut request = vec![5, command, 0];
    request.extend(
        Endpoint {
            host: Host::Ip(target.ip()),
            port: target.port(),
        }
        .encode(Format::Socks)
        .unwrap(),
    );
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 3];
    ctx()
        .run(stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, [5, 0, 0]);
    let endpoint = Endpoint::read(&mut stream, Format::Socks).await.unwrap();
    (stream, endpoint)
}
#[tokio::test]
#[ignore = "requires TERRARIS_XRAY pinned to the documented Xray commit"]
async fn official_xray_trojan_tcp_udp_interoperate() {
    let h = Harness::new("trojan").await;
    let (target, tcp) = echo().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target = socket.local_addr().unwrap();
    let udp = tokio::spawn(async move {
        let mut b = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut b).await.unwrap();
            socket.send_to(&b[..n], peer).await.unwrap();
        }
    });
    let socks = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let file = h.files.path().join("xray.json");
    std::fs::write(&file,serde_json::to_vec(&json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks.port(),"protocol":"socks","settings":{"auth":"noauth","udp":true}}],"outbounds":[{"protocol":"trojan","settings":{"servers":[{"address":"127.0.0.1","port":h.address.port(),"password":PASSWORD}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"localhost","pinnedPeerCertSha256":format!("{:x}",Sha256::digest(h.cert.as_ref()))}}}]})).unwrap()).unwrap();
    let mut child =
        tokio::process::Command::new(std::env::var("TERRARIS_XRAY").expect("Xray binary"))
            .args(["run", "-c"])
            .arg(file)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if TcpStream::connect(socks).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let (mut stream, _) = socks_connect(socks, 1, target).await;
    exchange(&mut stream, &[7; 32768]).await;
    drop(stream);
    let (control, relay) = socks_connect(socks, 3, "0.0.0.0:0".parse().unwrap()).await;
    let mut relay = relay.address().unwrap().socket_addr().unwrap();
    if relay.ip().is_unspecified() {
        relay.set_ip(Ipv4Addr::LOCALHOST.into());
    }
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = Endpoint::from_address(&Address::from_socket(udp_target).unwrap()).unwrap();
    for payload in [&b"trojan udp"[..], &[8; 4096][..]] {
        let mut bytes = vec![0, 0, 0];
        bytes.extend(endpoint.encode(Format::Socks).unwrap());
        bytes.extend(payload);
        socket.send_to(&bytes, relay).await.unwrap();
        let mut reply = vec![0; 16384];
        let (n, _) = ctx()
            .run(socket.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..3], &[0, 0, 0]);
        let (source, header) = Endpoint::parse(&reply[3..n], Format::Socks)
            .unwrap()
            .unwrap();
        assert_eq!(source, endpoint);
        assert_eq!(&reply[3 + header..n], payload);
    }
    drop(control);
    child.start_kill().unwrap();
    child.wait().await.unwrap();
    h.close().await;
    tcp.abort();
    tcp.await.ok();
    udp.abort();
    udp.await.ok();
}

#[tokio::test]
async fn anytls_reload_drains_existing_streams_and_rejects_new_streams_on_retired_carrier() {
    let h = Harness::new("anytls").await;
    let (target, task) = echo().await;
    let endpoint = Endpoint::from_address(&Address::from_socket(target).unwrap()).unwrap();
    let mut old = AnyClient::new(&h, 2).await;
    old.open(1, &endpoint).await;
    old.ack(1).await;
    let mut next = config(h.name, h.address);
    next["data"]["traffic_report_threshold"] = json!(2048);
    h.panel.push(Reply::json(next));
    h.panel.push(Reply::json(users()));
    h.supervisor.sync_config(&ctx()).await.unwrap();
    old.open(2, &endpoint).await;
    let rejected = old.next().await;
    assert_eq!(rejected.command, aw::SYNACK);
    assert_eq!(rejected.id, 2);
    assert!(!rejected.data.is_empty());
    let fin = old.next().await;
    assert_eq!(fin.command, aw::FIN);
    assert_eq!(fin.id, 2);
    old.send(aw::PSH, 1, b"draining").await;
    assert_eq!(old.next().await.data.as_slice(), b"draining");
    let mut new = AnyClient::new(&h, 2).await;
    new.open(1, &endpoint).await;
    new.ack(1).await;
    new.send(aw::PSH, 1, b"new generation").await;
    assert_eq!(new.next().await.data.as_slice(), b"new generation");
    old.send(aw::FIN, 1, b"").await;
    let closed = ctx().run(old.read.next()).await.unwrap();
    assert!(closed.is_err() || closed.unwrap().is_none());
    drop(old);
    drop(new);
    h.close().await;
    task.abort();
    task.await.ok();
}

#[tokio::test]
async fn vless_tls_and_uot_use_common_certificate_and_udp_runtime() {
    let h = Harness::new("vless").await;
    let (target, tcp) = echo().await;
    let mut stream = h.tls().await;
    terraris::protocol::vless::wire::Request {
        uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
        command: terraris::protocol::vless::wire::Command::Tcp,
        target: Some(Address::from_socket(target).unwrap()),
    }
    .write(&mut stream)
    .await
    .unwrap();
    let mut response = [0; 2];
    ctx()
        .run(stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [0, 0]);
    exchange(&mut stream, b"VLESS over rustls").await;
    drop(stream);
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = Address::from_socket(socket.local_addr().unwrap()).unwrap();
    let udp = tokio::spawn(async move {
        let mut bytes = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            socket.send_to(&bytes[..n], peer).await.unwrap();
        }
    });
    for version in [Version::V1, Version::V2] {
        let mut stream = h.tls().await;
        // Real UoT clients use a zero port for the reserved control domain.
        let mut request = vec![0];
        request.extend(uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes());
        request.extend([0, 1, 0, 0, 2]);
        request.push(version.domain().len() as u8);
        request.extend(version.domain().as_bytes());
        stream.write_all(&request).await.unwrap();
        ctx()
            .run(stream.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, [0, 0]);
        let codec = version.write(&mut stream, None).await.unwrap();
        packet::write(&mut stream, &codec, &address, b"uot")
            .await
            .unwrap();
        let (_, scope) = resources();
        let mut reader = packet::Reader::new(stream, codec, scope);
        let reply = ctx().run(reader.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(reply.address, address);
        assert_eq!(reply.payload.as_slice(), b"uot");
        drop(reply);
        drop(reader);
    }
    h.close().await;
    tcp.abort();
    tcp.await.ok();
    udp.abort();
    udp.await.ok();
}

#[tokio::test]
async fn per_protocol_pem_paths_resolve_locally_and_sni_mismatch_is_rejected() {
    let files = tempfile::tempdir().unwrap();
    write_identity(files.path());
    let path = files.path().join("terraris.toml");
    std::fs::write(
        &path,
        r#"
[panel]
base_url="http://127.0.0.1:1"
server_id=1
secret_env="TEST_UNUSED_SECRET"
[tls]
cert_file="missing-default.pem"
key_file="missing-default-key.pem"
[tls.protocols.anytls]
cert_file="cert.pem"
key_file="key.pem"
"#,
    )
    .unwrap();
    let settings = terraris::config::Config::load(&path).unwrap().tls;
    assert_eq!(
        settings.protocols["anytls"].cert_file,
        files.path().join("cert.pem")
    );
    let panel = MockPanel::start(vec![Reply::json(config(
        "anytls",
        "127.0.0.1:443".parse().unwrap(),
    ))])
    .await;
    let mut options = panel.options();
    options.wire_mode = WireMode::Json;
    let connection = PPanelConnection::new(options).unwrap();
    let terraris::panel::Fetch::Changed { value, .. } =
        connection.server().get_config(None).await.unwrap()
    else {
        panic!("config");
    };
    let mut protocol = value.protocols[0].clone();
    let identity = settings.prepare(&protocol).unwrap();
    assert!(!identity.reload_required().unwrap());
    protocol.sni = "other.example".into();
    assert!(settings.prepare(&protocol).is_err());
    protocol.sni = "localhost".into();
    protocol.alpn = vec![String::new()];
    assert!(settings.prepare(&protocol).is_err());
    protocol.alpn.clear();
    protocol.protocol = ProtocolName::new("trojan").unwrap();
    assert!(settings.prepare(&protocol).is_err());
}

async fn web_peer(h: &Harness, transport: &str) -> (Stream, Budget) {
    transport_peer(h.cert.clone(), h.address, transport).await
}
async fn transport_peer(
    cert: rustls::pki_types::CertificateDer<'static>,
    address: SocketAddr,
    transport: &str,
) -> (Stream, Budget) {
    transport_peer_security(cert, address, transport, true).await
}
async fn transport_peer_security(
    cert: rustls::pki_types::CertificateDer<'static>,
    address: SocketAddr,
    transport: &str,
    secure: bool,
) -> (Stream, Budget) {
    let connector = transport_connector(cert, address, transport, secure, 0).await;
    let (budget, scope) = resources();
    let (stream, _) = connector.connect(&[address], &scope, &ctx()).await.unwrap();
    (stream, budget)
}
async fn transport_connector(
    cert: rustls::pki_types::CertificateDer<'static>,
    address: SocketAddr,
    transport: &str,
    secure: bool,
    early: usize,
) -> Arc<dyn terraris::transport::Outbound> {
    transport_connector_extra(cert, address, transport, secure, early, None).await
}
async fn transport_connector_extra(
    cert: rustls::pki_types::CertificateDer<'static>,
    address: SocketAddr,
    transport: &str,
    secure: bool,
    early: usize,
    xhttp: Option<(&str, &str, Value)>,
) -> Arc<dyn terraris::transport::Outbound> {
    let mut value = config("vless", address);
    value["data"]["outbound"] = json!([{"name":"remote","protocol":"vless","address":"127.0.0.1","port":address.port(),"uuid":PASSWORD,"security":"tls","sni":"localhost","host":"localhost","transport":transport,"path":if transport=="grpc"{""}else{"/relay"},"service_name":if transport=="grpc"{"terraris"}else{""}}]);
    if early > 0 {
        value["data"]["outbound"][0]["path"] = json!(format!("/relay?ed={early}"));
    }
    if !secure {
        let outbound = &mut value["data"]["outbound"][0];
        outbound["security"] = json!("none");
        outbound["sni"] = json!("");
    }
    if let Some((mode, alpn, extra)) = xhttp {
        let o = &mut value["data"]["outbound"][0];
        o["xhttp_mode"] = json!(mode);
        o["xhttp_extra"] = json!(extra.to_string());
        if !alpn.is_empty() {
            o["alpn"] = json!([alpn]);
        }
    }
    let panel = MockPanel::start(vec![Reply::json(value)]).await;
    let mut options = panel.options();
    options.wire_mode = WireMode::Json;
    let connection = PPanelConnection::new(options).unwrap();
    let terraris::panel::Fetch::Changed { value, .. } =
        connection.server().get_config(None).await.unwrap()
    else {
        panic!("config");
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let roots = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    terraris::transport::Registry::builtin()
        .outbound(&value.outbounds[0], Arc::new(roots))
        .unwrap()
}
#[tokio::test]
async fn web_transports_carry_vless_tls_with_flow_control_and_release_resources() {
    for transport in ["ws", "httpupgrade", "grpc"] {
        for secure in [false, true] {
            let h = Harness::with_security("vless", transport, secure).await;
            let (target, echo) = echo().await;
            let (mut stream, budget) =
                transport_peer_security(h.cert.clone(), h.address, transport, secure).await;
            terraris::protocol::vless::wire::Request {
                uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
                command: terraris::protocol::vless::wire::Command::Tcp,
                target: Some(Address::from_socket(target).unwrap()),
            }
            .write(&mut stream)
            .await
            .unwrap();
            let mut response = [0; 2];
            ctx()
                .run(stream.read_exact(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(response, [0, 0], "{transport}");
            let payload = vec![42; 512 << 10];
            let mut reply = vec![0; payload.len()];
            let (mut read, mut write) = tokio::io::split(stream);
            ctx()
                .run(async {
                    tokio::try_join!(write.write_all(&payload), read.read_exact(&mut reply))
                })
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, payload, "{transport}");
            if transport != "ws" {
                ctx().run(write.shutdown()).await.unwrap().unwrap();
                let mut eof = [0];
                assert_eq!(
                    ctx().run(read.read(&mut eof)).await.unwrap().unwrap(),
                    0,
                    "{transport} half-close"
                );
            }
            drop(read);
            drop(write);
            assert_eq!(budget.snapshot().used().bytes(), 0, "{transport}");
            h.close().await;
            echo.abort();
            echo.await.ok();
        }
    }
}
#[tokio::test]
#[ignore = "requires TERRARIS_XRAY pinned to the documented Xray commit"]
async fn official_xray_web_transports_vless_and_trojan_interoperate() {
    for protocol in ["vless", "trojan"] {
        for (transport, multi) in [
            ("ws", false),
            ("httpupgrade", false),
            ("grpc", false),
            ("grpc", true),
        ] {
            let h = Harness::with_transport(protocol, transport).await;
            let (target, echo) = echo().await;
            let socks = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap()
                .local_addr()
                .unwrap();
            let mut settings = json!({"network":transport,"security":"tls","tlsSettings":{"serverName":"localhost","pinnedPeerCertSha256":format!("{:x}",Sha256::digest(h.cert.as_ref()))}});
            match transport {
                "ws" => settings["wsSettings"] = json!({"host":"localhost","path":"/relay"}),
                "httpupgrade" => {
                    settings["httpupgradeSettings"] = json!({"host":"localhost","path":"/relay"})
                }
                "grpc" => {
                    settings["grpcSettings"] =
                        json!({"authority":"localhost","serviceName":"terraris","multiMode":multi})
                }
                _ => unreachable!(),
            }
            let mut outbound = json!({"protocol":protocol,"streamSettings":settings});
            outbound["settings"] = if protocol == "trojan" {
                json!({"servers":[{"address":"127.0.0.1","port":h.address.port(),"password":PASSWORD}]})
            } else {
                json!({"vnext":[{"address":"127.0.0.1","port":h.address.port(),"users":[{"id":PASSWORD,"encryption":"none"}]}]})
            };
            let file = h.files.path().join("web-client.json");
            let log = h.files.path().join("web-client.log");
            std::fs::write(&file,serde_json::to_vec(&json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks.port(),"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[outbound]})).unwrap()).unwrap();
            let mut child =
                tokio::process::Command::new(std::env::var("TERRARIS_XRAY").expect("Xray binary"))
                    .args(["run", "-c"])
                    .arg(file)
                    .stdout(std::fs::File::create(&log).unwrap())
                    .stderr(std::fs::OpenOptions::new().append(true).open(&log).unwrap())
                    .kill_on_drop(true)
                    .spawn()
                    .unwrap();
            let start = tokio::time::Instant::now();
            loop {
                if TcpStream::connect(socks).await.is_ok() {
                    break;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(5) && child.try_wait().unwrap().is_none(),
                    "{}",
                    std::fs::read_to_string(&log).unwrap()
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let mut streams = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = socks_connect(socks, 1, target).await;
                exchange(&mut stream, &[7; 32768]).await;
                streams.push(stream);
            }
            for mut stream in streams {
                exchange(&mut stream, b"reuse existing logical streams").await;
            }
            child.start_kill().unwrap();
            child.wait().await.unwrap();
            h.close().await;
            echo.abort();
            echo.await.ok();
        }
    }
}

#[tokio::test]
#[ignore = "requires TERRARIS_XRAY pinned to the documented Xray commit"]
async fn native_web_outbounds_interoperate_with_xray_servers() {
    for transport in ["ws", "httpupgrade", "grpc"] {
        let files = tempfile::tempdir().unwrap();
        let cert = write_identity(files.path());
        let (target, echo) = echo().await;
        let address = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let mut settings = json!({"network":transport,"security":"tls","tlsSettings":{"certificates":[{"certificateFile":files.path().join("cert.pem"),"keyFile":files.path().join("key.pem")}]}});
        match transport {
            "ws" => settings["wsSettings"] = json!({"host":"localhost","path":"/relay"}),
            "httpupgrade" => {
                settings["httpupgradeSettings"] = json!({"host":"localhost","path":"/relay"})
            }
            "grpc" => settings["grpcSettings"] = json!({"serviceName":"terraris"}),
            _ => unreachable!(),
        }
        let file = files.path().join("web-server.json");
        let log = files.path().join("web-server.log");
        std::fs::write(&file,serde_json::to_vec(&json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":address.port(),"protocol":"vless","settings":{"clients":[{"id":PASSWORD}],"decryption":"none"},"streamSettings":settings}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]})).unwrap()).unwrap();
        let mut child =
            tokio::process::Command::new(std::env::var("TERRARIS_XRAY").expect("Xray binary"))
                .args(["run", "-c"])
                .arg(file)
                .stdout(std::fs::File::create(&log).unwrap())
                .stderr(std::fs::OpenOptions::new().append(true).open(&log).unwrap())
                .kill_on_drop(true)
                .spawn()
                .unwrap();
        let start = tokio::time::Instant::now();
        loop {
            if TcpStream::connect(address).await.is_ok() {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5) && child.try_wait().unwrap().is_none(),
                "{}",
                std::fs::read_to_string(&log).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let connector = transport_connector(
            cert,
            address,
            transport,
            true,
            if transport == "ws" { 2048 } else { 0 },
        )
        .await;
        let (budget, scope) = resources();
        for _ in 0..3 {
            let (mut stream, _) = connector.connect(&[address], &scope, &ctx()).await.unwrap();
            terraris::protocol::vless::wire::Request {
                uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
                command: terraris::protocol::vless::wire::Command::Tcp,
                target: Some(Address::from_socket(target).unwrap()),
            }
            .write(&mut stream)
            .await
            .unwrap();
            stream.write_all(b"first payload").await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = [0; 2];
            ctx()
                .run(stream.read_exact(&mut reply))
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "{transport}: {error:?}; {}",
                        std::fs::read_to_string(&log).unwrap()
                    )
                })
                .unwrap();
            assert_eq!(reply, [0, 0], "{transport}");
            let mut first = [0; 13];
            ctx()
                .run(stream.read_exact(&mut first))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&first, b"first payload");
            exchange(&mut stream, &[2; 32768]).await;
            drop(stream);
        }
        connector.close(&ctx()).await.unwrap();
        assert_eq!(budget.snapshot().used().bytes(), 0);
        child.start_kill().unwrap();
        child.wait().await.unwrap();
        echo.abort();
        echo.await.ok();
    }
}

#[derive(Clone, PartialEq, prost::Message)]
struct TestHunks {
    #[prost(bytes = "vec", repeated, tag = "1")]
    data: Vec<Vec<u8>>,
}
fn grpc_message(parts: Vec<Vec<u8>>) -> bytes::Bytes {
    use prost::Message;
    let body = TestHunks { data: parts }.encode_to_vec();
    let mut frame = vec![0];
    frame.extend((body.len() as u32).to_be_bytes());
    frame.extend(body);
    frame.into()
}
async fn grpc_open(
    sender: &h2::client::SendRequest<bytes::Bytes>,
    multi: bool,
) -> (h2::RecvStream, h2::SendStream<bytes::Bytes>) {
    let mut sender = sender.clone().ready().await.unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri(format!(
            "https://localhost/terraris/{}",
            if multi { "TunMulti" } else { "Tun" }
        ))
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    let (response, send) = sender.send_request(request, false).unwrap();
    let response = ctx().run(response).await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    (response.into_body(), send)
}
async fn grpc_reply(recv: &mut h2::RecvStream, n: usize) -> Vec<u8> {
    use prost::Message;
    ctx()
        .run(async {
            let mut framed = Vec::<u8>::new();
            let mut output = Vec::new();
            while output.len() < n {
                let bytes = recv.data().await.expect("gRPC EOF").unwrap();
                let len = bytes.len();
                framed.extend(bytes);
                recv.flow_control().release_capacity(len).unwrap();
                while framed.len() >= 5 {
                    assert_eq!(framed[0], 0);
                    let length = u32::from_be_bytes(framed[1..5].try_into().unwrap()) as usize;
                    if framed.len() < 5 + length {
                        break;
                    }
                    let message = TestHunks::decode(&framed[5..5 + length]).unwrap();
                    for part in message.data {
                        output.extend(part);
                    }
                    framed.drain(..5 + length);
                }
            }
            assert_eq!(output.len(), n);
            assert!(framed.is_empty());
            output
        })
        .await
        .unwrap()
}
#[tokio::test]
async fn grpc_multiplexes_isolates_bad_streams_and_drains_generations() {
    let h = Harness::with_transport("vless", "grpc").await;
    let (target, echo) = echo().await;
    let mut builder = h2::client::Builder::new();
    builder.initial_window_size(1);
    let (sender, connection) = builder.handshake(h.tls().await).await.unwrap();
    let driver = tokio::spawn(connection);
    let (mut bad, mut bad_send) = grpc_open(&sender, false).await;
    bad_send
        .send_data(bytes::Bytes::from_static(&[1, 0, 0, 0, 0]), false)
        .unwrap();
    assert!(
        ctx()
            .run(bad.data())
            .await
            .unwrap()
            .is_none_or(|r| r.is_err())
    );
    drop(bad);
    drop(bad_send);
    let mut request = Vec::new();
    terraris::protocol::vless::wire::Request {
        uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
        command: terraris::protocol::vless::wire::Command::Tcp,
        target: Some(Address::from_socket(target).unwrap()),
    }
    .write(&mut request)
    .await
    .unwrap();
    let (mut one, mut write_one) = grpc_open(&sender, false).await;
    let (mut two, mut write_two) = grpc_open(&sender, true).await;
    let mut single = request.clone();
    single.extend(b"first");
    write_one
        .send_data(grpc_message(vec![single]), false)
        .unwrap();
    write_two
        .send_data(
            grpc_message(vec![request.clone(), b"second".to_vec()]),
            false,
        )
        .unwrap();
    assert_eq!(grpc_reply(&mut one, 7).await, b"\0\0first");
    assert_eq!(grpc_reply(&mut two, 8).await, b"\0\0second");
    let mut next = web_config("vless", h.address, "grpc");
    next["data"]["traffic_report_threshold"] = json!(2048);
    h.panel.push(Reply::json(next));
    h.panel.push(Reply::json(users()));
    h.supervisor.sync_config(&ctx()).await.unwrap();
    write_one
        .send_data(grpc_message(vec![b"draining".to_vec()]), false)
        .unwrap();
    assert_eq!(grpc_reply(&mut one, 8).await, b"draining");
    let mut old_sender = sender.clone().ready().await.unwrap();
    let request = http::Request::builder()
        .method("POST")
        .uri("https://localhost/terraris/Tun")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .unwrap();
    if let Ok((response, _send)) = old_sender.send_request(request, false)
        && let Ok(response) = ctx().run(response).await.unwrap()
    {
        let mut body = response.into_body();
        assert!(
            ctx()
                .run(body.data())
                .await
                .unwrap()
                .is_none_or(|r| r.is_err())
        );
    }
    let (mut fresh, budget) = web_peer(&h, "grpc").await;
    terraris::protocol::vless::wire::Request {
        uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
        command: terraris::protocol::vless::wire::Command::Tcp,
        target: Some(Address::from_socket(target).unwrap()),
    }
    .write(&mut fresh)
    .await
    .unwrap();
    let mut response = [0; 2];
    ctx()
        .run(fresh.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    exchange(&mut fresh, b"new generation").await;
    h.panel.push(Reply::json(json!({"users":[]})));
    h.supervisor
        .runtime(&ProtocolName::new("vless").unwrap())
        .unwrap()
        .controller
        .sync_users(&ctx())
        .await
        .unwrap();
    assert!(
        ctx()
            .run(one.data())
            .await
            .unwrap()
            .is_none_or(|r| r.is_err())
    );
    assert!(
        ctx()
            .run(two.data())
            .await
            .unwrap()
            .is_none_or(|r| r.is_err())
    );
    assert!(ctx().run(fresh.read_u8()).await.unwrap().is_err());
    drop(fresh);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    drop(one);
    drop(two);
    drop(write_one);
    drop(write_two);
    drop(sender);
    drop(old_sender);
    h.close().await;
    driver.abort();
    driver.await.ok();
    echo.abort();
    echo.await.ok();
}

#[tokio::test]
async fn xhttp_all_modes_http_versions_streaming_reuse_and_shutdown() {
    for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
        for (secure, alpn) in [(false, ""), (true, "http/1.1"), (true, "h2"), (true, "h3")] {
            eprintln!("XHTTP {mode} {secure} {alpn}");
            let extra = json!({"scMinPostsIntervalMs":1,"scMaxEachPostBytes":65536,"xmux":{"maxConnections":1,"hMaxRequestTimes":5}});
            let h = Harness::with_xhttp_options(
                "vless",
                "xhttp",
                secure,
                Some((mode, alpn, extra.clone())),
            )
            .await;
            let connector = transport_connector_extra(
                h.cert.clone(),
                h.address,
                "xhttp",
                secure,
                0,
                Some((mode, alpn, extra)),
            )
            .await;
            let (budget, scope) = resources();
            let (target, echo) = echo().await;
            for i in 0..2 {
                let (mut stream, _) = ctx()
                    .run(connector.connect(&[h.address], &scope, &ctx()))
                    .await
                    .unwrap()
                    .unwrap();
                terraris::protocol::vless::wire::Request {
                    uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
                    command: terraris::protocol::vless::wire::Command::Tcp,
                    target: Some(Address::from_socket(target).unwrap()),
                }
                .write(&mut stream)
                .await
                .unwrap();
                let mut response = [0; 2];
                ctx()
                    .run(stream.read_exact(&mut response))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(response, [0, 0]);
                let payload = (0..256 * 1024)
                    .map(|n| (n * 197 + i * 71) as u8)
                    .collect::<Vec<_>>();
                let mut output = vec![0; payload.len()];
                let (mut r, mut w) = tokio::io::split(stream);
                ctx()
                    .run(async {
                        tokio::try_join!(w.write_all(&payload), r.read_exact(&mut output))
                    })
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(payload, output);
                if !matches!(mode, "packet-up" | "auto") {
                    ctx().run(w.shutdown()).await.unwrap().unwrap();
                    let mut b = [0];
                    assert_eq!(ctx().run(r.read(&mut b)).await.unwrap().unwrap(), 0);
                }
                drop(r);
                drop(w);
            }
            connector.close(&ctx()).await.unwrap();
            assert!(connector.idle());
            assert_eq!(budget.snapshot().used().bytes(), 0);
            h.close().await;
            echo.abort();
            echo.await.ok();
        }
    }
}

#[tokio::test]
#[ignore = "requires TERRARIS_POLARIS_XHTTP built from pinned Polaris"]
async fn polaris_xhttp_clients_interoperate_with_native_servers() {
    for (mode, extra) in xhttp_interop_cases() {
        for alpn in ["", "http/1.1", "h2", "h3"] {
            let h = Harness::with_xhttp_options(
                "vless",
                "xhttp",
                !alpn.is_empty(),
                Some((mode, alpn, extra.clone())),
            )
            .await;
            let (target, echo) = echo().await;
            let child = tokio::process::Command::new(
                std::env::var("TERRARIS_POLARIS_XHTTP").expect("Polaris peer"),
            )
            .args([
                "-role",
                "client",
                "-server",
                &h.address.to_string(),
                "-target",
                &target.to_string(),
                "-mode",
                mode,
                "-alpn",
                alpn,
                "-extra",
                &extra.to_string(),
                "-cert",
            ])
            .arg(h.files.path().join("cert.pem"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
            let output = tokio::time::timeout(Duration::from_secs(40), child.wait_with_output())
                .await
                .unwrap()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}/{alpn}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            h.close().await;
            echo.abort();
            echo.await.ok();
        }
    }
}
#[tokio::test]
#[ignore = "requires TERRARIS_POLARIS_XHTTP built from pinned Polaris"]
async fn native_xhttp_clients_interoperate_with_polaris_servers() {
    use tokio::io::AsyncBufReadExt;
    for (mode, extra) in xhttp_interop_cases() {
        for alpn in ["", "http/1.1", "h2", "h3"] {
            let files = tempfile::tempdir().unwrap();
            let cert = write_identity(files.path());
            let log = files.path().join("polaris.log");
            let mut child = tokio::process::Command::new(
                std::env::var("TERRARIS_POLARIS_XHTTP").expect("Polaris peer"),
            )
            .args([
                "-role",
                "server",
                "-mode",
                mode,
                "-alpn",
                alpn,
                "-extra",
                &extra.to_string(),
                "-cert",
            ])
            .arg(files.path().join("cert.pem"))
            .arg("-key")
            .arg(files.path().join("key.pem"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::fs::File::create(&log).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
            let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
            let ready = ctx()
                .run(lines.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let address: SocketAddr = ready.strip_prefix("READY ").unwrap().parse().unwrap();
            let connector = transport_connector_extra(
                cert,
                address,
                "xhttp",
                !alpn.is_empty(),
                0,
                Some((mode, alpn, extra.clone())),
            )
            .await;
            let (budget, scope) = resources();
            for i in 0..3 {
                let (mut stream, _) = connector
                    .connect(&[address], &scope, &ctx())
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{mode}/{alpn}: {e:?}; {}",
                            std::fs::read_to_string(&log).unwrap()
                        )
                    });
                terraris::protocol::vless::wire::Request {
                    uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
                    command: terraris::protocol::vless::wire::Command::Tcp,
                    target: Some(Address::from_socket("127.0.0.1:443".parse().unwrap()).unwrap()),
                }
                .write(&mut stream)
                .await
                .unwrap();
                let mut response = [0; 2];
                ctx()
                    .run(stream.read_exact(&mut response))
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{mode}/{alpn}: {e:?}; {}",
                            std::fs::read_to_string(&log).unwrap()
                        )
                    })
                    .unwrap();
                assert_eq!(response, [0, 0]);
                let payload = (0..256 * 1024)
                    .map(|n| (n * 197 + i * 71) as u8)
                    .collect::<Vec<_>>();
                let mut output = vec![0; payload.len()];
                let (mut r, mut w) = tokio::io::split(stream);
                ctx()
                    .run(async {
                        tokio::try_join!(w.write_all(&payload), r.read_exact(&mut output))
                    })
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(payload, output);
                drop(r);
                drop(w);
            }
            connector.close(&ctx()).await.unwrap();
            assert_eq!(budget.snapshot().used().bytes(), 0);
            child.start_kill().unwrap();
            child.wait().await.unwrap();
        }
    }
}
#[tokio::test]
#[ignore = "requires TERRARIS_XRAY pinned to the documented Xray commit"]
async fn xray_xhttp_clients_interoperate_with_native_servers() {
    for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
        for alpn in ["http/1.1", "h2", "h3"] {
            eprintln!("Xray -> native {mode}/{alpn}");
            let extra = json!({"scMinPostsIntervalMs":1,"scMaxEachPostBytes":65536,"xmux":{"maxConnections":1,"hMaxRequestTimes":5}});
            let h = Harness::with_xhttp_options(
                "vless",
                "xhttp",
                true,
                Some((mode, alpn, extra.clone())),
            )
            .await;
            let (target, echo) = echo().await;
            let socks = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap()
                .local_addr()
                .unwrap();
            let settings = json!({"network":"xhttp","security":"tls","tlsSettings":{"serverName":"localhost","alpn":[alpn],"pinnedPeerCertSha256":format!("{:x}",Sha256::digest(h.cert.as_ref()))},"xhttpSettings":{"host":"localhost","path":"/relay","mode":mode,"extra":extra}});
            let value = json!({"log":{"loglevel":"info"},"inbounds":[{"listen":"127.0.0.1","port":socks.port(),"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":h.address.port(),"users":[{"id":PASSWORD,"encryption":"none"}]}]},"streamSettings":settings}]});
            let log = h.files.path().join("xray-client.log");
            let mut child = xray_process(&value, h.files.path(), &log).await;
            for _ in 0..2 {
                let (mut stream, _) = socks_connect(socks, 1, target).await;
                exchange(&mut stream, &[71; 65536]).await;
            }
            child.start_kill().unwrap();
            child.wait().await.unwrap();
            h.close().await;
            echo.abort();
            echo.await.ok();
        }
    }
}
#[tokio::test]
#[ignore = "requires TERRARIS_XRAY pinned to the documented Xray commit"]
async fn native_xhttp_clients_interoperate_with_xray_servers() {
    for mode in ["auto", "packet-up", "stream-up", "stream-one"] {
        for alpn in ["http/1.1", "h2", "h3"] {
            let files = tempfile::tempdir().unwrap();
            let cert = write_identity(files.path());
            let (target, echo) = echo().await;
            let address = TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap()
                .local_addr()
                .unwrap();
            let extra = json!({"scMinPostsIntervalMs":1,"scMaxEachPostBytes":65536,"xmux":{"maxConnections":1,"hMaxRequestTimes":5}});
            let settings = json!({"network":"xhttp","security":"tls","tlsSettings":{"alpn":[alpn],"certificates":[{"certificateFile":files.path().join("cert.pem"),"keyFile":files.path().join("key.pem")}]},"xhttpSettings":{"host":"localhost","path":"/relay","mode":mode,"extra":extra}});
            let value = json!({"log":{"loglevel":"info"},"inbounds":[{"listen":"127.0.0.1","port":address.port(),"protocol":"vless","settings":{"clients":[{"id":PASSWORD}],"decryption":"none"},"streamSettings":settings}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"action":"allow","ip":["127.0.0.1/32"]}]}}]});
            let log = files.path().join("xray-server.log");
            let mut child = xray_process(&value, files.path(), &log).await;
            let connector = transport_connector_extra(
                cert,
                address,
                "xhttp",
                true,
                0,
                Some((mode, alpn, extra)),
            )
            .await;
            let (budget, scope) = resources();
            for _ in 0..2 {
                let (mut stream, _) = connector.connect(&[address], &scope, &ctx()).await.unwrap();
                terraris::protocol::vless::wire::Request {
                    uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
                    command: terraris::protocol::vless::wire::Command::Tcp,
                    target: Some(Address::from_socket(target).unwrap()),
                }
                .write(&mut stream)
                .await
                .unwrap();
                stream.write_all(b"first payload").await.unwrap();
                stream.flush().await.unwrap();
                let mut response = [0; 15];
                ctx()
                    .run(stream.read_exact(&mut response))
                    .await
                    .unwrap_or_else(|e| {
                        panic!(
                            "{mode}/{alpn}: {e:?}; {}",
                            std::fs::read_to_string(&log).unwrap()
                        )
                    })
                    .unwrap();
                assert_eq!(&response[..2], &[0, 0]);
                assert_eq!(&response[2..], b"first payload");
                exchange(&mut stream, &[91; 65536]).await;
                drop(stream);
            }
            connector.close(&ctx()).await.unwrap();
            assert_eq!(budget.snapshot().used().bytes(), 0);
            child.start_kill().unwrap();
            child.wait().await.unwrap();
            echo.abort();
            echo.await.ok();
        }
    }
}
async fn xray_process(
    value: &Value,
    directory: &std::path::Path,
    log: &std::path::Path,
) -> tokio::process::Child {
    let file = directory.join("xray-config.json");
    std::fs::write(&file, serde_json::to_vec(value).unwrap()).unwrap();
    let mut child =
        tokio::process::Command::new(std::env::var("TERRARIS_XRAY").expect("Xray binary"))
            .args(["run", "-c"])
            .arg(file)
            .stdout(std::fs::File::create(log).unwrap())
            .stderr(std::fs::OpenOptions::new().append(true).open(log).unwrap())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
    let start = tokio::time::Instant::now();
    loop {
        let output = std::fs::read_to_string(log).unwrap();
        if output.contains("started") {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5) && child.try_wait().unwrap().is_none(),
            "{output}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    child
}

fn xhttp_obfuscated(data: &str) -> Value {
    json!({"scMinPostsIntervalMs":1,"scMaxEachPostBytes":8192,"serverMaxHeaderBytes":32768,
        "sessionIDPlacement":"cookie","sessionIDKey":"sid","seqPlacement":"header","seqKey":"X-Part",
        "sessionIDTable":"hex","sessionIDLength":24,"uplinkDataPlacement":data,
        "uplinkHTTPMethod":"GET","uplinkChunkSize":512,
        "xPaddingObfsMode":true,"xPaddingPlacement":"query","xPaddingMethod":"tokenish","xPaddingBytes":"100-200",
        "noGRPCHeader":true,"noSSEHeader":true,"xmux":{"maxConnections":1,"hMaxRequestTimes":4}})
}
async fn vless_over_transport(
    connector: &Arc<dyn terraris::transport::Outbound>,
    addresses: &[SocketAddr],
    scope: &BufferScope,
    target: SocketAddr,
) -> Stream {
    let (mut stream, _) = ctx()
        .run(connector.connect(addresses, scope, &ctx()))
        .await
        .unwrap()
        .unwrap();
    terraris::protocol::vless::wire::Request {
        uuid: *uuid::Uuid::parse_str(PASSWORD).unwrap().as_bytes(),
        command: terraris::protocol::vless::wire::Command::Tcp,
        target: Some(Address::from_socket(target).unwrap()),
    }
    .write(&mut stream)
    .await
    .unwrap();
    let mut response = [0; 2];
    ctx()
        .run(stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, [0, 0]);
    stream
}
#[tokio::test]
async fn xhttp_header_cookie_uploads_and_h3_address_fallback() {
    for alpn in ["http/1.1", "h2", "h3"] {
        for placement in ["header", "cookie"] {
            let extra = xhttp_obfuscated(placement);
            let h = Harness::with_xhttp_options(
                "vless",
                "splithttp",
                true,
                Some(("packet-up", alpn, extra.clone())),
            )
            .await;
            let connector = transport_connector_extra(
                h.cert.clone(),
                h.address,
                "splithttp",
                true,
                0,
                Some(("packet-up", alpn, extra)),
            )
            .await;
            let (budget, scope) = resources();
            let (target, echo) = echo().await;
            let unavailable = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addresses = if alpn == "h3" {
                vec![unavailable.local_addr().unwrap(), h.address]
            } else {
                vec![h.address]
            };
            let mut stream = vless_over_transport(&connector, &addresses, &scope, target).await;
            let payload = (0..32 * 1024).map(|n| (n * 71) as u8).collect::<Vec<_>>();
            exchange(&mut stream, &payload).await;
            drop(stream);
            connector.close(&ctx()).await.unwrap();
            assert!(connector.idle());
            assert_eq!(budget.snapshot().used().bytes(), 0);
            h.close().await;
            echo.abort();
            echo.await.ok();
        }
    }
}
#[tokio::test]
async fn xhttp_split_download_and_generation_refresh_preserve_sessions_until_revocation() {
    let extra = json!({"scMinPostsIntervalMs":1,"scMaxEachPostBytes":8192,"xmux":{"maxConnections":1,"hMaxRequestTimes":2}});
    let h = Harness::with_xhttp_options(
        "vless",
        "xhttp",
        true,
        Some(("packet-up", "", extra.clone())),
    )
    .await;
    // A second ingress address forwards to the same backend session table. Its
    // independent client negotiates HTTP/1.1 while uploads use HTTP/2.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let download = listener.local_addr().unwrap();
    let address = h.address;
    let forward = tokio::spawn(async move {
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=listener.accept()=>{let(mut a,_)=accepted.unwrap();jobs.spawn(async move{let mut b=TcpStream::connect(address).await.unwrap();let _=tokio::io::copy_bidirectional(&mut a,&mut b).await;});},
                _=jobs.join_next(),if !jobs.is_empty()=>{}
            }
        }
    });
    let mut client_extra = extra.clone();
    client_extra["downloadSettings"] = json!({"address":"localhost","port":download.port(),"network":"splithttp","security":"tls","tlsSettings":{"serverName":"localhost","alpn":["http/1.1"]},"splithttpSettings":{"host":"localhost","path":"/relay","mode":"packet-up","extra":extra}});
    let connector = transport_connector_extra(
        h.cert.clone(),
        h.address,
        "xhttp",
        true,
        0,
        Some(("packet-up", "h2", client_extra)),
    )
    .await;
    let (budget, scope) = resources();
    let (target, echo) = echo().await;
    let mut stream = vless_over_transport(&connector, &[h.address], &scope, target).await;
    exchange(&mut stream, b"before refresh").await;
    let mut next = web_config("vless", h.address, "xhttp");
    next["data"]["traffic_report_threshold"] = json!(2048);
    let p = &mut next["data"]["protocols"][0];
    p["xhttp_mode"] = json!("packet-up");
    p["xhttp_extra"] = json!(extra.to_string());
    h.panel.push(Reply::json(next));
    h.panel.push(Reply::json(users()));
    h.supervisor.sync_config(&ctx()).await.unwrap();
    for i in 0..5 {
        exchange(&mut stream, format!("after refresh {i}").as_bytes()).await;
    }
    let mut fresh = vless_over_transport(&connector, &[h.address], &scope, target).await;
    exchange(&mut fresh, b"new session").await;
    h.panel.push(Reply::json(json!({"users":[]})));
    h.supervisor
        .runtime(&ProtocolName::new("vless").unwrap())
        .unwrap()
        .controller
        .sync_users(&ctx())
        .await
        .unwrap();
    assert!(ctx().run(stream.read_u8()).await.unwrap().is_err());
    assert!(ctx().run(fresh.read_u8()).await.unwrap().is_err());
    drop(stream);
    drop(fresh);
    connector.close(&ctx()).await.unwrap();
    assert!(connector.idle());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    h.close().await;
    forward.abort();
    forward.await.ok();
    echo.abort();
    echo.await.ok();
}

fn xhttp_interop_cases() -> Vec<(&'static str, Value)> {
    let defaults = json!({"scMinPostsIntervalMs":1,"scMaxEachPostBytes":65536,"xmux":{"maxConnections":1,"hMaxRequestTimes":5}});
    let mut cases = ["auto", "packet-up", "stream-up", "stream-one"]
        .into_iter()
        .map(|m| (m, defaults.clone()))
        .collect::<Vec<_>>();
    cases.push(("packet-up", xhttp_obfuscated("header")));
    cases.push(("packet-up", xhttp_obfuscated("cookie")));
    cases
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_default_packet_posts_sustain_sixteen_concurrent_streams() {
    for alpn in ["h2", "h3"] {
        for extra in [
            json!({}),
            json!({"xmux":{"maxConnections":1,"hMaxRequestTimes":8}}),
        ] {
            eprintln!("default packet-up 16 flows: {alpn}");
            let h = Harness::with_xhttp_options(
                "vless",
                "xhttp",
                true,
                Some(("packet-up", alpn, extra.clone())),
            )
            .await;
            let connector = transport_connector_extra(
                h.cert.clone(),
                h.address,
                "xhttp",
                true,
                0,
                Some(("packet-up", alpn, extra.clone())),
            )
            .await;
            // One shared default connection scope, including all upload pipes and
            // in-flight HTTP/QUIC body leases for the sixteen outbound streams.
            let budget = Budget::new(Limits::new(4 << 20, 256).unwrap());
            let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
            let (target, echo) = echo().await;
            let mut flows = Vec::new();
            for _ in 0..16 {
                flows.push(vless_over_transport(&connector, &[h.address], &scope, target).await);
            }
            let mut jobs = tokio::task::JoinSet::new();
            for (id, stream) in flows.into_iter().enumerate() {
                jobs.spawn(async move {
                    let (mut reader, mut writer) = tokio::io::split(stream);
                    let send = async {
                        let data = vec![id as u8; 65536];
                        for _ in 0..64 {
                            writer.write_all(&data).await.unwrap();
                        }
                    };
                    let receive = async {
                        let mut data = vec![0; 65536];
                        for n in 0..64 {
                            reader.read_exact(&mut data).await.unwrap();
                            assert!(data.iter().all(|v| *v == id as u8));
                            if n % 8 == 0 {
                                tokio::task::yield_now().await;
                            }
                        }
                    };
                    tokio::join!(send, receive);
                });
            }
            tokio::time::timeout(Duration::from_secs(20), async {
                while let Some(r) = jobs.join_next().await {
                    r.unwrap();
                }
            })
            .await
            .unwrap();
            connector.close(&ctx()).await.unwrap();
            assert!(connector.idle());
            assert_eq!(budget.snapshot().used().bytes(), 0);
            h.close().await;
            echo.abort();
            echo.await.ok();
        }
    }
}
