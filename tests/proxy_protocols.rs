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
        let address = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let files = tempfile::tempdir().unwrap();
        let cert = write_identity(files.path());
        let panel = MockPanel::start(vec![
            Reply::json(config(name, address)).etag("\"proxy-config\""),
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
                    drain_timeout: Duration::from_secs(30),
                    close_timeout: Duration::from_secs(1),
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
