// SPDX-License-Identifier: GPL-3.0-only
mod support;
use base64::{Engine as _, engine::general_purpose::STANDARD};
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
        shadowsocks::{Client, Method},
        socksaddr::Endpoint,
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
const USERS: [&str; 2] = [
    "b831381d-6324-4d53-ad4f-8cda48b30811",
    "0831381d-6324-4d53-ad4f-8cda48b30812",
];
const METHODS: [&str; 8] = [
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];
fn context() -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(10)).unwrap()),
    )
}
fn resources() -> (Budget, BufferScope) {
    let budget = Budget::new(Limits::new(32 << 20, 4096).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
    (budget, scope)
}
fn users() -> Value {
    json!({"users":[{"id":1,"uuid":USERS[0],"speed_limit":0,"device_limit":0},{"id":2,"uuid":USERS[1],"speed_limit":0,"device_limit":0}]})
}
fn server_key(method: Method) -> String {
    if method.identity() {
        "0123456789abcdef0123456789abcdef"[..method.key_len()].to_owned()
    } else {
        String::new()
    }
}
fn password(method: Method, who: usize, identity: bool) -> String {
    if !method.modern() {
        return USERS[who].into();
    }
    let user = STANDARD.encode(&USERS[who].as_bytes()[..method.key_len()]);
    if identity && method.identity() {
        format!("{}:{user}", STANDARD.encode(server_key(method)))
    } else {
        user
    }
}
fn config(method: Method, address: SocketAddr, identity: bool) -> Value {
    json!({"code":200,"data":{"pull_interval":300,"push_interval":300,"traffic_report_threshold":1024,"ip_strategy":"prefer_ipv4","dns":[],"block":[],"outbound":[],"protocols":[{"type":"shadowsocks","enable":true,"port":address.port(),"network":"tcp,udp","cipher":method.name(),"server_key":if identity{server_key(method)}else{String::new()},"uot":true}],"total":1}})
}
struct Harness {
    panel: MockPanel,
    supervisor: Arc<Supervisor<protocol::Registry>>,
    address: SocketAddr,
    budget: Budget,
    method: Method,
    identity: bool,
}
impl Harness {
    async fn new(name: &str) -> Self {
        Self::start(name, true).await
    }
    async fn start(name: &str, identity: bool) -> Self {
        let method = Method::parse(name).unwrap();
        let address = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let panel = MockPanel::start(vec![
            Reply::json(config(method, address, identity)),
            Reply::json(users()),
        ])
        .await;
        let mut options = panel.options();
        options.wire_mode = WireMode::Json;
        let pins = options.fingerprints.clone();
        let connection: Arc<dyn Connection> = Arc::new(PPanelConnection::new(options).unwrap());
        let factory = protocol::Registry::builtin(
            connection.clone(),
            protocol::vless::Options {
                listen: Ipv4Addr::LOCALHOST.into(),
                ..Default::default()
            },
            flow::Options::default(),
            Default::default(),
            Default::default(),
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
                    drain_timeout: Duration::from_millis(100),
                    close_timeout: Duration::from_secs(2),
                    ..Default::default()
                },
                Metrics::default(),
                pins,
                None,
            )
            .unwrap(),
        );
        supervisor.sync_config(&context()).await.unwrap();
        Self {
            panel,
            supervisor,
            address,
            budget,
            method,
            identity,
        }
    }
    fn client(&self, who: usize) -> Client {
        Client::new(
            self.method.name(),
            &password(self.method, who, self.identity),
        )
        .unwrap()
    }
    async fn connect(&self, who: usize, target: SocketAddr, scope: &BufferScope) -> Stream {
        self.client(who)
            .connect(
                Box::new(TcpStream::connect(self.address).await.unwrap()),
                &Endpoint::from_address(&Address::from_socket(target).unwrap()).unwrap(),
                scope,
                &context(),
            )
            .await
            .unwrap()
    }
    async fn close(&self) {
        self.panel.push(Reply::json(json!({"code":200})));
        self.panel.push(Reply::json(json!({"code":200})));
        self.supervisor.close(&context()).await.unwrap();
        assert_eq!(self.budget.snapshot().used().bytes(), 0);
        assert_eq!(self.budget.snapshot().used().allocations(), 0);
    }
}
async fn tcp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let mut children = tokio::task::JoinSet::new();
        loop {
            tokio::select! {accepted=listener.accept()=>{let(mut stream,_)=accepted.unwrap();children.spawn(async move{let(mut r,mut w)=stream.split();let _=tokio::io::copy(&mut r,&mut w).await;});},_=children.join_next(),if !children.is_empty()=>{}}
        }
    });
    (address, job)
}
async fn udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let mut data = vec![0; 65536];
        loop {
            let (n, source) = socket.recv_from(&mut data).await.unwrap();
            socket.send_to(&data[..n], source).await.unwrap();
        }
    });
    (address, job)
}
async fn exchange(stream: &mut Stream, payload: &[u8]) {
    let mut result = vec![0; payload.len()];
    let (mut r, mut w) = tokio::io::split(stream);
    context()
        .run(async { tokio::try_join!(w.write_all(payload), r.read_exact(&mut result)) })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, payload);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_aead_methods_tcp_udp_multiuser_and_shutdown() {
    for method in METHODS {
        eprintln!("Shadowsocks {method}");
        let h = Harness::new(method).await;
        let (target, tcp) = tcp_echo().await;
        let (udp_target, udp) = udp_echo().await;
        let (memory, scope) = resources();
        for who in 0..2 {
            let mut stream = h.connect(who, target, &scope).await;
            let payload = (0..256 * 1024)
                .map(|n| (n * 197 + who * 71) as u8)
                .collect::<Vec<_>>();
            exchange(&mut stream, &payload).await;
            context().run(stream.shutdown()).await.unwrap().unwrap();
            assert_eq!(
                context()
                    .run(stream.read_u8())
                    .await
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
            drop(stream);
            let mut codec = h.client(who).datagrams().unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(h.address).await.unwrap();
            for payload in [vec![], b"udp".to_vec(), vec![who as u8; 8192]] {
                let wire = codec
                    .encode(
                        &Endpoint::from_address(&Address::from_socket(udp_target).unwrap())
                            .unwrap(),
                        &payload,
                        &scope,
                    )
                    .unwrap();
                socket.send(wire.as_slice()).await.unwrap();
                drop(wire);
                let mut wire = vec![0; 65536];
                let n = context()
                    .run(socket.recv(&mut wire))
                    .await
                    .unwrap()
                    .unwrap();
                let (source, body) = codec.decode(&wire[..n], &scope).unwrap();
                assert_eq!(
                    source.address().unwrap(),
                    Address::from_socket(udp_target).unwrap()
                );
                assert_eq!(body.as_slice(), payload);
            }
        }
        let runtime = h
            .supervisor
            .runtime(&ProtocolName::new("shadowsocks").unwrap())
            .unwrap();
        context()
            .run(async {
                loop {
                    if let Some(batch) = runtime.core().reports().traffic_batch(0, 10).unwrap() {
                        let correct = batch.values().len() == 2
                            && batch
                                .values()
                                .iter()
                                .all(|v| v.upload == 262144 + 8195 && v.download == 262144 + 8195);
                        drop(batch);
                        if correct {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .unwrap();
        assert_eq!(memory.snapshot().used().bytes(), 0);
        h.close().await;
        tcp.abort();
        tcp.await.ok();
        udp.abort();
        udp.await.ok();
    }
}
#[tokio::test]
async fn aes_2022_single_psk_mode_and_derived_key_collision_rejection() {
    let h = Harness::start("2022-blake3-aes-128-gcm", false).await;
    let (target, echo) = tcp_echo().await;
    let (memory, scope) = resources();
    let mut stream = h.connect(1, target, &scope).await;
    exchange(&mut stream, b"single PSK").await;
    h.panel.push(Reply::json(json!({"users":[{"id":1,"uuid":"abcdefghijklmnop-one"},{"id":2,"uuid":"abcdefghijklmnop-two"}]})));
    assert!(
        h.supervisor
            .runtime(&ProtocolName::new("shadowsocks").unwrap())
            .unwrap()
            .controller
            .sync_users(&context())
            .await
            .is_err()
    );
    exchange(&mut stream, b"old snapshot remains live").await;
    drop(stream);
    assert_eq!(memory.snapshot().used().bytes(), 0);
    h.close().await;
    echo.abort();
    echo.await.ok();
}

#[tokio::test]
#[ignore = "requires TERRARIS_SS_PEER built from tests/interop/shadowsocks"]
async fn independent_go_clients_interoperate_with_all_native_ciphers() {
    for name in METHODS {
        let h = Harness::new(name).await;
        let (tcp_target, tcp) = tcp_echo().await;
        let (udp_target, udp) = udp_echo().await;
        for who in 0..2 {
            let child = tokio::process::Command::new(
                std::env::var("TERRARIS_SS_PEER").expect("SS peer binary"),
            )
            .args([
                "-cipher",
                name,
                "-password",
                &password(h.method, who, true),
                "-server",
                &h.address.to_string(),
                "-tcp",
                &tcp_target.to_string(),
                "-udp",
                &udp_target.to_string(),
                "-uot",
            ])
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
                "{name}/{who}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        h.close().await;
        tcp.abort();
        tcp.await.ok();
        udp.abort();
        udp.await.ok();
    }
}
#[tokio::test]
#[ignore = "requires TERRARIS_SS_PEER built from tests/interop/shadowsocks"]
async fn native_clients_interoperate_with_independent_go_servers() {
    use tokio::io::AsyncBufReadExt;
    for name in METHODS {
        eprintln!("native -> Go {name}");
        let method = Method::parse(name).unwrap();
        let secret = password(method, 0, true);
        let directory = tempfile::tempdir().unwrap();
        let log = directory.path().join("peer.log");
        let mut child = tokio::process::Command::new(
            std::env::var("TERRARIS_SS_PEER").expect("SS peer binary"),
        )
        .args(["-role", "server", "-cipher", name, "-password", &secret])
        .stdout(std::process::Stdio::piped())
        .stderr(std::fs::File::create(&log).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
        let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
        let ready = context()
            .run(lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let server: SocketAddr = ready.strip_prefix("READY ").unwrap().parse().unwrap();
        let (target, echo) = tcp_echo().await;
        let (memory, scope) = resources();
        let client = Client::new(name, &secret).unwrap();
        for _ in 0..2 {
            let mut stream = client
                .connect(
                    Box::new(TcpStream::connect(server).await.unwrap()),
                    &Endpoint::from_address(&Address::from_socket(target).unwrap()).unwrap(),
                    &scope,
                    &context(),
                )
                .await
                .unwrap();
            exchange(&mut stream, &vec![91; 256 << 10]).await;
            drop(stream);
        }
        let mut codec = client.datagrams().unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(server).await.unwrap();
        for data in [vec![], b"independent UDP".to_vec(), vec![17; 8192]] {
            let wire = codec
                .encode(
                    &Endpoint::from_address(&Address::from_socket(target).unwrap()).unwrap(),
                    &data,
                    &scope,
                )
                .unwrap();
            socket.send(wire.as_slice()).await.unwrap();
            drop(wire);
            let mut reply = vec![0; 65536];
            let n = context()
                .run(socket.recv(&mut reply))
                .await
                .unwrap_or_else(|e| {
                    panic!("{name}: {e:?}; {}", std::fs::read_to_string(&log).unwrap())
                })
                .unwrap();
            let (source, plain) = codec.decode(&reply[..n], &scope).unwrap();
            assert_eq!(
                source.address().unwrap(),
                Address::from_socket(target).unwrap()
            );
            assert_eq!(plain.as_slice(), data);
        }
        assert_eq!(memory.snapshot().used().bytes(), 0);
        child.start_kill().unwrap();
        child.wait().await.unwrap();
        echo.abort();
        echo.await.ok();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_session_rebind_replay_reload_and_revocation() {
    for name in ["2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"] {
        let h = Harness::new(name).await;
        let (memory, scope) = resources();
        let mut codec = h.client(0).datagrams().unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let destination =
            Endpoint::from_address(&Address::from_socket(target.local_addr().unwrap()).unwrap())
                .unwrap();
        let one = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let two = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire = codec.encode(&destination, b"first", &scope).unwrap();
        one.send_to(wire.as_slice(), h.address).await.unwrap();
        let mut data = [0; 64];
        let (n, first_port) = context()
            .run(target.recv_from(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..n], b"first");
        target.send_to(b"reply", first_port).await.unwrap();
        let mut reply = vec![0; 65536];
        let (n, _) = context()
            .run(one.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
        let (_, plain) = codec.decode(&reply[..n], &scope).unwrap();
        assert_eq!(plain.as_slice(), b"reply");
        drop(plain);
        one.send_to(wire.as_slice(), h.address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(60), target.recv_from(&mut data))
                .await
                .is_err()
        );
        drop(wire);
        let wire = codec.encode(&destination, b"rebind", &scope).unwrap();
        two.send_to(wire.as_slice(), h.address).await.unwrap();
        drop(wire);
        let (n, second_port) = context()
            .run(target.recv_from(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_port, second_port);
        assert_eq!(&data[..n], b"rebind");
        target.send_to(b"new address", second_port).await.unwrap();
        let (n, _) = context()
            .run(two.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
        codec.decode(&reply[..n], &scope).unwrap();
        let mut next = config(h.method, h.address, true);
        next["data"]["traffic_report_threshold"] = json!(2048);
        h.panel.push(Reply::json(next));
        h.panel.push(Reply::json(users()));
        h.supervisor.sync_config(&context()).await.unwrap();
        let wire = codec.encode(&destination, b"reload", &scope).unwrap();
        two.send_to(wire.as_slice(), h.address).await.unwrap();
        drop(wire);
        let (n, third_port) = context()
            .run(target.recv_from(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(third_port, first_port);
        assert_eq!(&data[..n], b"reload");
        h.panel.push(Reply::json(json!({"users":[]})));
        h.supervisor
            .runtime(&ProtocolName::new("shadowsocks").unwrap())
            .unwrap()
            .controller
            .sync_users(&context())
            .await
            .unwrap();
        let wire = codec.encode(&destination, b"revoked", &scope).unwrap();
        two.send_to(wire.as_slice(), h.address).await.unwrap();
        drop(wire);
        assert!(
            tokio::time::timeout(Duration::from_millis(80), target.recv_from(&mut data))
                .await
                .is_err()
        );
        assert_eq!(memory.snapshot().used().bytes(), 0);
        h.close().await;
    }
}

async fn outbound_connector(
    h: &Harness,
    uot: bool,
) -> (
    Arc<dyn terraris::outbound::Connector>,
    Arc<terraris::dns::system::System>,
) {
    let mut value = config(h.method, h.address, h.identity);
    value["data"]["outbound"] = json!([{"name":"ss","protocol":"shadowsocks","address":"127.0.0.1","port":h.address.port(),"cipher":h.method.name(),"password":password(h.method,0,h.identity),"uot":uot,"uot_version":if uot{2}else{0}}]);
    let panel = MockPanel::start(vec![Reply::json(value)]).await;
    let mut options = panel.options();
    options.wire_mode = WireMode::Json;
    let connection = PPanelConnection::new(options).unwrap();
    let terraris::panel::Fetch::Changed { value, .. } =
        connection.server().get_config(None).await.unwrap()
    else {
        panic!("config")
    };
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let system = terraris::dns::system::System::new(4);
    let context = terraris::outbound::registry::Context {
        tls: Arc::new(tls),
        system: system.clone(),
        transports: Arc::new(terraris::transport::Registry::builtin()),
    };
    let connector = terraris::outbound::Registry::builtin()
        .compile(&value.outbounds[0], &context)
        .unwrap()
        .unwrap();
    (connector, system)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_registry_tcp_native_udp_and_uot_all_methods() {
    for name in METHODS {
        let h = Harness::new(name).await;
        let (target, tcp) = tcp_echo().await;
        let (udp_target, udp) = udp_echo().await;
        let (memory, scope) = resources();
        for uot in [false, true] {
            let (connector, system) = outbound_connector(&h, uot).await;
            let mut stream = connector
                .connect(&Address::from_socket(target).unwrap(), &scope, &context())
                .await
                .unwrap();
            exchange(&mut stream, b"registered SS outbound").await;
            drop(stream);
            let packets = connector.packet(scope.clone(), &context()).await.unwrap();
            for payload in [b"".as_slice(), b"registry datagram".as_slice()] {
                packets
                    .send(
                        &Address::from_socket(udp_target).unwrap(),
                        payload,
                        &context(),
                    )
                    .await
                    .unwrap();
                let reply = packets.recv(&context()).await.unwrap();
                assert_eq!(reply.source, Address::from_socket(udp_target).unwrap());
                assert_eq!(reply.payload.as_slice(), payload);
            }
            packets.abort();
            drop(packets);
            connector.close(&context()).await.unwrap();
            assert!(connector.idle());
            system.close(&context()).await.unwrap();
        }
        assert_eq!(memory.snapshot().used().bytes(), 0);
        h.close().await;
        tcp.abort();
        tcp.await.ok();
        udp.abort();
        udp.await.ok();
    }
}
#[tokio::test]
async fn tcp_revocation_and_failed_transport_reload_preserve_valid_configuration() {
    for name in ["chacha20-ietf-poly1305", "2022-blake3-aes-256-gcm"] {
        let h = Harness::new(name).await;
        let (target, echo) = tcp_echo().await;
        let (memory, scope) = resources();
        let mut live = h.connect(0, target, &scope).await;
        exchange(&mut live, b"before").await;
        let mut bad = config(h.method, h.address, true);
        bad["data"]["protocols"][0]["cipher"] = json!("aes-128-cfb");
        h.panel.push(Reply::json(bad));
        assert!(h.supervisor.sync_config(&context()).await.is_err());
        exchange(&mut live, b"still active").await;
        h.panel.push(Reply::json(json!({"users":[]})));
        h.supervisor
            .runtime(&ProtocolName::new("shadowsocks").unwrap())
            .unwrap()
            .controller
            .sync_users(&context())
            .await
            .unwrap();
        assert!(context().run(live.read_u8()).await.unwrap().is_err());
        drop(live);
        assert_eq!(memory.snapshot().used().bytes(), 0);
        h.close().await;
        echo.abort();
        echo.await.ok();
    }
}

#[tokio::test]
async fn device_denial_precedes_both_tcp_and_udp_forwarding() {
    let h = Harness::new("2022-blake3-aes-128-gcm").await;
    let mut limited = users();
    limited["users"][0]["device_limit"] = json!(1);
    h.panel.push(Reply::json(limited));
    let runtime = h
        .supervisor
        .runtime(&ProtocolName::new("shadowsocks").unwrap())
        .unwrap();
    runtime.controller.sync_users(&context()).await.unwrap();
    h.panel
        .push(Reply::json(json!({"allowed":false,"ttl_seconds":300})));
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (memory, scope) = resources();
    let mut client = h.connect(0, target.local_addr().unwrap(), &scope).await;
    assert!(context().run(client.read_u8()).await.unwrap().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(40), target.accept())
            .await
            .is_err()
    );
    drop(client);
    let destination = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut codec = h.client(0).datagrams().unwrap();
    let wire = codec
        .encode(
            &Endpoint::from_address(
                &Address::from_socket(destination.local_addr().unwrap()).unwrap(),
            )
            .unwrap(),
            b"denied",
            &scope,
        )
        .unwrap();
    sender.send_to(wire.as_slice(), h.address).await.unwrap();
    drop(wire);
    let mut b = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(60), destination.recv_from(&mut b))
            .await
            .is_err()
    );
    assert_eq!(runtime.core().reports().snapshot().online_ips, 0);
    assert_eq!(runtime.core().reports().snapshot().pending_bytes, 0);
    assert_eq!(memory.snapshot().used().bytes(), 0);
    h.close().await;
}
#[tokio::test]
async fn failed_udp_bind_rolls_back_the_prepared_tcp_listener() {
    let h = Harness::new("aes-128-gcm").await;
    let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = occupied.local_addr().unwrap();
    h.panel.push(Reply::json(config(h.method, address, true)));
    h.panel.push(Reply::json(users()));
    assert!(h.supervisor.sync_config(&context()).await.is_err());
    let available = TcpListener::bind(address).await.unwrap();
    drop(available);
    let (target, echo) = tcp_echo().await;
    let (memory, scope) = resources();
    let mut stream = h.connect(0, target, &scope).await;
    exchange(&mut stream, b"rollback survived").await;
    drop(stream);
    assert_eq!(memory.snapshot().used().bytes(), 0);
    h.close().await;
    echo.abort();
    echo.await.ok();
}
