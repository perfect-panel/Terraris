// SPDX-License-Identifier: GPL-3.0-only
mod support;
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use support::{MockPanel, Reply};
use terraris::{
    buffer::BufferScope,
    network::Address,
    panel::{Connection, ProtocolName, WireMode, ppanel::PPanelConnection},
    protocol::{
        flow,
        vless::{self, wire, xudp},
    },
    resource::{Budget, Limits},
    supervisor::{Options, Supervisor},
    task::CancellationToken,
    telemetry::Metrics,
    time::{Deadline, OperationContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
const UUID1: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const UUID2: &str = "b831381d-6324-4d53-ad4f-8cda48b30812";
fn ctx() -> OperationContext {
    OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(10)).unwrap()),
    )
}
async fn unused() -> SocketAddr {
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    socket.local_addr().unwrap()
}
fn config(address: SocketAddr) -> Value {
    json!({"code":200,"data":{"pull_interval":300,"push_interval":300,"traffic_report_threshold":1024,"ip_strategy":"prefer_ipv4","dns":[],"block":[],"outbound":[],"protocols":[{"type":"vless","enable":true,"port":address.port(),"network":"tcp","transport":"tcp","security":"none","encryption":"none","ratio":1}],"total":1}})
}
fn users() -> Value {
    json!({"users":[{"id":1,"uuid":UUID1,"speed_limit":0,"device_limit":0},{"id":2,"uuid":UUID2,"speed_limit":0,"device_limit":0}]})
}
struct Node {
    panel: MockPanel,
    supervisor: Arc<Supervisor<vless::Factory>>,
    address: SocketAddr,
    budget: Budget,
}
impl Node {
    async fn new(mut configure: impl FnMut(&mut Value), userlist: Value) -> Self {
        let address = unused().await;
        let mut value = config(address);
        configure(&mut value);
        let panel = MockPanel::start(vec![Reply::json(value), Reply::json(userlist)]).await;
        let mut options = panel.options();
        options.wire_mode = WireMode::Json;
        let pins = options.fingerprints.clone();
        let connection: Arc<dyn Connection> = Arc::new(PPanelConnection::new(options).unwrap());
        let factory = Arc::new(
            vless::Factory::new(
                connection.clone(),
                vless::Options {
                    listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ..Default::default()
                },
                flow::Options::default(),
            )
            .unwrap(),
        );
        let budget = Budget::new(Limits::new(32 << 20, 4096).unwrap());
        let buffers = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        let supervisor = Arc::new(
            Supervisor::new(
                connection,
                factory,
                buffers,
                Options {
                    drain_timeout: Duration::from_secs(1),
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
            budget,
        }
    }
    fn runtime(&self) -> Arc<terraris::protocol::runtimekit::Runtime> {
        self.supervisor
            .runtime(&ProtocolName::new("vless").unwrap())
            .unwrap()
    }
    async fn connect(
        &self,
        uuid: &str,
        command: wire::Command,
        target: Option<Address>,
    ) -> TcpStream {
        let mut client = TcpStream::connect(self.address).await.unwrap();
        wire::Request {
            uuid: *uuid::Uuid::parse_str(uuid).unwrap().as_bytes(),
            command,
            target,
        }
        .write(&mut client)
        .await
        .unwrap();
        let mut response = [0; 2];
        tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, [0, 0]);
        client
    }
    async fn close(&self) {
        self.panel.push(Reply::json(json!({"code":200})));
        self.panel.push(Reply::json(json!({"code":200})));
        self.supervisor.close(&ctx()).await.unwrap();
        assert_eq!(self.budget.snapshot().used().bytes(), 0);
    }
}
async fn echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {accepted=listener.accept()=>{let (stream,_)=accepted.unwrap();tasks.spawn(async move{let (mut read,mut write)=stream.into_split();tokio::io::copy(&mut read,&mut write).await.ok();write.shutdown().await.ok();});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
    });
    (address, task)
}
async fn udp_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 65535];
        loop {
            let (n, source) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&buffer[..n], source).await.unwrap();
        }
    });
    (address, task)
}
async fn exchange(client: &mut TcpStream, data: &[u8]) {
    client.write_all(data).await.unwrap();
    let mut result = vec![0; data.len()];
    tokio::time::timeout(Duration::from_secs(3), client.read_exact(&mut result))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result, data);
}

#[tokio::test]
async fn tcp_users_are_metered_separately_and_removed_user_is_cancelled() {
    let node = Node::new(|_| {}, users()).await;
    let (address, echo) = echo().await;
    let target = Some(Address::from_socket(address).unwrap());
    let mut first = node
        .connect(UUID1, wire::Command::Tcp, target.clone())
        .await;
    let mut second = node.connect(UUID2, wire::Command::Tcp, target).await;
    exchange(&mut first, b"first").await;
    exchange(&mut second, b"second").await;
    node.panel.push(Reply::json(
        json!({"users":[{"id":2,"uuid":UUID2,"speed_limit":0,"device_limit":0}]}),
    ));
    node.runtime().controller.sync_users(&ctx()).await.unwrap();
    let mut end = [0; 1];
    let closed = tokio::time::timeout(Duration::from_secs(3), first.read(&mut end))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0);
    exchange(&mut second, b"alive").await;
    let reports = node.runtime().core().reports().clone();
    let batch = reports.traffic_batch(0, 10).unwrap().unwrap();
    assert_eq!(batch.values()[0].upload, 5);
    assert_eq!(batch.values()[0].download, 5);
    assert_eq!(batch.values()[1].upload, 11);
    assert_eq!(batch.values()[1].download, 11);
    drop(batch);
    drop(first);
    drop(second);
    node.close().await;
    echo.abort();
    echo.await.ok();
}
#[tokio::test]
async fn same_port_generation_reuses_ingress_and_failure_keeps_live_service() {
    let node = Node::new(|_| {}, users()).await;
    let (address, echo) = echo().await;
    let target = Some(Address::from_socket(address).unwrap());
    let mut old = node
        .connect(UUID1, wire::Command::Tcp, target.clone())
        .await;
    let generation = node.supervisor.snapshot().generation;
    let mut bad = config(node.address);
    bad["data"]["protocols"][0]["flow"] = json!("xtls-rprx-vision");
    node.panel.push(Reply::json(bad));
    assert!(node.supervisor.sync_config(&ctx()).await.is_err());
    assert_eq!(node.supervisor.snapshot().generation, generation);
    exchange(&mut old, b"retained").await;
    let mut replacement = config(node.address);
    replacement["data"]["traffic_report_threshold"] = json!(2048);
    node.panel.push(Reply::json(replacement));
    node.panel.push(Reply::json(users()));
    node.supervisor.sync_config(&ctx()).await.unwrap();
    assert_ne!(node.supervisor.snapshot().generation, generation);
    let mut new = node.connect(UUID1, wire::Command::Tcp, target).await;
    exchange(&mut old, b"old").await;
    exchange(&mut new, b"new").await;
    drop(old);
    drop(new);
    node.close().await;
    assert!(TcpListener::bind(node.address).await.is_ok());
    echo.abort();
    echo.await.ok();
}
#[tokio::test]
async fn ordinary_udp_preserves_empty_and_multiple_datagrams() {
    let node = Node::new(|_| {}, users()).await;
    let (address, echo) = udp_echo().await;
    let mut client = node
        .connect(
            UUID1,
            wire::Command::Udp,
            Some(Address::from_socket(address).unwrap()),
        )
        .await;
    for payload in [&b""[..], &b"a"[..], &vec![0x55; 8192][..]] {
        client
            .write_all(&(payload.len() as u16).to_be_bytes())
            .await
            .unwrap();
        client.write_all(payload).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(3), client.read_u16())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n as usize, payload.len());
        let mut output = vec![0; n as usize];
        client.read_exact(&mut output).await.unwrap();
        assert_eq!(output, payload);
    }
    assert_eq!(
        node.runtime().core().reports().snapshot().pending_bytes,
        2 * 8193
    );
    drop(client);
    node.close().await;
    echo.abort();
    echo.await.ok();
}
#[tokio::test]
async fn xudp_multiplexes_ids_and_per_packet_destinations() {
    let node = Node::new(|_| {}, users()).await;
    let (a, echo_a) = udp_echo().await;
    let (b, echo_b) = udp_echo().await;
    let client = node.connect(UUID1, wire::Command::Xudp, None).await;
    let (read, mut write) = client.into_split();
    let receive_budget = Budget::new(Limits::new(1 << 20, 32).unwrap());
    let mut reader = xudp::Reader::new(
        read,
        BufferScope::new(receive_budget.root_scope(), 65535).unwrap(),
        65535,
    )
    .unwrap();
    for (id, status, destination, payload) in [
        (1, xudp::Status::New, a, &b"one"[..]),
        (2, xudp::Status::New, b, &b"two"[..]),
        (1, xudp::Status::Keep, b, &b"move"[..]),
        (2, xudp::Status::Keep, a, &b""[..]),
    ] {
        let metadata = xudp::Metadata {
            id,
            status,
            data: true,
            error: false,
            target: Some(Address::from_socket(destination).unwrap()),
            global_id: if status == xudp::Status::New {
                Some([id as u8; 8])
            } else {
                None
            },
        };
        xudp::write(&mut write, &metadata, Some(payload))
            .await
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(3), reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.metadata.id, id);
        assert_eq!(
            response.metadata.target.unwrap().socket_addr(),
            Some(destination)
        );
        assert_eq!(response.payload.unwrap().as_slice(), payload);
    }
    assert_eq!(node.runtime().core().reports().snapshot().pending_bytes, 20);
    drop(reader);
    drop(write);
    node.close().await;
    echo_a.abort();
    echo_b.abort();
    echo_a.await.ok();
    echo_b.await.ok();
}

async fn socks(address: SocketAddr, command: u8, target: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut request = vec![5, command, 0, 1];
    let IpAddr::V4(ip) = target.ip() else {
        panic!("IPv4 fixture")
    };
    request.extend(ip.octets());
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let ip = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
    let bind = SocketAddr::new(
        IpAddr::V4(if ip.is_unspecified() {
            Ipv4Addr::LOCALHOST
        } else {
            ip
        }),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    (stream, bind)
}
#[tokio::test]
#[ignore = "requires TERRARIS_XRAY pinned to the documented Xray commit"]
async fn official_xray_proxies_tcp_and_xudp_with_all_encryption_modes() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let binary = std::env::var("TERRARIS_XRAY").expect("path to Xray binary");
    for mode in ["none", "native", "xorpub", "random"] {
        let private = URL_SAFE_NO_PAD.encode([0x42; 32]);
        let encryption = if mode == "none" {
            "none".to_owned()
        } else {
            vless::encryption::Config::parse(&format!(
                "mlkem768x25519plus.{mode}.600s.100-35-35.{private}"
            ))
            .unwrap()
            .client_encryption(true)
            .unwrap()
        };
        let node = Node::new(
            |value| {
                if mode != "none" {
                    let protocol = &mut value["data"]["protocols"][0];
                    protocol["encryption"] = json!("mlkem768x25519plus");
                    protocol["encryption_mode"] = json!(mode);
                    protocol["encryption_ticket"] = json!("600s");
                    protocol["encryption_server_padding"] = json!("100-35-35");
                    protocol["encryption_private_key"] = json!(private);
                }
            },
            users(),
        )
        .await;
        let socks_address = unused().await;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("xray.json");
        let log = dir.path().join("xray.log");
        let value = json!({"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":socks_address.port(),"protocol":"socks","settings":{"auth":"noauth","udp":true,"ip":"127.0.0.1"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":node.address.port(),"users":[{"id":UUID1,"encryption":encryption}]}]},"streamSettings":{"network":"tcp","security":"none"},"mux":{"enabled":true,"concurrency":-1,"xudpConcurrency":8,"xudpProxyUDP443":"allow"}}]});
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let logfile = std::fs::File::create(&log).unwrap();
        let mut child = tokio::process::Command::new(&binary)
            .args(["run", "-config"])
            .arg(&path)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(logfile)
            .spawn()
            .unwrap();
        let start = tokio::time::Instant::now();
        loop {
            if TcpStream::connect(socks_address).await.is_ok() {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "Xray startup: {}",
                std::fs::read_to_string(&log).unwrap()
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "Xray exited: {}",
                std::fs::read_to_string(&log).unwrap()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let (tcp_address, tcp_echo) = echo().await;
        for _ in 0..2 {
            let (mut stream, _) = socks(socks_address, 1, tcp_address).await;
            exchange(&mut stream, &vec![0x5a; 65536]).await;
        }
        // Keep the same Xray process/ticket across a configuration generation.
        let mut next = config(node.address);
        next["data"]["traffic_report_threshold"] = json!(2048);
        if mode != "none" {
            let protocol = &mut next["data"]["protocols"][0];
            protocol["encryption"] = json!("mlkem768x25519plus");
            protocol["encryption_mode"] = json!(mode);
            protocol["encryption_ticket"] = json!("600s");
            protocol["encryption_server_padding"] = json!("100-35-35");
            protocol["encryption_private_key"] = json!(private);
        }
        node.panel.push(Reply::json(next));
        node.panel.push(Reply::json(users()));
        node.supervisor.sync_config(&ctx()).await.unwrap();
        let (mut after_reload, _) = socks(socks_address, 1, tcp_address).await;
        exchange(
            &mut after_reload,
            b"resumption after generation replacement",
        )
        .await;
        drop(after_reload);
        let (first_udp, first_task) = udp_echo().await;
        let (second_udp, second_task) = udp_echo().await;
        let (association, relay) = socks(socks_address, 3, "0.0.0.0:0".parse().unwrap()).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for target in [first_udp, second_udp] {
            let mut request = vec![0, 0, 0, 1, 127, 0, 0, 1];
            request.extend(target.port().to_be_bytes());
            request.extend(b"xudp");
            udp.send_to(&request, relay).await.unwrap();
            let mut response = [0; 1024];
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut response))
                .await
                .unwrap_or_else(|_| {
                    panic!("mode {mode}: {}", std::fs::read_to_string(&log).unwrap())
                })
                .unwrap();
            assert_eq!(&response[10..n], b"xudp");
        }
        drop(association);
        drop(udp);
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        node.close().await;
        tcp_echo.abort();
        first_task.abort();
        second_task.abort();
        tcp_echo.await.ok();
        first_task.await.ok();
        second_task.await.ok();
    }
}

#[tokio::test]
async fn device_denial_happens_before_target_dial_and_leaves_no_online_record() {
    let mut list = users();
    list["users"][0]["device_limit"] = json!(1);
    let node = Node::new(|_| {}, list).await;
    node.panel
        .push(Reply::json(json!({"allowed":false,"ttl_seconds":300})));
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(node.address).await.unwrap();
    wire::Request {
        uuid: *uuid::Uuid::parse_str(UUID1).unwrap().as_bytes(),
        command: wire::Command::Tcp,
        target: Some(Address::from_socket(target.local_addr().unwrap()).unwrap()),
    }
    .write(&mut client)
    .await
    .unwrap();
    let mut response = [0; 2];
    let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut response))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), target.accept())
            .await
            .is_err()
    );
    assert_eq!(node.runtime().core().reports().snapshot().online_ips, 0);
    assert!(
        node.panel
            .requests()
            .iter()
            .any(|r| r.path.ends_with("/device"))
    );
    drop(client);
    node.close().await;
}
#[tokio::test]
async fn xudp_session_limit_rejects_extra_id_and_keeps_existing_stream_usable() {
    let node = Node::new(|_| {}, users()).await;
    let (address, echo) = udp_echo().await;
    let client = node.connect(UUID1, wire::Command::Xudp, None).await;
    let (read, mut write) = client.into_split();
    let budget = Budget::new(Limits::new(1 << 20, 32).unwrap());
    let mut reader = xudp::Reader::new(
        read,
        BufferScope::new(budget.root_scope(), 65535).unwrap(),
        65535,
    )
    .unwrap();
    for id in 1..=33 {
        xudp::write(
            &mut write,
            &xudp::Metadata {
                id,
                status: xudp::Status::New,
                data: false,
                error: false,
                target: Some(Address::from_socket(address).unwrap()),
                global_id: None,
            },
            None,
        )
        .await
        .unwrap();
    }
    let rejected = tokio::time::timeout(Duration::from_secs(2), reader.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(rejected.metadata.id, 33);
    assert_eq!(rejected.metadata.status, xudp::Status::End);
    assert!(rejected.metadata.error);
    xudp::write(
        &mut write,
        &xudp::Metadata {
            id: 1,
            status: xudp::Status::Keep,
            data: true,
            error: false,
            target: None,
            global_id: None,
        },
        Some(b"usable"),
    )
    .await
    .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), reader.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(reply.payload.unwrap().as_slice(), b"usable");
    drop(reader);
    drop(write);
    node.close().await;
    echo.abort();
    echo.await.ok();
}
#[cfg(unix)]
#[tokio::test]
async fn run_cli_serves_vless_and_sigterm_closes_listener_and_flushes_reports() {
    let address = unused().await;
    let panel = MockPanel::start(vec![Reply::json(config(address)), Reply::json(users())]).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.toml");
    let log = dir.path().join("stderr.log");
    std::fs::write(&path,format!("[panel]\nbase_url = '{}/panel/api'\nserver_id=7\nsecret_env='TERRARIS_CLI_TEST_KEY'\nwire_format='json'\n[node]\nlisten='127.0.0.1'\ndrain_timeout_seconds=1\nshutdown_timeout_seconds=2\n",panel.url)).unwrap();
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_terraris"))
        .args(["run", "--config"])
        .arg(&path)
        .env("TERRARIS_CLI_TEST_KEY", support::SECRET)
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let started = tokio::time::Instant::now();
    loop {
        if TcpStream::connect(address).await.is_ok() {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{}",
            std::fs::read_to_string(&log).unwrap()
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "{}",
            std::fs::read_to_string(&log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let (target, echo) = echo().await;
    let mut client = TcpStream::connect(address).await.unwrap();
    wire::Request {
        uuid: *uuid::Uuid::parse_str(UUID1).unwrap().as_bytes(),
        command: wire::Command::Tcp,
        target: Some(Address::from_socket(target).unwrap()),
    }
    .write(&mut client)
    .await
    .unwrap();
    let mut response = [0; 2];
    client.read_exact(&mut response).await.unwrap();
    exchange(&mut client, b"cli proxy").await;
    drop(client);
    panel.push(Reply::json(json!({"code":200})));
    panel.push(Reply::json(json!({"code":200})));
    let status = tokio::process::Command::new("/bin/kill")
        .arg("-TERM")
        .arg(child.id().unwrap().to_string())
        .status()
        .await
        .unwrap();
    assert!(status.success());
    let status = tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(
        status.success(),
        "{}",
        std::fs::read_to_string(&log).unwrap()
    );
    assert!(TcpListener::bind(address).await.is_ok());
    assert!(panel.requests().iter().any(|r| r.path.ends_with("/push")));
    assert!(panel.requests().iter().any(|r| r.path.ends_with("/online")));
    echo.abort();
    echo.await.ok();
}

#[tokio::test]
async fn system_dns_jobs_are_joined_during_runtime_shutdown() {
    let node = Node::new(|_| {}, users()).await;
    let (address, echo) = echo().await;
    let mut client = node
        .connect(
            UUID1,
            wire::Command::Tcp,
            Some(Address::from_domain("localhost", address.port()).unwrap()),
        )
        .await;
    exchange(&mut client, b"resolved localhost").await;
    drop(client);
    node.close().await;
    echo.abort();
    echo.await.ok();
}

#[tokio::test]
async fn disabling_all_protocols_revokes_live_sessions_even_with_unused_egress_settings() {
    let node = Node::new(|_| {}, users()).await;
    let (address, echo) = echo().await;
    let mut client = node
        .connect(
            UUID1,
            wire::Command::Tcp,
            Some(Address::from_socket(address).unwrap()),
        )
        .await;
    exchange(&mut client, b"before disable").await;
    let mut disabled = config(node.address);
    disabled["data"]["protocols"][0]["enable"] = json!(false);
    disabled["data"]["block"] = json!(["full:unused.example.com"]);
    node.panel.push(Reply::json(disabled));
    node.supervisor.sync_config(&ctx()).await.unwrap();
    assert!(!node.supervisor.snapshot().ready);
    assert!(node.supervisor.snapshot().protocols.is_empty());
    let mut bytes = [0; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut bytes))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    drop(client);
    node.close().await;
    echo.abort();
    echo.await.ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rapid_reload_and_last_driver_release_do_not_deadlock_accept_routing() {
    let node = Node::new(|_| {}, users()).await;
    let address = node.address;
    let churn = tokio::spawn(async move {
        for _ in 0..200 {
            if let Ok(socket) = TcpStream::connect(address).await {
                drop(socket);
            }
            tokio::task::yield_now().await;
        }
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        for version in 0..20 {
            let mut next = config(node.address);
            next["data"]["traffic_report_threshold"] = json!(2048 + version);
            node.panel.push(Reply::json(next));
            node.panel.push(Reply::json(users()));
            node.supervisor.sync_config(&ctx()).await.unwrap();
            node.supervisor.reap_retired(&ctx()).await.unwrap();
        }
        churn.await.unwrap();
        node.close().await;
    })
    .await
    .unwrap();
}
