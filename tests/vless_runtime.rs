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
    factory: Arc<vless::Factory>,
}
impl Node {
    async fn new(configure: impl FnMut(&mut Value), userlist: Value) -> Self {
        Self::with_options(
            configure,
            userlist,
            vless::Options {
                listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
                ..Default::default()
            },
        )
        .await
    }
    async fn with_options(
        mut configure: impl FnMut(&mut Value),
        userlist: Value,
        protocol_options: vless::Options,
    ) -> Self {
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
                protocol_options,
                flow::Options::default(),
            )
            .unwrap(),
        );
        let budget = Budget::new(Limits::new(32 << 20, 4096).unwrap());
        let buffers = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
        let supervisor = Arc::new(
            Supervisor::new(
                connection,
                factory.clone(),
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
            factory,
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
        // Force the current encrypted/plain carrier to retire while keeping
        // Xray, its SOCKS UDP socket, and therefore its GlobalID alive.
        let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = observer.local_addr().unwrap();
        let mut request = vec![0, 0, 0, 1, 127, 0, 0, 1];
        request.extend(target.port().to_be_bytes());
        request.extend(b"gid-before");
        udp.send_to(&request, relay).await.unwrap();
        let before = receive_udp(&observer, b"gid-before").await;
        observer.send_to(b"before-ack", before).await.unwrap();
        let mut response = [0; 1024];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&response[10..n], b"before-ack");
        let mut migration = config(node.address);
        migration["data"]["traffic_report_threshold"] = json!(4096);
        if mode != "none" {
            let protocol = &mut migration["data"]["protocols"][0];
            protocol["encryption"] = json!("mlkem768x25519plus");
            protocol["encryption_mode"] = json!(mode);
            protocol["encryption_ticket"] = json!("600s");
            protocol["encryption_server_padding"] = json!("100-35-35");
            protocol["encryption_private_key"] = json!(private);
        }
        node.panel.push(Reply::json(migration));
        node.panel.push(Reply::json(users()));
        node.supervisor.sync_config(&ctx()).await.unwrap();
        node.supervisor.reap_retired(&ctx()).await.unwrap();
        assert!(
            node.factory.xudp_snapshot().detached > 0,
            "Xray must send a nonzero GlobalID"
        );
        let mut request = vec![0, 0, 0, 1, 127, 0, 0, 1];
        request.extend(target.port().to_be_bytes());
        request.extend(b"gid-after");
        let mut observed = [0; 1024];
        let mut after = None;
        for _ in 0..20 {
            udp.send_to(&request, relay).await.unwrap();
            if let Ok(Ok((n, source))) = tokio::time::timeout(
                Duration::from_millis(100),
                observer.recv_from(&mut observed),
            )
            .await
            {
                assert_eq!(&observed[..n], b"gid-after");
                after = Some(source);
                break;
            }
        }
        assert_eq!(
            after,
            Some(before),
            "Xray GlobalID must preserve the UDP source endpoint for {mode}"
        );
        observer.send_to(b"after-ack", before).await.unwrap();
        // One SOCKS UDP association carries replies from all destinations.
        // Xray's first retry on a new mux worker can use its original default
        // destination before later Keep frames carry the explicit destination.
        let mut received_ack = false;
        for _ in 0..20 {
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
            let reply_source = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(
                    response[4],
                    response[5],
                    response[6],
                    response[7],
                )),
                u16::from_be_bytes([response[8], response[9]]),
            );
            if reply_source == target {
                assert_eq!(&response[10..n], b"after-ack");
                received_ack = true;
                break;
            }
            assert!([first_udp, second_udp].contains(&reply_source));
        }
        assert!(received_ack);
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

type MuxReader = xudp::Reader<tokio::net::tcp::OwnedReadHalf>;
struct MuxPeer {
    reader: MuxReader,
    writer: tokio::net::tcp::OwnedWriteHalf,
}
impl MuxPeer {
    async fn connect(node: &Node, uuid: &str) -> Self {
        let stream = node.connect(uuid, wire::Command::Xudp, None).await;
        let (read, writer) = stream.into_split();
        let budget = Budget::new(Limits::new(1 << 20, 32).unwrap());
        Self {
            reader: xudp::Reader::new(
                read,
                BufferScope::new(budget.root_scope(), 65535).unwrap(),
                65535,
            )
            .unwrap(),
            writer,
        }
    }
    async fn new_flow(
        &mut self,
        id: u16,
        global: Option<[u8; 8]>,
        target: SocketAddr,
        payload: &[u8],
    ) {
        xudp::write(
            &mut self.writer,
            &xudp::Metadata {
                id,
                status: xudp::Status::New,
                data: true,
                error: false,
                target: Some(Address::from_socket(target).unwrap()),
                global_id: global,
            },
            Some(payload),
        )
        .await
        .unwrap();
    }
    async fn keep(&mut self, id: u16, payload: &[u8]) {
        xudp::write(
            &mut self.writer,
            &xudp::Metadata {
                id,
                status: xudp::Status::Keep,
                data: true,
                error: false,
                target: None,
                global_id: None,
            },
            Some(payload),
        )
        .await
        .unwrap();
    }
    async fn end(&mut self, id: u16) {
        xudp::write(
            &mut self.writer,
            &xudp::Metadata {
                id,
                status: xudp::Status::End,
                data: false,
                error: false,
                target: None,
                global_id: None,
            },
            None,
        )
        .await
        .unwrap();
    }
    async fn frame(&mut self) -> xudp::Frame {
        tokio::time::timeout(Duration::from_secs(3), self.reader.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    }
    async fn data(&mut self, id: u16, expected: &[u8]) {
        let frame = self.frame().await;
        assert_eq!(frame.metadata.id, id);
        assert_eq!(frame.metadata.status, xudp::Status::Keep);
        assert_eq!(frame.payload.unwrap().as_slice(), expected);
    }
}
async fn receive_udp(socket: &UdpSocket, expected: &[u8]) -> SocketAddr {
    let mut data = [0; 1024];
    let (n, peer) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut data))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&data[..n], expected);
    peer
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn global_id_reconnect_preserves_udp_port_and_forwards_buffered_reply_once() {
    let node = Node::new(|_| {}, users()).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut first = MuxPeer::connect(&node, UUID1).await;
    let global = Some([0x51; 8]);
    first
        .new_flow(1, global, target.local_addr().unwrap(), b"old")
        .await;
    let source = receive_udp(&target, b"old").await;
    target.send_to(b"ack", source).await.unwrap();
    first.data(1, b"ack").await;
    drop(first);
    until(|| node.factory.xudp_snapshot().detached == 1).await;
    let counted = node.runtime().core().reports().snapshot().pending_bytes;
    target.send_to(b"queued", source).await.unwrap();
    until(|| node.factory.xudp_snapshot().buffered_packets == 1).await;
    assert_eq!(
        node.runtime().core().reports().snapshot().pending_bytes,
        counted
    );
    let mut second = MuxPeer::connect(&node, UUID1).await;
    second
        .new_flow(9, global, target.local_addr().unwrap(), b"new")
        .await;
    assert_eq!(receive_udp(&target, b"new").await, source);
    second.data(9, b"queued").await;
    target.send_to(b"reply", source).await.unwrap();
    second.data(9, b"reply").await;
    assert_eq!(node.factory.xudp_snapshot().associations, 1);
    assert_eq!(
        node.runtime().core().reports().snapshot().pending_bytes,
        3 + 3 + 3 + 6 + 5
    );
    drop(second);
    node.close().await;
    assert_eq!(node.factory.xudp_snapshot().associations, 0);
    assert_eq!(node.factory.xudp_snapshot().tracked_tasks, 0);
}
#[tokio::test]
async fn active_global_takeover_rejects_old_packets_and_late_end_cannot_detach_new_owner() {
    let node = Node::new(|_| {}, users()).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let global = Some([0x52; 8]);
    let mut old = MuxPeer::connect(&node, UUID1).await;
    old.new_flow(1, global, target.local_addr().unwrap(), b"old")
        .await;
    let source = receive_udp(&target, b"old").await;
    let mut new = MuxPeer::connect(&node, UUID1).await;
    new.new_flow(42, global, target.local_addr().unwrap(), b"new")
        .await;
    assert_eq!(receive_udp(&target, b"new").await, source);
    let ended = old.frame().await;
    assert_eq!(ended.metadata.id, 1);
    assert_eq!(ended.metadata.status, xudp::Status::End);
    old.keep(1, b"stale").await;
    let ended = old.frame().await;
    assert_eq!(ended.metadata.status, xudp::Status::End);
    let mut bytes = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(30), target.recv_from(&mut bytes))
            .await
            .is_err()
    );
    old.end(1).await;
    drop(old);
    new.keep(42, b"live").await;
    assert_eq!(receive_udp(&target, b"live").await, source);
    target.send_to(b"after", source).await.unwrap();
    new.data(42, b"after").await;
    assert_eq!(node.factory.xudp_snapshot().attached, 1);
    drop(new);
    node.close().await;
}
#[tokio::test]
async fn global_ids_are_isolated_by_user_and_zero_ids_never_share_sockets() {
    let node = Node::new(|_| {}, users()).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut first = MuxPeer::connect(&node, UUID1).await;
    let mut second = MuxPeer::connect(&node, UUID2).await;
    let global = Some([0x53; 8]);
    first
        .new_flow(1, global, target.local_addr().unwrap(), b"user1")
        .await;
    let a = receive_udp(&target, b"user1").await;
    second
        .new_flow(2, global, target.local_addr().unwrap(), b"user2")
        .await;
    let b = receive_udp(&target, b"user2").await;
    assert_ne!(a, b);
    target.send_to(b"private1", a).await.unwrap();
    target.send_to(b"private2", b).await.unwrap();
    first.data(1, b"private1").await;
    second.data(2, b"private2").await;
    first
        .new_flow(3, Some([0; 8]), target.local_addr().unwrap(), b"zero1")
        .await;
    let a = receive_udp(&target, b"zero1").await;
    first
        .new_flow(4, Some([0; 8]), target.local_addr().unwrap(), b"zero2")
        .await;
    let b = receive_udp(&target, b"zero2").await;
    assert_ne!(a, b);
    drop(first);
    drop(second);
    until(|| node.factory.xudp_snapshot().associations == 2).await;
    node.close().await;
}
#[tokio::test]
async fn global_migration_survives_retired_generation_cleanup() {
    let node = Node::new(|_| {}, users()).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let global = Some([0x54; 8]);
    let mut old = MuxPeer::connect(&node, UUID1).await;
    old.new_flow(1, global, target.local_addr().unwrap(), b"before")
        .await;
    let source = receive_udp(&target, b"before").await;
    let mut next = config(node.address);
    next["data"]["traffic_report_threshold"] = json!(2048);
    node.panel.push(Reply::json(next));
    node.panel.push(Reply::json(users()));
    node.supervisor.sync_config(&ctx()).await.unwrap();
    let mut new = MuxPeer::connect(&node, UUID1).await;
    new.new_flow(11, global, target.local_addr().unwrap(), b"moved")
        .await;
    assert_eq!(receive_udp(&target, b"moved").await, source);
    drop(old);
    node.supervisor.reap_retired(&ctx()).await.unwrap();
    assert_eq!(node.supervisor.snapshot().retired, 0);
    new.keep(11, b"after").await;
    assert_eq!(receive_udp(&target, b"after").await, source);
    target.send_to(b"ok", source).await.unwrap();
    new.data(11, b"ok").await;
    drop(new);
    node.close().await;
}
#[tokio::test]
async fn detached_cache_is_bounded_and_expiry_releases_socket_and_buffers() {
    let options = vless::Options {
        listen: IpAddr::V4(Ipv4Addr::LOCALHOST),
        xudp_resume_timeout: Duration::from_millis(150),
        xudp_detached_packets: 2,
        max_xudp_associations: 1,
        ..Default::default()
    };
    let node = Node::with_options(|_| {}, users(), options).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut first = MuxPeer::connect(&node, UUID1).await;
    first
        .new_flow(1, Some([0x55; 8]), target.local_addr().unwrap(), b"first")
        .await;
    let source = receive_udp(&target, b"first").await;
    let mut extra = MuxPeer::connect(&node, UUID1).await;
    extra
        .new_flow(2, Some([0x56; 8]), target.local_addr().unwrap(), b"full")
        .await;
    assert_eq!(extra.frame().await.metadata.status, xudp::Status::End);
    drop(extra);
    drop(first);
    until(|| node.factory.xudp_snapshot().detached == 1).await;
    for _ in 0..8 {
        target.send_to(b"buffer", source).await.unwrap();
    }
    until(|| node.factory.xudp_snapshot().buffered_packets == 2).await;
    assert_eq!(node.runtime().core().reports().snapshot().pending_bytes, 5);
    tokio::time::sleep(Duration::from_millis(200)).await;
    until(|| {
        node.factory.xudp_snapshot().associations == 0 && node.budget.snapshot().used().bytes() == 0
    })
    .await;
    let _reserved = UdpSocket::bind(source).await.unwrap();
    node.close().await;
}
#[tokio::test]
async fn credential_change_discards_dormant_global_state_before_uuid_reuse() {
    let node = Node::new(|_| {}, users()).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let global = Some([0x57; 8]);
    let mut old = MuxPeer::connect(&node, UUID1).await;
    old.new_flow(1, global, target.local_addr().unwrap(), b"old")
        .await;
    let source = receive_udp(&target, b"old").await;
    drop(old);
    until(|| node.factory.xudp_snapshot().detached == 1).await;
    target.send_to(b"secret", source).await.unwrap();
    until(|| node.factory.xudp_snapshot().buffered_packets == 1).await;
    let new_uuid = "b831381d-6324-4d53-ad4f-8cda48b30813";
    let mut next = users();
    next["users"][0]["uuid"] = json!(new_uuid);
    node.panel.push(Reply::json(next));
    node.runtime().controller.sync_users(&ctx()).await.unwrap();
    until(|| {
        node.factory.xudp_snapshot().associations == 0 && node.budget.snapshot().used().bytes() == 0
    })
    .await;
    let _reserved = UdpSocket::bind(source).await.unwrap();
    let mut new = MuxPeer::connect(&node, new_uuid).await;
    new.new_flow(2, global, target.local_addr().unwrap(), b"new")
        .await;
    let current = receive_udp(&target, b"new").await;
    assert_ne!(current, source);
    target.send_to(b"fresh", current).await.unwrap();
    new.data(2, b"fresh").await;
    drop(new);
    node.close().await;
}

#[tokio::test]
async fn changed_egress_policy_does_not_reuse_a_global_socket_from_the_old_policy() {
    let node = Node::new(|_| {}, users()).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut first = MuxPeer::connect(&node, UUID1).await;
    let global = Some([0x58; 8]);
    first
        .new_flow(1, global, target.local_addr().unwrap(), b"old-policy")
        .await;
    let original = receive_udp(&target, b"old-policy").await;
    let mut next = config(node.address);
    next["data"]["ip_strategy"] = json!("ipv4_only");
    node.panel.push(Reply::json(next));
    node.panel.push(Reply::json(users()));
    node.supervisor.sync_config(&ctx()).await.unwrap();
    let mut second = MuxPeer::connect(&node, UUID1).await;
    second
        .new_flow(2, global, target.local_addr().unwrap(), b"new-policy")
        .await;
    let current = receive_udp(&target, b"new-policy").await;
    assert_ne!(current, original);
    drop(first);
    drop(second);
    node.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_global_claims_publish_one_reply_owner_and_keep_one_socket() {
    let node = Node::new(|_| {}, users()).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let global = Some([0x59; 8]);
    let mut first = MuxPeer::connect(&node, UUID1).await;
    first
        .new_flow(1, global, target.local_addr().unwrap(), b"base")
        .await;
    let original = receive_udp(&target, b"base").await;
    let mut left = MuxPeer::connect(&node, UUID1).await;
    let mut right = MuxPeer::connect(&node, UUID1).await;
    let address = target.local_addr().unwrap();
    tokio::join!(
        left.new_flow(2, global, address, b"left"),
        right.new_flow(3, global, address, b"right")
    );
    until(|| node.factory.xudp_snapshot().reattachments == 2).await;
    assert_eq!(node.factory.xudp_snapshot().associations, 1);
    assert_eq!(node.factory.xudp_snapshot().attached, 1);
    target.send_to(b"owner", original).await.unwrap();
    let (a, b) = tokio::join!(left.frame(), right.frame());
    assert_eq!(
        usize::from(a.metadata.status == xudp::Status::Keep)
            + usize::from(b.metadata.status == xudp::Status::Keep),
        1
    );
    let winner = if a.metadata.status == xudp::Status::Keep {
        a
    } else {
        b
    };
    assert_eq!(winner.payload.unwrap().as_slice(), b"owner");
    drop(first);
    drop(left);
    drop(right);
    node.close().await;
}

#[tokio::test]
async fn active_global_association_is_closed_and_joined_on_node_shutdown() {
    let node = Node::new(|_| {}, users()).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut client = MuxPeer::connect(&node, UUID1).await;
    client
        .new_flow(
            1,
            Some([0x60; 8]),
            target.local_addr().unwrap(),
            b"shutdown",
        )
        .await;
    let source = receive_udp(&target, b"shutdown").await;
    assert_eq!(node.factory.xudp_snapshot().attached, 1);
    node.close().await;
    assert_eq!(node.factory.xudp_snapshot().associations, 0);
    assert_eq!(node.factory.xudp_snapshot().tracked_tasks, 0);
    let _released = UdpSocket::bind(source).await.unwrap();
    drop(client);
}
#[tokio::test]
async fn global_migration_preserves_both_ipv4_and_ipv6_socket_owners() {
    let node = Node::new(|_| {}, users()).await;
    let v4 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let v6 = UdpSocket::bind("[::1]:0").await.unwrap();
    let global = Some([0x61; 8]);
    let mut old = MuxPeer::connect(&node, UUID1).await;
    old.new_flow(1, global, v4.local_addr().unwrap(), b"v4")
        .await;
    let source4 = receive_udp(&v4, b"v4").await;
    xudp::write(
        &mut old.writer,
        &xudp::Metadata {
            id: 1,
            status: xudp::Status::Keep,
            data: true,
            error: false,
            target: Some(Address::from_socket(v6.local_addr().unwrap()).unwrap()),
            global_id: None,
        },
        Some(b"v6"),
    )
    .await
    .unwrap();
    let source6 = receive_udp(&v6, b"v6").await;
    drop(old);
    until(|| node.factory.xudp_snapshot().detached == 1).await;
    let mut new = MuxPeer::connect(&node, UUID1).await;
    new.new_flow(7, global, v6.local_addr().unwrap(), b"v6-again")
        .await;
    assert_eq!(receive_udp(&v6, b"v6-again").await, source6);
    xudp::write(
        &mut new.writer,
        &xudp::Metadata {
            id: 7,
            status: xudp::Status::Keep,
            data: true,
            error: false,
            target: Some(Address::from_socket(v4.local_addr().unwrap()).unwrap()),
            global_id: None,
        },
        Some(b"v4-again"),
    )
    .await
    .unwrap();
    assert_eq!(receive_udp(&v4, b"v4-again").await, source4);
    v4.send_to(b"reply4", source4).await.unwrap();
    v6.send_to(b"reply6", source6).await.unwrap();
    let mut replies = std::collections::BTreeSet::new();
    for _ in 0..2 {
        let frame = new.frame().await;
        assert_eq!(frame.metadata.id, 7);
        replies.insert(frame.payload.unwrap().as_slice().to_vec());
    }
    assert_eq!(
        replies,
        std::collections::BTreeSet::from([b"reply4".to_vec(), b"reply6".to_vec()])
    );
    assert_eq!(node.factory.xudp_snapshot().associations, 1);
    drop(new);
    node.close().await;
}
