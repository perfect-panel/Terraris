// SPDX-License-Identifier: GPL-3.0-only

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{sync::Arc, time::Duration};
use terraris::{
    buffer::BufferScope,
    protocol::vless::encryption::{Config, Error, Limits as EncryptionLimits, Server},
    resource::{Budget, Limits},
    task::CancellationToken,
    time::{Deadline, OperationContext},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::Command,
};

#[tokio::test]
#[ignore = "requires TERRARIS_ENCRYPTION_CLIENT built from tests/interop/encryption"]
async fn pinned_xray_encryption_client_interoperates_and_replays_are_rejected() {
    let binary =
        std::env::var("TERRARIS_ENCRYPTION_CLIENT").expect("set Go interoperability helper path");
    for key_lengths in [vec![32], vec![64], vec![32, 64, 32]] {
        for mode in ["native", "xorpub", "random"] {
            for aes in [true, false] {
                for zero_rtt in [false, true] {
                    let private = key_lengths
                        .iter()
                        .map(|n| URL_SAFE_NO_PAD.encode(vec![0x42; *n]))
                        .collect::<Vec<_>>()
                        .join(".");
                    let config = Config::parse(&format!(
                        "mlkem768x25519plus.{mode}.600s.100-35-35.{private}"
                    ))
                    .unwrap();
                    let client = config.client_encryption(zero_rtt).unwrap();
                    let server =
                        Arc::new(Server::new(config, EncryptionLimits::default()).unwrap());
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let budget = Budget::new(Limits::new(1 << 20, 32).unwrap());
                    let buffers = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
                    let replay = zero_rtt;
                    let task = tokio::spawn(async move {
                        for index in 0..if replay { 3 } else { 2 } {
                            let (socket, _) = listener.accept().await.unwrap();
                            let context = OperationContext::new(
                                CancellationToken::new(),
                                Some(Deadline::after(Duration::from_secs(10)).unwrap()),
                            );
                            let result = server.handshake(socket, &buffers, &context).await;
                            if index == 2 {
                                assert!(matches!(result, Err(Error::Replay)));
                                continue;
                            }
                            let mut stream = result.expect("Xray handshake");
                            let mut packet = [0; 4096];
                            loop {
                                let n = stream.read(&mut packet).await.unwrap();
                                if n == 0 {
                                    break;
                                }
                                stream.write_all(&packet[..n]).await.unwrap();
                            }
                        }
                    });
                    let mut command = Command::new(&binary);
                    command.kill_on_drop(true).args([
                        "-address",
                        &address.to_string(),
                        "-config",
                        &client,
                        &format!("-aes={aes}"),
                        &format!("-replay={replay}"),
                    ]);
                    let output = tokio::time::timeout(Duration::from_secs(30), command.output())
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "mode={mode} aes={aes} zero={zero_rtt} keys={key_lengths:?}: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    let response: serde_json::Value =
                        serde_json::from_slice(&output.stdout).unwrap();
                    assert_eq!(response["resumed"], usize::from(zero_rtt));
                    tokio::time::timeout(Duration::from_secs(10), task)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(budget.snapshot().used().bytes(), 0);
                }
            }
        }
    }
}
