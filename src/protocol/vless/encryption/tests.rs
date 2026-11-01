// SPDX-License-Identifier: GPL-3.0-only
use super::{
    crypto::{Aead, Cipher, derive, hash},
    stream::{EncryptedStream, State},
    *,
};
use crate::{
    buffer::BufferScope,
    resource::{Budget, Limits as ResourceLimits},
    task::CancellationToken,
    time::{Deadline, OperationContext},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;
fn decode(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap())
        .collect()
}
fn buffers() -> (Budget, BufferScope) {
    let budget = Budget::new(ResourceLimits::new(1 << 20, 32).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 128 << 10).unwrap();
    (budget, scope)
}
fn state(client: bool, cipher: Cipher) -> State {
    let key = Zeroizing::new([0x42; 96]);
    let (read, write) = if client {
        (b"server".as_slice(), b"client".as_slice())
    } else {
        (b"client".as_slice(), b"server".as_slice())
    };
    State {
        read: Aead::new(read, key.as_ref(), cipher),
        write: Aead::new(write, key.as_ref(), cipher),
        key,
        read_mask: None,
        write_mask: None,
    }
}
#[test]
fn blake3_binary_contexts_and_aead_match_pinned_go_vectors() {
    let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/vless-crypto.json"
    )))
    .unwrap();
    let key: Vec<u8> = (0..96).collect();
    for vector in vectors["kdf"].as_array().unwrap() {
        let context: Vec<_> = (0..vector["length"].as_u64().unwrap())
            .map(|n| (n * 37 + 255) as u8)
            .collect();
        assert_eq!(
            derive(&context, &key).as_ref(),
            decode(vector["derived"].as_str().unwrap())
        );
    }
    for vector in vectors["aead"].as_array().unwrap() {
        let cipher = if vector["aes"].as_bool().unwrap() {
            Cipher::Aes256Gcm
        } else {
            Cipher::ChaCha20Poly1305
        };
        let mut body = b"authenticated application payload".to_vec();
        let header = [23, 3, 3, 0, (body.len() + 16) as u8];
        body.extend([0; 16]);
        Aead::new(&[0, 255, 128, 1], &key, cipher)
            .seal(&mut body, &header, None)
            .unwrap();
        assert_eq!(body, decode(vector["sealed"].as_str().unwrap()));
    }
    assert_eq!(
        hash(b"abc"),
        <Vec<u8> as TryInto<[u8; 32]>>::try_into(decode(
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        ))
        .unwrap()
    );
}
#[test]
fn configurations_reject_missing_keys_invalid_modes_and_unbounded_padding() {
    let key = URL_SAFE_NO_PAD.encode([0x42; 32]);
    for value in [
        format!("unknown.native.0.{key}"),
        format!("mlkem768x25519plus.unknown.0.{key}"),
        format!("mlkem768x25519plus.native.65536s.{key}"),
        format!("mlkem768x25519plus.native.10-1s.{key}"),
        format!("mlkem768x25519plus.native.0.99-35-35.{key}"),
        format!("mlkem768x25519plus.native.0.100-34-35.{key}"),
        format!("mlkem768x25519plus.native.0.100-70000-70000.{key}"),
        format!("mlkem768x25519plus.native.0.100-35-35.100-10001-10001.{key}"),
        format!("mlkem768x25519plus.native.0.{key}.bad"),
    ] {
        assert!(Config::parse(&value).is_err());
    }
    let keys = vec![key; 9].join(".");
    assert!(Config::parse(&format!("mlkem768x25519plus.native.0.{keys}")).is_err());
}
#[test]
fn mlkem_seed_public_key_matches_go_and_x25519_rejects_noncontributory_inputs() {
    let key = keys::ServerKey::from_seed(&[0x42; 64]).unwrap();
    assert_eq!(
        hash(&key.public()).to_vec(),
        decode("fa88246c20b3b266f6dd762098c644f8758af78f1214964c87e50ac969082eb3")
    );
    let key = keys::ServerKey::from_seed(&[0x42; 32]).unwrap();
    assert!(key.decapsulate(&[0; 32]).is_err());
    let mut peer = [1; 32];
    peer[31] = 0x80;
    assert!(key.decapsulate(&peer).is_err());
}
#[tokio::test]
async fn records_survive_short_io_and_rekey_after_nonce_wrap() {
    for cipher in [Cipher::Aes256Gcm, Cipher::ChaCha20Poly1305] {
        let (budget, buffers) = buffers();
        let (a, b) = tokio::io::duplex(7);
        let mut cs = state(true, cipher);
        let mut ss = state(false, cipher);
        cs.write.nonce = [255; 12];
        ss.read.nonce = [255; 12];
        let mut client = EncryptedStream::new(a, cs, &buffers).unwrap();
        let mut server = EncryptedStream::new(b, ss, &buffers).unwrap();
        let sending = async {
            client.write_all(&[0x55; 512]).await.unwrap();
            client.write_all(b"rekeyed").await.unwrap();
            client.shutdown().await.unwrap();
        };
        let receiving = async {
            let mut data = Vec::new();
            server.read_to_end(&mut data).await.unwrap();
            assert_eq!(&data[..512], &[0x55; 512]);
            assert_eq!(&data[512..], b"rekeyed");
        };
        tokio::join!(sending, receiving);
        drop(client);
        drop(server);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}
#[tokio::test]
async fn tampered_record_never_exposes_plaintext_and_poisons_reader() {
    let (budget, buffers) = buffers();
    let (mut raw, peer) = tokio::io::duplex(128);
    let mut server = EncryptedStream::new(peer, state(false, Cipher::Aes256Gcm), &buffers).unwrap();
    let header = [23, 3, 3, 0, 22];
    let mut body = b"secret".to_vec();
    body.extend([0; 16]);
    Aead::new(b"client", &[0x42; 96], Cipher::Aes256Gcm)
        .seal(&mut body, &header, None)
        .unwrap();
    body[21] ^= 1;
    raw.write_all(&header).await.unwrap();
    raw.write_all(&body).await.unwrap();
    let mut output = [0xa5; 16];
    assert!(server.read(&mut output).await.is_err());
    assert_eq!(output, [0xa5; 16]);
    assert!(server.read(&mut output).await.is_err());
    drop(server);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
#[tokio::test(start_paused = true)]
async fn cancelled_partial_write_cannot_acknowledge_a_different_plaintext() {
    let (budget, buffers) = buffers();
    let (a, _b) = tokio::io::duplex(1);
    let mut client = EncryptedStream::new(a, state(true, Cipher::Aes256Gcm), &buffers).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), client.write_all(b"first payload"))
            .await
            .is_err()
    );
    assert!(client.write_all(b"other payload").await.is_err());
    drop(client);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
#[tokio::test(start_paused = true)]
async fn handshake_timeout_reclaims_budget_and_does_not_poll_after_close() {
    let key = URL_SAFE_NO_PAD.encode([0x42; 32]);
    let server = Arc::new(
        Server::new(
            Config::parse(&format!("mlkem768x25519plus.native.0.{key}")).unwrap(),
            Limits::default(),
        )
        .unwrap(),
    );
    let (budget, buffers) = buffers();
    let (a, _b) = tokio::io::duplex(1024);
    let context = OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(1)).unwrap()),
    );
    assert!(server.handshake(a, &buffers, &context).await.is_err());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    server.close();
    let (a, _b) = tokio::io::duplex(1);
    assert!(matches!(
        server.handshake(a, &buffers, &context).await,
        Err(Error::Closed)
    ));
}

#[tokio::test]
async fn native_client_handshakes_and_resumes_with_all_appearances_and_key_kinds() {
    use ml_kem::{KeyExport, ml_kem_768::DecapsulationKey};
    use x25519_dalek::{PublicKey, StaticSecret};
    let context = OperationContext::new(
        CancellationToken::new(),
        Some(Deadline::after(Duration::from_secs(10)).unwrap()),
    );
    for mode in ["native", "xorpub", "random"] {
        for post_quantum in [false, true] {
            let (private, public) = if post_quantum {
                let seed = [0x38; 64];
                let key = DecapsulationKey::from_seed(seed.into());
                (
                    URL_SAFE_NO_PAD.encode(seed),
                    URL_SAFE_NO_PAD.encode(key.encapsulation_key().to_bytes()),
                )
            } else {
                let key = [0x52; 32];
                (
                    URL_SAFE_NO_PAD.encode(key),
                    URL_SAFE_NO_PAD.encode(PublicKey::from(&StaticSecret::from(key)).as_bytes()),
                )
            };
            let server = Server::new(
                Config::parse(&format!("mlkem768x25519plus.{mode}.60s.{private}")).unwrap(),
                Limits::default(),
            )
            .unwrap();
            let client = Client::new(
                ClientConfig::parse(&format!("mlkem768x25519plus.{mode}.0rtt.{public}")).unwrap(),
            );
            let (budget, scope) = buffers();
            for _ in 0..3 {
                let (a, b) = tokio::io::duplex(65536);
                let client_work = async {
                    let mut io = client.handshake(a, &scope, &context).await.unwrap();
                    io.write_all(b"client payload").await.unwrap();
                    io.flush().await.unwrap();
                    let mut response = [0; 14];
                    io.read_exact(&mut response).await.unwrap();
                    assert_eq!(&response, b"server payload");
                };
                let server_work = async {
                    let mut io = server.handshake(b, &scope, &context).await.unwrap();
                    let mut data = [0; 14];
                    io.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"client payload");
                    io.write_all(b"server payload").await.unwrap();
                    io.flush().await.unwrap();
                };
                context
                    .run(async {
                        tokio::join!(client_work, server_work);
                    })
                    .await
                    .unwrap();
                assert_eq!(budget.snapshot().used().bytes(), 0);
            }
        }
    }
}
