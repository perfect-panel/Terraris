// SPDX-License-Identifier: GPL-3.0-only
use std::time::Duration;
use terraris::{
    buffer::BufferScope,
    network::Address,
    protocol::vless::{
        wire::{self, Command, Request},
        xudp::{self, Metadata, Status},
    },
    resource::{Budget, Limits},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn scope() -> (Budget, BufferScope) {
    let budget = Budget::new(Limits::new(1 << 20, 32).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 65535).unwrap();
    (budget, scope)
}
#[tokio::test]
async fn vless_header_golden_bytes_and_addresses_roundtrip() {
    let request = Request {
        uuid: [0x42; 16],
        command: Command::Tcp,
        target: Some(Address::from_socket("127.0.0.1:443".parse().unwrap()).unwrap()),
    };
    let mut bytes = Vec::new();
    request.write(&mut bytes).await.unwrap();
    let mut golden = vec![0];
    golden.extend([0x42; 16]);
    golden.extend([0, 1, 1, 187, 1, 127, 0, 0, 1]);
    assert_eq!(bytes, golden);
    for address in ["127.0.0.1:443", "[::1]:1234", "example.com:53"] {
        let expected: Address = address.parse().unwrap();
        let request = Request {
            uuid: [1; 16],
            command: Command::Udp,
            target: Some(expected.clone()),
        };
        let mut bytes = vec![];
        request.write(&mut bytes).await.unwrap();
        let parsed = Request::read(&mut bytes.as_slice()).await.unwrap();
        assert_eq!(parsed.command, Command::Udp);
        assert_eq!(parsed.target, Some(expected));
    }
    let request = Request {
        uuid: [1; 16],
        command: Command::Xudp,
        target: None,
    };
    let mut bytes = vec![];
    request.write(&mut bytes).await.unwrap();
    assert_eq!(bytes.len(), 19);
    assert_eq!(bytes[18], 3);
}
#[tokio::test]
async fn invalid_version_commands_and_addons_are_rejected() {
    for (command, addons) in [(4, vec![]), (1, vec![10, 255]), (1, vec![10, 1, b'x'])] {
        let mut bytes = vec![0];
        bytes.extend([0; 16]);
        bytes.push(addons.len() as u8);
        bytes.extend(addons);
        bytes.push(command);
        bytes.extend([0, 80, 1, 127, 0, 0, 1]);
        assert!(Request::read(&mut bytes.as_slice()).await.is_err());
    }
    let mut bytes = [0; 19];
    bytes[0] = 1;
    assert!(Request::read(&mut bytes.as_slice()).await.is_err());
}
#[tokio::test(start_paused = true)]
async fn xudp_reader_keeps_partial_metadata_and_packet_when_next_is_cancelled() {
    let (budget, scope) = scope();
    let (mut sender, receiver) = tokio::io::duplex(1024);
    let metadata = Metadata {
        id: 42,
        status: Status::New,
        data: true,
        error: false,
        target: Some("127.0.0.1:53".parse().unwrap()),
        global_id: Some([7; 8]),
    };
    let mut encoded = vec![];
    xudp::write(&mut encoded, &metadata, Some(b"packet"))
        .await
        .unwrap();
    let mut reader = xudp::Reader::new(receiver, scope, 65535).unwrap();
    for (index, piece) in encoded.chunks(3).enumerate() {
        sender.write_all(piece).await.unwrap();
        if index * 3 + piece.len() < encoded.len() {
            assert!(
                tokio::time::timeout(Duration::from_millis(1), reader.next())
                    .await
                    .is_err()
            );
        }
    }
    let frame = reader.next().await.unwrap().unwrap();
    assert_eq!(frame.metadata.id, 42);
    assert_eq!(frame.metadata.global_id, Some([7; 8]));
    assert_eq!(frame.payload.as_ref().unwrap().as_slice(), b"packet");
    drop(frame);
    drop(reader);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
#[tokio::test]
async fn xudp_rejects_invalid_lengths_flags_networks_and_trailing_metadata() {
    for bytes in [
        vec![0, 3, 0, 0, 1],
        vec![2, 1],
        vec![0, 4, 0, 0, 2, 128],
        vec![0, 5, 0, 0, 1, 1, 1],
        vec![0, 5, 0, 0, 4, 0, 0],
    ] {
        let (budget, scope) = scope();
        let mut reader = xudp::Reader::new(bytes.as_slice(), scope, 65535).unwrap();
        assert!(reader.next().await.is_err());
        assert!(reader.next().await.is_err());
        drop(reader);
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
}
#[tokio::test]
async fn oversized_udp_payload_is_rejected_before_allocating_it() {
    let (budget, scope) = scope();
    let bytes = [0, 4, 0, 1, 2, 1, 0, 10];
    let mut reader = xudp::Reader::new(bytes.as_slice(), scope, 9).unwrap();
    assert!(matches!(reader.next().await, Err(wire::Error::TooLarge)));
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
#[tokio::test]
async fn empty_datagram_is_not_eof_and_end_control_has_no_payload() {
    let (budget, scope) = scope();
    let metadata = Metadata {
        id: 1,
        status: Status::Keep,
        data: true,
        error: false,
        target: None,
        global_id: None,
    };
    let mut bytes = vec![];
    xudp::write(&mut bytes, &metadata, Some(&[])).await.unwrap();
    xudp::write(
        &mut bytes,
        &Metadata {
            id: 1,
            status: Status::End,
            data: false,
            error: true,
            target: None,
            global_id: None,
        },
        None,
    )
    .await
    .unwrap();
    let mut reader = xudp::Reader::new(bytes.as_slice(), scope, 0).unwrap();
    let empty = reader.next().await.unwrap().unwrap();
    assert_eq!(empty.payload.unwrap().len(), 0);
    let end = reader.next().await.unwrap().unwrap();
    assert_eq!(end.metadata.status, Status::End);
    assert!(end.payload.is_none());
    assert!(reader.next().await.unwrap().is_none());
    drop(reader);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
#[tokio::test(start_paused = true)]
async fn ordinary_udp_length_prefix_survives_cancelled_reads() {
    let (budget, scope) = scope();
    let (mut sender, receiver) = tokio::io::duplex(16);
    let mut reader = wire::PacketReader::new(receiver, scope, 10);
    sender.write_all(&[0]).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), reader.next())
            .await
            .is_err()
    );
    sender.write_all(&[3, b'a']).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(1), reader.next())
            .await
            .is_err()
    );
    sender.write_all(b"bc").await.unwrap();
    let packet = reader.next().await.unwrap().unwrap();
    assert_eq!(packet.as_slice(), b"abc");
    drop(packet);
    drop(reader);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}
#[tokio::test]
async fn response_is_exactly_version_and_empty_addons() {
    let (mut tx, mut rx) = tokio::io::duplex(8);
    wire::write_response(&mut tx).await.unwrap();
    let mut response = [0xff; 2];
    rx.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [0, 0]);
}
