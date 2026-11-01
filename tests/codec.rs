// SPDX-License-Identifier: GPL-3.0-only

use std::net::{SocketAddr, SocketAddrV6};
use terraris::{
    buffer::{BufferLayout, BufferPool, BufferScope, PoolConfig},
    codec::{Error, FrameDecoder, LengthPrefix, Reader, Writer},
    network::Address,
    resource::{Budget, Limits},
    telemetry::{Counter, Metrics},
};

fn scope() -> (Budget, BufferScope) {
    let b = Budget::new(Limits::new(4096, 16).unwrap());
    let s = BufferScope::new(b.root_scope(), 1024).unwrap();
    (b, s)
}

#[test]
fn integer_primitives_are_big_endian_and_failed_reads_do_not_advance() {
    let (_, scope) = scope();
    let mut buffer = scope
        .try_lease(BufferLayout::new(0, 32, 0).unwrap())
        .unwrap();
    let mut writer = Writer::new(&mut buffer);
    writer.u8(7).unwrap();
    writer.u16_be(0x1234).unwrap();
    writer.u32_be(0x01020304).unwrap();
    writer.u64_be(0x0807060504030201).unwrap();
    assert_eq!(
        buffer.as_slice(),
        &[7, 0x12, 0x34, 1, 2, 3, 4, 8, 7, 6, 5, 4, 3, 2, 1]
    );
    let mut reader = Reader::new(buffer.as_slice(), 32).unwrap();
    assert_eq!(reader.u8().unwrap(), 7);
    assert_eq!(reader.u16_be().unwrap(), 0x1234);
    assert_eq!(reader.u32_be().unwrap(), 0x01020304);
    assert_eq!(reader.u64_be().unwrap(), 0x0807060504030201);
    reader.finish().unwrap();
    let position = reader.position();
    assert_eq!(reader.take(usize::MAX).unwrap_err(), Error::UnexpectedEof);
    assert_eq!(reader.position(), position);
    assert!(Reader::new(b"private", 3).is_err());
}

#[test]
fn address_vectors_match_rfc1928_destination_layout_and_roundtrip() {
    let (_, scope) = scope();
    let vectors = [
        ("127.0.0.1:443", vec![1, 127, 0, 0, 1, 1, 187]),
        (
            "example.com:80",
            [vec![3, 11], b"example.com".to_vec(), vec![0, 80]].concat(),
        ),
        ("[::1]:53", [vec![4], vec![0; 15], vec![1, 0, 53]].concat()),
    ];
    for (text, wire) in vectors {
        let address: Address = text.parse().unwrap();
        let mut buffer = scope
            .try_lease(BufferLayout::new(0, 259, 0).unwrap())
            .unwrap();
        Writer::new(&mut buffer).address(&address).unwrap();
        assert_eq!(buffer.as_slice(), wire);
        let mut reader = Reader::new(&wire, 259).unwrap();
        assert_eq!(reader.address().unwrap(), address);
        reader.finish().unwrap();
    }
}

#[test]
fn incomplete_or_malformed_addresses_restore_the_cursor_and_hide_contents() {
    let complete = [3, 3, b'a', b'.', b'b', 1, 187];
    for end in 0..complete.len() {
        let mut reader = Reader::new(&complete[..end], 259).unwrap();
        assert!(reader.address().is_err());
        assert_eq!(reader.position(), 0);
    }
    for bytes in [
        vec![99],
        vec![3, 0, 0, 80],
        vec![3, 3, 0xff, 0xff, 0xff, 0, 80],
        vec![1, 127, 0, 0, 1, 0, 0],
    ] {
        let mut reader = Reader::new(&bytes, 259).unwrap();
        assert!(reader.address().is_err());
        assert_eq!(reader.position(), 0);
    }
    let secret = b"SECRET@VALUE";
    let bytes = [vec![3, secret.len() as u8], secret.to_vec(), vec![0, 80]].concat();
    let mut reader = Reader::new(&bytes, 259).unwrap();
    let error = reader.address().unwrap_err();
    assert!(!format!("{error:?} {error} {reader:?}").contains("SECRET"));
}

#[test]
fn address_encoding_rejects_scope_loss_and_capacity_failure_atomically() {
    let (_, scope) = scope();
    let mut buffer = scope
        .try_lease(BufferLayout::new(0, 8, 0).unwrap())
        .unwrap();
    buffer.append_payload(b"ok").unwrap();
    let ipv6 = Address::from_socket(SocketAddr::V6(SocketAddrV6::new(
        "fe80::1".parse().unwrap(),
        443,
        0,
        3,
    )))
    .unwrap();
    assert_eq!(
        Writer::new(&mut buffer).address(&ipv6).unwrap_err(),
        Error::UnsupportedAddressMetadata
    );
    assert_eq!(buffer.as_slice(), b"ok");
    assert!(
        Writer::new(&mut buffer)
            .address(&"127.0.0.1:443".parse().unwrap())
            .is_err()
    );
    assert_eq!(buffer.as_slice(), b"ok");
}

#[test]
fn length_writer_checks_maximum_prefix_and_capacity_before_mutation() {
    let (_, scope) = scope();
    let mut buffer = scope
        .try_lease(BufferLayout::new(0, 8, 0).unwrap())
        .unwrap();
    buffer.append_payload(b"ok").unwrap();
    assert!(
        Writer::new(&mut buffer)
            .frame(LengthPrefix::U16, 2, b"abc")
            .is_err()
    );
    assert_eq!(buffer.as_slice(), b"ok");
    assert!(
        Writer::new(&mut buffer)
            .frame(LengthPrefix::U32, 8, b"abc")
            .is_err()
    );
    assert_eq!(buffer.as_slice(), b"ok");
    Writer::new(&mut buffer)
        .frame(LengthPrefix::U16, 8, b"abc")
        .unwrap();
    assert_eq!(buffer.as_slice(), b"ok\0\x03abc");
}

#[test]
fn fragmented_headers_and_payloads_decode_one_frame_without_overreading() {
    for prefix in [LengthPrefix::U16, LengthPrefix::U32] {
        let (budget, scope) = scope();
        let metrics = Metrics::default();
        let mut decoder = FrameDecoder::new(scope.clone(), prefix, 32, metrics.clone()).unwrap();
        let mut encoded = scope
            .try_lease(BufferLayout::new(0, 64, 0).unwrap())
            .unwrap();
        Writer::new(&mut encoded)
            .frame(prefix, 32, b"payload")
            .unwrap();
        let wire = encoded.as_slice().to_vec();
        drop(encoded);
        for cut in 0..=wire.len() {
            decoder.reset();
            let first = decoder.feed(&wire[..cut]).unwrap();
            assert_eq!(first.consumed, cut);
            if let Some(frame) = first.frame {
                assert_eq!(frame.as_slice(), b"payload");
            } else {
                let second = decoder.feed(&wire[cut..]).unwrap();
                assert_eq!(second.consumed, wire.len() - cut);
                assert_eq!(second.frame.unwrap().as_slice(), b"payload");
            }
            decoder.finish().unwrap();
            assert_eq!(budget.snapshot().used().bytes(), 0);
        }
        assert_eq!(
            metrics.snapshot().counter(Counter::FramesDecoded),
            (wire.len() + 1) as u64
        );
    }
}

#[test]
fn multiple_and_empty_frames_report_exact_consumption() {
    let (budget, scope) = scope();
    let mut decoder = FrameDecoder::new(scope, LengthPrefix::U16, 8, Metrics::default()).unwrap();
    let wire = b"\0\0\0\x03abc\0\x01z";
    let first = decoder.feed(wire).unwrap();
    assert_eq!(first.consumed, 2);
    assert!(first.frame.unwrap().is_empty());
    let second = decoder.feed(&wire[2..]).unwrap();
    assert_eq!(second.consumed, 5);
    assert_eq!(second.frame.unwrap().as_slice(), b"abc");
    let third = decoder.feed(&wire[7..]).unwrap();
    assert_eq!(third.consumed, 3);
    assert_eq!(third.frame.unwrap().as_slice(), b"z");
    decoder.finish().unwrap();
    assert_eq!(budget.snapshot().used().allocations(), 0);
}

#[test]
fn oversized_length_is_rejected_before_allocating_and_poison_is_explicit() {
    let (budget, scope) = scope();
    let metrics = Metrics::default();
    let mut decoder = FrameDecoder::new(scope, LengthPrefix::U32, 16, metrics.clone()).unwrap();
    assert_eq!(
        decoder.feed(&u32::MAX.to_be_bytes()).unwrap_err(),
        Error::LimitExceeded {
            requested: u32::MAX as usize,
            limit: 16
        }
    );
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert!(decoder.is_poisoned());
    assert_eq!(
        decoder.feed(b"anything").unwrap_err(),
        Error::DecoderPoisoned
    );
    assert_eq!(metrics.snapshot().counter(Counter::CodecRejected), 1);
    decoder.reset();
    assert!(decoder.feed(b"\0\0\0\0").unwrap().frame.unwrap().is_empty());
}

#[test]
fn eof_reset_and_drop_reclaim_partial_frame_capacity() {
    let (budget, scope) = scope();
    let metrics = Metrics::default();
    for operation in [0, 1, 2] {
        let mut decoder =
            FrameDecoder::new(scope.clone(), LengthPrefix::U16, 16, metrics.clone()).unwrap();
        assert!(decoder.feed(b"\0\x08abc").unwrap().frame.is_none());
        assert_eq!(decoder.buffered_bytes(), 3);
        assert_eq!(budget.snapshot().resident().bytes(), 8);
        match operation {
            0 => {
                assert_eq!(decoder.finish().unwrap_err(), Error::UnexpectedEof);
                assert!(decoder.is_poisoned());
            }
            1 => decoder.reset(),
            _ => drop(decoder),
        };
        assert_eq!(budget.snapshot().used().bytes(), 0);
    }
    let mut decoder = FrameDecoder::new(scope, LengthPrefix::U16, 16, metrics).unwrap();
    decoder.feed(b"\0").unwrap();
    assert_eq!(decoder.finish().unwrap_err(), Error::UnexpectedEof);
}

#[test]
fn exhausted_buffer_budget_is_reported_without_partial_output() {
    let budget = Budget::new(Limits::new(8, 1).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 8).unwrap();
    let held = scope
        .try_lease(BufferLayout::new(0, 8, 0).unwrap())
        .unwrap();
    let metrics = Metrics::default();
    let mut decoder = FrameDecoder::new(scope, LengthPrefix::U16, 8, metrics.clone()).unwrap();
    assert!(matches!(decoder.feed(b"\0\x08"), Err(Error::Buffer(_))));
    assert!(decoder.is_poisoned());
    assert_eq!(budget.snapshot().resident().bytes(), 8);
    assert_eq!(metrics.snapshot().counter(Counter::BufferRejected), 1);
    drop(held);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn decoded_shared_frame_keeps_pooled_allocation_after_decoder_drop() {
    let budget = Budget::new(Limits::new(64, 4).unwrap());
    let pool = BufferPool::new(
        budget.clone(),
        PoolConfig::new(vec![8, 16], 64, 4, 4).unwrap(),
    )
    .unwrap();
    let scope = pool
        .scope(budget.scope(Limits::new(64, 4).unwrap()).unwrap(), 32)
        .unwrap();
    let mut decoder =
        FrameDecoder::new(scope.clone(), LengthPrefix::U16, 16, Metrics::default()).unwrap();
    let frame = decoder.feed(b"\0\x03abc").unwrap().frame.unwrap();
    drop(decoder);
    assert_eq!(frame.capacity(), 8);
    assert_eq!(scope.snapshot().resident().bytes(), 8);
    drop(frame);
    assert_eq!(scope.snapshot().used().bytes(), 0);
    assert_eq!(pool.snapshot().idle_bytes, 8);
    pool.close();
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn decoder_maximum_must_fit_prefix_and_buffer_configuration() {
    let (_, scope) = scope();
    assert!(
        FrameDecoder::new(
            scope.clone(),
            LengthPrefix::U16,
            usize::MAX,
            Metrics::default()
        )
        .is_err()
    );
    assert!(FrameDecoder::new(scope, LengthPrefix::U32, 1025, Metrics::default()).is_err());
}
