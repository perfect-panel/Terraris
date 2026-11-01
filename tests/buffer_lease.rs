// SPDX-License-Identifier: GPL-3.0-only

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    thread,
};

use terraris::{
    buffer::{BufferLayout, BufferScope, Error, Region},
    resource::{Budget, Limits},
};
use tokio::io::{AsyncRead, ReadBuf};

fn setup() -> (Budget, BufferScope) {
    let budget = Budget::new(Limits::new(1024, 16).unwrap());
    let scope = BufferScope::new(budget.scope(Limits::new(512, 8).unwrap()).unwrap(), 256).unwrap();
    (budget, scope)
}

#[test]
fn layout_checks_overflow_address_space_and_allows_empty_payloads() {
    assert_eq!(
        BufferLayout::new(usize::MAX, 1, 0).unwrap_err(),
        Error::LayoutOverflow
    );
    assert_eq!(
        BufferLayout::new(0, usize::MAX, 1).unwrap_err(),
        Error::LayoutOverflow
    );
    assert_eq!(
        BufferLayout::new(isize::MAX as usize, 1, 0).unwrap_err(),
        Error::AddressSpaceExceeded
    );
    let layout = BufferLayout::new(4, 0, 8).unwrap();
    assert_eq!(
        (
            layout.headroom(),
            layout.payload_capacity(),
            layout.tailroom(),
            layout.capacity()
        ),
        (4, 0, 8, 12)
    );
    assert_eq!(BufferLayout::new(0, 0, 0).unwrap().capacity(), 0);
}

#[test]
fn full_allocation_is_charged_until_drop_even_when_readable_data_is_empty() {
    let (budget, scope) = setup();
    let layout = BufferLayout::new(4, 20, 8).unwrap();
    let mut buffer = scope.try_lease(layout).unwrap();
    assert!(buffer.is_empty());
    assert_eq!(buffer.capacity(), 32);
    assert_eq!(scope.snapshot().resident().bytes(), 32);
    assert_eq!(budget.snapshot().reserved().bytes(), 0);
    buffer.append_payload(b"hello").unwrap();
    buffer.consume(5).unwrap();
    assert!(buffer.is_empty());
    assert_eq!(scope.snapshot().used().bytes(), 32);
    buffer.clear();
    assert_eq!(scope.snapshot().used().bytes(), 32);
    thread::spawn(move || drop(buffer)).join().unwrap();
    assert_eq!(scope.snapshot().used().bytes(), 0);
    assert_eq!(budget.snapshot().used().allocations(), 0);
}

#[test]
fn payload_cannot_take_headroom_or_reserved_trailer_space() {
    let (_, scope) = setup();
    let mut buffer = scope
        .try_lease(BufferLayout::new(2, 4, 3).unwrap())
        .unwrap();
    buffer.append_payload(b"data").unwrap();
    assert!(matches!(
        buffer.append_payload(b"!"),
        Err(Error::NoSpace {
            region: Region::Payload,
            ..
        })
    ));
    assert_eq!(buffer.as_slice(), b"data");
    buffer.append_trailer(b"XY").unwrap();
    buffer.prepend_header(b"HH").unwrap();
    buffer.append_trailer(b"Z").unwrap();
    assert_eq!(buffer.as_slice(), b"HHdataXYZ");
    assert_eq!(buffer.remaining_payload(), 0);
    assert_eq!(buffer.remaining_headroom(), 0);
    assert_eq!(buffer.remaining_tailroom(), 0);
    assert_eq!(
        buffer.append_payload(b"!").unwrap_err(),
        Error::PayloadSealed
    );
    assert!(buffer.prepend_header(b"!").is_err());
    assert!(buffer.append_trailer(b"!").is_err());
    assert_eq!(buffer.as_slice(), b"HHdataXYZ");
}

#[test]
fn a_short_payload_does_not_turn_unused_payload_capacity_into_extra_tag_space() {
    let (_, scope) = setup();
    let mut buffer = scope
        .try_lease(BufferLayout::new(4, 100, 2).unwrap())
        .unwrap();
    buffer.append_payload(b"a").unwrap();
    assert_eq!(
        buffer.append_trailer(b"123").unwrap_err(),
        Error::NoSpace {
            region: Region::Tailroom,
            requested: 3,
            available: 2
        }
    );
    // Failure did not seal the payload or alter its bytes.
    buffer.append_payload(b"b").unwrap();
    buffer.append_trailer(b"12").unwrap();
    assert_eq!(buffer.as_slice(), b"ab12");
}

#[test]
fn framing_ranges_match_a_reference_packet_for_small_layouts() {
    let (_, scope) = setup();
    for head in 0..=4 {
        for payload in 0..=8 {
            for tail in 0..=4 {
                let mut buffer = scope
                    .try_lease(BufferLayout::new(head, payload, tail).unwrap())
                    .unwrap();
                buffer.append_payload(&vec![b'p'; payload]).unwrap();
                buffer.prepend_header(&vec![b'h'; head]).unwrap();
                buffer.append_trailer(&vec![b't'; tail]).unwrap();
                let expected = [vec![b'h'; head], vec![b'p'; payload], vec![b't'; tail]].concat();
                assert_eq!(buffer.as_slice(), expected);
                for index in 0..expected.len() {
                    assert_eq!(buffer.as_slice(), &expected[index..]);
                    buffer.consume(1).unwrap();
                }
                assert!(buffer.is_empty());
                assert_eq!(scope.snapshot().resident().bytes(), head + payload + tail);
                drop(buffer);
                assert_eq!(scope.snapshot().used().allocations(), 0);
            }
        }
    }
}

#[test]
fn truncation_and_consumption_cannot_resurrect_old_frame_data() {
    let (_, scope) = setup();
    let mut buffer = scope
        .try_lease(BufferLayout::new(2, 12, 2).unwrap())
        .unwrap();
    buffer.append_payload(b"abcdefgh").unwrap();
    buffer.consume(2).unwrap();
    buffer.truncate(3).unwrap();
    assert_eq!(buffer.as_slice(), b"cde");
    assert_eq!(buffer.append_payload(b"f").unwrap_err(), Error::NotWritable);
    assert_eq!(buffer.prepend_header(b"H").unwrap_err(), Error::NotWritable);
    assert_eq!(buffer.append_trailer(b"T").unwrap_err(), Error::NotWritable);
    assert!(buffer.truncate(4).is_err());
    assert!(buffer.consume(4).is_err());
    assert_eq!(buffer.as_slice(), b"cde");
    buffer.clear();
    buffer.append_payload(b"new").unwrap();
    assert_eq!(buffer.as_slice(), b"new");
}

#[test]
fn clear_does_not_expose_old_bytes_and_new_padding_is_zeroed() {
    let (_, scope) = setup();
    let mut buffer = scope
        .try_lease(BufferLayout::new(2, 12, 4).unwrap())
        .unwrap();
    buffer.append_payload(b"old sentinel").unwrap();
    buffer.prepend_header(b"HH").unwrap();
    buffer.append_trailer(b"TAG!").unwrap();
    assert!(!format!("{buffer:?}").contains("sentinel"));
    buffer.clear();
    assert!(buffer.as_slice().is_empty());
    buffer.append_zeroed(12).unwrap();
    buffer.append_trailer_zeroed(4).unwrap();
    assert_eq!(buffer.as_slice(), &[0; 16]);
    buffer.prepend_header(b"OK").unwrap();
    assert_eq!(&buffer.as_slice()[..2], b"OK");
    assert_eq!(&buffer.as_slice()[2..], &[0; 16]);
}

#[test]
fn oversize_operations_leave_buffer_and_budget_unchanged() {
    let (_, scope) = setup();
    let mut buffer = scope
        .try_lease(BufferLayout::new(2, 8, 2).unwrap())
        .unwrap();
    buffer.append_payload(b"ok").unwrap();
    let before = scope.snapshot();
    assert!(buffer.append_zeroed(usize::MAX).is_err());
    assert!(buffer.append_trailer_zeroed(usize::MAX).is_err());
    assert!(buffer.consume(usize::MAX).is_err());
    assert!(buffer.truncate(usize::MAX).is_err());
    assert!(buffer.prepend_header(b"too long").is_err());
    assert_eq!(buffer.as_slice(), b"ok");
    assert_eq!(scope.snapshot(), before);
    buffer.append_payload(b"!").unwrap();
    assert_eq!(buffer.as_slice(), b"ok!");
}

#[test]
fn batch_success_and_failure_preserve_existing_leases_and_parent_usage() {
    let budget = Budget::new(Limits::new(64, 8).unwrap());
    let parent = budget.scope(Limits::new(48, 6).unwrap()).unwrap();
    let scope = BufferScope::new(parent.child(Limits::new(40, 4).unwrap()).unwrap(), 32).unwrap();
    let small = BufferLayout::new(1, 6, 1).unwrap();
    let mut retained = scope.try_lease(small).unwrap();
    retained.append_payload(b"keep").unwrap();
    let before = [budget.snapshot(), parent.snapshot(), scope.snapshot()];
    assert!(
        scope
            .try_lease_many(&[BufferLayout::new(0, 24, 0).unwrap(); 2])
            .is_err()
    );
    assert!(
        scope
            .try_lease_many(&[small, BufferLayout::new(0, 33, 0).unwrap()])
            .is_err()
    );
    assert!(scope.try_lease_many(&[small; 5]).is_err());
    assert_eq!(
        [budget.snapshot(), parent.snapshot(), scope.snapshot()],
        before
    );
    assert_eq!(retained.as_slice(), b"keep");
    let pair = scope
        .try_lease_many(&[BufferLayout::new(4, 8, 4).unwrap(); 2])
        .unwrap();
    assert_eq!(scope.snapshot().resident().bytes(), 40);
    assert_eq!(parent.snapshot().resident().bytes(), 40);
    assert_eq!(budget.snapshot().resident().bytes(), 40);
    assert_eq!(budget.snapshot().reserved().bytes(), 0);
    drop(pair);
    assert_eq!(
        [budget.snapshot(), parent.snapshot(), scope.snapshot()],
        before
    );
    drop(retained);
    assert_eq!(budget.snapshot().used().allocations(), 0);
}

#[test]
fn empty_leases_are_bounded_by_slots_and_empty_batch_is_a_noop() {
    let budget = Budget::new(Limits::new(8, 2).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 8).unwrap();
    assert!(scope.try_lease_many(&[]).unwrap().is_empty());
    let empty = BufferLayout::new(0, 0, 0).unwrap();
    let leases = scope.try_lease_many(&[empty; 2]).unwrap();
    assert!(leases.iter().all(|b| b.is_empty() && b.capacity() == 0));
    assert_eq!(budget.snapshot().resident().bytes(), 0);
    assert_eq!(budget.snapshot().resident().allocations(), 2);
    assert!(scope.try_lease(empty).is_err());
    drop(leases);
    assert_eq!(budget.snapshot().used().allocations(), 0);
}

#[test]
fn cloned_scopes_share_limits_and_close_does_not_invalidate_existing_storage() {
    let budget = Budget::new(Limits::new(64, 4).unwrap());
    let scope = BufferScope::new(budget.root_scope(), 64).unwrap();
    let child = scope.child(Limits::new(32, 2).unwrap()).unwrap();
    let clone = child.clone();
    let mut lease = child
        .try_lease(BufferLayout::new(0, 24, 0).unwrap())
        .unwrap();
    assert!(
        clone
            .try_lease(BufferLayout::new(0, 16, 0).unwrap())
            .is_err()
    );
    clone.close();
    assert!(child.snapshot().is_closed());
    assert!(
        child
            .try_lease(BufferLayout::new(0, 0, 0).unwrap())
            .is_err()
    );
    assert!(child.try_lease_many(&[]).is_err());
    lease.append_payload(b"still valid").unwrap();
    assert_eq!(lease.as_slice(), b"still valid");
    drop(lease);
    assert_eq!(child.snapshot().used().bytes(), 0);
    assert!(!scope.snapshot().is_closed());
    drop(
        scope
            .try_lease(BufferLayout::new(0, 64, 0).unwrap())
            .unwrap(),
    );
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn allocation_limit_includes_headroom_and_tailroom() {
    let budget = Budget::new(Limits::new(1024, 8).unwrap());
    assert!(matches!(
        BufferScope::new(budget.root_scope(), 0),
        Err(Error::InvalidAllocationLimit)
    ));
    assert!(matches!(
        BufferScope::new(budget.root_scope(), usize::MAX),
        Err(Error::InvalidAllocationLimit)
    ));
    let scope = BufferScope::new(budget.root_scope(), 16).unwrap();
    assert!(matches!(
        scope.try_lease(BufferLayout::new(1, 16, 1).unwrap()),
        Err(Error::AllocationTooLarge {
            requested: 18,
            limit: 16
        })
    ));
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[tokio::test]
async fn bounded_read_commits_only_payload_bytes_and_distinguishes_capacity_from_eof() {
    let (_, scope) = setup();
    let mut lease = scope
        .try_lease(BufferLayout::new(4, 4, 4).unwrap())
        .unwrap();
    let mut source = &b"abcdef"[..];
    assert_eq!(lease.read_from(&mut source).await.unwrap(), 4);
    assert_eq!(lease.as_slice(), b"abcd");
    assert_eq!(
        lease.read_from(&mut source).await.unwrap_err().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(source, b"ef");
    lease.clear();
    assert_eq!(lease.read_from(&mut source).await.unwrap(), 2);
    assert_eq!(lease.read_from(&mut source).await.unwrap(), 0);
    assert_eq!(lease.as_slice(), b"ef");
    lease.prepend_header(b"HEAD").unwrap();
    lease.append_trailer(b"TAIL").unwrap();
    assert_eq!(lease.as_slice(), b"HEADefTAIL");
}

struct ErrorAfterWrite;
impl AsyncRead for ErrorAfterWrite {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        output.put_slice(b"bad");
        Poll::Ready(Err(io::Error::other("synthetic read failure")))
    }
}

#[tokio::test]
async fn failed_read_does_not_publish_bytes_written_by_the_failing_reader() {
    let (_, scope) = setup();
    let mut lease = scope
        .try_lease(BufferLayout::new(0, 8, 0).unwrap())
        .unwrap();
    lease.append_payload(b"good").unwrap();
    assert!(lease.read_from(&mut ErrorAfterWrite).await.is_err());
    assert_eq!(lease.as_slice(), b"good");
    lease.append_zeroed(4).unwrap();
    assert_eq!(lease.as_slice(), b"good\0\0\0\0");
}

#[tokio::test]
async fn cancelling_a_pending_read_returns_the_owned_buffer_budget() {
    let (budget, scope) = setup();
    let observed_scope = scope.clone();
    let (mut stream, peer) = tokio::io::duplex(8);
    let (ready, received) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let mut lease = scope
            .try_lease(BufferLayout::new(4, 16, 4).unwrap())
            .unwrap();
        ready.send(()).unwrap();
        lease.read_from(&mut stream).await.unwrap();
    });
    received.await.unwrap();
    assert_eq!(budget.snapshot().resident().bytes(), 24);
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(observed_scope.snapshot().used().bytes(), 0);
    assert_eq!(budget.snapshot().used().allocations(), 0);
    drop(peer);
}
