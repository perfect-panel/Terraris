// SPDX-License-Identifier: GPL-3.0-only

use std::{ops::Bound, thread};
use terraris::{
    buffer::{BufferLayout, BufferScope, Error},
    resource::{Budget, Limits},
};

fn scope(bytes: usize) -> (Budget, BufferScope) {
    let budget = Budget::new(Limits::new(bytes, 8).unwrap());
    let scope =
        BufferScope::new(budget.scope(Limits::new(bytes, 8).unwrap()).unwrap(), bytes).unwrap();
    (budget, scope)
}

#[test]
fn freeze_and_nested_views_retain_the_full_allocation_without_copying() {
    let (budget, scope) = scope(128);
    let mut lease = scope
        .try_lease(BufferLayout::new(4, 56, 4).unwrap())
        .unwrap();
    lease.append_payload(b"abcdef").unwrap();
    lease.prepend_header(b"HEAD").unwrap();
    lease.append_trailer(b"TAIL").unwrap();
    let pointer = lease.as_slice().as_ptr();
    let shared = lease.freeze();
    assert_eq!(shared.as_slice().as_ptr(), pointer);
    assert_eq!(shared.as_slice(), b"HEADabcdefTAIL");
    let nested = shared.slice(4..10).unwrap().slice(2..=2).unwrap();
    assert_eq!(nested.as_slice(), b"c");
    assert_eq!(nested.capacity(), 64);
    let empty = nested.slice(0..0).unwrap();
    drop(shared);
    drop(nested);
    assert_eq!(budget.snapshot().resident().bytes(), 64);
    assert_eq!(scope.snapshot().resident().bytes(), 64);
    drop(empty);
    assert_eq!(budget.snapshot().used().allocations(), 0);
    assert_eq!(scope.snapshot().used().bytes(), 0);
}

#[test]
fn slicing_is_relative_checked_and_never_exposes_unused_capacity() {
    let (_, scope) = scope(128);
    let mut lease = scope
        .try_lease(BufferLayout::new(4, 20, 4).unwrap())
        .unwrap();
    lease.append_payload(b"secret:abc").unwrap();
    lease.consume(7).unwrap();
    let view = lease.freeze();
    assert_eq!(view.as_slice(), b"abc");
    assert_eq!(view.slice(..=1).unwrap().as_slice(), b"ab");
    assert_eq!(view.slice(3..).unwrap().len(), 0);
    for range in [
        (Bound::Included(2), Bound::Excluded(1)),
        (Bound::Included(0), Bound::Included(usize::MAX)),
        (Bound::Excluded(usize::MAX), Bound::Unbounded),
        (Bound::Included(0), Bound::Excluded(4)),
    ] {
        assert!(matches!(view.slice(range), Err(Error::InvalidRange)));
    }
    assert!(!format!("{view:?}").contains("abc"));
}

#[test]
fn bytes_adapter_keeps_scope_and_process_ownership_through_nonempty_slices() {
    let (budget, scope) = scope(128);
    let mut lease = scope
        .try_lease(BufferLayout::new(0, 64, 0).unwrap())
        .unwrap();
    lease.append_payload(b"abcdef").unwrap();
    let shared = lease.freeze();
    let pointer = shared.as_slice().as_ptr();
    let bytes = shared.into_bytes();
    assert_eq!(bytes.as_ptr(), pointer);
    let slice = bytes.slice(1..2);
    let clone = slice.clone();
    drop(bytes);
    drop(slice);
    assert_eq!(budget.snapshot().resident().bytes(), 64);
    assert_eq!(clone.as_ref(), b"b");
    let clone = clone
        .try_into_mut()
        .expect_err("owner-backed Bytes cannot become mutable in place");
    assert_eq!(scope.snapshot().resident().bytes(), 64);
    thread::spawn(move || drop(clone)).join().unwrap();
    assert_eq!(budget.snapshot().used().bytes(), 0);
    assert_eq!(scope.snapshot().used().bytes(), 0);
}

#[test]
fn bytes_empty_slice_can_discard_ownership_without_affecting_sharedbuffer_semantics() {
    let (budget, scope) = scope(64);
    let mut lease = scope
        .try_lease(BufferLayout::new(0, 64, 0).unwrap())
        .unwrap();
    lease.append_payload(b"x").unwrap();
    let bytes = lease.freeze().into_bytes();
    let empty = bytes.slice(0..0);
    drop(bytes);
    assert!(empty.is_empty());
    assert_eq!(budget.snapshot().used().bytes(), 0);
    let owner_backed_empty = scope
        .try_lease(BufferLayout::new(0, 64, 0).unwrap())
        .unwrap()
        .freeze()
        .into_bytes();
    assert!(owner_backed_empty.is_empty());
    assert_eq!(budget.snapshot().resident().bytes(), 64);
    drop(owner_backed_empty);
    assert_eq!(budget.snapshot().used().bytes(), 0);
}

#[test]
fn copying_a_small_view_requires_overlapping_budget_and_preserves_source_on_failure() {
    let (budget, source_scope) = scope(64);
    let mut lease = source_scope
        .try_lease(BufferLayout::new(0, 64, 0).unwrap())
        .unwrap();
    lease.append_payload(b"payload").unwrap();
    let small = lease.freeze().slice(0..1).unwrap();
    assert!(small.copy_to(&source_scope).is_err());
    assert_eq!(small.as_slice(), b"p");
    let (other_budget, other_scope) = scope(64);
    let copy = small.copy_to(&other_scope).unwrap();
    assert_eq!(copy.capacity(), 1);
    assert_eq!(copy.as_slice(), b"p");
    assert_eq!(budget.snapshot().resident().bytes(), 64);
    assert_eq!(other_budget.snapshot().resident().bytes(), 1);
    drop(small);
    assert_eq!(budget.snapshot().used().bytes(), 0);
    drop(copy);
    assert_eq!(other_budget.snapshot().used().bytes(), 0);
}
