//! Sequence-number comparison, wrap handling and the RFC 3550 A.1 heuristic.

use rtp::seq::{seq_diff, seq_greater_than, seq_less_than, SourceState};

#[test]
fn ordering_across_wrap() {
    assert!(seq_greater_than(1, 0));
    assert!(seq_less_than(0, 1));
    // 0 comes "after" 65535 across the wrap boundary.
    assert!(seq_greater_than(0, 65535));
    assert!(seq_less_than(65535, 0));
}

#[test]
fn signed_difference_across_wrap() {
    // seq_diff(a, b) is the forward distance b - a.
    assert_eq!(seq_diff(5, 10), 5);
    assert_eq!(seq_diff(10, 5), -5);
    // forward from 65535 to 0 is +1 across the wrap.
    assert_eq!(seq_diff(65535, 0), 1);
    assert_eq!(seq_diff(0, 65535), -1);
}

#[test]
fn source_validates_after_min_sequential() {
    let mut s = SourceState::new(100);
    // First packet at the priming seq is still in probation.
    assert!(!s.update(100));
    // Second in-order packet establishes the source.
    assert!(s.update(101));
    assert!(s.update(102));
    assert_eq!(s.received(), 2);
}

#[test]
fn extended_max_tracks_cycles() {
    let mut s = SourceState::new(65534);
    s.update(65534);
    s.update(65535);
    // Wrap to 0 then 1 — one cycle should be added.
    s.update(0);
    s.update(1);
    assert_eq!(s.extended_max(), 65536 + 1);
}

#[test]
fn cumulative_loss_counts_gaps() {
    let mut s = SourceState::new(0);
    s.update(0);
    s.update(1); // established here
    // Skip 2 and 3, jump to 4.
    s.update(4);
    // expected spans 1..=4 (4 packets) from base; received = 3.
    assert!(s.cumulative_lost() >= 1);
}
