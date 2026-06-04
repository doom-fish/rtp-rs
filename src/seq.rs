//! Sequence-number arithmetic and the RFC 3550 Appendix A.1 source-validation
//! heuristic.
//!
//! 16-bit RTP sequence numbers wrap, so naive `<`/`>` comparison is wrong near
//! the wrap point. [`seq_less_than`] / [`seq_diff`] implement RFC 1982 serial
//! arithmetic. [`SourceState`] tracks a source across wraps and decides whether
//! a newly arrived packet is valid, using the `MAX_MISORDER` (100) /
//! `MIN_SEQUENTIAL` (2) thresholds from the RFC.

/// One past the maximum 16-bit sequence number (`1 << 16`).
pub const RTP_SEQ_MOD: u32 = 1 << 16;
/// Sequence jump beyond which a packet is treated as a possible large jump
/// rather than in-order (RFC 3550 A.1).
pub const MAX_DROPOUT: u32 = 3000;
/// How far a packet may be reordered before it counts as a new-source jump.
pub const MAX_MISORDER: u32 = 100;
/// Packets required in sequence before a source is declared valid.
pub const MIN_SEQUENTIAL: u32 = 2;

/// Returns `true` if 16-bit sequence number `a` precedes `b` under RFC 1982
/// serial-number arithmetic (handles the wrap at 65535 → 0).
#[must_use]
pub fn seq_less_than(a: u16, b: u16) -> bool {
    // a < b iff (b - a) is in the first half of the number space.
    let diff = b.wrapping_sub(a);
    diff != 0 && diff < 0x8000
}

/// Returns `true` if `a` comes after `b`.
#[must_use]
pub fn seq_greater_than(a: u16, b: u16) -> bool {
    seq_less_than(b, a)
}

/// Signed forward distance from `a` to `b` (`b - a`), accounting for one wrap.
/// Positive when `b` is ahead of `a`.
#[must_use]
pub fn seq_diff(a: u16, b: u16) -> i32 {
    let d = b.wrapping_sub(a);
    if d < 0x8000 {
        i32::from(d)
    } else {
        i32::from(d) - 0x1_0000
    }
}

/// Unsigned 32-bit timestamp forward distance (`b - a`) with wrap.
#[must_use]
pub fn ts_diff(a: u32, b: u32) -> i64 {
    let d = b.wrapping_sub(a);
    if d < 0x8000_0000 {
        i64::from(d)
    } else {
        i64::from(d) - (1_i64 << 32)
    }
}

/// Per-source state implementing the RFC 3550 Appendix A.1 sequence-number
/// validity heuristic plus extended (cycle-aware) sequence tracking.
#[derive(Clone, Debug)]
pub struct SourceState {
    base_seq: u32,
    max_seq: u16,
    bad_seq: u32,
    cycles: u32,
    probation: u32,
    received: u32,
    expected_prior: u32,
    received_prior: u32,
}

impl SourceState {
    /// Create a source primed for `seq`, requiring [`MIN_SEQUENTIAL`] in-order
    /// packets before it is considered valid.
    #[must_use]
    pub fn new(seq: u16) -> Self {
        let mut s = Self {
            base_seq: 0,
            max_seq: 0,
            bad_seq: 0,
            cycles: 0,
            probation: MIN_SEQUENTIAL,
            received: 0,
            expected_prior: 0,
            received_prior: 0,
        };
        s.init_seq(seq);
        s.max_seq = seq.wrapping_sub(1);
        s
    }

    /// RFC 3550 A.1 `init_seq`.
    fn init_seq(&mut self, seq: u16) {
        self.base_seq = u32::from(seq);
        self.max_seq = seq;
        self.bad_seq = RTP_SEQ_MOD + 1; // so seq == bad_seq is impossible
        self.cycles = 0;
        self.received = 0;
        self.received_prior = 0;
        self.expected_prior = 0;
    }

    /// RFC 3550 A.1 `update_seq`. Returns `true` if the packet is valid (the
    /// source is established or this packet establishes it).
    pub fn update(&mut self, seq: u16) -> bool {
        let udelta = u32::from(seq.wrapping_sub(self.max_seq));

        if self.probation > 0 {
            // Source is not yet validated; require packets in sequence.
            if seq == self.max_seq.wrapping_add(1) {
                self.probation -= 1;
                self.max_seq = seq;
                if self.probation == 0 {
                    self.init_seq(seq);
                    self.received += 1;
                    return true;
                }
            } else {
                self.probation = MIN_SEQUENTIAL - 1;
                self.max_seq = seq;
            }
            return false;
        } else if udelta < MAX_DROPOUT {
            // In order, with permissible gap.
            if seq < self.max_seq {
                // Sequence number wrapped.
                self.cycles += RTP_SEQ_MOD;
            }
            self.max_seq = seq;
        } else if udelta <= RTP_SEQ_MOD - MAX_MISORDER {
            // The sequence made a very large jump.
            if u32::from(seq) == self.bad_seq {
                // Two sequential packets — assume the other side restarted.
                self.init_seq(seq);
            } else {
                self.bad_seq = (u32::from(seq) + 1) & (RTP_SEQ_MOD - 1);
                return false;
            }
        } else {
            // Duplicate or reordered packet.
        }
        self.received += 1;
        true
    }

    /// Extended (cycle-aware) highest sequence number received.
    #[must_use]
    pub fn extended_max(&self) -> u32 {
        self.cycles + u32::from(self.max_seq)
    }

    /// Total packets expected since the base sequence number.
    #[must_use]
    pub fn expected(&self) -> u32 {
        self.extended_max().wrapping_sub(self.base_seq).wrapping_add(1)
    }

    /// Total packets actually received.
    #[must_use]
    pub const fn received(&self) -> u32 {
        self.received
    }

    /// Cumulative packets lost (expected minus received), clamped at 0.
    #[must_use]
    pub fn cumulative_lost(&self) -> u32 {
        self.expected().saturating_sub(self.received)
    }

    /// Compute the 8-bit fraction lost since the previous call and advance the
    /// interval baseline, per RFC 3550 §A.3. The result is `lost * 256 /
    /// expected` over the interval, saturated to 0..=255.
    pub fn fraction_lost(&mut self) -> u8 {
        let expected = self.expected();
        let expected_interval = expected.wrapping_sub(self.expected_prior);
        self.expected_prior = expected;
        let received_interval = self.received.wrapping_sub(self.received_prior);
        self.received_prior = self.received;
        let lost_interval = expected_interval.wrapping_sub(received_interval);
        if expected_interval == 0 || (lost_interval as i32) <= 0 {
            0
        } else {
            ((lost_interval << 8) / expected_interval) as u8
        }
    }

    /// The base sequence number captured at init.
    #[must_use]
    pub const fn base_seq(&self) -> u32 {
        self.base_seq
    }
}
