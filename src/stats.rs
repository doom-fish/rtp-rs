//! Reception statistics for building RTCP receiver reports.
//!
//! [`ReceptionStats`] bundles the RFC 3550 sequence-number heuristic
//! ([`crate::seq::SourceState`]) with the jitter estimator
//! ([`crate::jitter::Jitter`]) and tracks the data needed to fill in an RR
//! reception report block: fraction lost, cumulative lost, extended highest
//! sequence number, and interarrival jitter.

use crate::jitter::Jitter;
use crate::seq::SourceState;

/// Aggregated per-source reception statistics.
#[derive(Clone, Debug)]
pub struct ReceptionStats {
    ssrc: u32,
    source: SourceState,
    jitter: Jitter,
    /// Last SR timestamp middle-32 bits (for LSR field), if any.
    last_sr: u32,
    /// Local time the last SR was received, in 1/65536 s units (for DLSR).
    last_sr_arrival: u32,
}

impl ReceptionStats {
    /// Create statistics for source `ssrc`, primed with the first observed
    /// sequence number.
    #[must_use]
    pub fn new(ssrc: u32, first_seq: u16) -> Self {
        Self {
            ssrc,
            source: SourceState::new(first_seq),
            jitter: Jitter::new(),
            last_sr: 0,
            last_sr_arrival: 0,
        }
    }

    /// The SSRC these statistics describe.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Record an arriving data packet.
    ///
    /// `arrival` is the local arrival time in the media clock's timestamp units
    /// (see [`Jitter::update`]). Returns whether the packet was deemed valid by
    /// the sequence heuristic.
    pub fn on_packet(&mut self, seq: u16, rtp_timestamp: u32, arrival: u32) -> bool {
        let valid = self.source.update(seq);
        self.jitter.update(rtp_timestamp, arrival);
        valid
    }

    /// Record receipt of a sender report, capturing the values needed for the
    /// LSR/DLSR fields of the next RR.
    ///
    /// * `ntp_middle` — the middle 32 bits of the SR's 64-bit NTP timestamp.
    /// * `arrival_1_65536s` — local arrival time in units of 1/65536 second.
    pub fn on_sender_report(&mut self, ntp_middle: u32, arrival_1_65536s: u32) {
        self.last_sr = ntp_middle;
        self.last_sr_arrival = arrival_1_65536s;
    }

    /// Extended highest sequence number received.
    #[must_use]
    pub fn extended_highest_seq(&self) -> u32 {
        self.source.extended_max()
    }

    /// Cumulative number of packets lost.
    #[must_use]
    pub fn cumulative_lost(&self) -> u32 {
        self.source.cumulative_lost()
    }

    /// Fraction lost over the interval since the previous report (advances the
    /// interval baseline).
    pub fn fraction_lost(&mut self) -> u8 {
        self.source.fraction_lost()
    }

    /// Current interarrival jitter.
    #[must_use]
    pub fn jitter(&self) -> u32 {
        self.jitter.value()
    }

    /// Last-SR timestamp (LSR) field for an RR block.
    #[must_use]
    pub const fn last_sr(&self) -> u32 {
        self.last_sr
    }

    /// Delay-since-last-SR (DLSR) given the current local time, both in units
    /// of 1/65536 second. Returns 0 if no SR has been received.
    #[must_use]
    pub fn delay_since_last_sr(&self, now_1_65536s: u32) -> u32 {
        if self.last_sr == 0 {
            0
        } else {
            now_1_65536s.wrapping_sub(self.last_sr_arrival)
        }
    }

    /// Build a receiver-report reception block from the current state.
    ///
    /// `now_1_65536s` is the current local time in 1/65536-second units, used
    /// for the DLSR field.
    pub fn to_report_block(&mut self, now_1_65536s: u32) -> crate::rtcp::rr::ReportBlock {
        crate::rtcp::rr::ReportBlock {
            ssrc: self.ssrc,
            fraction_lost: self.fraction_lost(),
            cumulative_lost: self.cumulative_lost().min(0x007F_FFFF),
            extended_highest_seq: self.extended_highest_seq(),
            jitter: self.jitter(),
            last_sr: self.last_sr,
            delay_since_last_sr: self.delay_since_last_sr(now_1_65536s),
        }
    }
}
