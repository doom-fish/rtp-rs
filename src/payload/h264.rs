//! H.264 RTP payload format (RFC 6184), packetization mode 1.
//!
//! Implements the three NAL unit packetization modes used in practice:
//!
//! * **Single NAL unit** — a NAL that fits in the MTU is sent verbatim.
//! * **STAP-A** (type 24) — several small NALs aggregated into one packet.
//! * **FU-A** (type 28) — a large NAL fragmented across several packets.
//!
//! STAP-B, MTAP16/MTAP24 and FU-B (used only in interleaved mode / mode 2) are
//! intentionally not implemented. NAL units are handled **without** Annex B
//! start codes — a NAL unit here is the 1-byte NAL header followed by its RBSP.

use crate::error::{ensure_at_most, Error, Result};
use std::collections::VecDeque;

/// Coded slice of a non-IDR picture.
pub const NAL_NON_IDR: u8 = 1;
/// Coded slice of an IDR picture.
pub const NAL_IDR: u8 = 5;
/// Supplemental enhancement information.
pub const NAL_SEI: u8 = 6;
/// Sequence parameter set.
pub const NAL_SPS: u8 = 7;
/// Picture parameter set.
pub const NAL_PPS: u8 = 8;
/// Access unit delimiter.
pub const NAL_AUD: u8 = 9;
/// STAP-A aggregation packet type.
pub const NAL_STAP_A: u8 = 24;
/// FU-A fragmentation unit type.
pub const NAL_FU_A: u8 = 28;

/// A common dynamic payload type used for H.264; only a convention, the actual
/// value is negotiated out of band (e.g. via SDP).
pub const PAYLOAD_TYPE_DEFAULT: u8 = 96;

/// Return the NAL unit type (lower 5 bits of the header byte).
#[must_use]
pub fn nal_type(nal: &[u8]) -> u8 {
    nal.first().map_or(0, |b| b & 0x1F)
}

/// Whether the NAL unit is an IDR (key frame) slice.
#[must_use]
pub fn is_idr(nal: &[u8]) -> bool {
    nal_type(nal) == NAL_IDR
}

/// Whether the NAL unit is a parameter set (SPS or PPS).
#[must_use]
pub fn is_parameter_set(nal: &[u8]) -> bool {
    matches!(nal_type(nal), NAL_SPS | NAL_PPS)
}

/// Splits NAL units into RTP payloads.
#[derive(Clone, Debug)]
pub struct Packetizer {
    mtu: usize,
    sps: Option<Vec<u8>>,
    pps: Option<Vec<u8>>,
}

impl Packetizer {
    /// Create a packetizer that produces payloads no larger than `mtu` bytes.
    ///
    /// # Panics
    /// Panics if `mtu` is too small to carry a 2-byte FU-A overhead plus data.
    #[must_use]
    pub fn new(mtu: usize) -> Self {
        assert!(mtu > 2, "MTU must exceed FU-A header overhead");
        Self {
            mtu,
            sps: None,
            pps: None,
        }
    }

    /// The configured MTU.
    #[must_use]
    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Remember parameter sets so they can be injected ahead of IDR frames.
    pub fn set_parameter_sets(&mut self, sps: impl AsRef<[u8]>, pps: impl AsRef<[u8]>) {
        self.sps = Some(sps.as_ref().to_vec());
        self.pps = Some(pps.as_ref().to_vec());
    }

    /// Packetize a single NAL unit into one or more RTP payloads.
    ///
    /// Returns a Single NAL payload when it fits, otherwise FU-A fragments.
    #[must_use]
    pub fn packetize(&self, nal: &[u8]) -> Vec<Vec<u8>> {
        if nal.is_empty() {
            return Vec::new();
        }
        if nal.len() <= self.mtu {
            return vec![nal.to_vec()];
        }
        self.fragment_fu_a(nal)
    }

    /// Aggregate several NAL units into a single STAP-A payload.
    ///
    /// Returns `None` if there are fewer than two NALs, if any NAL is empty or
    /// larger than 65 535 bytes, or if the aggregate would exceed the MTU.
    #[must_use]
    pub fn aggregate(&self, nals: &[&[u8]]) -> Option<Vec<u8>> {
        if nals.len() < 2 {
            return None;
        }
        // STAP-A header byte + per-NAL (2-byte size prefix + data).
        let mut total = 1;
        let mut nri = 0u8;
        for nal in nals {
            if nal.is_empty() || nal.len() > usize::from(u16::MAX) {
                return None;
            }
            total += 2 + nal.len();
            nri = nri.max(nal[0] & 0x60);
        }
        if total > self.mtu {
            return None;
        }
        let mut out = Vec::with_capacity(total);
        out.push(nri | NAL_STAP_A);
        for nal in nals {
            #[allow(clippy::cast_possible_truncation)]
            let len = nal.len() as u16;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(nal);
        }
        Some(out)
    }

    /// Packetize an access unit (list of NAL units), injecting stored parameter
    /// sets before each IDR slice when available.
    #[must_use]
    pub fn packetize_access_unit(&self, nals: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for nal in nals {
            if is_idr(nal) {
                if let (Some(sps), Some(pps)) = (&self.sps, &self.pps) {
                    out.extend(self.packetize(sps));
                    out.extend(self.packetize(pps));
                }
            }
            out.extend(self.packetize(nal));
        }
        out
    }

    fn fragment_fu_a(&self, nal: &[u8]) -> Vec<Vec<u8>> {
        let header = nal[0];
        let indicator = (header & 0xE0) | NAL_FU_A;
        let nal_unit_type = header & 0x1F;
        let body = &nal[1..];
        let chunk = self.mtu - 2;
        let mut out = Vec::new();
        let mut offset = 0;
        while offset < body.len() {
            let end = (offset + chunk).min(body.len());
            let start = offset == 0;
            let last = end == body.len();
            let mut fu_header = nal_unit_type;
            if start {
                fu_header |= 0x80;
            }
            if last {
                fu_header |= 0x40;
            }
            let mut pkt = Vec::with_capacity(2 + (end - offset));
            pkt.push(indicator);
            pkt.push(fu_header);
            pkt.extend_from_slice(&body[offset..end]);
            out.push(pkt);
            offset = end;
        }
        out
    }
}

/// Reassembles RTP payloads back into NAL units.
#[derive(Clone, Debug)]
pub struct Depacketizer {
    fragment: Vec<u8>,
    assembling: bool,
    last_sequence: Option<u16>,
    max_nal_size: usize,
    completed: VecDeque<Vec<u8>>,
}

#[allow(missing_docs)]
pub const DEFAULT_MAX_NAL_SIZE: usize = 8 * 1024 * 1024;

impl Default for Depacketizer {
    fn default() -> Self {
        Self {
            fragment: Vec::new(),
            assembling: false,
            last_sequence: None,
            max_nal_size: DEFAULT_MAX_NAL_SIZE,
            completed: VecDeque::new(),
        }
    }
}

impl Depacketizer {
    /// Create an empty depacketizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(missing_docs)]
    #[must_use]
    pub fn with_max_nal_size(max_nal_size: usize) -> Self {
        Self {
            max_nal_size,
            ..Self::default()
        }
    }

    /// Feed one RTP payload together with the RTP sequence number of the
    /// packet that carried it. Returns the first completed NAL unit, if any.
    ///
    /// A single payload may complete several NAL units (STAP-A); call [`pop`]
    /// repeatedly afterwards to drain the rest.
    ///
    /// [`pop`]: Self::pop
    ///
    /// # Errors
    /// Returns [`Error::BadPayload`] for malformed STAP-A or FU-A payloads and
    /// for an FU-A fragment that does not directly follow the previous packet
    /// of the same NAL unit, and [`Error::TooLarge`] when a reassembled NAL
    /// unit would exceed the size limit. A partially reassembled NAL unit is
    /// discarded on any error.
    pub fn push(&mut self, sequence_number: u16, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        let follows = self
            .last_sequence
            .is_some_and(|last| sequence_number == last.wrapping_add(1));
        self.last_sequence = Some(sequence_number);
        if let Err(e) = self.push_internal(payload, follows) {
            self.discard_fragment();
            return Err(e);
        }
        Ok(self.completed.pop_front())
    }

    /// Remove the next already-completed NAL unit, if any.
    pub fn pop(&mut self) -> Option<Vec<u8>> {
        self.completed.pop_front()
    }

    fn discard_fragment(&mut self) {
        self.assembling = false;
        self.fragment.clear();
    }

    fn push_internal(&mut self, payload: &[u8], follows: bool) -> Result<()> {
        let first = *payload
            .first()
            .ok_or(Error::BadPayload("empty H.264 payload"))?;
        let nal_type = first & 0x1F;
        if nal_type != NAL_FU_A {
            self.discard_fragment();
        }
        match nal_type {
            NAL_STAP_A => self.depacketize_stap_a(payload),
            NAL_FU_A => self.depacketize_fu_a(payload, follows),
            1..=23 => {
                self.completed.push_back(payload.to_vec());
                Ok(())
            }
            other => Err(Error::BadPayload(match other {
                25..=27 | 29 => "unsupported H.264 aggregation/fragmentation type",
                _ => "invalid H.264 NAL unit type",
            })),
        }
    }

    fn depacketize_stap_a(&mut self, payload: &[u8]) -> Result<()> {
        let mut off = 1;
        while off < payload.len() {
            if off + 2 > payload.len() {
                return Err(Error::BadPayload("truncated STAP-A size prefix"));
            }
            let size = usize::from(u16::from_be_bytes([payload[off], payload[off + 1]]));
            off += 2;
            let end = off + size;
            if size == 0 || end > payload.len() {
                return Err(Error::BadPayload("truncated STAP-A NAL unit"));
            }
            self.completed.push_back(payload[off..end].to_vec());
            off = end;
        }
        Ok(())
    }

    fn depacketize_fu_a(&mut self, payload: &[u8], follows: bool) -> Result<()> {
        if payload.len() < 3 {
            return Err(Error::BadPayload("truncated FU-A payload"));
        }
        let indicator = payload[0];
        let fu_header = payload[1];
        let start = fu_header & 0x80 != 0;
        let end = fu_header & 0x40 != 0;
        let nal_unit_type = fu_header & 0x1F;
        if start {
            let reconstructed = (indicator & 0xE0) | nal_unit_type;
            self.fragment.clear();
            self.fragment.push(reconstructed);
            self.assembling = true;
        } else if !self.assembling {
            return Err(Error::BadPayload("FU-A continuation without start"));
        } else if !follows {
            return Err(Error::BadPayload("FU-A fragment missing (sequence gap)"));
        } else if self.fragment.first().map(|h| h & 0x1F) != Some(nal_unit_type) {
            return Err(Error::BadPayload("FU-A fragment of a different NAL unit"));
        }
        let body = &payload[2..];
        ensure_at_most(
            "reassembled FU-A NAL unit size",
            self.fragment.len() + body.len(),
            self.max_nal_size,
        )?;
        self.fragment.extend_from_slice(body);
        if end {
            self.assembling = false;
            self.completed.push_back(std::mem::take(&mut self.fragment));
        }
        Ok(())
    }
}
