//! Generic NACK feedback (PT 205, RTPFB FMT 1, RFC 4585 §6.2.1).
//!
//! Each FCI entry is a 16-bit packet ID (PID) plus a 16-bit bitmask (BLP) of
//! the following lost packets: bit `i` set means `PID + i + 1` was also lost.

use super::{be_u32, write_header, Header, PT_RTPFB};
use crate::error::{Error, Result};

/// RTPFB feedback message type for generic NACK.
pub const FMT: u8 = 1;

/// One NACK FCI entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NackEntry {
    /// Packet ID — the first lost sequence number.
    pub pid: u16,
    /// Bitmask of lost packets following the PID.
    pub blp: u16,
}

/// A generic NACK feedback packet.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Nack {
    /// SSRC of the feedback sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source being `NACK`ed.
    pub media_ssrc: u32,
    /// NACK FCI entries.
    pub entries: Vec<NackEntry>,
}

impl Nack {
    /// Build a NACK from a list of lost sequence numbers, packing them into the
    /// minimum number of PID/BLP entries.
    #[must_use]
    pub fn from_lost(sender_ssrc: u32, media_ssrc: u32, lost: &[u16]) -> Self {
        let mut sorted: Vec<u16> = lost.to_vec();
        sorted.sort_unstable();
        sorted.dedup();

        let mut entries: Vec<NackEntry> = Vec::new();
        for &seq in &sorted {
            if let Some(last) = entries.last_mut() {
                let diff = seq.wrapping_sub(last.pid);
                if (1..=16).contains(&diff) {
                    last.blp |= 1 << (diff - 1);
                    continue;
                }
            }
            entries.push(NackEntry { pid: seq, blp: 0 });
        }

        Self {
            sender_ssrc,
            media_ssrc,
            entries,
        }
    }

    /// Expand all entries into the full list of lost sequence numbers.
    #[must_use]
    pub fn lost_sequence_numbers(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for e in &self.entries {
            out.push(e.pid);
            for i in 0..16 {
                if e.blp & (1 << i) != 0 {
                    out.push(e.pid.wrapping_add(i + 1));
                }
            }
        }
        out
    }

    /// Serialize this packet (with header).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body_len = 8 + self.entries.len() * 4;
        let mut out = Vec::with_capacity(4 + body_len);
        write_header(&mut out, FMT, PT_RTPFB, body_len);
        out.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        out.extend_from_slice(&self.media_ssrc.to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.pid.to_be_bytes());
            out.extend_from_slice(&e.blp.to_be_bytes());
        }
        out
    }

    /// Parse a NACK packet from its bytes.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] if the buffer is short.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        if h.content_len < 12 {
            return Err(Error::Truncated {
                needed: 12,
                got: h.content_len,
            });
        }
        let sender_ssrc = be_u32(buf, 4);
        let media_ssrc = be_u32(buf, 8);
        let mut entries = Vec::new();
        let mut off = 12;
        while off + 4 <= h.content_len {
            entries.push(NackEntry {
                pid: u16::from_be_bytes([buf[off], buf[off + 1]]),
                blp: u16::from_be_bytes([buf[off + 2], buf[off + 3]]),
            });
            off += 4;
        }
        Ok(Self {
            sender_ssrc,
            media_ssrc,
            entries,
        })
    }
}
