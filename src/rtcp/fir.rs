//! Full Intra Request (PT 206, PSFB FMT 4, RFC 5104 §4.3.1).
//!
//! Each FCI entry is 8 bytes: a target SSRC, a one-byte command sequence
//! number, and three reserved bytes.

use super::{be_u32, write_header, Header, PT_PSFB};
use crate::error::{Error, Result};

/// PSFB feedback message type for FIR.
pub const FMT: u8 = 4;

/// One FIR FCI entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirEntry {
    /// SSRC of the source the intra request targets.
    pub ssrc: u32,
    /// Command sequence number (incremented per distinct request).
    pub seq_nr: u8,
}

/// A Full Intra Request.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Fir {
    /// SSRC of the feedback sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source (unused for FIR; kept for the common header).
    pub media_ssrc: u32,
    /// FIR FCI entries.
    pub entries: Vec<FirEntry>,
}

impl Fir {
    /// Serialize this packet (with header).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body_len = 8 + self.entries.len() * 8;
        let mut out = Vec::with_capacity(4 + body_len);
        write_header(&mut out, FMT, PT_PSFB, body_len);
        out.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        out.extend_from_slice(&self.media_ssrc.to_be_bytes());
        for e in &self.entries {
            out.extend_from_slice(&e.ssrc.to_be_bytes());
            out.push(e.seq_nr);
            out.extend_from_slice(&[0u8, 0, 0]);
        }
        out
    }

    /// Parse a FIR packet from its bytes.
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
        while off + 8 <= h.content_len {
            entries.push(FirEntry {
                ssrc: be_u32(buf, off),
                seq_nr: buf[off + 4],
            });
            off += 8;
        }
        Ok(Self {
            sender_ssrc,
            media_ssrc,
            entries,
        })
    }
}
