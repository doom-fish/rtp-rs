//! Slice Loss Indication (PT 206, PSFB FMT 2, RFC 4585 §6.3.2).
//!
//! Each FCI entry is 4 bytes: First (13 bits), Number (13 bits), `PictureID`
//! (6 bits).

use super::{be_u32, write_header, Header, PT_PSFB};
use crate::error::{Error, Result};

/// PSFB feedback message type for SLI.
pub const FMT: u8 = 2;

/// One SLI FCI entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SliEntry {
    /// Macroblock address of the first lost macroblock (13 bits).
    pub first: u16,
    /// Number of lost macroblocks (13 bits).
    pub number: u16,
    /// Picture identifier (6 bits).
    pub picture_id: u8,
}

/// A Slice Loss Indication.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Sli {
    /// SSRC of the feedback sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
    /// SLI FCI entries.
    pub entries: Vec<SliEntry>,
}

impl Sli {
    /// Serialize this packet (with header).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let body_len = 8 + self.entries.len() * 4;
        let mut out = Vec::with_capacity(4 + body_len);
        write_header(&mut out, FMT, PT_PSFB, body_len);
        out.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        out.extend_from_slice(&self.media_ssrc.to_be_bytes());
        for e in &self.entries {
            let word = (u32::from(e.first & 0x1FFF) << 19)
                | (u32::from(e.number & 0x1FFF) << 6)
                | u32::from(e.picture_id & 0x3F);
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Parse an SLI packet from its bytes.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] if the buffer is short.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        if h.total_len < 12 {
            return Err(Error::Truncated {
                needed: 12,
                got: h.total_len,
            });
        }
        let sender_ssrc = be_u32(buf, 4);
        let media_ssrc = be_u32(buf, 8);
        let mut entries = Vec::new();
        let mut off = 12;
        while off + 4 <= h.total_len {
            let word = be_u32(buf, off);
            entries.push(SliEntry {
                first: ((word >> 19) & 0x1FFF) as u16,
                number: ((word >> 6) & 0x1FFF) as u16,
                picture_id: (word & 0x3F) as u8,
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
