//! Picture Loss Indication (PT 206, PSFB FMT 1, RFC 4585 §6.3.1).
//!
//! PLI carries no FCI — it simply asks the encoder for a fresh intra frame.

use super::{be_u32, write_header, Header, PT_PSFB};
use crate::error::{Error, Result};

/// PSFB feedback message type for PLI.
pub const FMT: u8 = 1;

/// A Picture Loss Indication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Pli {
    /// SSRC of the feedback sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
}

impl Pli {
    /// Serialize this packet (with header).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        write_header(&mut out, FMT, PT_PSFB, 8);
        out.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        out.extend_from_slice(&self.media_ssrc.to_be_bytes());
        out
    }

    /// Parse a PLI packet from its bytes.
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
        Ok(Self {
            sender_ssrc: be_u32(buf, 4),
            media_ssrc: be_u32(buf, 8),
        })
    }
}
