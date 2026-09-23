//! Goodbye (PT 203).

use super::{be_u32, write_header, Header, PT_BYE};
use crate::error::{ensure_at_most, Error, Result};

/// A BYE packet: a list of leaving sources and an optional reason string.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Bye {
    /// SSRC/CSRC identifiers that are leaving.
    pub sources: Vec<u32>,
    /// Optional human-readable reason for leaving.
    pub reason: Option<Vec<u8>>,
}

impl Bye {
    /// Construct a BYE for a single source.
    #[must_use]
    pub fn new(ssrc: u32) -> Self {
        Self {
            sources: vec![ssrc],
            reason: None,
        }
    }

    /// Serialize this packet (with header).
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] for more than 31 sources or a reason longer
    /// than 255 bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure_at_most("RTCP BYE source count", self.sources.len(), 31)?;
        let mut body = Vec::new();
        for s in &self.sources {
            body.extend_from_slice(&s.to_be_bytes());
        }
        if let Some(reason) = &self.reason {
            ensure_at_most("RTCP BYE reason length", reason.len(), 255)?;
            body.push(reason.len() as u8);
            body.extend_from_slice(reason);
            let pad = (4 - body.len() % 4) % 4;
            body.extend(std::iter::repeat_n(0u8, pad));
        }
        let mut out = Vec::with_capacity(4 + body.len());
        write_header(&mut out, self.sources.len() as u8, PT_BYE, body.len())?;
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse a BYE packet from its bytes.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] if the buffer is short.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        let mut off = 4;
        let mut sources = Vec::with_capacity(h.count as usize);
        for _ in 0..h.count {
            if off + 4 > h.content_len {
                return Err(Error::Truncated {
                    needed: off + 4,
                    got: h.content_len,
                });
            }
            sources.push(be_u32(buf, off));
            off += 4;
        }
        let reason = if off < h.content_len {
            let len = buf[off] as usize;
            off += 1;
            if off + len > h.content_len {
                return Err(Error::Truncated {
                    needed: off + len,
                    got: h.content_len,
                });
            }
            Some(buf[off..off + len].to_vec())
        } else {
            None
        };
        Ok(Self { sources, reason })
    }
}
