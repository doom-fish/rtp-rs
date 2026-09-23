//! Goodbye (PT 203).

use super::{be_u32, write_header, Header, PT_BYE};
use crate::error::{Error, Result};

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
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let count = self.sources.len().min(31) as u8;
        let mut body = Vec::new();
        for s in self.sources.iter().take(31) {
            body.extend_from_slice(&s.to_be_bytes());
        }
        if let Some(reason) = &self.reason {
            let len = reason.len().min(255) as u8;
            body.push(len);
            body.extend_from_slice(&reason[..len as usize]);
            let pad = (4 - body.len() % 4) % 4;
            body.extend(std::iter::repeat(0u8).take(pad));
        }
        let mut out = Vec::with_capacity(4 + body.len());
        write_header(&mut out, count, PT_BYE, body.len());
        out.extend_from_slice(&body);
        out
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
