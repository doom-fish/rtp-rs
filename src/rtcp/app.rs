//! Application-defined (PT 204).
//!
//! Skeleton support: the subtype, SSRC, four-byte ASCII name, and an opaque
//! application data blob (which must be 32-bit aligned on the wire).

use super::{be_u32, write_header, Header, PT_APP};
use crate::error::{ensure_at_most, Error, Result};

/// An application-defined RTCP packet.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct App {
    /// Application-specific subtype (low 5 bits, carried in the RC nibble).
    pub subtype: u8,
    /// Source identifier.
    pub ssrc: u32,
    /// Four-byte ASCII name chosen by the application.
    pub name: [u8; 4],
    /// Opaque application data (will be zero-padded to a 32-bit boundary).
    pub data: Vec<u8>,
}

impl App {
    /// Serialize this packet (with header).
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] for a subtype above 31 or a packet longer
    /// than the RTCP length field can describe.
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure_at_most("RTCP APP subtype", usize::from(self.subtype), 31)?;
        let mut body = Vec::with_capacity(8 + self.data.len());
        body.extend_from_slice(&self.ssrc.to_be_bytes());
        body.extend_from_slice(&self.name);
        body.extend_from_slice(&self.data);
        let pad = (4 - body.len() % 4) % 4;
        body.extend(std::iter::repeat_n(0u8, pad));
        let mut out = Vec::with_capacity(4 + body.len());
        write_header(&mut out, self.subtype, PT_APP, body.len())?;
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse an application-defined packet from its bytes.
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
        let ssrc = be_u32(buf, 4);
        let name = [buf[8], buf[9], buf[10], buf[11]];
        let data = buf[12..h.content_len].to_vec();
        Ok(Self {
            subtype: h.count,
            ssrc,
            name,
            data,
        })
    }
}
