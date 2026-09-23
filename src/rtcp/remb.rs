//! Receiver Estimated Maximum Bitrate (PT 206, PSFB FMT 15,
//! draft-alvestrand-rmcat-remb).
//!
//! The FCI begins with the ASCII identifier `REMB`, a one-byte SSRC count, a
//! 6-bit exponent and 18-bit mantissa encoding the estimated bitrate
//! (`mantissa << exp` bits per second), then the list of constrained SSRCs.

use super::{be_u32, write_header, Header, PT_PSFB};
use crate::error::{Error, Result};

/// PSFB feedback message type for REMB.
pub const FMT: u8 = 15;

/// The `REMB` unique identifier.
pub const IDENTIFIER: [u8; 4] = *b"REMB";

/// A Receiver Estimated Maximum Bitrate packet.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Remb {
    /// SSRC of the feedback sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source (zero per the draft).
    pub media_ssrc: u32,
    /// Estimated maximum bitrate in bits per second.
    pub bitrate_bps: u64,
    /// SSRCs to which the estimate applies.
    pub ssrcs: Vec<u32>,
}

impl Remb {
    /// Encode `bitrate_bps` into the 6-bit exponent / 18-bit mantissa form.
    #[must_use]
    fn encode_bitrate(&self) -> (u8, u32) {
        let mut mantissa = self.bitrate_bps;
        let mut exp: u8 = 0;
        while mantissa > 0x0003_FFFF {
            mantissa >>= 1;
            exp += 1;
        }
        (exp, mantissa as u32)
    }

    /// Serialize this packet (with header).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let num = self.ssrcs.len().min(255) as u8;
        let body_len = 8 + 8 + num as usize * 4;
        let mut out = Vec::with_capacity(4 + body_len);
        write_header(&mut out, FMT, PT_PSFB, body_len);
        out.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        out.extend_from_slice(&self.media_ssrc.to_be_bytes());
        out.extend_from_slice(&IDENTIFIER);
        let (exp, mantissa) = self.encode_bitrate();
        out.push(num);
        out.push((exp << 2) | ((mantissa >> 16) & 0x03) as u8);
        out.push((mantissa >> 8) as u8);
        out.push(mantissa as u8);
        for s in self.ssrcs.iter().take(255) {
            out.extend_from_slice(&s.to_be_bytes());
        }
        out
    }

    /// Parse a REMB packet from its bytes.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] or [`Error::BadPayload`] on malformed input.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        if h.content_len < 20 {
            return Err(Error::Truncated {
                needed: 20,
                got: h.content_len,
            });
        }
        let sender_ssrc = be_u32(buf, 4);
        let media_ssrc = be_u32(buf, 8);
        if buf[12..16] != IDENTIFIER {
            return Err(Error::BadPayload("REMB identifier mismatch"));
        }
        let num = buf[16] as usize;
        let exp = (buf[17] >> 2) & 0x3F;
        let mantissa =
            (u32::from(buf[17] & 0x03) << 16) | (u32::from(buf[18]) << 8) | u32::from(buf[19]);
        let bitrate_bps = u64::from(mantissa)
            .checked_shl(u32::from(exp))
            .filter(|bps| bps >> exp == u64::from(mantissa))
            .ok_or(Error::BadPayload("REMB bitrate does not fit in 64 bits"))?;
        let mut ssrcs = Vec::with_capacity(num);
        let mut off = 20;
        for _ in 0..num {
            if off + 4 > h.content_len {
                return Err(Error::Truncated {
                    needed: off + 4,
                    got: h.content_len,
                });
            }
            ssrcs.push(be_u32(buf, off));
            off += 4;
        }
        Ok(Self {
            sender_ssrc,
            media_ssrc,
            bitrate_bps,
            ssrcs,
        })
    }
}
