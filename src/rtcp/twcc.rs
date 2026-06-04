//! Transport-wide congestion control feedback (PT 205, RTPFB FMT 15,
//! `draft-holmer-rmcat-transport-wide-cc-extensions`).
//!
//! The FCI records, for a run of transport-wide sequence numbers starting at
//! `base_seq`, whether each packet arrived and (if so) its arrival delta
//! relative to a 24-bit reference time. Packets are described by *status
//! chunks* (run-length or status-vector) followed by *receive deltas*.
//!
//! This implementation **encodes** using run-length chunks (one symbol per run)
//! which is always valid, and **decodes** both run-length and status-vector
//! chunks (1-bit and 2-bit) for interoperability with WebRTC peers and SFUs.

use super::{be_u32, write_header, Header, PT_RTPFB};
use crate::error::{Error, Result};

/// RTPFB feedback message type for transport-wide CC.
pub const FMT: u8 = 15;

/// Arrival status of one packet in a TWCC report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delta {
    /// Packet was not received.
    NotReceived,
    /// Received; delta encoded as one byte (250µs units, 0..=255).
    Small(u8),
    /// Received; delta encoded as a signed 16-bit value (250µs units).
    Large(i16),
}

impl Delta {
    /// The 2-bit status symbol for this delta.
    const fn symbol(self) -> u8 {
        match self {
            Self::NotReceived => 0,
            Self::Small(_) => 1,
            Self::Large(_) => 2,
        }
    }
}

/// A transport-wide congestion-control feedback packet.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Twcc {
    /// SSRC of the feedback sender.
    pub sender_ssrc: u32,
    /// SSRC of the media source.
    pub media_ssrc: u32,
    /// Transport-wide sequence number of the first packet in `statuses`.
    pub base_seq: u16,
    /// Reference time, 24-bit signed, in multiples of 64 ms.
    pub reference_time: i32,
    /// Feedback packet counter (increments per TWCC packet sent).
    pub fb_pkt_count: u8,
    /// Per-packet arrival status, starting at `base_seq`.
    pub statuses: Vec<Delta>,
}

impl Twcc {
    /// Serialize this packet (with header), including 32-bit padding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.sender_ssrc.to_be_bytes());
        body.extend_from_slice(&self.media_ssrc.to_be_bytes());
        body.extend_from_slice(&self.base_seq.to_be_bytes());
        body.extend_from_slice(&(self.statuses.len() as u16).to_be_bytes());
        // reference time (24-bit) + fb packet count (8-bit)
        let rt = (self.reference_time as u32) & 0x00FF_FFFF;
        body.push((rt >> 16) as u8);
        body.push((rt >> 8) as u8);
        body.push(rt as u8);
        body.push(self.fb_pkt_count);

        // Status chunks: run-length per maximal run of identical symbols.
        let mut i = 0;
        while i < self.statuses.len() {
            let sym = self.statuses[i].symbol();
            let mut run = 1usize;
            while i + run < self.statuses.len()
                && self.statuses[i + run].symbol() == sym
                && run < 0x1FFF
            {
                run += 1;
            }
            let chunk = (u16::from(sym) << 13) | (run as u16 & 0x1FFF);
            body.extend_from_slice(&chunk.to_be_bytes());
            i += run;
        }

        // Receive deltas in packet order.
        for s in &self.statuses {
            match s {
                Delta::NotReceived => {}
                Delta::Small(v) => body.push(*v),
                Delta::Large(v) => body.extend_from_slice(&v.to_be_bytes()),
            }
        }

        // Pad to 32-bit boundary.
        let pad = (4 - body.len() % 4) % 4;
        body.extend(std::iter::repeat(0u8).take(pad));

        let mut out = Vec::with_capacity(4 + body.len());
        write_header(&mut out, FMT, PT_RTPFB, body.len());
        out.extend_from_slice(&body);
        out
    }

    /// Parse a TWCC packet from its bytes.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] or [`Error::BadPayload`] on malformed input.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        if h.total_len < 20 {
            return Err(Error::Truncated {
                needed: 20,
                got: h.total_len,
            });
        }
        let sender_ssrc = be_u32(buf, 4);
        let media_ssrc = be_u32(buf, 8);
        let base_seq = u16::from_be_bytes([buf[12], buf[13]]);
        let status_count = u16::from_be_bytes([buf[14], buf[15]]) as usize;
        let rt_raw = (u32::from(buf[16]) << 16) | (u32::from(buf[17]) << 8) | u32::from(buf[18]);
        // sign-extend 24-bit
        let reference_time = if rt_raw & 0x0080_0000 != 0 {
            (rt_raw | 0xFF00_0000) as i32
        } else {
            rt_raw as i32
        };
        let fb_pkt_count = buf[19];

        // First pass: read status chunks until we have status_count symbols.
        let mut symbols: Vec<u8> = Vec::with_capacity(status_count);
        let mut off = 20;
        while symbols.len() < status_count {
            if off + 2 > h.total_len {
                return Err(Error::Truncated {
                    needed: off + 2,
                    got: h.total_len,
                });
            }
            let chunk = u16::from_be_bytes([buf[off], buf[off + 1]]);
            off += 2;
            if chunk & 0x8000 == 0 {
                // Run-length chunk.
                let sym = ((chunk >> 13) & 0x3) as u8;
                let run = (chunk & 0x1FFF) as usize;
                for _ in 0..run {
                    if symbols.len() >= status_count {
                        break;
                    }
                    symbols.push(sym);
                }
            } else if chunk & 0x4000 == 0 {
                // Status vector, 1-bit symbols (14 of them).
                for bit in (0..14).rev() {
                    if symbols.len() >= status_count {
                        break;
                    }
                    symbols.push(((chunk >> bit) & 0x1) as u8);
                }
            } else {
                // Status vector, 2-bit symbols (7 of them).
                for pair in (0..7).rev() {
                    if symbols.len() >= status_count {
                        break;
                    }
                    symbols.push(((chunk >> (pair * 2)) & 0x3) as u8);
                }
            }
        }

        // Second pass: read deltas per symbol.
        let mut statuses = Vec::with_capacity(status_count);
        for sym in symbols {
            match sym {
                0 | 3 => statuses.push(Delta::NotReceived),
                1 => {
                    if off + 1 > h.total_len {
                        return Err(Error::Truncated {
                            needed: off + 1,
                            got: h.total_len,
                        });
                    }
                    statuses.push(Delta::Small(buf[off]));
                    off += 1;
                }
                2 => {
                    if off + 2 > h.total_len {
                        return Err(Error::Truncated {
                            needed: off + 2,
                            got: h.total_len,
                        });
                    }
                    statuses.push(Delta::Large(i16::from_be_bytes([buf[off], buf[off + 1]])));
                    off += 2;
                }
                _ => return Err(Error::BadPayload("invalid TWCC status symbol")),
            }
        }

        Ok(Self {
            sender_ssrc,
            media_ssrc,
            base_seq,
            reference_time,
            fb_pkt_count,
            statuses,
        })
    }
}
