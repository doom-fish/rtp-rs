//! RTCP packet types (RFC 3550 §6) and feedback messages (RFC 4585 / 5104).
//!
//! Every RTCP packet starts with the same 4-byte header:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  RC/FMT |   PT          |             length            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! `length` is the size of the whole packet in 32-bit words **minus one**,
//! including the header. The `RC`/`FMT` nibble is a reception-report count for
//! SR/RR/SDES or a feedback message subtype for RTPFB/PSFB.
//!
//! [`RtcpPacket`] is the tagged union of all supported packets. Multiple RTCP
//! packets are concatenated into a [`compound::CompoundPacket`].

pub mod app;
pub mod bye;
pub mod compound;
pub mod fir;
pub mod nack;
pub mod pli;
pub mod remb;
pub mod rr;
pub mod sdes;
pub mod sli;
pub mod sr;
pub mod twcc;

use crate::error::{ensure_at_most, Error, Result};

/// Sender Report.
pub const PT_SR: u8 = 200;
/// Receiver Report.
pub const PT_RR: u8 = 201;
/// Source Description.
pub const PT_SDES: u8 = 202;
/// Goodbye.
pub const PT_BYE: u8 = 203;
/// Application-defined.
pub const PT_APP: u8 = 204;
/// Generic RTP feedback (RFC 4585).
pub const PT_RTPFB: u8 = 205;
/// Payload-specific feedback (RFC 4585 / 5104).
pub const PT_PSFB: u8 = 206;

/// A parsed RTCP packet.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RtcpPacket {
    /// Sender report (PT 200).
    SenderReport(sr::SenderReport),
    /// Receiver report (PT 201).
    ReceiverReport(rr::ReceiverReport),
    /// Source description (PT 202).
    SourceDescription(sdes::Sdes),
    /// Goodbye (PT 203).
    Bye(bye::Bye),
    /// Application-defined (PT 204).
    App(app::App),
    /// Generic NACK (PT 205, FMT 1).
    Nack(nack::Nack),
    /// Transport-wide congestion control (PT 205, FMT 15).
    Twcc(twcc::Twcc),
    /// Picture loss indication (PT 206, FMT 1).
    Pli(pli::Pli),
    /// Slice loss indication (PT 206, FMT 2).
    Sli(sli::Sli),
    /// Full intra request (PT 206, FMT 4).
    Fir(fir::Fir),
    /// Receiver estimated max bitrate (PT 206, FMT 15).
    Remb(remb::Remb),
}

impl RtcpPacket {
    /// Start building a receiver report.
    #[must_use]
    pub fn receiver_report(ssrc: u32) -> rr::ReceiverReportBuilder {
        rr::ReceiverReport::builder(ssrc)
    }

    /// Start building a sender report.
    #[must_use]
    pub fn sender_report(ssrc: u32) -> sr::SenderReportBuilder {
        sr::SenderReport::builder(ssrc)
    }

    /// Build a picture-loss indication for `media_ssrc`.
    #[must_use]
    pub fn pli(sender_ssrc: u32, media_ssrc: u32) -> pli::Pli {
        pli::Pli {
            sender_ssrc,
            media_ssrc,
        }
    }

    /// Build a full-intra-request for `media_ssrc` with sequence number `seq`.
    #[must_use]
    pub fn fir(sender_ssrc: u32, media_ssrc: u32, seq: u8) -> fir::Fir {
        fir::Fir {
            sender_ssrc,
            media_ssrc: 0,
            entries: vec![fir::FirEntry {
                ssrc: media_ssrc,
                seq_nr: seq,
            }],
        }
    }

    /// The RTCP payload type byte of this packet.
    #[must_use]
    pub const fn payload_type(&self) -> u8 {
        match self {
            Self::SenderReport(_) => PT_SR,
            Self::ReceiverReport(_) => PT_RR,
            Self::SourceDescription(_) => PT_SDES,
            Self::Bye(_) => PT_BYE,
            Self::App(_) => PT_APP,
            Self::Nack(_) | Self::Twcc(_) => PT_RTPFB,
            Self::Pli(_) | Self::Sli(_) | Self::Fir(_) | Self::Remb(_) => PT_PSFB,
        }
    }

    /// Serialize this single RTCP packet (with its own header).
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] when a count or length does not fit its wire
    /// field, instead of truncating it.
    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Self::SenderReport(p) => p.encode(),
            Self::ReceiverReport(p) => p.encode(),
            Self::SourceDescription(p) => p.encode(),
            Self::Bye(p) => p.encode(),
            Self::App(p) => p.encode(),
            Self::Nack(p) => p.encode(),
            Self::Twcc(p) => p.encode(),
            Self::Pli(p) => p.encode(),
            Self::Sli(p) => p.encode(),
            Self::Fir(p) => p.encode(),
            Self::Remb(p) => p.encode(),
        }
    }

    /// Parse a single RTCP packet from exactly its own bytes.
    ///
    /// # Errors
    /// Returns [`Error::Unsupported`] for unknown payload types and propagates
    /// truncation errors from the per-type parser.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        match h.pt {
            PT_SR => Ok(Self::SenderReport(sr::SenderReport::parse(buf)?)),
            PT_RR => Ok(Self::ReceiverReport(rr::ReceiverReport::parse(buf)?)),
            PT_SDES => Ok(Self::SourceDescription(sdes::Sdes::parse(buf)?)),
            PT_BYE => Ok(Self::Bye(bye::Bye::parse(buf)?)),
            PT_APP => Ok(Self::App(app::App::parse(buf)?)),
            PT_RTPFB => match h.count {
                nack::FMT => Ok(Self::Nack(nack::Nack::parse(buf)?)),
                twcc::FMT => Ok(Self::Twcc(twcc::Twcc::parse(buf)?)),
                _ => Err(Error::Unsupported("unknown RTPFB feedback type")),
            },
            PT_PSFB => match h.count {
                pli::FMT => Ok(Self::Pli(pli::Pli::parse(buf)?)),
                sli::FMT => Ok(Self::Sli(sli::Sli::parse(buf)?)),
                fir::FMT => Ok(Self::Fir(fir::Fir::parse(buf)?)),
                remb::FMT if h.content_len >= 16 && buf[12..16] == remb::IDENTIFIER => {
                    Ok(Self::Remb(remb::Remb::parse(buf)?))
                }
                _ => Err(Error::Unsupported("unknown PSFB feedback type")),
            },
            _ => Err(Error::Unsupported("unknown RTCP payload type")),
        }
    }
}

macro_rules! rtcp_from {
    ($from:path => $variant:ident) => {
        impl From<$from> for RtcpPacket {
            fn from(p: $from) -> Self {
                Self::$variant(p)
            }
        }
    };
}

rtcp_from!(sr::SenderReport => SenderReport);
rtcp_from!(rr::ReceiverReport => ReceiverReport);
rtcp_from!(sdes::Sdes => SourceDescription);
rtcp_from!(bye::Bye => Bye);
rtcp_from!(app::App => App);
rtcp_from!(nack::Nack => Nack);
rtcp_from!(twcc::Twcc => Twcc);
rtcp_from!(pli::Pli => Pli);
rtcp_from!(sli::Sli => Sli);
rtcp_from!(fir::Fir => Fir);
rtcp_from!(remb::Remb => Remb);

/// Parsed RTCP common header plus the offset/length of its body.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Header {
    /// Reception-report count or feedback message type (low 5 bits).
    pub count: u8,
    /// Payload type byte.
    pub pt: u8,
    /// Total packet length in bytes (header + body), derived from the length
    /// field.
    pub total_len: usize,
    pub content_len: usize,
}

impl Header {
    pub(crate) fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < 4 {
            return Err(Error::Truncated {
                needed: 4,
                got: buf.len(),
            });
        }
        let b0 = buf[0];
        let version = b0 >> 6;
        if version != 2 {
            return Err(Error::BadVersion(version));
        }
        let padding = b0 & 0x20 != 0;
        let count = b0 & 0x1F;
        let pt = buf[1];
        let words = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let total_len = (words + 1) * 4;
        if buf.len() < total_len {
            return Err(Error::Truncated {
                needed: total_len,
                got: buf.len(),
            });
        }
        let content_len = if padding {
            let pad = usize::from(buf[total_len - 1]);
            if pad == 0 || pad > total_len - 4 {
                return Err(Error::BadPadding(pad));
            }
            total_len - pad
        } else {
            total_len
        };
        Ok(Self {
            count,
            pt,
            total_len,
            content_len,
        })
    }
}

/// Write an RTCP common header into `out` for a packet whose body is
/// `body_len` bytes (must be 32-bit aligned). `count` is the RC/FMT nibble.
pub(crate) fn write_header(out: &mut Vec<u8>, count: u8, pt: u8, body_len: usize) -> Result<()> {
    debug_assert!(body_len % 4 == 0, "RTCP body must be 32-bit aligned");
    let words = body_len / 4;
    ensure_at_most(
        "RTCP packet length in 32-bit words",
        words,
        usize::from(u16::MAX),
    )?;
    out.push((2 << 6) | (count & 0x1F));
    out.push(pt);
    out.extend_from_slice(&(words as u16).to_be_bytes());
    Ok(())
}

/// Read a big-endian u32 at `off`, assuming bounds were validated by the header.
pub(crate) fn be_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
