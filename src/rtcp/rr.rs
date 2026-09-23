//! Receiver Report (PT 201) and the reception report block shared with SR.

use super::{be_u32, write_header, Header, PT_RR};
use crate::error::{Error, Result};

/// A single reception report block (24 bytes), used by both RR and SR.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ReportBlock {
    /// SSRC of the source this block reports on.
    pub ssrc: u32,
    /// Fraction of packets lost since the previous report (8-bit fixed point).
    pub fraction_lost: u8,
    /// Cumulative number of packets lost (24-bit, stored in low bits).
    pub cumulative_lost: u32,
    /// Extended highest sequence number received.
    pub extended_highest_seq: u32,
    /// Interarrival jitter.
    pub jitter: u32,
    /// Middle 32 bits of the NTP timestamp of the last SR received (LSR).
    pub last_sr: u32,
    /// Delay since last SR, in units of 1/65536 seconds (DLSR).
    pub delay_since_last_sr: u32,
}

impl ReportBlock {
    /// Serialized length of a report block.
    pub const LEN: usize = 24;

    pub(crate) fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        let fl_cl =
            (u32::from(self.fraction_lost) << 24) | (self.cumulative_lost & 0x00FF_FFFF);
        out.extend_from_slice(&fl_cl.to_be_bytes());
        out.extend_from_slice(&self.extended_highest_seq.to_be_bytes());
        out.extend_from_slice(&self.jitter.to_be_bytes());
        out.extend_from_slice(&self.last_sr.to_be_bytes());
        out.extend_from_slice(&self.delay_since_last_sr.to_be_bytes());
    }

    pub(crate) fn parse(buf: &[u8], off: usize) -> Self {
        let fl_cl = be_u32(buf, off + 4);
        Self {
            ssrc: be_u32(buf, off),
            fraction_lost: (fl_cl >> 24) as u8,
            cumulative_lost: fl_cl & 0x00FF_FFFF,
            extended_highest_seq: be_u32(buf, off + 8),
            jitter: be_u32(buf, off + 12),
            last_sr: be_u32(buf, off + 16),
            delay_since_last_sr: be_u32(buf, off + 20),
        }
    }
}

/// A Receiver Report.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ReceiverReport {
    /// SSRC of the report sender.
    pub ssrc: u32,
    /// Reception report blocks (0..=31).
    pub reports: Vec<ReportBlock>,
}

impl ReceiverReport {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> ReceiverReportBuilder {
        ReceiverReportBuilder::default()
    }

    /// Serialize this packet (with header).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let count = self.reports.len().min(31) as u8;
        let body_len = 4 + count as usize * ReportBlock::LEN;
        let mut out = Vec::with_capacity(4 + body_len);
        write_header(&mut out, count, PT_RR, body_len);
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for b in self.reports.iter().take(31) {
            b.write(&mut out);
        }
        out
    }

    /// Parse a Receiver Report from its bytes.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] if the buffer is short.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        if h.content_len < 8 {
            return Err(Error::Truncated {
                needed: 8,
                got: h.content_len,
            });
        }
        let ssrc = be_u32(buf, 4);
        let mut reports = Vec::with_capacity(h.count as usize);
        let mut off = 8;
        for _ in 0..h.count {
            if off + ReportBlock::LEN > h.content_len {
                return Err(Error::Truncated {
                    needed: off + ReportBlock::LEN,
                    got: h.content_len,
                });
            }
            reports.push(ReportBlock::parse(buf, off));
            off += ReportBlock::LEN;
        }
        Ok(Self { ssrc, reports })
    }
}

/// Builder for [`ReceiverReport`].
#[derive(Clone, Debug, Default)]
pub struct ReceiverReportBuilder {
    rr: ReceiverReport,
}

impl ReceiverReportBuilder {
    /// Set the reporter SSRC.
    #[must_use]
    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.rr.ssrc = ssrc;
        self
    }

    /// Add a reception report block.
    #[must_use]
    pub fn add_block(mut self, block: ReportBlock) -> Self {
        self.rr.reports.push(block);
        self
    }

    /// Finish building into an [`RtcpPacket`](super::RtcpPacket).
    #[must_use]
    pub fn build(self) -> super::RtcpPacket {
        super::RtcpPacket::ReceiverReport(self.rr)
    }
}
