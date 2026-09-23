//! Sender Report (PT 200).

use super::rr::ReportBlock;
use super::{be_u32, write_header, Header, PT_SR};
use crate::error::{ensure_at_most, Error, Result};

/// A Sender Report: sender info block plus zero or more reception reports.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SenderReport {
    /// SSRC of the sender.
    pub ssrc: u32,
    /// 64-bit NTP timestamp (wallclock at the time of this report).
    pub ntp_timestamp: u64,
    /// RTP timestamp corresponding to the same instant as `ntp_timestamp`.
    pub rtp_timestamp: u32,
    /// Total RTP data packets sent.
    pub packet_count: u32,
    /// Total payload octets sent.
    pub octet_count: u32,
    /// Reception report blocks (0..=31).
    pub reports: Vec<ReportBlock>,
}

impl SenderReport {
    /// Middle 32 bits of the NTP timestamp (the LSR field of a remote RR).
    #[must_use]
    pub const fn ntp_middle(&self) -> u32 {
        (self.ntp_timestamp >> 16) as u32
    }

    /// Start a builder.
    #[must_use]
    pub fn builder(ssrc: u32) -> SenderReportBuilder {
        SenderReportBuilder {
            sr: Self {
                ssrc,
                ..Self::default()
            },
        }
    }

    /// Serialize this packet (with header).
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] for more than 31 report blocks.
    pub fn encode(&self) -> Result<Vec<u8>> {
        ensure_at_most("RTCP sender report block count", self.reports.len(), 31)?;
        let body_len = 24 + self.reports.len() * ReportBlock::LEN;
        let mut out = Vec::with_capacity(4 + body_len);
        write_header(&mut out, self.reports.len() as u8, PT_SR, body_len)?;
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        out.extend_from_slice(&self.ntp_timestamp.to_be_bytes());
        out.extend_from_slice(&self.rtp_timestamp.to_be_bytes());
        out.extend_from_slice(&self.packet_count.to_be_bytes());
        out.extend_from_slice(&self.octet_count.to_be_bytes());
        for b in &self.reports {
            b.write(&mut out);
        }
        Ok(out)
    }

    /// Parse a Sender Report from its bytes.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] if the buffer is short.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        if h.content_len < 28 {
            return Err(Error::Truncated {
                needed: 28,
                got: h.content_len,
            });
        }
        let ssrc = be_u32(buf, 4);
        let ntp_timestamp = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let rtp_timestamp = be_u32(buf, 16);
        let packet_count = be_u32(buf, 20);
        let octet_count = be_u32(buf, 24);
        let mut reports = Vec::with_capacity(h.count as usize);
        let mut off = 28;
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
        Ok(Self {
            ssrc,
            ntp_timestamp,
            rtp_timestamp,
            packet_count,
            octet_count,
            reports,
        })
    }
}

/// Builder for [`SenderReport`].
#[derive(Clone, Debug)]
pub struct SenderReportBuilder {
    sr: SenderReport,
}

impl SenderReportBuilder {
    /// Set the NTP timestamp.
    #[must_use]
    pub fn ntp_timestamp(mut self, ntp: u64) -> Self {
        self.sr.ntp_timestamp = ntp;
        self
    }

    /// Set the RTP timestamp.
    #[must_use]
    pub fn rtp_timestamp(mut self, ts: u32) -> Self {
        self.sr.rtp_timestamp = ts;
        self
    }

    /// Set the sender packet and octet counts.
    #[must_use]
    pub fn counts(mut self, packets: u32, octets: u32) -> Self {
        self.sr.packet_count = packets;
        self.sr.octet_count = octets;
        self
    }

    /// Add a reception report block.
    #[must_use]
    pub fn add_block(mut self, block: ReportBlock) -> Self {
        self.sr.reports.push(block);
        self
    }

    /// Finish building into an [`RtcpPacket`](super::RtcpPacket).
    #[must_use]
    pub fn build(self) -> super::RtcpPacket {
        super::RtcpPacket::SenderReport(self.sr)
    }
}
