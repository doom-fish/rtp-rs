//! RTCP compound packet handling and validation (RFC 3550 §6.1).
//!
//! Multiple RTCP packets are concatenated with no separators; the length field
//! of each common header is used to find the next. A valid compound packet
//! must begin with a Sender Report or Receiver Report (unless reduced-size
//! RTCP, RFC 5506, is in use — not handled here) so that statistics are always
//! carried.

use super::{Header, RtcpPacket};
use crate::error::{Error, Result};

/// A sequence of RTCP packets transmitted together in one datagram.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CompoundPacket {
    /// The constituent packets, in order.
    pub packets: Vec<RtcpPacket>,
}

impl CompoundPacket {
    /// Create an empty compound packet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a packet.
    #[must_use]
    pub fn add(mut self, packet: RtcpPacket) -> Self {
        self.packets.push(packet);
        self
    }

    /// Whether the compound packet contains a BYE.
    #[must_use]
    pub fn has_bye(&self) -> bool {
        self.packets
            .iter()
            .any(|p| matches!(p, RtcpPacket::Bye(_)))
    }

    /// Validate the structural rules: non-empty and first packet is SR or RR.
    ///
    /// # Errors
    /// Returns [`Error::BadCompound`] if the rules are violated.
    pub fn validate(&self) -> Result<()> {
        let Some(first) = self.packets.first() else {
            return Err(Error::BadCompound("compound packet is empty"));
        };
        if !matches!(
            first,
            RtcpPacket::SenderReport(_) | RtcpPacket::ReceiverReport(_)
        ) {
            return Err(Error::BadCompound(
                "first packet must be a Sender or Receiver Report",
            ));
        }
        Ok(())
    }

    /// Serialize the compound packet.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for p in &self.packets {
            out.extend_from_slice(&p.encode());
        }
        out
    }

    /// Parse and validate a compound packet from a datagram.
    ///
    /// # Errors
    /// Propagates parse errors and returns [`Error::BadCompound`] if the
    /// first-packet rule is violated.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let compound = Self::parse_lenient(buf)?;
        compound.validate()?;
        Ok(compound)
    }

    /// Parse a compound packet **without** enforcing the first-packet rule.
    ///
    /// Useful for reduced-size RTCP or for inspecting malformed streams.
    ///
    /// # Errors
    /// Propagates per-packet parse errors.
    pub fn parse_lenient(buf: &[u8]) -> Result<Self> {
        let mut packets = Vec::new();
        let mut off = 0;
        while off < buf.len() {
            let h = Header::parse(&buf[off..])?;
            let end = off + h.total_len;
            if end > buf.len() {
                return Err(Error::Truncated {
                    needed: end,
                    got: buf.len(),
                });
            }
            packets.push(RtcpPacket::parse(&buf[off..end])?);
            off = end;
        }
        Ok(Self { packets })
    }
}
