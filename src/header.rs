//! RTP fixed header codec (RFC 3550 §5.1).
//!
//! The 12-byte fixed header is followed by an optional CSRC list (0..=15
//! entries) and an optional one header extension. When the extension (X) bit is
//! set, a 4-byte `(profile, length)` header precedes the extension data, where
//! **length is measured in 32-bit words and excludes the 4-byte header**
//! (RFC 3550 §5.3.1) — a common source of off-by-four bugs.

use crate::error::{ensure_at_most, Error, Result};

/// Length of the fixed RTP header, before any CSRCs or extension.
pub const FIXED_HEADER_LEN: usize = 12;

/// A parsed (or to-be-built) RTP fixed header plus its CSRC list and raw
/// extension block.
///
/// Field accessors return values; mutation goes through the builder on
/// [`crate::RtpPacket`] or the setters here. The raw extension bytes are stored
/// verbatim (already 32-bit aligned) so that a parse/build cycle is lossless;
/// use [`crate::extension`] to interpret them.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RtpHeader {
    pub(crate) padding: bool,
    pub(crate) extension: bool,
    pub(crate) marker: bool,
    pub(crate) payload_type: u8,
    pub(crate) sequence_number: u16,
    pub(crate) timestamp: u32,
    pub(crate) ssrc: u32,
    pub(crate) csrc: Vec<u32>,
    pub(crate) ext_profile: u16,
    pub(crate) ext_data: Vec<u8>,
}

impl RtpHeader {
    /// RTP version. This crate only ever emits or accepts version 2.
    #[must_use]
    pub const fn version(&self) -> u8 {
        2
    }

    /// Whether the padding (P) bit is set.
    #[must_use]
    pub const fn has_padding(&self) -> bool {
        self.padding
    }

    /// Whether the extension (X) bit is set.
    #[must_use]
    pub const fn has_extension(&self) -> bool {
        self.extension
    }

    /// Whether the marker (M) bit is set.
    #[must_use]
    pub const fn marker(&self) -> bool {
        self.marker
    }

    /// The 7-bit payload type (dynamic, negotiated per session).
    #[must_use]
    pub const fn payload_type(&self) -> u8 {
        self.payload_type
    }

    /// The 16-bit sequence number.
    #[must_use]
    pub const fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// The 32-bit media timestamp.
    #[must_use]
    pub const fn timestamp(&self) -> u32 {
        self.timestamp
    }

    /// The 32-bit synchronization source identifier.
    #[must_use]
    pub const fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The contributing-source list (0..=15 entries).
    #[must_use]
    pub fn csrc(&self) -> &[u32] {
        &self.csrc
    }

    /// The extension profile word, if the X bit is set.
    #[must_use]
    pub const fn extension_profile(&self) -> Option<u16> {
        if self.extension {
            Some(self.ext_profile)
        } else {
            None
        }
    }

    /// The raw (32-bit aligned) extension block bytes, if the X bit is set.
    #[must_use]
    pub fn extension_data(&self) -> Option<&[u8]> {
        if self.extension {
            Some(&self.ext_data)
        } else {
            None
        }
    }

    /// Set the marker bit.
    pub fn set_marker(&mut self, marker: bool) {
        self.marker = marker;
    }

    /// Set the payload type (low 7 bits used).
    pub fn set_payload_type(&mut self, pt: u8) {
        self.payload_type = pt & 0x7F;
    }

    /// Set the sequence number.
    pub fn set_sequence_number(&mut self, seq: u16) {
        self.sequence_number = seq;
    }

    /// Set the timestamp.
    pub fn set_timestamp(&mut self, ts: u32) {
        self.timestamp = ts;
    }

    /// Set the SSRC.
    pub fn set_ssrc(&mut self, ssrc: u32) {
        self.ssrc = ssrc;
    }

    /// Total length of this header on the wire (fixed + CSRCs + extension),
    /// i.e. the offset at which the payload begins.
    #[must_use]
    pub fn len_on_wire(&self) -> usize {
        let mut len = FIXED_HEADER_LEN + self.csrc.len() * 4;
        if self.extension {
            len += 4 + self.ext_data.len();
        }
        len
    }

    /// Parse a fixed header (plus CSRCs and extension) from the front of `buf`.
    ///
    /// Returns the header and the byte offset at which the payload starts.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] if the buffer is too short and
    /// [`Error::BadVersion`] if the version field is not 2.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < FIXED_HEADER_LEN {
            return Err(Error::Truncated {
                needed: FIXED_HEADER_LEN,
                got: buf.len(),
            });
        }
        let b0 = buf[0];
        let version = b0 >> 6;
        if version != 2 {
            return Err(Error::BadVersion(version));
        }
        let padding = b0 & 0x20 != 0;
        let extension = b0 & 0x10 != 0;
        let cc = (b0 & 0x0F) as usize;

        let b1 = buf[1];
        let marker = b1 & 0x80 != 0;
        let payload_type = b1 & 0x7F;

        let sequence_number = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        let mut off = FIXED_HEADER_LEN;
        let csrc_bytes = cc * 4;
        if buf.len() < off + csrc_bytes {
            return Err(Error::Truncated {
                needed: off + csrc_bytes,
                got: buf.len(),
            });
        }
        let mut csrc = Vec::with_capacity(cc);
        for _ in 0..cc {
            csrc.push(u32::from_be_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ]));
            off += 4;
        }

        let mut ext_profile = 0u16;
        let mut ext_data = Vec::new();
        if extension {
            if buf.len() < off + 4 {
                return Err(Error::Truncated {
                    needed: off + 4,
                    got: buf.len(),
                });
            }
            ext_profile = u16::from_be_bytes([buf[off], buf[off + 1]]);
            // Length is in 32-bit words and EXCLUDES the 4-byte header.
            let words = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            off += 4;
            let ext_len = words * 4;
            if buf.len() < off + ext_len {
                return Err(Error::Truncated {
                    needed: off + ext_len,
                    got: buf.len(),
                });
            }
            ext_data = buf[off..off + ext_len].to_vec();
            off += ext_len;
        }

        Ok((
            Self {
                padding,
                extension,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc,
                csrc,
                ext_profile,
                ext_data,
            },
            off,
        ))
    }

    /// Serialize the header (fixed + CSRCs + extension) into `out`.
    ///
    /// The padding (P) bit reflects the header's padding flag; the caller is
    /// responsible for actually appending the padding bytes to the payload.
    ///
    /// # Errors
    /// Returns [`Error::TooLarge`] for more than 15 CSRCs or an extension
    /// block longer than 65 535 32-bit words; nothing is written to `out`.
    ///
    /// # Panics
    /// Panics in debug builds if the stored extension data is not 32-bit
    /// aligned; the builder guarantees alignment.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        ensure_at_most("CSRC count", self.csrc.len(), 15)?;
        if self.extension {
            ensure_at_most(
                "header extension length in 32-bit words",
                self.ext_data.len() / 4,
                usize::from(u16::MAX),
            )?;
        }
        let cc = self.csrc.len() as u8;
        let mut b0 = (2u8 << 6) | cc;
        if self.padding {
            b0 |= 0x20;
        }
        if self.extension {
            b0 |= 0x10;
        }
        out.push(b0);

        let mut b1 = self.payload_type & 0x7F;
        if self.marker {
            b1 |= 0x80;
        }
        out.push(b1);

        out.extend_from_slice(&self.sequence_number.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.ssrc.to_be_bytes());
        for c in &self.csrc {
            out.extend_from_slice(&c.to_be_bytes());
        }
        if self.extension {
            debug_assert!(
                self.ext_data.len() % 4 == 0,
                "extension data must be 32-bit aligned"
            );
            out.extend_from_slice(&self.ext_profile.to_be_bytes());
            let words = (self.ext_data.len() / 4) as u16;
            out.extend_from_slice(&words.to_be_bytes());
            out.extend_from_slice(&self.ext_data);
        }
        Ok(())
    }
}
