//! The shared byte-buffer contract used by `rtp`, `srtp` and `rtc`.
//!
//! # Coordination contract (read before changing anything here)
//!
//! `rtp-rs`, `srtp-rs` and `rtc-rs` are three sibling crates with a hidden
//! coupling: they all touch the **same byte buffer** at different layers, and
//! the rules below must hold for SRTP authentication and zero-copy hand-off to
//! work. If you change a type in this file you are changing an ABI that two
//! other crates depend on.
//!
//! ## The three views
//!
//! * [`RtpPacket`] — an **immutable borrow** (`&'a [u8]`). The cheap, zero-copy
//!   read path. Produced by [`RtpPacket::parse`]. Holds no owned bytes.
//! * [`RtpPacketMut`] — a **mutable borrow** (`&'a mut [u8]`). The in-place
//!   decrypt path used by SRTP: SRTP receives an encrypted datagram, parses the
//!   header (which is *not* encrypted), decrypts the payload in place through
//!   [`RtpPacketMut::payload_mut`], then `freeze()`s it into an [`RtpPacket`].
//! * [`RtpPacketOwned`] — **owned bytes** (`Vec<u8>`). The jitter-buffer storage
//!   path: [`RtpPacket::to_owned`] copies the wire bytes so the packet can
//!   outlive the receive buffer.
//!
//! ## Invariants every view guarantees
//!
//! 1. [`Packet::as_bytes`] returns the **entire original wire packet**, header
//!    included. SRTP authenticates (HMAC) over these exact bytes, so they must
//!    never be re-serialized or reordered — always the bytes as received/built.
//! 2. [`Packet::payload`] returns the payload **with RTP padding removed**. The
//!    padding bytes live inside `as_bytes()` but are not part of the media
//!    payload an application or depacketizer should see.
//! 3. [`Packet::header`] exposes every header field by value through getters; it
//!    never borrows beyond the packet's own lifetime.
//! 4. The payload offset is stable: `as_bytes()[payload_offset()..]` is the
//!    payload-plus-padding region. SRTP relies on this to know which byte range
//!    to encrypt/decrypt without re-parsing.
//!
//! ## Why this matters for SRTP
//!
//! SRTP must HMAC over the *original* header bytes (including CSRCs and the
//! header extension), then encrypt only the payload region. If `rtp-rs` ever
//! handed SRTP a re-encoded header the authentication tag would not match. That
//! is why [`RtpPacketMut`] keeps a single backing `&mut [u8]` and exposes the
//! header by *parsed value* but the bytes by *borrowed slice*.

use crate::error::{ensure_at_most, Result};
use crate::extension::{self, Extension};
use crate::header::RtpHeader;
use crate::padding;

/// Common read interface shared by the borrowed and owned packet views.
///
/// See the [module documentation](self) for the invariants each method must
/// uphold.
pub trait Packet: sealed::Sealed {
    /// The parsed RTP header.
    fn header(&self) -> &RtpHeader;

    /// The media payload, with RTP padding stripped.
    fn payload(&self) -> &[u8];

    /// The entire original wire packet (header + payload + padding). SRTP
    /// authenticates over exactly these bytes.
    fn as_bytes(&self) -> &[u8];

    /// Byte offset within [`Packet::as_bytes`] where the payload begins.
    fn payload_offset(&self) -> usize;
}

/// Zero-copy immutable view over a complete RTP packet.
#[derive(Clone, Debug)]
pub struct RtpPacket<'a> {
    bytes: &'a [u8],
    header: RtpHeader,
    payload_off: usize,
    payload_end: usize,
}

impl<'a> RtpPacket<'a> {
    /// Parse a complete RTP packet from `bytes`.
    ///
    /// # Errors
    /// Propagates [`crate::Error`] from header parsing or padding validation.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        let (header, payload_off) = RtpHeader::parse(bytes)?;
        let payload_end = if header.has_padding() {
            let region = &bytes[payload_off..];
            // strip validates the trailing length byte
            let stripped = padding::strip(region)?;
            payload_off + stripped.len()
        } else {
            bytes.len()
        };
        Ok(Self {
            bytes,
            header,
            payload_off,
            payload_end,
        })
    }

    /// Start a builder for a new packet.
    #[must_use]
    pub fn builder() -> RtpPacketBuilder {
        RtpPacketBuilder::new()
    }

    /// Parsed header extensions (RFC 8285). Empty if the X bit is unset or the
    /// profile is not an RFC 8285 profile.
    #[must_use]
    pub fn extensions(&self) -> Vec<Extension> {
        match (self.header.extension_profile(), self.header.extension_data()) {
            (Some(profile), Some(data)) => extension::decode(profile, data).unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Copy the wire bytes into an owned packet for jitter-buffer storage.
    #[must_use]
    pub fn to_owned(&self) -> RtpPacketOwned {
        RtpPacketOwned {
            bytes: self.bytes.to_vec(),
            header: self.header.clone(),
            payload_off: self.payload_off,
            payload_end: self.payload_end,
        }
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::RtpPacket<'_> {}
    impl Sealed for super::RtpPacketOwned {}
}

impl Packet for RtpPacket<'_> {
    fn header(&self) -> &RtpHeader {
        &self.header
    }
    fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_off..self.payload_end]
    }
    fn as_bytes(&self) -> &[u8] {
        self.bytes
    }
    fn payload_offset(&self) -> usize {
        self.payload_off
    }
}

/// Mutable view used by SRTP for in-place decryption.
///
/// The header is parsed eagerly (it is never encrypted), but the backing buffer
/// is retained as `&mut [u8]` so the payload region can be decrypted in place.
/// Call [`RtpPacketMut::freeze`] to obtain an immutable [`RtpPacket`] once the
/// payload is in the clear.
#[derive(Debug)]
pub struct RtpPacketMut<'a> {
    bytes: &'a mut [u8],
    header: RtpHeader,
    payload_off: usize,
}

impl<'a> RtpPacketMut<'a> {
    /// Parse the header of `bytes` in place, retaining mutable access.
    ///
    /// Padding is **not** stripped here: while the payload is still encrypted
    /// the trailing length byte is meaningless. Strip it after `freeze()`.
    ///
    /// # Errors
    /// Propagates [`crate::Error`] from header parsing.
    pub fn parse(bytes: &'a mut [u8]) -> Result<Self> {
        let (header, payload_off) = RtpHeader::parse(bytes)?;
        Ok(Self {
            bytes,
            header,
            payload_off,
        })
    }

    /// The parsed header.
    #[must_use]
    pub const fn header(&self) -> &RtpHeader {
        &self.header
    }

    /// The payload-plus-padding region (immutable).
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_off..]
    }

    /// The payload-plus-padding region for in-place decryption.
    pub fn payload_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.payload_off..]
    }

    /// The entire wire packet (immutable). SRTP authenticates over these bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// The entire wire packet (mutable).
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    /// Offset where the payload begins.
    #[must_use]
    pub const fn payload_offset(&self) -> usize {
        self.payload_off
    }

    /// Re-borrow as an immutable [`RtpPacket`], stripping padding if present.
    ///
    /// # Errors
    /// Propagates [`crate::Error`] if the padding length byte is invalid.
    pub fn freeze(self) -> Result<RtpPacket<'a>> {
        RtpPacket::parse(self.bytes)
    }
}

/// Owned RTP packet, used for jitter-buffer storage and by the builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RtpPacketOwned {
    bytes: Vec<u8>,
    header: RtpHeader,
    payload_off: usize,
    payload_end: usize,
}

impl RtpPacketOwned {
    /// Parse an owned copy of `bytes`.
    ///
    /// # Errors
    /// Propagates [`crate::Error`] from parsing.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Ok(RtpPacket::parse(bytes)?.to_owned())
    }

    /// Borrow this owned packet as a zero-copy [`RtpPacket`] view.
    #[must_use]
    pub fn as_view(&self) -> RtpPacket<'_> {
        RtpPacket {
            bytes: &self.bytes,
            header: self.header.clone(),
            payload_off: self.payload_off,
            payload_end: self.payload_end,
        }
    }

    /// Consume the packet and return the owned wire bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Parsed header extensions (RFC 8285).
    #[must_use]
    pub fn extensions(&self) -> Vec<Extension> {
        self.as_view().extensions()
    }
}

impl Packet for RtpPacketOwned {
    fn header(&self) -> &RtpHeader {
        &self.header
    }
    fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_off..self.payload_end]
    }
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    fn payload_offset(&self) -> usize {
        self.payload_off
    }
}

/// Fluent builder for an [`RtpPacketOwned`].
///
/// Mirrors the public API shape: set fields, push extensions, set the payload,
/// then [`RtpPacketBuilder::build`].
#[derive(Clone, Debug, Default)]
pub struct RtpPacketBuilder {
    header: RtpHeader,
    extensions: Vec<Extension>,
    payload: Vec<u8>,
    pad_to: usize,
}

impl RtpPacketBuilder {
    /// Create an empty builder (version 2, payload type 0).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the marker bit.
    #[must_use]
    pub fn marker(mut self, marker: bool) -> Self {
        self.header.marker = marker;
        self
    }

    /// Set the payload type.
    #[must_use]
    pub fn payload_type(mut self, pt: u8) -> Self {
        self.header.payload_type = pt;
        self
    }

    /// Set the sequence number.
    #[must_use]
    pub fn sequence_number(mut self, seq: u16) -> Self {
        self.header.sequence_number = seq;
        self
    }

    /// Set the timestamp.
    #[must_use]
    pub fn timestamp(mut self, ts: u32) -> Self {
        self.header.timestamp = ts;
        self
    }

    /// Set the SSRC.
    #[must_use]
    pub fn ssrc(mut self, ssrc: u32) -> Self {
        self.header.ssrc = ssrc;
        self
    }

    /// Append a contributing source.
    #[must_use]
    pub fn csrc(mut self, csrc: u32) -> Self {
        self.header.csrc.push(csrc);
        self
    }

    /// Add a header extension element.
    #[must_use]
    pub fn extension(mut self, ext: Extension) -> Self {
        self.extensions.push(ext);
        self
    }

    /// Set the payload bytes.
    #[must_use]
    pub fn payload(mut self, payload: impl AsRef<[u8]>) -> Self {
        self.payload = payload.as_ref().to_vec();
        self
    }

    /// Request that the final packet be zero-padded up to a multiple of
    /// `align` bytes (sets the P bit). Useful for block ciphers in SRTP.
    #[must_use]
    pub fn pad_to(mut self, align: usize) -> Self {
        self.pad_to = align;
        self
    }

    /// Build the owned packet.
    ///
    /// # Errors
    /// Returns the [`extension::encode`] error for an extension that cannot be
    /// encoded (out-of-range element ID or length), and
    /// [`crate::Error::TooLarge`] for a payload type above 127, more than 15
    /// CSRCs, an extension block longer than 65 535 32-bit words, or a
    /// [`pad_to`](Self::pad_to) alignment above 256 bytes (the padding count
    /// is a single byte).
    pub fn build(mut self) -> Result<RtpPacketOwned> {
        ensure_at_most("padding alignment", self.pad_to, 256)?;
        if !self.extensions.is_empty() {
            let (profile, mut data) = extension::encode(&self.extensions)?;
            // Pad the extension block to a 32-bit word boundary.
            let pad = padding::pad_to(data.len(), 4);
            data.extend(std::iter::repeat_n(0u8, pad));
            self.header.extension = true;
            self.header.ext_profile = profile;
            self.header.ext_data = data;
        }

        let header_len = self.header.len_on_wire();
        let payload_off = header_len;
        let payload_end = payload_off + self.payload.len();

        // Decide padding before writing the header so the P bit is correct.
        let mut pad_count = 0usize;
        if self.pad_to > 1 {
            let total = payload_end;
            let need = padding::pad_to(total, self.pad_to);
            if need > 0 {
                // padding byte count includes its own length byte, so pad to
                // the next boundary that leaves room for the count byte.
                pad_count = need;
            }
        }
        self.header.padding = pad_count > 0;

        let mut bytes = Vec::with_capacity(payload_end + pad_count);
        self.header.write(&mut bytes)?;
        bytes.extend_from_slice(&self.payload);
        padding::append(&mut bytes, pad_count)?;

        Ok(RtpPacketOwned {
            bytes,
            header: self.header,
            payload_off,
            payload_end,
        })
    }
}
