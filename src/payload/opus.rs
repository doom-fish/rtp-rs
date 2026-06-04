//! Opus RTP payload format (RFC 7587).
//!
//! The RTP payload is the Opus packet verbatim — there is no additional RTP
//! framing. This module therefore provides a thin inspector over the Opus
//! **TOC** (table of contents) byte (RFC 6716 §3.1) rather than a packetizer:
//! callers place an encoded Opus packet directly into the RTP payload.

use crate::error::{Error, Result};

/// Audio bandwidth signalled by the Opus TOC `config` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bandwidth {
    /// Narrowband (4 kHz).
    Narrow,
    /// Mediumband (6 kHz).
    Medium,
    /// Wideband (8 kHz).
    Wide,
    /// Super-wideband (12 kHz).
    SuperWide,
    /// Fullband (20 kHz).
    Full,
}

/// The coding mode signalled by the Opus TOC `config` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// SILK-only (speech).
    Silk,
    /// Hybrid (speech + music).
    Hybrid,
    /// CELT-only (music / low latency).
    Celt,
}

/// A borrowed view over an Opus packet placed in an RTP payload.
#[derive(Clone, Copy, Debug)]
pub struct OpusPacket<'a> {
    bytes: &'a [u8],
}

impl<'a> OpusPacket<'a> {
    /// Wrap an Opus packet (the verbatim RTP payload).
    ///
    /// # Errors
    /// Returns [`Error::BadPayload`] if the packet is empty.
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::BadPayload("empty Opus packet"));
        }
        Ok(Self { bytes })
    }

    /// The raw Opus packet bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The TOC byte.
    #[must_use]
    pub fn toc(&self) -> u8 {
        self.bytes[0]
    }

    /// The 5-bit `config` field (0..=31).
    #[must_use]
    pub fn config(&self) -> u8 {
        self.bytes[0] >> 3
    }

    /// Whether the stereo (`s`) flag is set.
    #[must_use]
    pub fn is_stereo(&self) -> bool {
        self.bytes[0] & 0x04 != 0
    }

    /// The 2-bit frame-count code (`c`).
    #[must_use]
    pub fn frame_count_code(&self) -> u8 {
        self.bytes[0] & 0x03
    }

    /// The number of Opus frames in the packet.
    ///
    /// For code 3 (arbitrary) the count is read from the frame-count byte.
    #[must_use]
    pub fn frame_count(&self) -> u8 {
        match self.frame_count_code() {
            0 => 1,
            1 | 2 => 2,
            _ => self.bytes.get(1).map_or(0, |b| b & 0x3F),
        }
    }

    /// The coding mode implied by `config`.
    #[must_use]
    pub fn mode(&self) -> Mode {
        match self.config() {
            0..=11 => Mode::Silk,
            12..=15 => Mode::Hybrid,
            _ => Mode::Celt,
        }
    }

    /// The audio bandwidth implied by `config`.
    #[must_use]
    pub fn bandwidth(&self) -> Bandwidth {
        match self.config() {
            0..=3 => Bandwidth::Narrow,
            4..=7 => Bandwidth::Medium,
            8..=11 => Bandwidth::Wide,
            12 | 13 => Bandwidth::SuperWide,
            14 | 15 => Bandwidth::Full,
            16..=19 => Bandwidth::Narrow,
            20..=23 => Bandwidth::Wide,
            24..=27 => Bandwidth::SuperWide,
            _ => Bandwidth::Full,
        }
    }

    /// The duration of a single frame in microseconds, per the `config` table.
    #[must_use]
    pub fn frame_duration_us(&self) -> u32 {
        match self.config() {
            // SILK frame sizes: 10, 20, 40, 60 ms across each bandwidth group.
            0 | 4 | 8 => 10_000,
            1 | 5 | 9 => 20_000,
            2 | 6 | 10 => 40_000,
            3 | 7 | 11 => 60_000,
            // Hybrid: 10 or 20 ms.
            12 | 14 => 10_000,
            13 | 15 => 20_000,
            // CELT: 2.5, 5, 10, 20 ms.
            16 | 20 | 24 | 28 => 2_500,
            17 | 21 | 25 | 29 => 5_000,
            18 | 22 | 26 | 30 => 10_000,
            _ => 20_000,
        }
    }
}
