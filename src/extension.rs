//! RFC 8285 header-extension codec plus a typed [`Extension`] enum.
//!
//! Two profiles are supported:
//!
//! * **One-byte** (`profile == 0xBEDE`): each element is `(id << 4) | (len-1)`
//!   followed by `len` data bytes. `id` is 1..=14, data length 1..=16.
//! * **Two-byte** (`profile & 0xFFF0 == 0x1000`): each element is an `id` byte,
//!   a length byte (0..=255), then that many data bytes.
//!
//! Element IDs are negotiated per session (in SDP via `a=extmap`), so the
//! low-level parser only ever yields opaque [`Extension::Generic`] elements
//! keyed by their numeric ID. The convenience constructors ([`Extension::mid`],
//! [`Extension::twcc`], [`Extension::abs_send_time`]) attach sensible default
//! IDs that callers should override with [`Extension::with_id`] to match their
//! negotiated mapping. Typed accessors ([`Extension::as_twcc`], etc.) reinterpret
//! a parsed element's bytes.

use crate::error::{Error, Result};

/// Profile identifier for the RFC 8285 one-byte extension form.
pub const PROFILE_ONE_BYTE: u16 = 0xBEDE;
/// High 12 bits identifying the RFC 8285 two-byte extension form (`0x100x`).
pub const PROFILE_TWO_BYTE: u16 = 0x1000;

/// Default element ID for the MID extension when none is negotiated.
pub const DEFAULT_ID_MID: u8 = 1;
/// Default element ID for the abs-send-time extension when none is negotiated.
pub const DEFAULT_ID_ABS_SEND_TIME: u8 = 2;
/// Default element ID for the transport-wide-CC extension when none is negotiated.
pub const DEFAULT_ID_TWCC: u8 = 3;

/// A single RFC 8285 header extension element.
///
/// The typed variants exist for ergonomic *building*. Parsing always produces
/// [`Extension::Generic`] because the semantic meaning of an element ID is only
/// known from the SDP negotiation, which this crate does not handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Extension {
    /// Media identification (`urn:ietf:params:rtp-hdrext:sdes:mid`).
    Mid {
        /// Negotiated element ID.
        id: u8,
        /// UTF-8 MID value bytes.
        value: Vec<u8>,
    },
    /// Transport-wide congestion-control sequence number
    /// (`draft-holmer-rmcat-transport-wide-cc-extensions`).
    Twcc {
        /// Negotiated element ID.
        id: u8,
        /// 16-bit transport-wide sequence number.
        seq: u16,
    },
    /// Absolute send time (`abs-send-time`), a 24-bit 6.18 fixed-point value.
    AbsSendTime {
        /// Negotiated element ID.
        id: u8,
        /// 24-bit value (only the low 24 bits are significant).
        value: u32,
    },
    /// Any other extension, stored opaquely.
    Generic {
        /// Element ID (1..=14 for one-byte, 1..=255 for two-byte).
        id: u8,
        /// Raw element data bytes.
        data: Vec<u8>,
    },
}

impl Extension {
    /// Build a MID extension with the default element ID.
    #[must_use]
    pub fn mid(value: impl AsRef<[u8]>) -> Self {
        Self::Mid {
            id: DEFAULT_ID_MID,
            value: value.as_ref().to_vec(),
        }
    }

    /// Build a transport-wide-CC extension with the default element ID.
    #[must_use]
    pub const fn twcc(seq: u16) -> Self {
        Self::Twcc {
            id: DEFAULT_ID_TWCC,
            seq,
        }
    }

    /// Build an abs-send-time extension with the default element ID.
    ///
    /// Only the low 24 bits of `value` are used.
    #[must_use]
    pub const fn abs_send_time(value: u32) -> Self {
        Self::AbsSendTime {
            id: DEFAULT_ID_ABS_SEND_TIME,
            value: value & 0x00FF_FFFF,
        }
    }

    /// Build an opaque generic extension.
    #[must_use]
    pub fn generic(id: u8, data: impl AsRef<[u8]>) -> Self {
        Self::Generic {
            id,
            data: data.as_ref().to_vec(),
        }
    }

    /// Return a copy of this extension with its element ID replaced.
    #[must_use]
    pub fn with_id(self, id: u8) -> Self {
        match self {
            Self::Mid { value, .. } => Self::Mid { id, value },
            Self::Twcc { seq, .. } => Self::Twcc { id, seq },
            Self::AbsSendTime { value, .. } => Self::AbsSendTime { id, value },
            Self::Generic { data, .. } => Self::Generic { id, data },
        }
    }

    /// The negotiated element ID of this extension.
    #[must_use]
    pub const fn id(&self) -> u8 {
        match self {
            Self::Mid { id, .. }
            | Self::Twcc { id, .. }
            | Self::AbsSendTime { id, .. }
            | Self::Generic { id, .. } => *id,
        }
    }

    /// The on-the-wire data bytes of this extension (without ID/length framing).
    #[must_use]
    pub fn data(&self) -> Vec<u8> {
        match self {
            Self::Mid { value, .. } => value.clone(),
            Self::Twcc { seq, .. } => seq.to_be_bytes().to_vec(),
            Self::AbsSendTime { value, .. } => {
                let b = value.to_be_bytes();
                vec![b[1], b[2], b[3]]
            }
            Self::Generic { data, .. } => data.clone(),
        }
    }

    /// Interpret this extension's bytes as a MID string slice.
    #[must_use]
    pub fn as_mid(&self) -> Option<Vec<u8>> {
        match self {
            Self::Mid { value, .. } => Some(value.clone()),
            Self::Generic { data, .. } => Some(data.clone()),
            _ => None,
        }
    }

    /// Interpret this extension's bytes as a 16-bit transport-wide sequence number.
    #[must_use]
    pub fn as_twcc(&self) -> Option<u16> {
        match self {
            Self::Twcc { seq, .. } => Some(*seq),
            Self::Generic { data, .. } if data.len() >= 2 => {
                Some(u16::from_be_bytes([data[0], data[1]]))
            }
            _ => None,
        }
    }

    /// Interpret this extension's bytes as a 24-bit abs-send-time value.
    #[must_use]
    pub fn as_abs_send_time(&self) -> Option<u32> {
        match self {
            Self::AbsSendTime { value, .. } => Some(*value),
            Self::Generic { data, .. } if data.len() >= 3 => {
                Some(u32::from_be_bytes([0, data[0], data[1], data[2]]))
            }
            _ => None,
        }
    }
}

/// Does this set of extensions require the two-byte profile?
///
/// The one-byte form cannot encode an element with ID > 14, zero-length data,
/// or data longer than 16 bytes.
fn needs_two_byte(exts: &[Extension]) -> bool {
    exts.iter().any(|e| {
        let len = e.data().len();
        e.id() == 0 || e.id() > 14 || len == 0 || len > 16
    })
}

/// Encode a set of extensions into a `(profile, data)` pair.
///
/// The returned `data` is the inner extension block **without** the 4-byte
/// `profile + length` header (that is written by [`crate::header`]). It is *not*
/// padded to a 32-bit boundary here; the header codec handles word alignment.
///
/// Returns an error if an element ID is out of range for the chosen profile.
///
/// # Errors
/// Returns [`Error::BadExtension`] if an element cannot be encoded under the
/// selected RFC 8285 profile (e.g. an ID or length out of range).
pub fn encode(exts: &[Extension]) -> Result<(u16, Vec<u8>)> {
    if needs_two_byte(exts) {
        encode_two_byte(exts).map(|d| (PROFILE_TWO_BYTE, d))
    } else {
        encode_one_byte(exts).map(|d| (PROFILE_ONE_BYTE, d))
    }
}

fn encode_one_byte(exts: &[Extension]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for e in exts {
        let id = e.id();
        let data = e.data();
        if !(1..=14).contains(&id) {
            return Err(Error::BadExtension("one-byte element ID out of range 1..=14"));
        }
        if data.is_empty() || data.len() > 16 {
            return Err(Error::BadExtension("one-byte data length out of range 1..=16"));
        }
        // len field is encoded as (actual_len - 1)
        out.push((id << 4) | ((data.len() as u8) - 1));
        out.extend_from_slice(&data);
    }
    Ok(out)
}

fn encode_two_byte(exts: &[Extension]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for e in exts {
        let id = e.id();
        let data = e.data();
        if id == 0 {
            return Err(Error::BadExtension("two-byte element ID must be 1..=255"));
        }
        if data.len() > 255 {
            return Err(Error::BadExtension("two-byte data length exceeds 255"));
        }
        out.push(id);
        out.push(data.len() as u8);
        out.extend_from_slice(&data);
    }
    Ok(out)
}

/// Decode an extension block given its profile and inner data bytes.
///
/// Trailing padding (`0x00`) bytes are skipped. Unknown profiles yield a
/// [`Error::BadExtension`]; callers that need lossless storage should keep the
/// raw bytes from the header instead.
///
/// # Errors
/// Returns [`Error::BadExtension`] for an unknown profile or a malformed
/// element within the block.
pub fn decode(profile: u16, data: &[u8]) -> Result<Vec<Extension>> {
    if profile == PROFILE_ONE_BYTE {
        decode_one_byte(data)
    } else if profile & 0xFFF0 == PROFILE_TWO_BYTE {
        decode_two_byte(data)
    } else {
        Err(Error::BadExtension("unknown RFC 8285 profile"))
    }
}

fn decode_one_byte(data: &[u8]) -> Result<Vec<Extension>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        if b == 0 {
            // padding
            i += 1;
            continue;
        }
        let id = b >> 4;
        let len = ((b & 0x0F) as usize) + 1;
        if id == 15 {
            // reserved: signals "stop processing"
            break;
        }
        i += 1;
        if i + len > data.len() {
            return Err(Error::BadExtension("one-byte element overruns block"));
        }
        out.push(Extension::Generic {
            id,
            data: data[i..i + len].to_vec(),
        });
        i += len;
    }
    Ok(out)
}

fn decode_two_byte(data: &[u8]) -> Result<Vec<Extension>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let id = data[i];
        if id == 0 {
            // padding
            i += 1;
            continue;
        }
        if i + 1 >= data.len() {
            return Err(Error::BadExtension("two-byte element missing length"));
        }
        let len = data[i + 1] as usize;
        i += 2;
        if i + len > data.len() {
            return Err(Error::BadExtension("two-byte element overruns block"));
        }
        out.push(Extension::Generic {
            id,
            data: data[i..i + len].to_vec(),
        });
        i += len;
    }
    Ok(out)
}
