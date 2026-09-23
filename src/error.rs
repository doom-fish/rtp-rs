//! Error type shared by every codec in this crate.

use core::fmt;

/// Result alias used throughout `rtp`.
pub type Result<T> = core::result::Result<T, Error>;

/// All the ways parsing or building an RTP/RTCP structure can fail.
///
/// The variants are intentionally coarse: this crate is a wire codec, so the
/// caller usually only needs to know *that* a buffer was malformed, not the
/// exact byte offset. Where an offset would help debugging it is included in
/// the variant payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The buffer was shorter than the minimum required for this structure.
    ///
    /// `needed` is the number of bytes the parser wanted, `got` is what was
    /// actually available.
    Truncated {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        got: usize,
    },
    /// A protocol version field did not hold the expected value (RTP/RTCP
    /// version 2).
    BadVersion(u8),
    /// A length field disagreed with the actual buffer length.
    BadLength {
        /// What the length field claimed.
        declared: usize,
        /// What the buffer actually held.
        actual: usize,
    },
    /// The padding length byte was zero or larger than the buffer.
    BadPadding(usize),
    /// An RTCP compound packet violated a structural rule (e.g. the first
    /// packet was not an SR or RR).
    BadCompound(&'static str),
    /// An unknown or unsupported packet/payload type was encountered where a
    /// known one was required.
    Unsupported(&'static str),
    /// A header-extension profile or element was malformed (RFC 8285).
    BadExtension(&'static str),
    /// A payload-format specific error (H.264 / Opus).
    BadPayload(&'static str),
    #[allow(missing_docs)]
    TooLarge {
        what: &'static str,
        max: usize,
        actual: usize,
    },
}

pub(crate) const fn ensure_at_most(what: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        Err(Error::TooLarge { what, max, actual })
    } else {
        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, got } => {
                write!(f, "buffer truncated: needed {needed} bytes, got {got}")
            }
            Self::BadVersion(v) => write!(f, "unexpected protocol version {v} (want 2)"),
            Self::BadLength { declared, actual } => {
                write!(f, "length mismatch: declared {declared}, actual {actual}")
            }
            Self::BadPadding(p) => write!(f, "invalid padding length {p}"),
            Self::BadCompound(why) => write!(f, "invalid RTCP compound packet: {why}"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
            Self::BadExtension(why) => write!(f, "invalid header extension: {why}"),
            Self::BadPayload(why) => write!(f, "invalid payload: {why}"),
            Self::TooLarge { what, max, actual } => {
                write!(f, "{what} is {actual}, the limit is {max}")
            }
        }
    }
}

impl std::error::Error for Error {}
