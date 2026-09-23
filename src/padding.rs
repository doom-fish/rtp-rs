//! RTP padding helpers (RFC 3550 §5.1).
//!
//! When the padding (P) bit is set, the **last** byte of the packet holds the
//! total number of padding bytes, *including itself*. Those bytes sit after the
//! payload and must be stripped before the payload is consumed.

use crate::error::{Error, Result};

/// Strip RFC 3550 padding from a buffer whose P bit is set.
///
/// `buf` is the region from the end of the header onwards (payload + padding).
/// Returns the payload slice with the trailing padding removed.
///
/// # Errors
/// Returns [`Error::BadPadding`] if the trailing length byte is zero or larger
/// than the buffer.
pub fn strip(buf: &[u8]) -> Result<&[u8]> {
    let Some(&pad_len) = buf.last() else {
        return Err(Error::BadPadding(0));
    };
    let pad_len = pad_len as usize;
    if pad_len == 0 || pad_len > buf.len() {
        return Err(Error::BadPadding(pad_len));
    }
    Ok(&buf[..buf.len() - pad_len])
}

/// Append `count` padding bytes (count includes the trailing length byte).
///
/// The intermediate bytes are zeroed and the final byte is set to `count`,
/// matching RFC 3550. A `count` of 0 is a no-op.
///
/// # Errors
/// Returns [`Error::BadPadding`] if `count` exceeds 255 (the field is one byte).
pub fn append(buf: &mut Vec<u8>, count: usize) -> Result<()> {
    if count == 0 {
        return Ok(());
    }
    if count > 255 {
        return Err(Error::BadPadding(count));
    }
    buf.extend(std::iter::repeat_n(0u8, count - 1));
    buf.push(count as u8);
    Ok(())
}

/// Compute the number of padding bytes needed to round `len` up to a multiple
/// of `align`. Returns 0 when already aligned. `align` of 0 or 1 yields 0.
#[must_use]
pub fn pad_to(len: usize, align: usize) -> usize {
    if align <= 1 {
        return 0;
    }
    let rem = len % align;
    if rem == 0 {
        0
    } else {
        align - rem
    }
}
