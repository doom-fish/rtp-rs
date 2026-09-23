//! Source Description (PT 202).

use super::{be_u32, write_header, Header, PT_SDES};
use crate::error::{Error, Result};

/// SDES item type: canonical end-point identifier (CNAME).
pub const ITEM_CNAME: u8 = 1;
/// SDES item type: user name (NAME).
pub const ITEM_NAME: u8 = 2;
/// SDES item type: email address (EMAIL).
pub const ITEM_EMAIL: u8 = 3;
/// SDES item type: phone number (PHONE).
pub const ITEM_PHONE: u8 = 4;
/// SDES item type: geographic location (LOC).
pub const ITEM_LOC: u8 = 5;
/// SDES item type: application/tool name (TOOL).
pub const ITEM_TOOL: u8 = 6;
/// SDES item type: notice/status (NOTE).
pub const ITEM_NOTE: u8 = 7;
/// SDES item type: private extension (PRIV).
pub const ITEM_PRIV: u8 = 8;

/// A single SDES item (type + text).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdesItem {
    /// Item type (e.g. [`ITEM_CNAME`]).
    pub item_type: u8,
    /// Item text bytes (max 255).
    pub text: Vec<u8>,
}

impl SdesItem {
    /// Convenience constructor for a CNAME item.
    #[must_use]
    pub fn cname(text: impl AsRef<[u8]>) -> Self {
        Self {
            item_type: ITEM_CNAME,
            text: text.as_ref().to_vec(),
        }
    }
}

/// An SDES chunk: one source identifier and its items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SdesChunk {
    /// SSRC/CSRC this chunk describes.
    pub source: u32,
    /// Items in this chunk.
    pub items: Vec<SdesItem>,
}

/// A Source Description packet.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Sdes {
    /// Chunks (one per source, 0..=31).
    pub chunks: Vec<SdesChunk>,
}

impl Sdes {
    /// Serialize this packet (with header).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let count = self.chunks.len().min(31) as u8;
        let mut body = Vec::new();
        for chunk in self.chunks.iter().take(31) {
            let start = body.len();
            body.extend_from_slice(&chunk.source.to_be_bytes());
            for item in &chunk.items {
                body.push(item.item_type);
                let len = item.text.len().min(255) as u8;
                body.push(len);
                body.extend_from_slice(&item.text[..len as usize]);
            }
            // Terminating END (0) item, then pad chunk to a 32-bit boundary.
            body.push(0);
            let chunk_len = body.len() - start;
            let pad = (4 - chunk_len % 4) % 4;
            body.extend(std::iter::repeat(0u8).take(pad));
        }
        let mut out = Vec::with_capacity(4 + body.len());
        write_header(&mut out, count, PT_SDES, body.len());
        out.extend_from_slice(&body);
        out
    }

    /// Parse a Source Description packet from its bytes.
    ///
    /// # Errors
    /// Returns [`Error::Truncated`] or [`Error::BadCompound`] on malformed input.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        let h = Header::parse(buf)?;
        let mut chunks = Vec::with_capacity(h.count as usize);
        let mut off = 4;
        for _ in 0..h.count {
            if off + 4 > h.content_len {
                return Err(Error::Truncated {
                    needed: off + 4,
                    got: h.content_len,
                });
            }
            let source = be_u32(buf, off);
            let chunk_start = off;
            off += 4;
            let mut items = Vec::new();
            loop {
                if off >= h.content_len {
                    return Err(Error::BadCompound("SDES chunk missing terminator"));
                }
                let item_type = buf[off];
                if item_type == 0 {
                    off += 1;
                    break;
                }
                if off + 1 >= h.content_len {
                    return Err(Error::Truncated {
                        needed: off + 2,
                        got: h.content_len,
                    });
                }
                let len = buf[off + 1] as usize;
                off += 2;
                if off + len > h.content_len {
                    return Err(Error::Truncated {
                        needed: off + len,
                        got: h.content_len,
                    });
                }
                items.push(SdesItem {
                    item_type,
                    text: buf[off..off + len].to_vec(),
                });
                off += len;
            }
            // Skip padding to the next 32-bit boundary relative to chunk start.
            let consumed = off - chunk_start;
            let pad = (4 - consumed % 4) % 4;
            off += pad;
            chunks.push(SdesChunk { source, items });
        }
        Ok(Self { chunks })
    }
}
