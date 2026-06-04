//! RTP payload formats.
//!
//! Each media format lives in its own submodule with a packetizer (media → RTP
//! payloads) and depacketizer (RTP payloads → media). A trivial pass-through
//! [`RawPayload`] is provided for testing and for formats that need no framing.

pub mod h264;
pub mod opus;

/// A pass-through payload: the RTP payload bytes are the media bytes verbatim.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RawPayload(pub Vec<u8>);

impl RawPayload {
    /// Wrap media bytes.
    #[must_use]
    pub fn new(bytes: impl AsRef<[u8]>) -> Self {
        Self(bytes.as_ref().to_vec())
    }

    /// The media bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the owned bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for RawPayload {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
