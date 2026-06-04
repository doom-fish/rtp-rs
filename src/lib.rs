//! `rtp` — a pure-Rust, zero-dependency RTP/RTCP codec (RFC 3550).
//!
//! This crate implements the on-the-wire formats used by real-time media
//! transports: the RTP packet header (RFC 3550 §5), RFC 8285 header
//! extensions, the RTCP control packets (SR/RR/SDES/BYE/APP) and the feedback
//! messages used by WebRTC peers and SFUs (NACK, PLI, SLI, FIR, REMB and
//! transport-wide congestion control). It also provides packetizers for the
//! H.264 (RFC 6184) and Opus (RFC 7587) payload formats, plus the
//! sequence-number, jitter and reception-statistics bookkeeping from
//! RFC 3550's appendices.
//!
//! The crate has **no dependencies** and does all of its work over plain byte
//! slices. It is the shared wire layer that the sibling `srtp` and `rtc`
//! crates build on, so [`packet`] defines a careful borrowing contract:
//! [`RtpPacket::as_bytes`] always returns the exact original wire bytes so
//! that an SRTP authentication tag computed over them stays valid.
//!
//! # Example
//!
//! ```
//! use rtp::{Extension, Packet, RtpPacket};
//!
//! // Build a packet.
//! let bytes = RtpPacket::builder()
//!     .payload_type(96)
//!     .sequence_number(1000)
//!     .timestamp(0xDEAD_BEEF)
//!     .ssrc(0x1234_5678)
//!     .extension(Extension::mid("0"))
//!     .payload([0x67, 0x42, 0x00, 0x1f])
//!     .build()
//!     .into_bytes();
//!
//! // Parse it back.
//! let pkt = RtpPacket::parse(&bytes).unwrap();
//! assert_eq!(pkt.header().payload_type(), 96);
//! assert_eq!(pkt.header().sequence_number(), 1000);
//! assert_eq!(pkt.payload(), &[0x67, 0x42, 0x00, 0x1f]);
//! ```
#![warn(missing_docs)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::missing_const_for_fn,
    clippy::match_same_arms,
    clippy::struct_field_names,
    clippy::should_implement_trait,
    clippy::module_name_repetitions
)]

pub mod error;
pub mod extension;
pub mod header;
pub mod jitter;
pub mod packet;
pub mod padding;
pub mod payload;
pub mod rtcp;
pub mod seq;
pub mod stats;

pub use error::{Error, Result};
pub use extension::Extension;
pub use header::RtpHeader;
pub use jitter::Jitter;
pub use packet::{Packet, RtpPacket, RtpPacketBuilder, RtpPacketMut, RtpPacketOwned};
pub use rtcp::{compound::CompoundPacket, RtcpPacket};
pub use stats::ReceptionStats;

pub use payload::{h264, opus};
