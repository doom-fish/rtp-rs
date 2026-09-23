# rtp-rs

A pure-Rust, **zero-dependency** RTP/RTCP codec (RFC 3550) with RFC 8285 header
extensions, the RTCP feedback messages used by WebRTC peers and SFUs, and
packetizers for the H.264 and Opus payload formats.

`rtp-rs` is the shared wire layer that the sibling `srtp-rs` and `rtc-rs`
crates build on. It does all of its work over plain byte slices: there is no
`bytes`, `byteorder`, `nom` or any other dependency — just `std` and integer
`from_be_bytes` / `to_be_bytes`.

The crate is not published to crates.io (`publish = false`); depend on it by
path from a sibling checkout:

```toml
[dependencies]
rtp = { package = "rtp-rs", path = "../rtp-rs", version = "0.1" }
```

## Features

| Area | Coverage |
|------|----------|
| **RTP header** (RFC 3550 §5) | parse/build, CSRC list, padding, RFC 8285 extensions |
| **Header extensions** (RFC 8285) | one-byte (`0xBEDE`) and two-byte (`0x100x`) profiles; MID, abs-send-time, transport-wide-CC and generic elements |
| **RTCP** (RFC 3550 §6) | SR, RR, SDES, BYE, APP, compound packets with validation |
| **RTCP feedback** (RFC 4585 / 5104) | NACK, PLI, SLI, FIR, REMB, transport-wide congestion control (TWCC) |
| **H.264 payload** (RFC 6184) | Single NAL, STAP-A, FU-A (packetization mode 1); SPS/PPS injection |
| **Opus payload** (RFC 7587) | verbatim payload with TOC inspection (mode, bandwidth, frame count, duration) |
| **Statistics** | RFC 3550 A.1 sequence validation, A.8 jitter estimator, reception-report blocks |

## Quick start

Build a packet:

```rust
use rtp::{Extension, Packet, RtpPacket};

let bytes = RtpPacket::builder()
    .payload_type(96)
    .sequence_number(1000)
    .timestamp(0xDEAD_BEEF)
    .ssrc(0x1234_5678)
    .extension(Extension::mid("0"))
    .extension(Extension::twcc(42))
    .payload([0x67, 0x42, 0x00, 0x1f])
    .build()?
    .into_bytes();

let pkt = RtpPacket::parse(&bytes).unwrap();
assert_eq!(pkt.header().payload_type(), 96);
assert_eq!(pkt.payload(), &[0x67, 0x42, 0x00, 0x1f]);
```

Packetize H.264:

```rust
use rtp::h264::{Depacketizer, Packetizer};

let packetizer = Packetizer::new(1200);     // payload MTU in bytes
let payloads = packetizer.packetize(&nal);  // Single NAL or FU-A fragments

let mut depacketizer = Depacketizer::new();
for (seq, p) in (first_seq..).zip(&payloads) {
    if let Some(nal) = depacketizer.push(seq, p)? {
        // complete NAL unit reassembled
    }
}
```

RTCP compound packet:

```rust
use rtp::{CompoundPacket, RtcpPacket};

let rr = RtcpPacket::receiver_report().ssrc(0xFEED_FACE).build();
let nack = RtcpPacket::nack(media_ssrc, &[17, 18, 20]);
let pli = RtcpPacket::pli(media_ssrc);

let compound = CompoundPacket::new()
    .add(rr)
    .add(nack.into())
    .add(pli.into());
let bytes = compound.encode()?;
```

`CompoundPacket::parse` skips RTCP packet types it does not model (XR, TMMBR,
non-REMB application feedback) instead of rejecting the datagram, and honours
the RTCP padding bit.

## Limits on untrusted input

- FU-A reassembly stops at `h264::DEFAULT_MAX_NAL_SIZE` (8 MiB, configurable
  with `Depacketizer::with_max_nal_size`) and requires consecutive RTP
  sequence numbers; a gap discards the partial NAL unit.
- TWCC feedback announcing more than `rtcp::twcc::MAX_STATUSES` (32 768)
  statuses is rejected.
- Encoders return `Error::TooLarge` for any count or length that does not fit
  its wire field; nothing is silently truncated.

## The borrowing contract

Because `srtp-rs` authenticates and decrypts in place, [`packet`] defines a
careful contract: `RtpPacket::as_bytes()` always returns the *exact original
wire bytes* so that an SRTP authentication tag computed over them stays valid,
and `payload_offset()` is stable so the encrypt/decrypt range is unambiguous.
`RtpPacketMut` keeps a single `&mut [u8]` backing buffer for in-place
decryption and `freeze()`s into an immutable `RtpPacket` once the payload is in
the clear. Never re-serialize a header you intend to authenticate.

## Examples

```sh
cargo run --example 01_parse_packet
cargo run --example 02_build_packet
cargo run --example 03_h264_packetize
cargo run --example 04_rtcp_compound
```

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
