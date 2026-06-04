# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-06-04

Initial release.

### Added

- **RTP header codec** (RFC 3550 §5): zero-copy parse and a fluent builder,
  CSRC lists, padding, and the marker / payload-type / sequence / timestamp /
  SSRC fields.
- **RFC 8285 header extensions**: one-byte (`0xBEDE`) and two-byte (`0x100x`)
  profiles, with typed MID, abs-send-time, transport-wide-CC and generic
  elements; the profile is selected automatically based on element sizes.
- **Borrowing contract** (`packet` module): `RtpPacket` (immutable view),
  `RtpPacketMut` (in-place SRTP decryption), `RtpPacketOwned` (jitter-buffer
  storage) and `RtpPacketBuilder`, all sharing the `Packet` trait. `as_bytes()`
  returns the exact wire bytes and `payload_offset()` is stable, so SRTP
  authentication tags stay valid.
- **RTCP** (RFC 3550 §6): Sender Report, Receiver Report, SDES, BYE, APP and
  compound-packet parsing/validation.
- **RTCP feedback** (RFC 4585 / 5104): generic NACK, PLI, SLI, FIR, REMB and
  transport-wide congestion control (TWCC) with run-length and status-vector
  chunk decoding.
- **H.264 payload** (RFC 6184, packetization mode 1): Single NAL, STAP-A and
  FU-A packetization and depacketization, NAL-type helpers, and SPS/PPS
  injection ahead of IDR frames.
- **Opus payload** (RFC 7587): verbatim payload handling plus TOC inspection
  (coding mode, audio bandwidth, frame count, per-frame duration).
- **Statistics**: RFC 3550 A.1 sequence-number validation with cycle-aware
  extended sequence numbers, the A.8 interarrival-jitter estimator, and
  reception-report block construction.
- Four runnable examples and an integration test suite covering header,
  extension, RTCP, H.264, Opus, sequence-wrap and jitter round-trips.

### Notes

- Zero runtime dependencies; pure `std` + integer byte conversions.
- Deferred to a later release: H.264 STAP-B / MTAP / FU-B and packetization
  mode 0; the APP packet carries an opaque body only.

[0.1.0]: https://github.com/doom-fish/rtp-rs/releases/tag/v0.1.0
