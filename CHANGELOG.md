# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Security

- H.264 FU-A reassembly is bounded (`h264::DEFAULT_MAX_NAL_SIZE`, 8 MiB,
  configurable with `Depacketizer::with_max_nal_size`) and requires fragments
  with consecutive RTP sequence numbers and the same NAL type. A peer that
  never sets the End bit can no longer grow memory without bound, and a lost
  middle fragment no longer splices two NAL units.
- TWCC feedback announcing more than `rtcp::twcc::MAX_STATUSES` (32 768)
  statuses is rejected; a 40-byte packet previously expanded to 65 535.

### Fixed

- Compound RTCP parsing skips packet types this crate does not model (XR,
  TMMBR, application-layer feedback other than REMB, unknown RTPFB/PSFB
  formats) instead of failing the whole datagram and losing its SR/RR.
- The RTCP padding bit is honoured: padding is no longer decoded as NACK, FIR
  or SLI entries or APP data, and a zero or oversized padding count is
  rejected.
- REMB bitrates whose `mantissa << exp` overflows 64 bits are rejected instead
  of silently truncated.
- The jitter estimator wraps the transit difference to 32 bits as RFC 3550
  A.8 does; jitter no longer spikes when transit crosses ±2³¹.
- `SourceState::fraction_lost` saturates at 255; 100 % loss was reported as 0.
- `SourceState` counters wrap instead of panicking in debug builds after 2³²
  packets.
- `ReceptionStats::to_report_block` clamps the cumulative loss to 0x7FFFFF as
  RFC 3550 A.3 requires; masking it to 24 bits reported more than 2²³ lost
  packets as a negative count.
- `Nack::from_lost` packs losses across the 65535 → 0 wrap into shared
  PID/BLP entries.
- `RtpPacketBuilder::build` no longer panics on an invalid extension or a
  `pad_to` alignment above 256.

### Changed

- **Breaking:** `h264::Depacketizer::push` takes the RTP sequence number:
  `push(sequence_number, payload)`. Any non-FU-A packet discards an
  unfinished FU-A.
- **Breaking:** `RtpPacketBuilder::build` returns `Result<RtpPacketOwned>`.
  It fails for an extension that cannot be encoded, more than 15 CSRCs
  (`csrc` no longer drops them silently), an extension block over 65 535
  words, or a `pad_to` alignment above 256.
- **Breaking:** `RtpHeader::write`, `RtcpPacket::encode`,
  `CompoundPacket::encode` and every per-type RTCP `encode` return `Result`
  and fail with `Error::TooLarge` instead of truncating: more than 31 report
  blocks, SDES chunks or BYE sources, SDES items or BYE reasons over 255 bytes,
  more than 255 REMB SSRCs or `rtcp::twcc::MAX_STATUSES` TWCC statuses (the
  same limit parsing applies), an APP subtype above 31, or a packet longer
  than the 16-bit length field. An SDES item of type 0 is rejected with
  `Error::BadPayload`.
- **Breaking:** out-of-range values are rejected instead of silently masked.
  `RtpHeader::set_payload_type` returns `Result`, and `RtpHeader::write` and
  `RtpPacketBuilder::build` (whose `payload_type` no longer masks) fail for a
  payload type above 127. `Sli::encode` fails for a `first` or `number` above
  8191 or a `picture_id` above 63. RR and SR `encode` fail for a
  `cumulative_lost` wider than 24 bits.
- **Breaking:** the `Packet` trait is sealed; only `RtpPacket` and
  `RtpPacketOwned` implement it. Consumers such as SRTP derive the IV from
  `header()` while encrypting `as_bytes()`, so a foreign implementation whose
  header disagreed with its bytes could reuse a keystream.
- `CompoundPacket::parse` checks that the first packet on the wire is an SR
  or RR, since unknown packets are now skipped.
- `rust-version` is 1.82.

### Added

- `Error::TooLarge { what, max, actual }`.
- `h264::DEFAULT_MAX_NAL_SIZE` and `h264::Depacketizer::with_max_nal_size`.
- `rtcp::twcc::MAX_STATUSES`.
- Regression tests for malformed and oversize input.

## [0.1.0] - 2026-06-04

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

[0.2.0]: https://github.com/doom-fish/rtp-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/doom-fish/rtp-rs/releases/tag/v0.1.0
