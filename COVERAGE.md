# Coverage

This crate implements the RTP/RTCP wire formats by hand against the relevant
RFCs. The tables below record what is covered, what is intentionally deferred,
and the honest gaps.

## RFC coverage

| RFC | Title | Status |
|-----|-------|--------|
| 3550 | RTP / RTCP | header, SR, RR, SDES, BYE, APP, compound, A.1 sequence, A.8 jitter |
| 3551 | A/V profile | payload-type numbering only (no static-PT tables baked in) |
| 8285 | Header extensions | one-byte and two-byte profiles, full |
| 4585 | RTP/AVPF feedback | NACK, PLI, SLI |
| 5104 | Codec control (AVPF) | FIR |
| 6184 | H.264 payload | Single NAL, STAP-A, FU-A (mode 1) |
| 7587 | Opus payload | verbatim payload + TOC inspection |
| —    | REMB draft | receiver-estimated max bitrate |
| —    | TWCC (transport-cc) | transport-wide congestion control |

## RTCP packet types

| Type | PT / FMT | Encode | Parse |
|------|----------|--------|-------|
| Sender Report | 200 | ✅ | ✅ |
| Receiver Report | 201 | ✅ | ✅ |
| SDES | 202 | ✅ | ✅ |
| BYE | 203 | ✅ | ✅ |
| APP | 204 | ✅ (opaque body) | ✅ |
| Generic NACK | 205 / 1 | ✅ | ✅ |
| TWCC | 205 / 15 | ✅ | ✅ |
| PLI | 206 / 1 | ✅ | ✅ |
| SLI | 206 / 2 | ✅ | ✅ |
| FIR | 206 / 4 | ✅ | ✅ |
| REMB | 206 / 15 | ✅ | ✅ |

## H.264 (RFC 6184)

| Unit | Packetize | Depacketize |
|------|-----------|-------------|
| Single NAL (1–23) | ✅ | ✅ |
| STAP-A (24) | ✅ | ✅ |
| FU-A (28) | ✅ | ✅ |
| STAP-B (25) | ❌ deferred | ❌ |
| MTAP16/24 (26/27) | ❌ deferred | ❌ |
| FU-B (29) | ❌ deferred | ❌ |

Packetization mode 1 only; interleaved mode (2) is out of scope.

## Deferred / known gaps

- **H.264**: STAP-B, MTAP16, MTAP24, FU-B and packetization mode 0/2.
- **RTCP APP**: the application-defined body is carried as opaque bytes; no
  per-application schema is interpreted.
- **RTCP XR** (RFC 3611) and reduced-size RTCP (RFC 5506) are not implemented.
  Packet types this crate does not model (XR, TMMBR/TMMBN, application-layer
  feedback other than REMB, unknown RTPFB/PSFB formats) are skipped when a
  compound packet is parsed. `CompoundPacket::parse_lenient` exists so callers
  can inspect reduced-size streams; `CompoundPacket::parse` still requires the
  first packet on the wire to be an SR or RR.
- **SDES**: CNAME and the standard item types are encoded/parsed; PRIV items
  are carried but not specially interpreted.

## Limits on untrusted input

| Input | Limit |
|-------|-------|
| FU-A reassembly | `h264::DEFAULT_MAX_NAL_SIZE` (8 MiB), configurable; fragments must have consecutive sequence numbers and the same NAL type |
| TWCC status count | `rtcp::twcc::MAX_STATUSES` (32 768) |
| REMB bitrate | rejected when `mantissa << exp` overflows 64 bits |
| RTCP padding | honoured; a zero or oversized padding count is rejected |
| Encoders | counts and lengths that do not fit their wire field return `Error::TooLarge` |

## Validation

- 68 integration tests plus a crate doctest cover header, extension, RTCP
  (SR/RR/NACK/PLI/FIR/SLI/REMB/TWCC), H.264 packetize/depacketize, Opus TOC,
  sequence-number wrap and jitter round-trips, and malformed input: unknown
  and padded RTCP packets, TWCC expansion, REMB overflow, unterminated or
  interrupted FU-A sequences, and oversize encoder input.
- `cargo clippy --all-targets --all-features -- -D warnings` is clean with
  `pedantic` and `nursery` lint groups enabled (intentional wire-codec casts are allowed
  crate-wide; see `src/lib.rs`).
- `cargo doc` builds with no warnings.
