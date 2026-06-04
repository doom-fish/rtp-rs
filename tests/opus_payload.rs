//! Opus payload TOC inspection (RFC 7587 / RFC 6716).

use rtp::opus::{Bandwidth, Mode, OpusPacket};

#[test]
fn silk_narrowband_20ms_mono() {
    // config=1 (SILK NB 20 ms), stereo=0, c=0 (1 frame).
    let toc = 1 << 3;
    let bytes = [toc, 0x00];
    let pkt = OpusPacket::parse(&bytes).unwrap();
    assert_eq!(pkt.config(), 1);
    assert!(!pkt.is_stereo());
    assert_eq!(pkt.frame_count(), 1);
    assert_eq!(pkt.mode(), Mode::Silk);
    assert_eq!(pkt.bandwidth(), Bandwidth::Narrow);
    assert_eq!(pkt.frame_duration_us(), 20_000);
}

#[test]
fn celt_fullband_stereo_two_frames() {
    // config=31 (CELT FB 20 ms), stereo=1, c=1 (2 frames).
    let toc = (31 << 3) | 0x04 | 0x01;
    let bytes = [toc, 0xFF];
    let pkt = OpusPacket::parse(&bytes).unwrap();
    assert_eq!(pkt.config(), 31);
    assert!(pkt.is_stereo());
    assert_eq!(pkt.frame_count(), 2);
    assert_eq!(pkt.mode(), Mode::Celt);
    assert_eq!(pkt.bandwidth(), Bandwidth::Full);
}

#[test]
fn hybrid_superwideband() {
    // config=12 (Hybrid SWB 10 ms).
    let toc = 12 << 3;
    let bytes = [toc];
    let pkt = OpusPacket::parse(&bytes).unwrap();
    assert_eq!(pkt.mode(), Mode::Hybrid);
    assert_eq!(pkt.bandwidth(), Bandwidth::SuperWide);
    assert_eq!(pkt.frame_duration_us(), 10_000);
}

#[test]
fn arbitrary_frame_count_code_three() {
    // config=16 CELT, c=3 (arbitrary), frame-count byte says 4 frames.
    let toc = (16 << 3) | 0x03;
    let bytes = [toc, 0x04];
    let pkt = OpusPacket::parse(&bytes).unwrap();
    assert_eq!(pkt.frame_count_code(), 3);
    assert_eq!(pkt.frame_count(), 4);
}

#[test]
fn empty_packet_rejected() {
    assert!(OpusPacket::parse(&[]).is_err());
}
