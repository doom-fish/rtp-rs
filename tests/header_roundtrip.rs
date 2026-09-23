//! RTP fixed-header encode/parse round-trips.

use rtp::{Packet, RtpPacket};

#[test]
fn minimal_header_round_trip() {
    let pkt = RtpPacket::builder()
        .payload_type(96)
        .sequence_number(0x0539)
        .timestamp(0xDEAD_BEEF)
        .ssrc(0x1234_5678)
        .payload([1, 2, 3, 4])
        .build()
        .unwrap();

    let bytes = pkt.into_bytes();
    let parsed = RtpPacket::parse(&bytes).unwrap();
    let h = parsed.header();
    assert_eq!(h.version(), 2);
    assert_eq!(h.payload_type(), 96);
    assert_eq!(h.sequence_number(), 0x0539);
    assert_eq!(h.timestamp(), 0xDEAD_BEEF);
    assert_eq!(h.ssrc(), 0x1234_5678);
    assert!(!h.marker());
    assert_eq!(parsed.payload(), &[1, 2, 3, 4]);
    assert_eq!(parsed.payload_offset(), 12);
}

#[test]
fn marker_and_csrc_round_trip() {
    let pkt = RtpPacket::builder()
        .payload_type(111)
        .sequence_number(42)
        .timestamp(1000)
        .ssrc(0xAABB_CCDD)
        .marker(true)
        .csrc(0x1111_1111)
        .csrc(0x2222_2222)
        .payload([0xFF])
        .build()
        .unwrap();

    let bytes = pkt.into_bytes();
    let parsed = RtpPacket::parse(&bytes).unwrap();
    let h = parsed.header();
    assert!(h.marker());
    assert_eq!(h.payload_type(), 111);
    assert_eq!(h.csrc(), &[0x1111_1111, 0x2222_2222]);
    // payload offset = 12 fixed header + 2*4 CSRC
    assert_eq!(parsed.payload_offset(), 20);
    assert_eq!(parsed.payload(), &[0xFF]);
}

#[test]
fn padding_is_stripped_from_payload() {
    let pkt = RtpPacket::builder()
        .payload_type(96)
        .sequence_number(1)
        .ssrc(7)
        .payload([0xAB, 0xCD])
        .pad_to(8)
        .build()
        .unwrap();

    let bytes = pkt.into_bytes();
    // 12 header + payload(2) padded up to a multiple of 8 => 16 bytes on the wire.
    assert_eq!(bytes.len(), 16);
    let parsed = RtpPacket::parse(&bytes).unwrap();
    assert!(parsed.header().has_padding());
    assert_eq!(parsed.payload(), &[0xAB, 0xCD]);
}

#[test]
fn truncated_buffer_is_rejected() {
    assert!(RtpPacket::parse(&[0x80, 0x60, 0x00]).is_err());
}
