//! RFC 8285 header-extension encode/decode round-trips.

use rtp::extension::{self, PROFILE_ONE_BYTE, PROFILE_TWO_BYTE};
use rtp::{Extension, Packet, RtpPacket};

#[test]
fn one_byte_profile_round_trip() {
    let exts = vec![Extension::mid("0"), Extension::twcc(0x1234)];
    let (profile, data) = extension::encode(&exts).unwrap();
    assert_eq!(profile, PROFILE_ONE_BYTE);

    let decoded = extension::decode(profile, &data).unwrap();
    // Decoded elements are Generic (semantics need SDP); compare by id + bytes.
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].id(), 1);
    assert_eq!(decoded[0].as_mid(), Some(b"0".to_vec()));
    assert_eq!(decoded[1].id(), 3);
    assert_eq!(decoded[1].as_twcc(), Some(0x1234));
}

#[test]
fn two_byte_profile_used_for_long_values() {
    // A value longer than 16 bytes forces the two-byte profile.
    let long = vec![0xABu8; 20];
    let exts = vec![Extension::generic(5, &long)];
    let (profile, data) = extension::encode(&exts).unwrap();
    assert_eq!(profile & 0xFFF0, PROFILE_TWO_BYTE);

    let decoded = extension::decode(profile, &data).unwrap();
    assert_eq!(decoded.len(), 1);
    assert_eq!(decoded[0].id(), 5);
    assert_eq!(decoded[0].data(), long);
}

#[test]
fn extensions_survive_full_packet_round_trip() {
    let pkt = RtpPacket::builder()
        .payload_type(96)
        .sequence_number(7)
        .ssrc(0x99)
        .extension(Extension::mid("video"))
        .extension(Extension::abs_send_time(0x00AB_CDEF))
        .payload([0u8; 3])
        .build();

    let bytes = pkt.into_bytes();
    let parsed = RtpPacket::parse(&bytes).unwrap();
    assert!(parsed.header().has_extension());

    let exts = parsed.extensions();
    assert_eq!(exts.len(), 2);
    assert_eq!(exts[0].as_mid(), Some(b"video".to_vec()));
    assert_eq!(exts[1].as_abs_send_time(), Some(0x00AB_CDEF));
}
