use rtp::rtcp::nack::NackEntry;
use rtp::rtcp::twcc::{Delta, MAX_STATUSES};
use rtp::{CompoundPacket, Error, RtcpPacket};

const RR: [u8; 8] = [0x80, 0xC9, 0x00, 0x01, 0xFE, 0xED, 0xFA, 0xCE];
const XR: [u8; 8] = [0x80, 0xCF, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11];
const PLI: [u8; 12] = [
    0x81, 0xCE, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x42, 0x42,
];
const NON_REMB_AFB: [u8; 20] = [
    0x8F, 0xCE, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, b'A', b'B', b'C', b'D',
    0x00, 0x00, 0x00, 0x00,
];
const TMMBR: [u8; 20] = [
    0x83, 0xCD, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78,
    0x04, 0x00, 0x00, 0x00,
];

fn concat(parts: &[&[u8]]) -> Vec<u8> {
    parts.iter().flat_map(|p| p.iter().copied()).collect()
}

#[test]
fn unknown_packet_types_are_skipped_in_compound_packets() {
    let datagram = concat(&[&RR, &XR, &NON_REMB_AFB, &TMMBR, &PLI]);
    let compound = CompoundPacket::parse(&datagram).expect("known packets survive");
    assert_eq!(compound.packets.len(), 2);
    assert!(
        matches!(compound.packets[0], RtcpPacket::ReceiverReport(ref rr) if rr.ssrc == 0xFEED_FACE)
    );
    assert!(matches!(compound.packets[1], RtcpPacket::Pli(ref p) if p.media_ssrc == 0x4242));

    let lenient = CompoundPacket::parse_lenient(&datagram).unwrap();
    assert_eq!(lenient, compound);
}

#[test]
fn single_unknown_packet_is_still_reported_as_unsupported() {
    assert!(matches!(RtcpPacket::parse(&XR), Err(Error::Unsupported(_))));
    assert!(matches!(
        RtcpPacket::parse(&NON_REMB_AFB),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        RtcpPacket::parse(&TMMBR),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn strict_parse_still_requires_a_report_first_on_the_wire() {
    let datagram = concat(&[&XR, &RR]);
    assert!(matches!(
        CompoundPacket::parse(&datagram),
        Err(Error::BadCompound(_))
    ));
    let lenient = CompoundPacket::parse_lenient(&datagram).unwrap();
    assert_eq!(lenient.packets.len(), 1);

    assert!(matches!(
        CompoundPacket::parse(&XR),
        Err(Error::BadCompound(_))
    ));
    assert_eq!(
        CompoundPacket::parse_lenient(&XR).unwrap().packets,
        [] as [rtp::RtcpPacket; 0]
    );
}

#[test]
fn malformed_known_packet_still_fails_the_datagram() {
    let mut truncated_pli = PLI;
    truncated_pli[3] = 0x01;
    let datagram = concat(&[&RR, &truncated_pli[..8]]);
    assert!(CompoundPacket::parse(&datagram).is_err());
}

#[test]
fn rtcp_padding_is_not_decoded_as_nack_entries() {
    let padded_nack = [
        0xA1, 0xCD, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x10, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04,
    ];
    let RtcpPacket::Nack(nack) = RtcpPacket::parse(&padded_nack).unwrap() else {
        panic!("expected NACK");
    };
    assert_eq!(nack.entries, vec![NackEntry { pid: 16, blp: 0 }]);
    assert_eq!(nack.lost_sequence_numbers(), vec![16]);

    let datagram = concat(&[&RR, &padded_nack]);
    let compound = CompoundPacket::parse(&datagram).unwrap();
    assert_eq!(compound.packets.len(), 2);
}

#[test]
fn rtcp_padding_is_stripped_from_app_data() {
    let padded_app = [
        0xA0, 0xCC, 0x00, 0x04, 0x00, 0x00, 0x00, 0x09, b'T', b'E', b'S', b'T', 0x01, 0x02, 0x03,
        0x04, 0x00, 0x00, 0x00, 0x04,
    ];
    let RtcpPacket::App(app) = RtcpPacket::parse(&padded_app).unwrap() else {
        panic!("expected APP");
    };
    assert_eq!(app.name, *b"TEST");
    assert_eq!(app.data, vec![1, 2, 3, 4]);
}

#[test]
fn invalid_rtcp_padding_is_rejected() {
    let mut zero_pad = PLI;
    zero_pad[0] |= 0x20;
    zero_pad[11] = 0;
    assert_eq!(RtcpPacket::parse(&zero_pad), Err(Error::BadPadding(0)));

    let mut oversized_pad = PLI;
    oversized_pad[0] |= 0x20;
    oversized_pad[11] = 9;
    assert_eq!(RtcpPacket::parse(&oversized_pad), Err(Error::BadPadding(9)));

    let mut pad_eats_body = PLI;
    pad_eats_body[0] |= 0x20;
    pad_eats_body[11] = 8;
    assert!(matches!(
        RtcpPacket::parse(&pad_eats_body),
        Err(Error::Truncated { .. })
    ));
}

fn twcc_not_received(status_count: u16, chunks: &[u16]) -> Vec<u8> {
    let mut body = vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x64];
    body.extend_from_slice(&status_count.to_be_bytes());
    body.extend_from_slice(&[0x00, 0x00, 0x2A, 0x03]);
    for chunk in chunks {
        body.extend_from_slice(&chunk.to_be_bytes());
    }
    while body.len() % 4 != 0 {
        body.push(0);
    }
    let words = u16::try_from(body.len() / 4).unwrap();
    let mut packet = vec![0x8F, 0xCD];
    packet.extend_from_slice(&words.to_be_bytes());
    packet.extend_from_slice(&body);
    packet
}

#[test]
fn twcc_expansion_is_capped() {
    let hostile = twcc_not_received(u16::MAX, &[0x1FFF; 9]);
    assert!(hostile.len() <= 40);
    assert_eq!(
        RtcpPacket::parse(&hostile),
        Err(Error::TooLarge {
            what: "TWCC packet status count",
            max: MAX_STATUSES,
            actual: usize::from(u16::MAX),
        })
    );

    let at_limit = twcc_not_received(
        u16::try_from(MAX_STATUSES).unwrap(),
        &[0x1FFF, 0x1FFF, 0x1FFF, 0x1FFF, 0x0004],
    );
    let RtcpPacket::Twcc(twcc) = RtcpPacket::parse(&at_limit).unwrap() else {
        panic!("expected TWCC");
    };
    assert_eq!(twcc.statuses.len(), MAX_STATUSES);
    assert!(twcc.statuses.iter().all(|d| *d == Delta::NotReceived));
}

fn remb(exp: u8, mantissa: u32) -> Vec<u8> {
    let mut packet = vec![
        0x8F, 0xCE, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, b'R', b'E', b'M',
        b'B', 0x01,
    ];
    let m = mantissa.to_be_bytes();
    packet.push((exp << 2) | (m[1] & 0x03));
    packet.push(m[2]);
    packet.push(m[3]);
    packet.extend_from_slice(&[0x00, 0x00, 0x12, 0x34]);
    packet
}

#[test]
fn remb_bitrate_overflow_is_rejected() {
    assert!(matches!(
        RtcpPacket::parse(&remb(63, 0x3_FFFF)),
        Err(Error::BadPayload(_))
    ));
    assert!(matches!(
        RtcpPacket::parse(&remb(47, 0x3_FFFF)),
        Err(Error::BadPayload(_))
    ));

    let RtcpPacket::Remb(max) = RtcpPacket::parse(&remb(46, 0x3_FFFF)).unwrap() else {
        panic!("expected REMB");
    };
    assert_eq!(max.bitrate_bps, 0x3_FFFF_u64 << 46);

    let RtcpPacket::Remb(top_bit) = RtcpPacket::parse(&remb(63, 1)).unwrap() else {
        panic!("expected REMB");
    };
    assert_eq!(top_bit.bitrate_bps, 1_u64 << 63);
    assert_eq!(top_bit.ssrcs, vec![0x1234]);
}
