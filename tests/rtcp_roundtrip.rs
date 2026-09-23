//! RTCP encode/parse round-trips for every supported packet type.

use rtp::rtcp::fir::{Fir, FirEntry};
use rtp::rtcp::remb::Remb;
use rtp::rtcp::rr::ReportBlock;
use rtp::rtcp::sli::{Sli, SliEntry};
use rtp::rtcp::twcc::{Delta, Twcc};
use rtp::RtcpPacket;

fn round_trip(pkt: &RtcpPacket) -> RtcpPacket {
    let bytes = pkt.encode().unwrap();
    assert_eq!(bytes.len() % 4, 0, "RTCP packets are 32-bit aligned");
    RtcpPacket::parse(&bytes).unwrap()
}

#[test]
fn sender_report_round_trip() {
    let sr = RtcpPacket::sender_report(0x1111_2222)
        .ntp_timestamp(0x0123_4567_89AB_CDEF)
        .rtp_timestamp(0xDEAD_BEEF)
        .counts(100, 12345)
        .add_block(ReportBlock {
            ssrc: 0x3333_4444,
            fraction_lost: 5,
            cumulative_lost: 9,
            extended_highest_seq: 500,
            jitter: 20,
            last_sr: 0xAAAA,
            delay_since_last_sr: 0xBBBB,
        })
        .build();
    assert_eq!(round_trip(&sr), sr);
}

#[test]
fn receiver_report_round_trip() {
    let rr = RtcpPacket::receiver_report()
        .ssrc(0xFEED_FACE)
        .add_block(ReportBlock {
            ssrc: 0x1234,
            fraction_lost: 0,
            cumulative_lost: 0,
            extended_highest_seq: 1,
            jitter: 0,
            last_sr: 0,
            delay_since_last_sr: 0,
        })
        .build();
    assert_eq!(round_trip(&rr), rr);
}

#[test]
fn nack_round_trip_and_expansion() {
    let nack: RtcpPacket = RtcpPacket::nack(0xABCD, &[10, 11, 12, 50]).into();
    if let RtcpPacket::Nack(n) = &nack {
        assert_eq!(n.lost_sequence_numbers(), vec![10, 11, 12, 50]);
    } else {
        panic!("expected NACK");
    }
    assert_eq!(round_trip(&nack), nack);
}

#[test]
fn pli_round_trip() {
    let pli: RtcpPacket = RtcpPacket::pli(0x4242).into();
    assert_eq!(round_trip(&pli), pli);
}

#[test]
fn fir_round_trip() {
    let fir = RtcpPacket::Fir(Fir {
        sender_ssrc: 1,
        media_ssrc: 0,
        entries: vec![FirEntry {
            ssrc: 0x9999,
            seq_nr: 7,
        }],
    });
    assert_eq!(round_trip(&fir), fir);
}

#[test]
fn sli_round_trip() {
    let sli = RtcpPacket::Sli(Sli {
        sender_ssrc: 1,
        media_ssrc: 2,
        entries: vec![SliEntry {
            first: 100,
            number: 200,
            picture_id: 5,
        }],
    });
    assert_eq!(round_trip(&sli), sli);
}

#[test]
fn remb_round_trip() {
    let remb = RtcpPacket::Remb(Remb {
        sender_ssrc: 1,
        media_ssrc: 0,
        bitrate_bps: 2_500_000,
        ssrcs: vec![0x1111, 0x2222],
    });
    let parsed = round_trip(&remb);
    if let RtcpPacket::Remb(r) = parsed {
        // Bitrate is quantized to a 6-bit exp / 18-bit mantissa form, so it may
        // be rounded down; require it within one quantization step.
        assert!(r.bitrate_bps <= 2_500_000);
        assert!(r.bitrate_bps >= 2_500_000 - (2_500_000 >> 18) - 1);
        assert_eq!(r.ssrcs, vec![0x1111, 0x2222]);
    } else {
        panic!("expected REMB");
    }
}

#[test]
fn twcc_round_trip() {
    let twcc = RtcpPacket::Twcc(Twcc {
        sender_ssrc: 1,
        media_ssrc: 2,
        base_seq: 100,
        reference_time: 42,
        fb_pkt_count: 3,
        statuses: vec![
            Delta::Small(10),
            Delta::Small(20),
            Delta::NotReceived,
            Delta::Large(300),
        ],
    });
    let parsed = round_trip(&twcc);
    if let RtcpPacket::Twcc(t) = parsed {
        assert_eq!(t.base_seq, 100);
        assert_eq!(t.reference_time, 42);
        assert_eq!(t.fb_pkt_count, 3);
        assert_eq!(t.statuses, twcc_statuses());
    } else {
        panic!("expected TWCC");
    }
}

fn twcc_statuses() -> Vec<Delta> {
    vec![
        Delta::Small(10),
        Delta::Small(20),
        Delta::NotReceived,
        Delta::Large(300),
    ]
}

#[test]
fn nack_packs_losses_across_the_sequence_wrap() {
    use rtp::rtcp::nack::{Nack, NackEntry};

    let nack = Nack::from_lost(1, 2, &[1, 65535, 0, 65534]);
    assert_eq!(
        nack.entries,
        vec![NackEntry {
            pid: 65534,
            blp: 0b111
        }]
    );
    assert_eq!(nack.lost_sequence_numbers(), vec![65534, 65535, 0, 1]);

    let spread = Nack::from_lost(1, 2, &[3, 40_000, 65_530]);
    assert_eq!(spread.entries.len(), 2);
    let mut lost = spread.lost_sequence_numbers();
    lost.sort_unstable();
    assert_eq!(lost, vec![3, 40_000, 65_530]);
}
