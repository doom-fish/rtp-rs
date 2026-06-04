//! Build and parse an RTCP compound packet (RR + NACK + PLI).

use rtp::rtcp::rr::ReportBlock;
use rtp::{CompoundPacket, RtcpPacket};

fn main() {
    let media_ssrc = 0x1234_5678;

    let rr = RtcpPacket::receiver_report()
        .ssrc(0xFEED_FACE)
        .add_block(ReportBlock {
            ssrc: media_ssrc,
            fraction_lost: 12,
            cumulative_lost: 34,
            extended_highest_seq: 1000,
            jitter: 56,
            last_sr: 0,
            delay_since_last_sr: 0,
        })
        .build();

    let nack = RtcpPacket::nack(media_ssrc, &[17, 18, 20, 100]);
    let pli = RtcpPacket::pli(media_ssrc);

    let compound = CompoundPacket::new()
        .add(rr)
        .add(nack.into())
        .add(pli.into());

    let bytes = compound.encode();
    println!("compound packet: {} bytes", bytes.len());

    let parsed = CompoundPacket::parse(&bytes).expect("valid compound");
    println!("parsed {} packets:", parsed.packets.len());
    for p in &parsed.packets {
        println!("  PT {} -> {p:?}", p.payload_type());
    }
}
