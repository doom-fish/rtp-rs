//! Build an RTP packet with RFC 8285 header extensions, then round-trip it.

use rtp::{Extension, Packet, RtpPacket};

fn main() {
    let nal = [0x67u8, 0x42, 0x00, 0x1F];

    let packet = RtpPacket::builder()
        .payload_type(96)
        .sequence_number(1000)
        .timestamp(0xDEAD_BEEF)
        .ssrc(0x1234_5678)
        .marker(true)
        .extension(Extension::mid("0"))
        .extension(Extension::twcc(42))
        .payload(nal.as_slice())
        .build()
        .expect("valid packet");

    let bytes = packet.into_bytes();
    println!("encoded {} bytes: {:02X?}", bytes.len(), bytes);

    let parsed = RtpPacket::parse(&bytes).expect("round-trip parse");
    assert_eq!(parsed.header().payload_type(), 96);
    assert_eq!(parsed.header().sequence_number(), 1000);
    assert!(parsed.header().marker());
    assert_eq!(parsed.payload(), &nal);

    println!("extensions: {:?}", parsed.extensions());
    println!("round-trip OK");
}
