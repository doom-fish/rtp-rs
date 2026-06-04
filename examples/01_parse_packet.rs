//! Parse an RTP packet from raw bytes and print its header fields.

use rtp::{Packet, RtpPacket};

fn main() {
    // A minimal RTP packet: V=2, PT=96, seq=0x0539, ts=0xDEADBEEF, ssrc=0x12345678,
    // followed by a four-byte payload.
    let bytes: [u8; 16] = [
        0x80, 0x60, 0x05, 0x39, 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x67, 0x42, 0x00,
        0x1F,
    ];

    let pkt = RtpPacket::parse(&bytes).expect("valid RTP packet");
    let h = pkt.header();

    println!("version        = {}", h.version());
    println!("payload_type   = {}", h.payload_type());
    println!("sequence       = {}", h.sequence_number());
    println!("timestamp      = 0x{:08X}", h.timestamp());
    println!("ssrc           = 0x{:08X}", h.ssrc());
    println!("marker         = {}", h.marker());
    println!("payload        = {:02X?}", pkt.payload());
    println!("payload_offset = {}", pkt.payload_offset());
}
