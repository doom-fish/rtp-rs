//! Packetize a large H.264 NAL unit into FU-A fragments and reassemble it.

use rtp::h264::{Depacketizer, Packetizer};

fn main() {
    // A synthetic IDR NAL: 1-byte header (type 5) + 600 bytes of RBSP.
    let mut nal = vec![0x65u8];
    nal.extend((0..600u32).map(|i| (i % 251) as u8));

    let packetizer = Packetizer::new(300);
    let fragments = packetizer.packetize(&nal);
    println!("NAL of {} bytes -> {} FU-A packets", nal.len(), fragments.len());
    for (i, f) in fragments.iter().enumerate() {
        println!("  fragment {i}: {} bytes (indicator=0x{:02X})", f.len(), f[0]);
    }

    let mut depacketizer = Depacketizer::new();
    let mut reassembled = None;
    for frag in &fragments {
        if let Some(nal) = depacketizer.push(frag).expect("valid FU-A") {
            reassembled = Some(nal);
        }
    }

    assert_eq!(reassembled.as_deref(), Some(nal.as_slice()));
    println!("reassembled NAL matches original");
}
