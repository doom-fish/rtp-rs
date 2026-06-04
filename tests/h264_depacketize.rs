//! H.264 depacketization: FU-A reassembly, STAP-A splitting, error handling.

use rtp::h264::{Depacketizer, Packetizer};

#[test]
fn fu_a_round_trip() {
    let mut nal = vec![0x61u8]; // non-IDR, NRI=3
    nal.extend((0..500u32).map(|i| (i % 255) as u8));

    let fragments = Packetizer::new(200).packetize(&nal);
    let mut depack = Depacketizer::new();
    let mut out = None;
    for f in &fragments {
        if let Some(n) = depack.push(f).unwrap() {
            out = Some(n);
        }
    }
    assert_eq!(out, Some(nal));
}

#[test]
fn fu_a_continuation_without_start_errors() {
    let mut depack = Depacketizer::new();
    // FU-A indicator (0x7C), FU header without S bit (type 1), some data.
    let bogus = [0x7Cu8, 0x01, 0xAA, 0xBB];
    assert!(depack.push(&bogus).is_err());
}

#[test]
fn single_nal_passthrough() {
    let mut depack = Depacketizer::new();
    let nal = [0x41u8, 0x9A, 0x00];
    let out = depack.push(&nal).unwrap().unwrap();
    assert_eq!(out, nal);
}

#[test]
fn truncated_stap_a_errors() {
    let mut depack = Depacketizer::new();
    // STAP-A header (type 24) then a size prefix claiming 10 bytes but no data.
    let bogus = [0x78u8, 0x00, 0x0A, 0x01];
    assert!(depack.push(&bogus).is_err());
}

#[test]
fn empty_payload_errors() {
    let mut depack = Depacketizer::new();
    assert!(depack.push(&[]).is_err());
}
