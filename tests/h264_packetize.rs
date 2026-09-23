//! H.264 packetization: Single NAL, STAP-A and FU-A.

use rtp::h264::{nal_type, Depacketizer, Packetizer, NAL_FU_A, NAL_STAP_A};

#[test]
fn small_nal_is_sent_as_single() {
    let nal = vec![0x67u8, 0x42, 0x00, 0x1F]; // SPS
    let pkts = Packetizer::new(1200).packetize(&nal);
    assert_eq!(pkts.len(), 1);
    assert_eq!(pkts[0], nal);
    assert_eq!(nal_type(&pkts[0]), 7);
}

#[test]
fn large_nal_fragments_into_fu_a() {
    let mut nal = vec![0x65u8]; // IDR header
    nal.extend(std::iter::repeat_n(0xAB, 1000));

    let pkts = Packetizer::new(300).packetize(&nal);
    assert!(pkts.len() >= 4);
    // Every fragment carries the FU-A type in its indicator.
    for p in &pkts {
        assert_eq!(p[0] & 0x1F, NAL_FU_A);
    }
    // Start bit on first, end bit on last.
    assert_eq!(pkts[0][1] & 0x80, 0x80);
    assert_eq!(pkts.last().unwrap()[1] & 0x40, 0x40);
}

#[test]
fn aggregate_builds_stap_a() {
    let sps = vec![0x67u8, 0x42, 0x00, 0x1F];
    let pps = vec![0x68u8, 0xCE, 0x3C, 0x80];
    let agg = Packetizer::new(1200)
        .aggregate(&[&sps, &pps])
        .expect("fits in MTU");
    assert_eq!(agg[0] & 0x1F, NAL_STAP_A);

    // Reassemble.
    let mut depack = Depacketizer::new();
    let first = depack.push(1, &agg).unwrap().unwrap();
    let second = depack.pop().unwrap();
    assert_eq!(first, sps);
    assert_eq!(second, pps);
}

#[test]
fn parameter_sets_injected_before_idr() {
    let sps = vec![0x67u8, 0x42, 0x00, 0x1F];
    let pps = vec![0x68u8, 0xCE, 0x3C, 0x80];
    let idr = {
        let mut v = vec![0x65u8];
        v.extend([0u8; 10]);
        v
    };

    let mut pktzr = Packetizer::new(1200);
    pktzr.set_parameter_sets(&sps, &pps);
    let out = pktzr.packetize_access_unit(std::slice::from_ref(&idr));
    // SPS, PPS, then IDR — three single-NAL payloads.
    assert_eq!(out.len(), 3);
    assert_eq!(nal_type(&out[0]), 7);
    assert_eq!(nal_type(&out[1]), 8);
    assert_eq!(out[2], idr);
}
