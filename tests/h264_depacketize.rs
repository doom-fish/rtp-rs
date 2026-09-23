//! H.264 depacketization: FU-A reassembly, STAP-A splitting, error handling.

use rtp::h264::{Depacketizer, Packetizer, DEFAULT_MAX_NAL_SIZE};
use rtp::Error;

#[test]
fn fu_a_round_trip() {
    let mut nal = vec![0x61u8]; // non-IDR, NRI=3
    nal.extend((0..500u32).map(|i| (i % 255) as u8));

    let fragments = Packetizer::new(200).packetize(&nal);
    let mut depack = Depacketizer::new();
    let mut out = None;
    for (seq, f) in (100u16..).zip(&fragments) {
        if let Some(n) = depack.push(seq, f).unwrap() {
            out = Some(n);
        }
    }
    assert_eq!(out, Some(nal));
}

#[test]
fn fu_a_round_trip_across_sequence_wrap() {
    let mut nal = vec![0x65u8];
    nal.extend((0..900u32).map(|i| (i % 253) as u8));

    let fragments = Packetizer::new(200).packetize(&nal);
    assert!(fragments.len() >= 4);
    let mut depack = Depacketizer::new();
    let mut out = None;
    let mut seq = 65534u16;
    for f in &fragments {
        if let Some(n) = depack.push(seq, f).unwrap() {
            out = Some(n);
        }
        seq = seq.wrapping_add(1);
    }
    assert_eq!(out, Some(nal));
}

#[test]
fn fu_a_continuation_without_start_errors() {
    let mut depack = Depacketizer::new();
    // FU-A indicator (0x7C), FU header without S bit (type 1), some data.
    let bogus = [0x7Cu8, 0x01, 0xAA, 0xBB];
    assert!(depack.push(1, &bogus).is_err());
}

#[test]
fn single_nal_passthrough() {
    let mut depack = Depacketizer::new();
    let nal = [0x41u8, 0x9A, 0x00];
    let out = depack.push(7, &nal).unwrap().unwrap();
    assert_eq!(out, nal);
}

#[test]
fn truncated_stap_a_errors() {
    let mut depack = Depacketizer::new();
    // STAP-A header (type 24) then a size prefix claiming 10 bytes but no data.
    let bogus = [0x78u8, 0x00, 0x0A, 0x01];
    assert!(depack.push(1, &bogus).is_err());
}

#[test]
fn empty_payload_errors() {
    let mut depack = Depacketizer::new();
    assert!(depack.push(1, &[]).is_err());
}

#[test]
fn default_limit_is_exposed() {
    assert_eq!(DEFAULT_MAX_NAL_SIZE, 8 * 1024 * 1024);
}

#[test]
fn fu_a_without_end_bit_is_capped() {
    let mut depack = Depacketizer::with_max_nal_size(1000);
    let start = [0x7Cu8, 0x81, 0xAA, 0xAA];
    assert_eq!(depack.push(0, &start).unwrap(), None);

    let mut middle = vec![0x7Cu8, 0x01];
    middle.extend(std::iter::repeat_n(0x55, 300));
    let mut seq = 1u16;
    let err = loop {
        match depack.push(seq, &middle) {
            Ok(None) => seq += 1,
            Ok(Some(nal)) => panic!("an unterminated FU-A produced a NAL of {} bytes", nal.len()),
            Err(e) => break e,
        }
        assert!(seq < 10, "the reassembly limit was never enforced");
    };
    assert_eq!(
        err,
        Error::TooLarge {
            what: "reassembled FU-A NAL unit size",
            max: 1000,
            actual: 3 + 4 * 300,
        }
    );

    assert!(
        depack.push(seq + 1, &middle).is_err(),
        "the oversized fragment must be discarded, not resumed"
    );
    let end = [0x7Cu8, 0x41, 0x01];
    assert!(depack.push(seq + 2, &end).is_err());
    assert_eq!(depack.pop(), None);
}

#[test]
fn lost_middle_fragment_is_not_spliced() {
    let mut first = vec![0x65u8];
    first.extend(std::iter::repeat_n(0x11, 500));
    let mut second = vec![0x65u8];
    second.extend(std::iter::repeat_n(0x22, 500));

    let packetizer = Packetizer::new(200);
    let a = packetizer.packetize(&first);
    let b = packetizer.packetize(&second);
    assert!(a.len() >= 3 && b.len() >= 3);

    let mut depack = Depacketizer::new();
    let mut seq = 10u16;
    assert_eq!(depack.push(seq, &a[0]).unwrap(), None);
    seq += 2;
    assert!(
        depack.push(seq, &a[2]).is_err(),
        "a fragment after a sequence gap must be rejected"
    );
    for f in &a[3..] {
        seq += 1;
        assert!(depack.push(seq, f).is_err());
    }

    let mut out = Vec::new();
    for f in &b {
        seq += 1;
        if let Some(nal) = depack.push(seq, f).unwrap() {
            out.push(nal);
        }
    }
    assert_eq!(out, vec![second]);
}

#[test]
fn fragment_of_another_nal_type_is_rejected() {
    let mut depack = Depacketizer::new();
    assert_eq!(depack.push(1, &[0x7C, 0x85, 0xAA]).unwrap(), None);
    assert!(depack.push(2, &[0x7C, 0x41, 0xBB]).is_err());
    assert!(
        depack.push(3, &[0x7C, 0x45, 0xCC]).is_err(),
        "the mismatched assembly must have been discarded"
    );
}

#[test]
fn single_nal_interrupting_fu_a_discards_the_fragment() {
    let mut depack = Depacketizer::new();
    assert_eq!(depack.push(1, &[0x7C, 0x85, 0xAA]).unwrap(), None);
    assert_eq!(
        depack.push(2, &[0x41, 0x01]).unwrap(),
        Some(vec![0x41, 0x01])
    );
    assert!(depack.push(3, &[0x7C, 0x45, 0xBB]).is_err());
}
