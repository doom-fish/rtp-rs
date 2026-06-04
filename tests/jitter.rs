//! Interarrival jitter estimator (RFC 3550 §6.4.1 / §A.8).

use rtp::Jitter;

#[test]
fn constant_spacing_yields_zero_jitter() {
    let mut j = Jitter::new();
    // Arrival advances exactly in step with the RTP timestamp: D == 0 always.
    for k in 0..10u32 {
        j.update(k * 160, k * 160);
    }
    assert_eq!(j.value(), 0);
    assert!(j.value_f64().abs() < f64::EPSILON);
}

#[test]
fn varying_spacing_matches_hand_computation() {
    // Worked example, J_i = J_{i-1} + (|D| - J_{i-1}) / 16.
    let mut j = Jitter::new();
    j.update(0, 0); // transit 0  (primes have_prev)
    j.update(160, 180); // transit 20, D=20 -> J = 1.25
    j.update(320, 340); // transit 20, D=0  -> J = 1.171875
    j.update(480, 520); // transit 40, D=20 -> J = 2.3486328125

    let expected = 2.348_632_812_5;
    assert!((j.value_f64() - expected).abs() < 1e-9, "got {}", j.value_f64());
    assert_eq!(j.value(), 2);
}

#[test]
fn jitter_handles_timestamp_wrap() {
    let mut j = Jitter::new();
    // Straddle the 32-bit wrap; wrapping subtraction keeps the transit sane.
    j.update(0xFFFF_FF00, 0xFFFF_FF00);
    j.update(0x0000_0060, 0x0000_0060); // +0x160 both, D == 0
    assert_eq!(j.value(), 0);
}
