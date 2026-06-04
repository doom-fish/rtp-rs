//! Interarrival jitter estimation (RFC 3550 §6.4.1 / §A.8).
//!
//! Jitter is the smoothed mean deviation of the difference `D` between packet
//! spacing at the sender (RTP timestamp units) and at the receiver (arrival
//! time, converted to the same units). The estimator is:
//!
//! ```text
//! D(i-1, i) = (R_i - R_{i-1}) - (S_i - S_{i-1})
//! J_i = J_{i-1} + (|D(i-1, i)| - J_{i-1}) / 16
//! ```
//!
//! where `R` is arrival time and `S` is the RTP timestamp, both in timestamp
//! units. The reported jitter is `floor(J)`.

/// Running interarrival-jitter estimator for a single source.
#[derive(Clone, Debug, Default)]
pub struct Jitter {
    jitter: f64,
    last_transit: i64,
    have_prev: bool,
}

impl Jitter {
    /// Create an empty estimator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one packet.
    ///
    /// * `rtp_timestamp` — the packet's RTP timestamp (`S`).
    /// * `arrival` — the local arrival time **expressed in the same clock units
    ///   as the RTP timestamp** (`R`). For an 8 kHz clock this is
    ///   `arrival_seconds * 8000`.
    ///
    /// Both are 32-bit values that may wrap; the transit difference is computed
    /// with wrapping subtraction so wrap is handled transparently.
    pub fn update(&mut self, rtp_timestamp: u32, arrival: u32) {
        let transit = i64::from(arrival.wrapping_sub(rtp_timestamp) as i32);
        if self.have_prev {
            let d = (transit - self.last_transit).abs();
            self.jitter += (d as f64 - self.jitter) / 16.0;
        } else {
            self.have_prev = true;
        }
        self.last_transit = transit;
    }

    /// Current jitter estimate as a floating-point value in timestamp units.
    #[must_use]
    pub const fn value_f64(&self) -> f64 {
        self.jitter
    }

    /// Current jitter estimate truncated to an integer, as carried in RTCP
    /// receiver reports.
    #[must_use]
    pub fn value(&self) -> u32 {
        self.jitter as u32
    }
}
