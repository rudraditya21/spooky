use std::time::Instant;

/// A leaky token-bucket rate limiter for new QUIC connection accepts.
///
/// Tokens refill at `rate_per_sec` tokens/second up to a cap of `burst`.
/// Each new `quiche::accept` call consumes one token; if the bucket is empty
/// the packet is silently dropped (no panic, no connection state allocated).
pub(crate) struct TokenBucket {
    /// Maximum tokens the bucket can hold (burst capacity).
    burst: f64,
    /// Tokens added per second.
    rate_per_sec: f64,
    /// Current available tokens.
    tokens: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl TokenBucket {
    pub(super) fn new(rate_per_sec: u32, burst: u32) -> Self {
        let burst = (burst.max(1)) as f64;
        let rate_per_sec = rate_per_sec.max(1) as f64;
        Self {
            burst,
            rate_per_sec,
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    pub(super) fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        // Refill is intentionally bounded by `burst`: after long idle periods, precision
        // beyond "enough to fill the bucket" is irrelevant and we clamp to capacity.
        let refill = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64()
            * self.rate_per_sec;
        self.last_refill = now;

        if refill.is_finite() && refill > 0.0 {
            self.tokens = (self.tokens + refill).min(self.burst);
        } else if !refill.is_finite() {
            self.tokens = self.burst;
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    pub(super) fn reconfigure(&mut self, rate_per_sec: u32, burst: u32) {
        let burst = burst.max(1) as f64;
        let rate_per_sec = rate_per_sec.max(1) as f64;
        self.burst = burst;
        self.rate_per_sec = rate_per_sec;
        self.tokens = self.tokens.min(self.burst);
        self.last_refill = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::TokenBucket;
    use std::time::Duration;

    #[test]
    fn long_idle_refill_is_capped_to_burst() {
        let mut tb = TokenBucket::new(1_000, 3);
        assert!(tb.try_consume());
        assert!(tb.try_consume());
        assert!(tb.try_consume());
        assert!(!tb.try_consume());

        tb.last_refill = tb
            .last_refill
            .checked_sub(Duration::from_secs(60))
            .expect("time subtraction");

        assert!(tb.try_consume(), "long idle should refill bucket");
        assert!(tb.tokens.is_finite());
        assert!(tb.tokens <= tb.burst);
    }

    #[test]
    fn reconfigure_clamps_tokens_to_new_burst() {
        let mut tb = TokenBucket::new(100, 5);
        assert!(tb.try_consume());
        assert!(tb.try_consume());
        tb.reconfigure(200, 2);

        assert_eq!(tb.burst, 2.0);
        assert_eq!(tb.rate_per_sec, 200.0);
        assert!(tb.tokens <= tb.burst);
    }
}
