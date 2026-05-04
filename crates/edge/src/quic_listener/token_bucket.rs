use std::time::Instant;

/// A leaky token-bucket rate limiter for new QUIC connection accepts.
///
/// Tokens refill at `rate_per_sec` tokens/second up to a cap of `burst`.
/// Each new `quiche::accept` call consumes one token; if the bucket is empty
/// the packet is silently dropped (no panic, no connection state allocated).
pub(crate) struct TokenBucket {
    /// Maximum tokens the bucket can hold (burst capacity).
    burst: f64,
    /// Tokens added per nanosecond (= rate_per_sec / 1_000_000_000).
    tokens_per_ns: f64,
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
            tokens_per_ns: rate_per_sec / 1_000_000_000.0,
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    pub(super) fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed_ns = now.saturating_duration_since(self.last_refill).as_nanos() as f64;
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed_ns * self.tokens_per_ns).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
