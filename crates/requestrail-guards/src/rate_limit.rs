//! Token-bucket rate limiting guard.

use dashmap::DashMap;
use parking_lot::Mutex;
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;
use std::time::{Duration, Instant};

/// A token-bucket rate limiter that tracks request counts per client.
///
/// Each client (identified by `ctx.source` or `ctx.remote_addr`) gets
/// a bucket with a configurable capacity and refill rate. When the bucket
/// is empty, requests are blocked.
pub struct RateLimitGuard {
    buckets: DashMap<String, Mutex<TokenBucket>>,
    capacity: u32,
    refill_rate: f64, // tokens per second
    refill_interval: Duration,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    capacity: u32,
    refill_rate: f64,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            tokens: capacity as f64,
            last_refill: Instant::now(),
            capacity,
            refill_rate,
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
    }
}

impl RateLimitGuard {
    /// Create a new rate limit guard.
    ///
    /// - `capacity`: maximum burst size (tokens in the bucket)
    /// - `requests_per_second`: steady-state refill rate
    pub fn new(capacity: u32, requests_per_second: f64) -> Self {
        Self {
            buckets: DashMap::new(),
            capacity,
            refill_rate: requests_per_second,
            refill_interval: Duration::from_secs_f64(1.0 / requests_per_second),
        }
    }

    /// Extract the client key from the context.
    fn client_key(ctx: &Context) -> String {
        ctx.source
            .clone()
            .or_else(|| ctx.remote_addr.clone())
            .unwrap_or_else(|| "anonymous".to_string())
    }
}

impl Guard for RateLimitGuard {
    fn name(&self) -> &str {
        "rate_limiter"
    }

    fn description(&self) -> &str {
        "Token-bucket rate limiter per client identity"
    }

    fn priority(&self) -> u32 {
        10
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let key = Self::client_key(ctx);

        let bucket = self.buckets
            .entry(key.clone())
            .or_insert_with(|| Mutex::new(TokenBucket::new(self.capacity, self.refill_rate)));

        let mut bucket = bucket.lock();
        if bucket.try_consume() {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::block(format!(
                "rate limit exceeded for client '{key}' (capacity: {}, rate: {}/s)",
                self.capacity, self.refill_rate
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_budget() {
        let guard = RateLimitGuard::new(5, 10.0);
        let ctx = Context::new("test").with_source("client-a");

        for _ in 0..5 {
            let verdict = guard.evaluate(&ctx).unwrap();
            assert!(verdict.is_allow());
        }
    }

    #[test]
    fn blocks_over_budget() {
        let guard = RateLimitGuard::new(2, 0.1); // very slow refill
        let ctx = Context::new("test").with_source("client-b");

        // Consume all tokens
        guard.evaluate(&ctx).unwrap();
        guard.evaluate(&ctx).unwrap();

        // Should be blocked now
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
        assert!(verdict.to_string().contains("rate limit exceeded"));
    }

    #[test]
    fn separate_buckets_per_client() {
        let guard = RateLimitGuard::new(1, 0.1);

        let ctx_a = Context::new("test").with_source("client-a");
        let ctx_b = Context::new("test").with_source("client-b");

        assert!(guard.evaluate(&ctx_a).unwrap().is_allow());
        assert!(guard.evaluate(&ctx_b).unwrap().is_allow());

        // Both exhausted now
        assert!(guard.evaluate(&ctx_a).unwrap().is_block());
        assert!(guard.evaluate(&ctx_b).unwrap().is_block());
    }

    #[test]
    fn anonymous_clients_share_bucket() {
        let guard = RateLimitGuard::new(1, 0.1);
        let ctx = Context::new("test"); // no source
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }
}
