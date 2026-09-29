//! Nonce-based replay protection guard.

use dashmap::DashMap;
use std::time::{Duration, Instant};
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;

/// Prevents replay attacks by tracking request nonces.
///
/// Each request must include a unique nonce (in `ctx.nonce`). The guard
/// remembers seen nonces for a configurable window and blocks duplicates.
pub struct ReplayProtectionGuard {
    seen_nonces: DashMap<String, Instant>,
    window: Duration,
}

impl ReplayProtectionGuard {
    /// Create a new replay protection guard.
    ///
    /// `window` — how long to remember nonces before they can be reused.
    pub fn new(window: Duration) -> Self {
        Self {
            seen_nonces: DashMap::new(),
            window,
        }
    }

    /// Evict expired nonces (best-effort cleanup).
    fn evict_expired(&self) {
        let cutoff = Instant::now() - self.window;
        self.seen_nonces.retain(|_, v| *v > cutoff);
    }
}

impl Guard for ReplayProtectionGuard {
    fn name(&self) -> &str {
        "replay_protection"
    }

    fn description(&self) -> &str {
        "Nonce-based replay attack prevention"
    }

    fn priority(&self) -> u32 {
        4
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let nonce = ctx.nonce.as_deref().ok_or_else(|| {
            GuardError::MissingField("nonce".into())
        })?;

        // Periodic cleanup
        if self.seen_nonces.len() > 10_000 {
            self.evict_expired();
        }

        // Check for replay
        if self.seen_nonces.contains_key(nonce) {
            return Ok(Verdict::block(format!(
                "replay detected: nonce '{nonce}' already used"
            )));
        }

        // Record this nonce
        self.seen_nonces.insert(nonce.to_string(), Instant::now());

        Ok(Verdict::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_use_allowed() {
        let guard = ReplayProtectionGuard::new(Duration::from_secs(60));
        let ctx = Context::new("test").with_nonce("nonce-1");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn replay_blocked() {
        let guard = ReplayProtectionGuard::new(Duration::from_secs(60));
        let ctx = Context::new("test").with_nonce("nonce-2");

        assert!(guard.evaluate(&ctx).unwrap().is_allow());
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn different_nonces_allowed() {
        let guard = ReplayProtectionGuard::new(Duration::from_secs(60));

        let ctx1 = Context::new("test").with_nonce("nonce-a");
        let ctx2 = Context::new("test").with_nonce("nonce-b");

        assert!(guard.evaluate(&ctx1).unwrap().is_allow());
        assert!(guard.evaluate(&ctx2).unwrap().is_allow());
    }

    #[test]
    fn missing_nonce_errors() {
        let guard = ReplayProtectionGuard::new(Duration::from_secs(60));
        let ctx = Context::new("test");
        assert!(guard.evaluate(&ctx).is_err());
    }
}
