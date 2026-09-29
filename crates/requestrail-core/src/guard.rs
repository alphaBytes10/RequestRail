//! Guard trait — the central abstraction every security module implements.

use crate::context::Context;
use crate::error::GuardError;
use crate::verdict::Verdict;

/// A synchronous security check that inspects a [`Context`] and returns a
/// [`Verdict`].
///
/// Guards are the building blocks of a [`super::Pipeline`]. Each guard
/// implements a single security concern (authentication, PII detection,
/// rate limiting, etc.) and is composed with other guards to form a
/// complete security policy.
///
/// # Contract
/// - `evaluate` **must not panic**. If it does, the pipeline catches the
///   panic and applies the configured [`super::FailPolicy`].
/// - `evaluate` should be deterministic for the same input.
/// - `name` must return a stable, unique identifier (e.g. `"pii_detection"`).
pub trait Guard: Send + Sync {
    /// A stable, unique name for this guard (e.g. `"rate_limiter"`).
    fn name(&self) -> &str;

    /// Evaluate the request context and return a verdict.
    ///
    /// Returns `Ok(Verdict)` on success, or `Err(GuardError)` if the
    /// guard itself failed (not the request).
    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError>;

    /// Optional human-readable description of what this guard checks.
    fn description(&self) -> &str {
        "No description provided"
    }

    /// Priority hint — lower numbers run first. Default is 100.
    fn priority(&self) -> u32 {
        100
    }
}

/// A boxed, thread-safe guard for dynamic dispatch.
pub type BoxGuard = Box<dyn Guard>;

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysAllow;

    impl Guard for AlwaysAllow {
        fn name(&self) -> &str {
            "always_allow"
        }

        fn evaluate(&self, _ctx: &Context) -> Result<Verdict, GuardError> {
            Ok(Verdict::Allow)
        }
    }

    #[test]
    fn guard_trait_works() {
        let guard = AlwaysAllow;
        let ctx = Context::new("test");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_allow());
        assert_eq!(guard.name(), "always_allow");
        assert_eq!(guard.priority(), 100);
    }
}
