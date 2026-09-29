//! Fail-policy configuration.

use serde::{Deserialize, Serialize};

/// What to do when a guard returns `Err(_)` instead of a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailPolicy {
    /// Treat a guard error as `Verdict::Allow` (fail-open).
    ///
    /// Use when availability is more important than strict security
    /// (e.g. a best-effort PII scanner).
    Open,

    /// Treat a guard error as `Verdict::Block` (fail-closed).
    ///
    /// Use for critical security checks where a broken guard must
    /// not silently let traffic through.
    Closed,
}

impl Default for FailPolicy {
    fn default() -> Self {
        Self::Closed
    }
}

impl std::fmt::Display for FailPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => write!(f, "fail-open"),
            Self::Closed => write!(f, "fail-closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_closed() {
        assert_eq!(FailPolicy::default(), FailPolicy::Closed);
    }

    #[test]
    fn display() {
        assert_eq!(FailPolicy::Open.to_string(), "fail-open");
        assert_eq!(FailPolicy::Closed.to_string(), "fail-closed");
    }
}
