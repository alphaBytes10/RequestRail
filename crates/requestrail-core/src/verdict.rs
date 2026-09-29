//! Verdict type — the outcome of a guard evaluation.

use serde::{Deserialize, Serialize};

/// The decision a [`super::Guard`] returns after evaluating a request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Verdict {
    /// The request is allowed to proceed.
    Allow,

    /// The request is blocked. Carries a human-readable reason.
    Block {
        /// Why the request was blocked.
        reason: String,
    },

    /// The request is allowed but the body should be modified
    /// (e.g. PII redaction).
    Modify {
        /// The replacement body.
        new_body: String,
        /// What was modified.
        reason: String,
    },
}

impl Verdict {
    /// Convenience constructor for a block verdict.
    pub fn block(reason: impl Into<String>) -> Self {
        Self::Block {
            reason: reason.into(),
        }
    }

    /// Convenience constructor for a modify verdict.
    pub fn modify(new_body: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Modify {
            new_body: new_body.into(),
            reason: reason.into(),
        }
    }

    /// Returns `true` if this verdict allows the request.
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if this verdict blocks the request.
    pub fn is_block(&self) -> bool {
        matches!(self, Self::Block { .. })
    }

    /// Returns `true` if this verdict modifies the request.
    pub fn is_modify(&self) -> bool {
        matches!(self, Self::Modify { .. })
    }

    /// Returns the blocking reason if this is a `Block` verdict.
    pub fn block_reason(&self) -> Option<&str> {
        match self {
            Self::Block { reason } => Some(reason),
            _ => None,
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Block { reason } => write!(f, "BLOCK: {reason}"),
            Self::Modify { reason, .. } => write!(f, "MODIFY: {reason}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_constructors() {
        assert!(Verdict::Allow.is_allow());
        assert!(Verdict::block("bad").is_block());
        assert!(Verdict::modify("clean", "redacted PII").is_modify());
    }

    #[test]
    fn verdict_display() {
        assert_eq!(Verdict::Allow.to_string(), "ALLOW");
        assert_eq!(Verdict::block("nope").to_string(), "BLOCK: nope");
    }

    #[test]
    fn verdict_block_reason() {
        let v = Verdict::block("reason");
        assert_eq!(v.block_reason(), Some("reason"));
        assert_eq!(Verdict::Allow.block_reason(), None);
    }

    #[test]
    fn verdict_serializes() {
        let v = Verdict::block("test");
        let json = serde_json::to_string(&v).unwrap();
        assert!(json.contains("Block"));
        assert!(json.contains("test"));
    }
}
