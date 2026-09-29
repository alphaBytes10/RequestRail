//! Error types for guards and the pipeline.

use thiserror::Error;

/// An error produced by a [`super::Guard`] during evaluation.
///
/// This represents a failure *of the guard itself* — not a policy
/// decision to block a request. For blocking, guards return
/// `Ok(Verdict::Block { .. })`.
#[derive(Debug, Error)]
pub enum GuardError {
    /// The guard encountered an internal error.
    #[error("guard internal error: {0}")]
    Internal(String),

    /// The guard's configuration is invalid.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// The guard timed out.
    #[error("guard timed out after {0}ms")]
    Timeout(u64),

    /// A required field was missing from the context.
    #[error("missing required context field: {0}")]
    MissingField(String),

    /// Catch-all for external errors.
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

/// Errors that can occur at the pipeline level.
#[derive(Debug, Error)]
pub enum PipelineError {
    /// A guard returned an error and the fail policy escalated it.
    #[error("guard '{guard}' failed: {source}")]
    GuardFailed {
        guard: String,
        source: GuardError,
    },

    /// A guard panicked.
    #[error("guard '{guard}' panicked: {message}")]
    GuardPanicked {
        guard: String,
        message: String,
    },

    /// The pipeline has no guards configured.
    #[error("pipeline has no guards")]
    Empty,

    /// Pipeline-level timeout.
    #[error("pipeline deadline exceeded")]
    DeadlineExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_error_display() {
        let e = GuardError::Internal("oops".into());
        assert_eq!(e.to_string(), "guard internal error: oops");
    }

    #[test]
    fn pipeline_error_display() {
        let e = PipelineError::GuardPanicked {
            guard: "test".into(),
            message: "boom".into(),
        };
        assert!(e.to_string().contains("panicked"));
    }
}
