//! Observer trait for pipeline lifecycle hooks.

use crate::context::Context;
use crate::verdict::Verdict;

/// Optional hooks invoked during pipeline evaluation.
///
/// Implement this to integrate structured logging, distributed tracing,
/// or external telemetry without modifying the pipeline itself.
pub trait Observer: Send + Sync {
    /// Called before a guard is evaluated.
    fn on_guard_start(&self, guard_name: &str, ctx: &Context) {
        let _ = (guard_name, ctx);
    }

    /// Called after a guard finishes successfully.
    fn on_guard_end(&self, guard_name: &str, verdict: &Verdict, duration_ms: u64) {
        let _ = (guard_name, verdict, duration_ms);
    }

    /// Called when a guard errors.
    fn on_guard_error(&self, guard_name: &str, error: &str) {
        let _ = (guard_name, error);
    }

    /// Called when a guard panics.
    fn on_guard_panic(&self, guard_name: &str, message: &str) {
        let _ = (guard_name, message);
    }

    /// Called when the pipeline produces a final verdict.
    fn on_pipeline_complete(&self, verdict: &Verdict, total_duration_ms: u64) {
        let _ = (verdict, total_duration_ms);
    }
}

/// A default no-op observer.
pub struct NoopObserver;

impl Observer for NoopObserver {}

/// A tracing-based observer that emits spans and events.
pub struct TracingObserver;

impl Observer for TracingObserver {
    fn on_guard_start(&self, guard_name: &str, ctx: &Context) {
        tracing::debug!(guard = guard_name, request_id = %ctx.request_id, "guard evaluation started");
    }

    fn on_guard_end(&self, guard_name: &str, verdict: &Verdict, duration_ms: u64) {
        tracing::info!(
            guard = guard_name,
            verdict = %verdict,
            duration_ms = duration_ms,
            "guard evaluation completed"
        );
    }

    fn on_guard_error(&self, guard_name: &str, error: &str) {
        tracing::error!(guard = guard_name, error = error, "guard evaluation failed");
    }

    fn on_guard_panic(&self, guard_name: &str, message: &str) {
        tracing::error!(guard = guard_name, panic = message, "guard panicked");
    }

    fn on_pipeline_complete(&self, verdict: &Verdict, total_duration_ms: u64) {
        tracing::info!(
            verdict = %verdict,
            total_duration_ms = total_duration_ms,
            "pipeline evaluation complete"
        );
    }
}
