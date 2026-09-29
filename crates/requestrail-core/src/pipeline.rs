//! Pipeline — ordered chain of guards that produces a final verdict.
//!
//! The pipeline evaluates guards in order. On the first `Block` verdict it
//! short-circuits and returns immediately. `Modify` verdicts update the
//! context body and the pipeline continues. If all guards return `Allow`,
//! the pipeline returns `Allow`.
//!
//! Guard panics are caught via `std::panic::catch_unwind` and handled
//! according to the configured [`super::FailPolicy`].

use crate::context::Context;
use crate::deadline::Deadline;
use crate::error::{GuardError, PipelineError};
use crate::guard::{BoxGuard, Guard};
use crate::metrics::MetricsCollector;
use crate::observe::{NoopObserver, Observer};
use crate::policy::FailPolicy;
use crate::trace::{AuditBuilder, AuditEntry, GuardResult};
use crate::verdict::Verdict;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A configured evaluation pipeline.
///
/// # Example
/// ```rust
/// use requestrail_core::{Context, Pipeline, Verdict};
///
/// // An empty pipeline allows everything.
/// let pipeline = Pipeline::new();
/// let ctx = Context::new("hello");
/// let (verdict, _audit) = pipeline.evaluate(ctx).unwrap();
/// assert!(verdict.is_allow());
/// ```
pub struct Pipeline {
    guards: Vec<BoxGuard>,
    fail_policy: FailPolicy,
    deadline: Option<Duration>,
    observer: Arc<dyn Observer>,
}

impl Pipeline {
    /// Create an empty pipeline with default settings (fail-closed, no deadline).
    pub fn new() -> Self {
        Self {
            guards: Vec::new(),
            fail_policy: FailPolicy::Closed,
            deadline: None,
            observer: Arc::new(NoopObserver),
        }
    }

    /// Add a guard to the pipeline. Guards run in insertion order.
    pub fn with(mut self, guard: impl Guard + 'static) -> Self {
        self.guards.push(Box::new(guard));
        self
    }

    /// Add a boxed guard.
    pub fn with_boxed(mut self, guard: BoxGuard) -> Self {
        self.guards.push(guard);
        self
    }

    /// Set the fail policy.
    pub fn fail_policy(mut self, policy: FailPolicy) -> Self {
        self.fail_policy = policy;
        self
    }

    /// Set a pipeline-wide deadline.
    pub fn deadline(mut self, timeout: Duration) -> Self {
        self.deadline = Some(timeout);
        self
    }

    /// Set an observer for lifecycle hooks.
    pub fn observer(mut self, observer: impl Observer + 'static) -> Self {
        self.observer = Arc::new(observer);
        self
    }

    /// Returns the number of guards in the pipeline.
    pub fn len(&self) -> usize {
        self.guards.len()
    }

    /// Returns true if the pipeline has no guards.
    pub fn is_empty(&self) -> bool {
        self.guards.is_empty()
    }

    /// Evaluate all guards against the given context.
    ///
    /// Returns the final verdict and a structured audit entry.
    ///
    /// On the first `Block`, the pipeline short-circuits.
    /// On `Modify`, the body is updated and evaluation continues.
    /// Guard panics are caught and handled per the fail policy.
    pub fn evaluate(&self, mut ctx: Context) -> Result<(Verdict, AuditEntry), PipelineError> {
        let pipeline_start = Instant::now();
        let deadline = self.deadline.map(Deadline::new);
        let mut metrics = MetricsCollector::new();

        let mut audit = AuditBuilder::new(&ctx.request_id)
            .source(ctx.source.as_deref())
            .method(ctx.method.as_deref())
            .path(ctx.path.as_deref());

        let mut final_verdict = Verdict::Allow;

        for guard in &self.guards {
            // Check deadline before each guard
            if let Some(ref dl) = deadline {
                if dl.is_exceeded() {
                    audit.mark_short_circuit();
                    return Err(PipelineError::DeadlineExceeded);
                }
            }

            let guard_name = guard.name().to_string();
            self.observer.on_guard_start(&guard_name, &ctx);
            let guard_start = Instant::now();

            // Catch panics
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                guard.evaluate(&ctx)
            }));

            let guard_duration = guard_start.elapsed();
            let duration_ms = guard_duration.as_millis() as u64;

            match result {
                Ok(Ok(verdict)) => {
                    metrics.record_guard(&guard_name, guard_duration, &verdict.to_string());
                    self.observer.on_guard_end(&guard_name, &verdict, duration_ms);
                    audit.record(&guard_name, GuardResult::Verdict(verdict.to_string()), duration_ms);

                    match verdict {
                        Verdict::Allow => {
                            // Continue to next guard
                        }
                        Verdict::Block { .. } => {
                            final_verdict = verdict;
                            audit.mark_short_circuit();
                            break;
                        }
                        Verdict::Modify { new_body, reason } => {
                            ctx.body = new_body;
                            // Continue with modified body
                            tracing::debug!(
                                guard = guard_name.as_str(),
                                reason = reason.as_str(),
                                "body modified by guard"
                            );
                        }
                    }
                }
                Ok(Err(err)) => {
                    let err_str = err.to_string();
                    self.observer.on_guard_error(&guard_name, &err_str);
                    audit.record(&guard_name, GuardResult::Error(err_str.clone()), duration_ms);
                    metrics.record_guard(&guard_name, guard_duration, &format!("ERROR: {err_str}"));

                    match self.fail_policy {
                        FailPolicy::Closed => {
                            final_verdict = Verdict::block(format!(
                                "guard '{guard_name}' failed (fail-closed): {err_str}"
                            ));
                            audit.mark_short_circuit();
                            break;
                        }
                        FailPolicy::Open => {
                            tracing::warn!(
                                guard = guard_name.as_str(),
                                error = err_str.as_str(),
                                "guard error ignored (fail-open)"
                            );
                            // Continue to next guard
                        }
                    }
                }
                Err(panic_info) => {
                    let message = panic_message(&panic_info);
                    self.observer.on_guard_panic(&guard_name, &message);
                    audit.record(&guard_name, GuardResult::Panic(message.clone()), duration_ms);
                    metrics.record_guard(&guard_name, guard_duration, &format!("PANIC: {message}"));

                    match self.fail_policy {
                        FailPolicy::Closed => {
                            final_verdict = Verdict::block(format!(
                                "guard '{guard_name}' panicked (fail-closed): {message}"
                            ));
                            audit.mark_short_circuit();
                            break;
                        }
                        FailPolicy::Open => {
                            tracing::warn!(
                                guard = guard_name.as_str(),
                                panic = message.as_str(),
                                "guard panic ignored (fail-open)"
                            );
                            // Continue to next guard
                        }
                    }
                }
            }
        }

        let total_duration_ms = pipeline_start.elapsed().as_millis() as u64;
        self.observer.on_pipeline_complete(&final_verdict, total_duration_ms);
        let audit_entry = audit.finalize(&final_verdict, total_duration_ms);

        Ok((final_verdict, audit_entry))
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("guard_count", &self.guards.len())
            .field("fail_policy", &self.fail_policy)
            .field("deadline", &self.deadline)
            .finish()
    }
}

/// Extract a message from a panic payload.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GuardError;

    struct AllowGuard;
    impl Guard for AllowGuard {
        fn name(&self) -> &str { "allow" }
        fn evaluate(&self, _: &Context) -> Result<Verdict, GuardError> {
            Ok(Verdict::Allow)
        }
    }

    struct BlockGuard(String);
    impl Guard for BlockGuard {
        fn name(&self) -> &str { "block" }
        fn evaluate(&self, _: &Context) -> Result<Verdict, GuardError> {
            Ok(Verdict::block(&self.0))
        }
    }

    struct PanicGuard;
    impl Guard for PanicGuard {
        fn name(&self) -> &str { "panic" }
        fn evaluate(&self, _: &Context) -> Result<Verdict, GuardError> {
            panic!("intentional test panic");
        }
    }

    struct ErrorGuard;
    impl Guard for ErrorGuard {
        fn name(&self) -> &str { "error" }
        fn evaluate(&self, _: &Context) -> Result<Verdict, GuardError> {
            Err(GuardError::Internal("test error".into()))
        }
    }

    struct ModifyGuard;
    impl Guard for ModifyGuard {
        fn name(&self) -> &str { "modify" }
        fn evaluate(&self, _: &Context) -> Result<Verdict, GuardError> {
            Ok(Verdict::modify("REDACTED", "body was redacted"))
        }
    }

    #[test]
    fn empty_pipeline_allows() {
        let pipeline = Pipeline::new();
        let ctx = Context::new("test");
        let (verdict, audit) = pipeline.evaluate(ctx).unwrap();
        assert!(verdict.is_allow());
        assert!(!audit.short_circuited);
    }

    #[test]
    fn all_allow() {
        let pipeline = Pipeline::new()
            .with(AllowGuard)
            .with(AllowGuard);
        let ctx = Context::new("test");
        let (verdict, audit) = pipeline.evaluate(ctx).unwrap();
        assert!(verdict.is_allow());
        assert_eq!(audit.guard_traces.len(), 2);
    }

    #[test]
    fn short_circuits_on_block() {
        let pipeline = Pipeline::new()
            .with(AllowGuard)
            .with(BlockGuard("denied".into()))
            .with(AllowGuard); // should not run

        let ctx = Context::new("test");
        let (verdict, audit) = pipeline.evaluate(ctx).unwrap();
        assert!(verdict.is_block());
        assert_eq!(audit.guard_traces.len(), 2);
        assert!(audit.short_circuited);
    }

    #[test]
    fn panic_fail_closed() {
        let pipeline = Pipeline::new()
            .fail_policy(FailPolicy::Closed)
            .with(PanicGuard);

        let ctx = Context::new("test");
        let (verdict, _) = pipeline.evaluate(ctx).unwrap();
        assert!(verdict.is_block());
        assert!(verdict.to_string().contains("panicked"));
    }

    #[test]
    fn panic_fail_open() {
        let pipeline = Pipeline::new()
            .fail_policy(FailPolicy::Open)
            .with(PanicGuard)
            .with(AllowGuard);

        let ctx = Context::new("test");
        let (verdict, _) = pipeline.evaluate(ctx).unwrap();
        assert!(verdict.is_allow());
    }

    #[test]
    fn error_fail_closed() {
        let pipeline = Pipeline::new()
            .fail_policy(FailPolicy::Closed)
            .with(ErrorGuard);

        let ctx = Context::new("test");
        let (verdict, _) = pipeline.evaluate(ctx).unwrap();
        assert!(verdict.is_block());
    }

    #[test]
    fn error_fail_open() {
        let pipeline = Pipeline::new()
            .fail_policy(FailPolicy::Open)
            .with(ErrorGuard)
            .with(AllowGuard);

        let ctx = Context::new("test");
        let (verdict, _) = pipeline.evaluate(ctx).unwrap();
        assert!(verdict.is_allow());
    }

    #[test]
    fn modify_updates_body() {
        let pipeline = Pipeline::new()
            .with(ModifyGuard)
            .with(AllowGuard);

        let ctx = Context::new("sensitive data");
        let (verdict, audit) = pipeline.evaluate(ctx).unwrap();
        assert!(verdict.is_allow());
        assert_eq!(audit.guard_traces.len(), 2);
    }

    #[test]
    fn deadline_exceeded() {
        let pipeline = Pipeline::new()
            .deadline(Duration::from_nanos(1)) // Extremely tight deadline
            .with(AllowGuard);

        // Sleep a tiny bit to ensure deadline passes
        std::thread::sleep(Duration::from_millis(1));
        let ctx = Context::new("test");
        let result = pipeline.evaluate(ctx);
        assert!(result.is_err());
    }

    #[test]
    fn pipeline_debug() {
        let p = Pipeline::new().with(AllowGuard);
        let debug = format!("{:?}", p);
        assert!(debug.contains("Pipeline"));
        assert!(debug.contains("guard_count"));
    }
}
