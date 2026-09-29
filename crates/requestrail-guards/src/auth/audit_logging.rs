//! Audit logging guard — always allows, records structured audit trail.

use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;
use chrono::Utc;
use serde::Serialize;

/// A pass-through guard that logs every request for audit purposes.
///
/// This guard always returns `Allow` — it only exists to create a
/// structured audit record. Place it first or last in the pipeline
/// depending on whether you want to log all attempts or only
/// allowed requests.
pub struct AuditLoggingGuard {
    log_body: bool,
}

#[derive(Debug, Serialize)]
struct AuditRecord {
    timestamp: String,
    request_id: String,
    source: Option<String>,
    method: Option<String>,
    path: Option<String>,
    role: Option<String>,
    remote_addr: Option<String>,
    body_length: usize,
    body_preview: Option<String>,
}

impl AuditLoggingGuard {
    /// Create a new audit logging guard.
    pub fn new() -> Self {
        Self { log_body: false }
    }

    /// Include a body preview (first 200 chars) in the audit log.
    pub fn with_body_preview(mut self) -> Self {
        self.log_body = true;
        self
    }
}

impl Default for AuditLoggingGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for AuditLoggingGuard {
    fn name(&self) -> &str {
        "audit_logging"
    }

    fn description(&self) -> &str {
        "Structured audit logging (always allows)"
    }

    fn priority(&self) -> u32 {
        0 // Run first
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let record = AuditRecord {
            timestamp: Utc::now().to_rfc3339(),
            request_id: ctx.request_id.clone(),
            source: ctx.source.clone(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            role: ctx.role.clone(),
            remote_addr: ctx.remote_addr.clone(),
            body_length: ctx.body.len(),
            body_preview: if self.log_body {
                Some(ctx.body.chars().take(200).collect())
            } else {
                None
            },
        };

        tracing::info!(
            audit = %serde_json::to_string(&record).unwrap_or_else(|_| "serialization error".into()),
            "request audit"
        );

        Ok(Verdict::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_allows() {
        let guard = AuditLoggingGuard::new();
        let ctx = Context::new("anything")
            .with_source("test-svc")
            .with_path("/api/data");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn with_body_preview() {
        let guard = AuditLoggingGuard::new().with_body_preview();
        let ctx = Context::new("test body content");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }
}
