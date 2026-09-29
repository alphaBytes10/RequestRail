//! Structured audit trace for pipeline evaluations.

use crate::verdict::Verdict;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A structured audit log entry produced after every pipeline evaluation.
///
/// Contains enough information to reconstruct what happened, which guards
/// ran, what they decided, and why. Suitable for JSON serialization and
/// shipping to a SIEM / log aggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique request identifier.
    pub request_id: String,

    /// When the evaluation started.
    pub timestamp: DateTime<Utc>,

    /// Caller identity (if known).
    pub source: Option<String>,

    /// Request method.
    pub method: Option<String>,

    /// Request path.
    pub path: Option<String>,

    /// Per-guard trace records.
    pub guard_traces: Vec<GuardTrace>,

    /// The final verdict.
    pub final_verdict: String,

    /// Total evaluation time in milliseconds.
    pub total_duration_ms: u64,

    /// Whether the pipeline short-circuited.
    pub short_circuited: bool,
}

/// Trace record for a single guard evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardTrace {
    /// Guard name.
    pub guard: String,
    /// Verdict or error.
    pub result: GuardResult,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// The outcome of a single guard evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardResult {
    /// Guard returned a verdict.
    Verdict(String),
    /// Guard returned an error.
    Error(String),
    /// Guard panicked.
    Panic(String),
    /// Guard was skipped.
    Skipped,
}

/// Builder for constructing an audit entry during pipeline evaluation.
#[derive(Debug)]
pub struct AuditBuilder {
    request_id: String,
    timestamp: DateTime<Utc>,
    source: Option<String>,
    method: Option<String>,
    path: Option<String>,
    guard_traces: Vec<GuardTrace>,
    short_circuited: bool,
}

impl AuditBuilder {
    /// Start a new audit builder.
    pub fn new(request_id: &str) -> Self {
        Self {
            request_id: request_id.to_string(),
            timestamp: Utc::now(),
            source: None,
            method: None,
            path: None,
            guard_traces: Vec::new(),
            short_circuited: false,
        }
    }

    /// Set the caller source.
    pub fn source(mut self, source: Option<&str>) -> Self {
        self.source = source.map(|s| s.to_string());
        self
    }

    /// Set the request method.
    pub fn method(mut self, method: Option<&str>) -> Self {
        self.method = method.map(|s| s.to_string());
        self
    }

    /// Set the request path.
    pub fn path(mut self, path: Option<&str>) -> Self {
        self.path = path.map(|s| s.to_string());
        self
    }

    /// Record a guard trace.
    pub fn record(&mut self, guard: &str, result: GuardResult, duration_ms: u64) {
        self.guard_traces.push(GuardTrace {
            guard: guard.to_string(),
            result,
            duration_ms,
        });
    }

    /// Mark the evaluation as short-circuited.
    pub fn mark_short_circuit(&mut self) {
        self.short_circuited = true;
    }

    /// Finalize into an audit entry.
    pub fn finalize(self, final_verdict: &Verdict, total_duration_ms: u64) -> AuditEntry {
        AuditEntry {
            request_id: self.request_id,
            timestamp: self.timestamp,
            source: self.source,
            method: self.method,
            path: self.path,
            guard_traces: self.guard_traces,
            final_verdict: final_verdict.to_string(),
            total_duration_ms,
            short_circuited: self.short_circuited,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_builder() {
        let mut builder = AuditBuilder::new("req-123")
            .source(Some("svc-a"))
            .method(Some("POST"))
            .path(Some("/api/v1/data"));

        builder.record("auth", GuardResult::Verdict("ALLOW".into()), 2);
        builder.record("pii", GuardResult::Verdict("BLOCK: PII detected".into()), 5);
        builder.mark_short_circuit();

        let entry = builder.finalize(&Verdict::block("PII detected"), 7);
        assert_eq!(entry.request_id, "req-123");
        assert_eq!(entry.guard_traces.len(), 2);
        assert!(entry.short_circuited);
        assert!(entry.final_verdict.contains("BLOCK"));
    }

    #[test]
    fn audit_serializes_to_json() {
        let mut builder = AuditBuilder::new("req-456");
        builder.record("rate_limit", GuardResult::Verdict("ALLOW".into()), 1);
        let entry = builder.finalize(&Verdict::Allow, 1);
        let json = serde_json::to_string_pretty(&entry).unwrap();
        assert!(json.contains("req-456"));
        assert!(json.contains("rate_limit"));
    }
}
