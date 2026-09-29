//! Pipeline metrics and telemetry.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Lightweight telemetry collected during a pipeline evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    /// Total wall-clock time for the pipeline evaluation.
    pub total_duration: Duration,

    /// Per-guard evaluation durations.
    pub guard_durations: Vec<GuardMetric>,

    /// Number of guards that ran.
    pub guards_evaluated: usize,

    /// Number of guards that were skipped (e.g. due to short-circuit).
    pub guards_skipped: usize,

    /// Final verdict string.
    pub final_verdict: String,
}

/// Timing and result for a single guard evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardMetric {
    /// Guard name.
    pub name: String,
    /// Time taken by this guard.
    pub duration: Duration,
    /// The verdict or error this guard produced.
    pub result: String,
}

/// Accumulator used during pipeline evaluation.
#[derive(Debug)]
pub struct MetricsCollector {
    start: std::time::Instant,
    guard_metrics: Vec<GuardMetric>,
    guards_skipped: usize,
}

impl MetricsCollector {
    /// Create a new collector.
    pub fn new() -> Self {
        Self {
            start: std::time::Instant::now(),
            guard_metrics: Vec::new(),
            guards_skipped: 0,
        }
    }

    /// Record a guard evaluation result.
    pub fn record_guard(&mut self, name: &str, duration: Duration, result: &str) {
        self.guard_metrics.push(GuardMetric {
            name: name.to_string(),
            duration,
            result: result.to_string(),
        });
    }

    /// Increment the skipped guard counter.
    pub fn record_skip(&mut self) {
        self.guards_skipped += 1;
    }

    /// Finalize into a `Metrics` snapshot.
    pub fn finalize(self, final_verdict: &str) -> Metrics {
        Metrics {
            total_duration: self.start.elapsed(),
            guards_evaluated: self.guard_metrics.len(),
            guards_skipped: self.guards_skipped,
            guard_durations: self.guard_metrics,
            final_verdict: final_verdict.to_string(),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Thread-safe aggregate counters across many evaluations.
#[derive(Debug)]
pub struct AggregateMetrics {
    inner: Mutex<AggregateInner>,
}

#[derive(Debug, Default)]
struct AggregateInner {
    total_evaluations: u64,
    total_allows: u64,
    total_blocks: u64,
    total_errors: u64,
    guard_block_counts: HashMap<String, u64>,
}

impl AggregateMetrics {
    /// Create a new aggregate metrics tracker.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(AggregateInner::default()),
        }
    }

    /// Record an allow verdict.
    pub fn record_allow(&self) {
        let mut inner = self.inner.lock();
        inner.total_evaluations += 1;
        inner.total_allows += 1;
    }

    /// Record a block verdict with the guard that blocked.
    pub fn record_block(&self, guard_name: &str) {
        let mut inner = self.inner.lock();
        inner.total_evaluations += 1;
        inner.total_blocks += 1;
        *inner.guard_block_counts.entry(guard_name.to_string()).or_insert(0) += 1;
    }

    /// Record a pipeline error.
    pub fn record_error(&self) {
        let mut inner = self.inner.lock();
        inner.total_evaluations += 1;
        inner.total_errors += 1;
    }

    /// Get a snapshot of the counters.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let inner = self.inner.lock();
        MetricsSnapshot {
            total_evaluations: inner.total_evaluations,
            total_allows: inner.total_allows,
            total_blocks: inner.total_blocks,
            total_errors: inner.total_errors,
            guard_block_counts: inner.guard_block_counts.clone(),
        }
    }
}

impl Default for AggregateMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable snapshot of aggregate metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub total_evaluations: u64,
    pub total_allows: u64,
    pub total_blocks: u64,
    pub total_errors: u64,
    pub guard_block_counts: HashMap<String, u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_collector() {
        let mut mc = MetricsCollector::new();
        mc.record_guard("test", Duration::from_millis(5), "ALLOW");
        mc.record_skip();
        let m = mc.finalize("ALLOW");
        assert_eq!(m.guards_evaluated, 1);
        assert_eq!(m.guards_skipped, 1);
        assert_eq!(m.final_verdict, "ALLOW");
    }

    #[test]
    fn aggregate_metrics() {
        let agg = AggregateMetrics::new();
        agg.record_allow();
        agg.record_allow();
        agg.record_block("pii");
        agg.record_error();
        let snap = agg.snapshot();
        assert_eq!(snap.total_evaluations, 4);
        assert_eq!(snap.total_allows, 2);
        assert_eq!(snap.total_blocks, 1);
        assert_eq!(snap.total_errors, 1);
        assert_eq!(snap.guard_block_counts.get("pii"), Some(&1));
    }
}
