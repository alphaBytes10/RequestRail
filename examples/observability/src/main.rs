//! Observability & Telemetry Demo
//!
//! Demonstrates the use of Observers and AggregateMetrics to monitor
//! pipeline performance and block rates.

use requestrail_core::{
    Context, Pipeline, AggregateMetrics, 
    observe::{Observer, TracingObserver}
};
use requestrail_guards::{RateLimitGuard, PiiDetectionGuard, AuditLoggingGuard};
use requestrail_guards::pii::PiiMode;
use std::sync::Arc;
use std::time::Duration;

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("RequestRail — Observability Demo\n");

    let aggregate = Arc::new(AggregateMetrics::new());
    
    // Create an observer that logs spans and records metrics
    struct CustomObserver {
        metrics: Arc<AggregateMetrics>,
        tracer: TracingObserver,
    }

    impl Observer for CustomObserver {
        fn on_guard_start(&self, guard_name: &str, ctx: &Context) {
            self.tracer.on_guard_start(guard_name, ctx);
        }

        fn on_guard_end(&self, guard_name: &str, verdict: &requestrail_core::Verdict, duration_ms: u64) {
            self.tracer.on_guard_end(guard_name, verdict, duration_ms);
            
            if verdict.is_block() {
                self.metrics.record_block(guard_name);
            }
        }

        fn on_guard_error(&self, guard_name: &str, error: &str) {
            self.tracer.on_guard_error(guard_name, error);
            self.metrics.record_error();
        }

        fn on_pipeline_complete(&self, verdict: &requestrail_core::Verdict, duration_ms: u64) {
            self.tracer.on_pipeline_complete(verdict, duration_ms);
            if verdict.is_allow() || verdict.is_modify() {
                self.metrics.record_allow();
            }
        }
    }

    let observer = CustomObserver {
        metrics: aggregate.clone(),
        tracer: TracingObserver,
    };

    let pipeline = Pipeline::new()
        .observer(observer)
        .deadline(Duration::from_millis(50))
        .with(AuditLoggingGuard::new())
        .with(RateLimitGuard::new(2, 10.0))
        .with(PiiDetectionGuard::new(PiiMode::Block).expect("patterns"));

    // Simulate traffic
    let bodies = vec![
        "clean request 1",
        "clean request 2",
        "My email is test@example.com", // blocked by PII
        "clean request 3",              // blocked by RateLimit (capacity = 2)
    ];

    for (i, body) in bodies.iter().enumerate() {
        println!("\n--- Request {} ---", i + 1);
        let ctx = Context::new(body).with_source("client-x");
        let _ = pipeline.evaluate(ctx);
    }

    // Print aggregate metrics
    println!("\n=== Final Aggregate Metrics ===");
    let snap = aggregate.snapshot();
    println!("Total Evaluated: {}", snap.total_evaluations);
    println!("Total Allowed  : {}", snap.total_allows);
    println!("Total Blocked  : {}", snap.total_blocks);
    println!("Total Errors   : {}", snap.total_errors);
    println!("Block Counts   : {:?}", snap.guard_block_counts);
}
