//! Axum HTTP middleware demo.
//!
//! Demonstrates how to wrap an Axum application with the RequestRail middleware.
//! Run with: `cargo run --example axum_middleware`

use axum::{
    routing::{get, post},
    Router, Json, middleware,
};
use requestrail_core::Pipeline;
use requestrail_guards::{PiiDetectionGuard, RateLimitGuard, AuditLoggingGuard};
use requestrail_guards::pii::PiiMode;
use requestrail_http::requestrail_middleware;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::fmt::format::FmtSpan;

#[tokio::main]
async fn main() {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_span_events(FmtSpan::CLOSE)
        .init();

    tracing::info!("Starting RequestRail Axum demo on 0.0.0.0:3000");

    // Build the security pipeline
    let pipeline = Arc::new(
        Pipeline::new()
            .with(AuditLoggingGuard::new().with_body_preview())
            .with(RateLimitGuard::new(5, 1.0)) // 5 req burst, 1 req/sec
            .with(PiiDetectionGuard::new(PiiMode::Block).expect("patterns"))
    );

    // Build the Axum router
    let app = Router::new()
        .route("/", get(|| async { "RequestRail is protecting this API\n" }))
        .route("/api/echo", post(echo_handler))
        .layer(middleware::from_fn(move |req, next| {
            requestrail_middleware(pipeline.clone(), req, next)
        }));

    // Start the server
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn echo_handler(body: String) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "success",
        "echo": body,
    }))
}
