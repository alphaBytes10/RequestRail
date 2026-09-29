//! # RequestRail HTTP
//!
//! Axum/Tower middleware adapter for the RequestRail security pipeline.
//!
//! Provides [`RequestRailLayer`] and [`RequestRailMiddleware`] that wrap
//! an Axum handler or Tower service, running the security pipeline on
//! every incoming request before forwarding to the inner handler.
//!
//! # Example
//! ```rust,no_run
//! use axum::{Router, routing::post};
//! use requestrail_core::Pipeline;
//! use requestrail_http::RequestRailLayer;
//! use std::sync::Arc;
//!
//! let pipeline = Arc::new(Pipeline::new());
//! let app = Router::new()
//!     .route("/echo", post(|| async { "ok" }))
//!     .layer(RequestRailLayer::new(pipeline));
//! ```

use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use requestrail_core::{Context, Pipeline, Verdict};
use std::sync::Arc;

/// Axum middleware layer for RequestRail.
#[derive(Clone)]
pub struct RequestRailLayer {
    pipeline: Arc<Pipeline>,
}

impl RequestRailLayer {
    /// Create a new middleware layer wrapping the given pipeline.
    pub fn new(pipeline: Arc<Pipeline>) -> Self {
        Self { pipeline }
    }
}

impl<S> tower::Layer<S> for RequestRailLayer {
    type Service = RequestRailMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestRailMiddleware {
            inner,
            pipeline: self.pipeline.clone(),
        }
    }
}

/// The middleware service that evaluates requests through the pipeline.
#[derive(Clone)]
pub struct RequestRailMiddleware<S> {
    inner: S,
    pipeline: Arc<Pipeline>,
}

/// Axum middleware function for use with `axum::middleware::from_fn`.
///
/// # Example
/// ```rust,no_run
/// use axum::{Router, routing::post, middleware};
/// use requestrail_core::Pipeline;
/// use requestrail_http::requestrail_middleware;
/// use std::sync::Arc;
///
/// async fn handler() -> &'static str { "ok" }
///
/// let pipeline = Arc::new(Pipeline::new());
/// let app = Router::new()
///     .route("/echo", post(handler))
///     .layer(middleware::from_fn(move |req, next| {
///         let p = pipeline.clone();
///         requestrail_middleware(p, req, next)
///     }));
/// ```
pub async fn requestrail_middleware(
    pipeline: Arc<Pipeline>,
    request: Request,
    next: Next,
) -> Response {
    let (parts, body) = request.into_parts();

    // Collect body bytes
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "failed to read request body").into_response();
        }
    };

    let body_str = String::from_utf8_lossy(&body_bytes).to_string();

    // Build context from HTTP request
    let mut ctx = Context::new(&body_str)
        .with_method(parts.method.as_str())
        .with_path(parts.uri.path())
        .with_content_length(body_bytes.len());

    // Extract source from headers
    if let Some(auth) = parts.headers.get("authorization") {
        if let Ok(v) = auth.to_str() {
            ctx = ctx.with_meta("authorization", v);
        }
    }

    if let Some(source) = parts.headers.get("x-requestrail-source") {
        if let Ok(v) = source.to_str() {
            ctx = ctx.with_source(v);
        }
    }

    if let Some(role) = parts.headers.get("x-requestrail-role") {
        if let Ok(v) = role.to_str() {
            ctx = ctx.with_role(v);
        }
    }

    if let Some(sig) = parts.headers.get("x-requestrail-signature") {
        if let Ok(v) = sig.to_str() {
            ctx = ctx.with_signature(v);
        }
    }

    if let Some(nonce) = parts.headers.get("x-requestrail-nonce") {
        if let Ok(v) = nonce.to_str() {
            ctx = ctx.with_nonce(v);
        }
    }

    // Run the pipeline
    match pipeline.evaluate(ctx) {
        Ok((verdict, audit)) => {
            match verdict {
                Verdict::Allow => {
                    // Reconstruct request and forward
                    let request = Request::from_parts(parts, Body::from(body_bytes));
                    let mut response = next.run(request).await;
                    // Add audit header
                    response.headers_mut().insert(
                        "x-requestrail-request-id",
                        audit.request_id.parse().unwrap_or_default(),
                    );
                    response
                }
                Verdict::Block { reason } => {
                    let body = serde_json::json!({
                        "error": "blocked",
                        "reason": reason,
                        "request_id": audit.request_id,
                    });
                    (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
                }
                Verdict::Modify { new_body, .. } => {
                    // Forward with modified body
                    let request = Request::from_parts(parts, Body::from(Bytes::from(new_body)));
                    let mut response = next.run(request).await;
                    response.headers_mut().insert(
                        "x-requestrail-modified",
                        "true".parse().unwrap_or_default(),
                    );
                    response
                }
            }
        }
        Err(err) => {
            let body = serde_json::json!({
                "error": "pipeline_error",
                "reason": err.to_string(),
            });
            (StatusCode::INTERNAL_SERVER_ERROR, axum::Json(body)).into_response()
        }
    }
}
