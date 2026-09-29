//! # RequestRail Core
//!
//! The foundational crate of the **RequestRail** security gateway.
//!
//! This crate provides:
//! - [`Guard`] — the central trait every security module implements
//! - [`Pipeline`] — an ordered chain of guards that produces a final [`Verdict`]
//! - [`Context`] — per-request metadata carried through the pipeline
//! - [`Verdict`] — the allow / block / modify decision
//! - [`Policy`] — fail-open vs fail-closed behaviour on guard errors
//! - [`AuditEntry`] — structured audit log records
//! - [`Metrics`] — lightweight pipeline telemetry
//!
//! Guards run **synchronously and inline** in the request path. No async
//! runtime is required; the pipeline can be embedded in any Rust program.

pub mod context;
pub mod deadline;
pub mod error;
pub mod guard;
pub mod metrics;
pub mod observe;
pub mod pipeline;
pub mod policy;
pub mod trace;
pub mod verdict;

// Re-exports for ergonomic use
pub use context::Context;
pub use error::{GuardError, PipelineError};
pub use guard::Guard;
pub use metrics::Metrics;
pub use observe::Observer;
pub use pipeline::Pipeline;
pub use policy::FailPolicy;
pub use verdict::Verdict;
