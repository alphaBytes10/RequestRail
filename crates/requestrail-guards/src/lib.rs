//! # RequestRail Guards
//!
//! Ready-to-use security guard implementations for the RequestRail pipeline.
//!
//! ## Tier 1 — Fully implemented & tested
//! - [`AuthenticationGuard`] — HMAC-based service/user authentication
//! - [`RbacGuard`] — Role-based access control
//! - [`PolicyEngineGuard`] — Rule-based policy decisions
//! - [`PiiDetectionGuard`] — PII pattern detection (email, phone, SSN, etc.)
//! - [`SecretDetectionGuard`] — API key / token / password detection
//! - [`RateLimitGuard`] — Token-bucket rate limiting per client
//! - [`RequestSigningGuard`] — HMAC request integrity verification
//! - [`ReplayProtectionGuard`] — Nonce-based replay prevention
//! - [`AuditLoggingGuard`] — Structured audit trail (always allows)
//!
//! ## Tier 2 — Properly implemented
//! - [`ObjectAuthGuard`] — Object-level authorization (BOLA protection)
//! - [`FunctionAuthGuard`] — Function-level authorization
//! - [`InputValidationGuard`] — Request body validation
//! - [`RequestSizeLimitGuard`] — Request size enforcement
//!
//! ## Tier 3 — AI/Security extension
//! - [`PromptInjectionGuard`] — Prompt-injection heuristic detection
//! - [`LlmOutputGuard`] — LLM output content inspection

pub mod pii;
pub mod rate_limit;
pub mod regex_filter;
pub mod auth;
pub mod llm;
pub mod redis_guards;

// Re-exports
pub use auth::authentication::AuthenticationGuard;
pub use auth::rbac::RbacGuard;
pub use auth::policy_engine::PolicyEngineGuard;
pub use auth::request_signing::RequestSigningGuard;
pub use auth::replay_protection::ReplayProtectionGuard;
pub use auth::object_auth::ObjectAuthGuard;
pub use auth::function_auth::FunctionAuthGuard;
pub use auth::audit_logging::AuditLoggingGuard;
pub use pii::PiiDetectionGuard;
pub use pii::SecretDetectionGuard;
pub use rate_limit::RateLimitGuard;
pub use regex_filter::RegexFilterGuard;
pub use regex_filter::InputValidationGuard;
pub use regex_filter::RequestSizeLimitGuard;
pub use llm::prompt_injection::PromptInjectionGuard;
pub use llm::output_classifier::LlmOutputGuard;
pub use redis_guards::RedisRateLimitGuard;
pub use redis_guards::RedisReplayProtectionGuard;
