//! Per-request context carried through the guard pipeline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Metadata and body associated with a single request evaluation.
///
/// Every [`super::Guard`] receives a shared reference to `Context`, and the
/// [`super::Pipeline`] owns it for the lifetime of one evaluation pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Context {
    /// Unique identifier for this request evaluation.
    pub request_id: String,

    /// Timestamp when this context was created.
    pub timestamp: DateTime<Utc>,

    /// The raw body / payload being evaluated.
    pub body: String,

    /// HTTP method (GET, POST, …) — if applicable.
    pub method: Option<String>,

    /// Request path (e.g. `/api/v1/users`).
    pub path: Option<String>,

    /// The identity of the caller (service name, user ID, API-key hash, …).
    pub source: Option<String>,

    /// Role of the caller for RBAC decisions.
    pub role: Option<String>,

    /// Target resource identifier for object-level authorization.
    pub target_resource: Option<String>,

    /// Owner of the target resource for object-level authorization.
    pub resource_owner: Option<String>,

    /// HMAC signature attached to the request (hex-encoded).
    pub signature: Option<String>,

    /// Nonce for replay-protection.
    pub nonce: Option<String>,

    /// Arbitrary key-value metadata a guard can inspect.
    pub metadata: HashMap<String, String>,

    /// Content-length or body size in bytes.
    pub content_length: Option<usize>,

    /// IP address of the caller.
    pub remote_addr: Option<String>,

    /// Headers as key-value pairs.
    pub headers: HashMap<String, String>,
}

impl Context {
    /// Create a minimal context with only a body.
    pub fn new(body: impl Into<String>) -> Self {
        Self {
            request_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            body: body.into(),
            method: None,
            path: None,
            source: None,
            role: None,
            target_resource: None,
            resource_owner: None,
            signature: None,
            nonce: None,
            metadata: HashMap::new(),
            content_length: None,
            remote_addr: None,
            headers: HashMap::new(),
        }
    }

    /// Builder-style setter for HTTP method.
    pub fn with_method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }

    /// Builder-style setter for request path.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// Builder-style setter for caller identity.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Builder-style setter for caller role.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.role = Some(role.into());
        self
    }

    /// Builder-style setter for target resource.
    pub fn with_target_resource(mut self, resource: impl Into<String>) -> Self {
        self.target_resource = Some(resource.into());
        self
    }

    /// Builder-style setter for resource owner.
    pub fn with_resource_owner(mut self, owner: impl Into<String>) -> Self {
        self.resource_owner = Some(owner.into());
        self
    }

    /// Builder-style setter for HMAC signature.
    pub fn with_signature(mut self, sig: impl Into<String>) -> Self {
        self.signature = Some(sig.into());
        self
    }

    /// Builder-style setter for nonce.
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Builder-style setter for content length.
    pub fn with_content_length(mut self, len: usize) -> Self {
        self.content_length = Some(len);
        self
    }

    /// Builder-style setter for remote address.
    pub fn with_remote_addr(mut self, addr: impl Into<String>) -> Self {
        self.remote_addr = Some(addr.into());
        self
    }

    /// Insert a metadata key-value pair.
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Insert a header key-value pair.
    pub fn with_header(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_builder() {
        let ctx = Context::new("hello")
            .with_method("POST")
            .with_path("/api/echo")
            .with_source("service-a")
            .with_role("admin")
            .with_meta("tenant", "acme");

        assert_eq!(ctx.body, "hello");
        assert_eq!(ctx.method.as_deref(), Some("POST"));
        assert_eq!(ctx.path.as_deref(), Some("/api/echo"));
        assert_eq!(ctx.source.as_deref(), Some("service-a"));
        assert_eq!(ctx.role.as_deref(), Some("admin"));
        assert_eq!(ctx.metadata.get("tenant").map(|s| s.as_str()), Some("acme"));
        assert!(!ctx.request_id.is_empty());
    }

    #[test]
    fn context_serializes() {
        let ctx = Context::new("test");
        let json = serde_json::to_string(&ctx).unwrap();
        assert!(json.contains("request_id"));
        assert!(json.contains("test"));
    }
}
