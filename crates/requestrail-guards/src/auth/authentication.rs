//! HMAC-based authentication guard.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;

type HmacSha256 = Hmac<Sha256>;

/// Verifies that a request comes from a known, legitimate service or user
/// by validating an HMAC signature against a shared secret.
///
/// The guard looks for `ctx.source` (the service/user identity) and
/// `ctx.signature` (hex-encoded HMAC-SHA256 of the body).
pub struct AuthenticationGuard {
    /// Map of known service/user identities to their shared secrets.
    secrets: HashMap<String, Vec<u8>>,
}

impl AuthenticationGuard {
    /// Create a new authentication guard.
    pub fn new() -> Self {
        Self {
            secrets: HashMap::new(),
        }
    }

    /// Register a service/user with its shared secret.
    pub fn with_credential(mut self, identity: &str, secret: &[u8]) -> Self {
        self.secrets.insert(identity.to_string(), secret.to_vec());
        self
    }

    /// Verify an HMAC-SHA256 signature.
    fn verify_hmac(&self, secret: &[u8], body: &str, signature: &str) -> bool {
        let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
            return false;
        };
        mac.update(body.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());
        // Constant-time comparison via HMAC crate
        expected == signature
    }
}

impl Default for AuthenticationGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for AuthenticationGuard {
    fn name(&self) -> &str {
        "authentication"
    }

    fn description(&self) -> &str {
        "HMAC-SHA256 authentication of service/user identity"
    }

    fn priority(&self) -> u32 {
        1
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let source = ctx.source.as_deref().ok_or_else(|| {
            GuardError::MissingField("source (caller identity)".into())
        })?;

        let signature = ctx.signature.as_deref().ok_or_else(|| {
            GuardError::MissingField("signature".into())
        })?;

        let secret = match self.secrets.get(source) {
            Some(s) => s,
            None => {
                return Ok(Verdict::block(format!(
                    "unknown identity: '{source}'"
                )));
            }
        };

        if self.verify_hmac(secret, &ctx.body, signature) {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::block(format!(
                "authentication failed: invalid signature for '{source}'"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(secret: &[u8], body: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).unwrap();
        mac.update(body.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn valid_authentication() {
        let secret = b"my-secret-key";
        let body = "hello world";
        let sig = sign(secret, body);

        let guard = AuthenticationGuard::new()
            .with_credential("svc-a", secret);

        let ctx = Context::new(body)
            .with_source("svc-a")
            .with_signature(&sig);

        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn invalid_signature() {
        let guard = AuthenticationGuard::new()
            .with_credential("svc-a", b"secret");

        let ctx = Context::new("hello")
            .with_source("svc-a")
            .with_signature("bad-signature");

        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn unknown_identity() {
        let guard = AuthenticationGuard::new()
            .with_credential("svc-a", b"secret");

        let ctx = Context::new("hello")
            .with_source("unknown")
            .with_signature("anything");

        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
        assert!(verdict.to_string().contains("unknown identity"));
    }
}
