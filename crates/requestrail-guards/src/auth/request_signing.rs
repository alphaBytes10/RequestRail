//! HMAC request signing guard — verifies request integrity.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;

type HmacSha256 = Hmac<Sha256>;

/// Verifies that the request body has not been tampered with in transit.
///
/// Checks the HMAC-SHA256 signature in `ctx.signature` against the body
/// using a shared signing key. This is separate from the authentication
/// guard — it only checks integrity, not identity.
pub struct RequestSigningGuard {
    signing_key: Vec<u8>,
}

impl RequestSigningGuard {
    /// Create a new request signing guard with the given key.
    pub fn new(signing_key: &[u8]) -> Self {
        Self {
            signing_key: signing_key.to_vec(),
        }
    }

    /// Compute an HMAC-SHA256 signature for a body.
    pub fn sign(key: &[u8], body: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
        mac.update(body.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

impl Guard for RequestSigningGuard {
    fn name(&self) -> &str {
        "request_signing"
    }

    fn description(&self) -> &str {
        "HMAC-SHA256 request integrity verification"
    }

    fn priority(&self) -> u32 {
        3
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let signature = ctx.signature.as_deref().ok_or_else(|| {
            GuardError::MissingField("signature".into())
        })?;

        let expected = Self::sign(&self.signing_key, &ctx.body);

        if expected == signature {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::block("request integrity check failed: signature mismatch"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_signature() {
        let key = b"signing-key-123";
        let body = "important data";
        let sig = RequestSigningGuard::sign(key, body);

        let guard = RequestSigningGuard::new(key);
        let ctx = Context::new(body).with_signature(&sig);
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn tampered_body() {
        let key = b"signing-key-123";
        let sig = RequestSigningGuard::sign(key, "original data");

        let guard = RequestSigningGuard::new(key);
        let ctx = Context::new("tampered data").with_signature(&sig);
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn missing_signature() {
        let guard = RequestSigningGuard::new(b"key");
        let ctx = Context::new("data");
        assert!(guard.evaluate(&ctx).is_err());
    }
}
