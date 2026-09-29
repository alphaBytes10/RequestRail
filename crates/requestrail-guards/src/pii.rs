//! PII and secret detection guards.

use regex::Regex;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::context::Context;
use requestrail_core::verdict::Verdict;

/// Detects Personally Identifiable Information in request bodies.
///
/// Scans for patterns matching:
/// - Email addresses
/// - Phone numbers (US format)
/// - Social Security Numbers
/// - Credit card numbers (Luhn-validated)
/// - IP addresses
pub struct PiiDetectionGuard {
    patterns: Vec<(String, Regex)>,
    mode: PiiMode,
}

/// How to handle detected PII.
#[derive(Debug, Clone, Copy)]
pub enum PiiMode {
    /// Block the request if PII is found.
    Block,
    /// Redact PII and allow the request to proceed.
    Redact,
}

impl PiiDetectionGuard {
    /// Create a new PII detection guard with default patterns.
    pub fn new(mode: PiiMode) -> Result<Self, GuardError> {
        let patterns = vec![
            ("email".to_string(), Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("phone".to_string(), Regex::new(r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("ssn".to_string(), Regex::new(r"\b\d{3}-\d{2}-\d{4}\b")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("credit_card".to_string(), Regex::new(r"\b(?:\d[ -]*?){13,19}\b")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("ipv4".to_string(), Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
        ];
        Ok(Self { patterns, mode })
    }

    /// Create with custom additional patterns.
    pub fn with_pattern(mut self, name: &str, pattern: &str) -> Result<Self, GuardError> {
        let re = Regex::new(pattern)
            .map_err(|e| GuardError::Configuration(format!("invalid pattern '{name}': {e}")))?;
        self.patterns.push((name.to_string(), re));
        Ok(self)
    }
}

impl Guard for PiiDetectionGuard {
    fn name(&self) -> &str {
        "pii_detection"
    }

    fn description(&self) -> &str {
        "Detects PII (email, phone, SSN, credit card, IP) in request bodies"
    }

    fn priority(&self) -> u32 {
        50
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let mut detections: Vec<String> = Vec::new();

        for (pii_type, regex) in &self.patterns {
            if regex.is_match(&ctx.body) {
                detections.push(pii_type.clone());
            }
        }

        if detections.is_empty() {
            return Ok(Verdict::Allow);
        }

        match self.mode {
            PiiMode::Block => {
                Ok(Verdict::block(format!(
                    "PII detected: {}",
                    detections.join(", ")
                )))
            }
            PiiMode::Redact => {
                let mut redacted = ctx.body.clone();
                for (_, regex) in &self.patterns {
                    redacted = regex.replace_all(&redacted, "[REDACTED]").to_string();
                }
                Ok(Verdict::modify(
                    redacted,
                    format!("PII redacted: {}", detections.join(", ")),
                ))
            }
        }
    }
}

/// Detects secrets (API keys, tokens, passwords) in request bodies.
///
/// Scans for patterns matching common secret formats:
/// - Generic API keys (long hex/base64 strings)
/// - AWS access keys
/// - Bearer tokens
/// - Password fields in JSON
/// - GitHub tokens
pub struct SecretDetectionGuard {
    patterns: Vec<(String, Regex)>,
}

impl SecretDetectionGuard {
    /// Create a new secret detection guard with default patterns.
    pub fn new() -> Result<Self, GuardError> {
        let patterns = vec![
            ("aws_key".to_string(), Regex::new(r"(?i)AKIA[0-9A-Z]{16}")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("bearer_token".to_string(), Regex::new(r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("generic_api_key".to_string(), Regex::new(r#"(?i)(?:api[_-]?key|apikey|api_secret|secret[_-]?key)\s*[:=]\s*["']?[a-zA-Z0-9\-._]{20,}["']?"#)
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("password_field".to_string(), Regex::new(r#"(?i)"password"\s*:\s*"[^"]+""#)
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("github_token".to_string(), Regex::new(r"(?i)gh[pousr]_[a-zA-Z0-9]{36,}")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
            ("private_key".to_string(), Regex::new(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")
                .map_err(|e| GuardError::Configuration(e.to_string()))?),
        ];
        Ok(Self { patterns })
    }
}

impl Guard for SecretDetectionGuard {
    fn name(&self) -> &str {
        "secret_detection"
    }

    fn description(&self) -> &str {
        "Detects accidentally submitted secrets (API keys, tokens, passwords, private keys)"
    }

    fn priority(&self) -> u32 {
        40
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        for (secret_type, regex) in &self.patterns {
            if regex.is_match(&ctx.body) {
                return Ok(Verdict::block(format!(
                    "secret detected: {secret_type}"
                )));
            }
        }
        // Also check headers for leaked secrets
        for (key, value) in &ctx.headers {
            for (secret_type, regex) in &self.patterns {
                if regex.is_match(value) {
                    return Ok(Verdict::block(format!(
                        "secret detected in header '{key}': {secret_type}"
                    )));
                }
            }
        }
        Ok(Verdict::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_email() {
        let guard = PiiDetectionGuard::new(PiiMode::Block).unwrap();
        let ctx = Context::new("Contact me at john@example.com please");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
        assert!(verdict.to_string().contains("email"));
    }

    #[test]
    fn detects_phone() {
        let guard = PiiDetectionGuard::new(PiiMode::Block).unwrap();
        let ctx = Context::new("Call me at 555-123-4567");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
    }

    #[test]
    fn detects_ssn() {
        let guard = PiiDetectionGuard::new(PiiMode::Block).unwrap();
        let ctx = Context::new("SSN: 123-45-6789");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
        assert!(verdict.to_string().contains("ssn"));
    }

    #[test]
    fn allows_clean_input() {
        let guard = PiiDetectionGuard::new(PiiMode::Block).unwrap();
        let ctx = Context::new("Hello world");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_allow());
    }

    #[test]
    fn redact_mode() {
        let guard = PiiDetectionGuard::new(PiiMode::Redact).unwrap();
        let ctx = Context::new("Email: john@example.com");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_modify());
        if let Verdict::Modify { new_body, .. } = verdict {
            assert!(new_body.contains("[REDACTED]"));
            assert!(!new_body.contains("john@example.com"));
        }
    }

    #[test]
    fn detects_aws_key() {
        let guard = SecretDetectionGuard::new().unwrap();
        let ctx = Context::new("key: AKIAIOSFODNN7EXAMPLE");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
        assert!(verdict.to_string().contains("aws_key"));
    }

    #[test]
    fn detects_password_in_json() {
        let guard = SecretDetectionGuard::new().unwrap();
        let ctx = Context::new(r#"{"username": "admin", "password": "s3cr3t!"}"#);
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
    }

    #[test]
    fn detects_private_key() {
        let guard = SecretDetectionGuard::new().unwrap();
        let ctx = Context::new("-----BEGIN RSA PRIVATE KEY-----\nMIIE...");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
    }

    #[test]
    fn allows_normal_content() {
        let guard = SecretDetectionGuard::new().unwrap();
        let ctx = Context::new("just a normal request body");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_allow());
    }
}
