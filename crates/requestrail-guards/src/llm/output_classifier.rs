//! LLM output content classifier guard.

use regex::Regex;
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;

/// Inspects LLM output for sensitive information leakage.
///
/// Designed to be placed in a post-processing pipeline that checks
/// model responses before they reach the end user. Detects:
/// - System prompt leakage
/// - Internal configuration details
/// - Code execution artifacts
/// - Harmful content indicators
pub struct LlmOutputGuard {
    patterns: Vec<(String, Regex)>,
}

impl LlmOutputGuard {
    /// Create a new LLM output guard with default patterns.
    pub fn new() -> Result<Self, GuardError> {
        let patterns = vec![
            ("system_prompt_leak".into(), compile(
                r"(?i)(?:my\s+)?(?:system\s+)?(?:prompt|instructions?)\s+(?:is|are|says?|tells?)\s*:"
            )?),
            ("internal_config".into(), compile(
                r"(?i)(?:internal|private|secret|hidden)\s+(?:api|key|token|config|setting|password)\s*[:=]"
            )?),
            ("code_execution".into(), compile(
                r"(?i)(?:executing|running|eval)\s*\(.*\)"
            )?),
            ("harmful_instruction".into(), compile(
                r"(?i)(?:here(?:'s| is) how to|step(?:-|\s)by(?:-|\s)step guide to)\s+(?:hack|break into|exploit|bypass security)"
            )?),
        ];
        Ok(Self { patterns })
    }

    /// Add a custom output pattern.
    pub fn with_pattern(mut self, name: &str, pattern: &str) -> Result<Self, GuardError> {
        self.patterns.push((name.to_string(), compile(pattern)?));
        Ok(self)
    }
}

fn compile(pattern: &str) -> Result<Regex, GuardError> {
    Regex::new(pattern)
        .map_err(|e| GuardError::Configuration(format!("invalid pattern: {e}")))
}

impl Guard for LlmOutputGuard {
    fn name(&self) -> &str {
        "llm_output"
    }

    fn description(&self) -> &str {
        "LLM output inspection for sensitive information leakage"
    }

    fn priority(&self) -> u32 {
        80
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        for (name, regex) in &self.patterns {
            if regex.is_match(&ctx.body) {
                return Ok(Verdict::block(format!(
                    "LLM output blocked: {name}"
                )));
            }
        }
        Ok(Verdict::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_system_prompt_leak() {
        let guard = LlmOutputGuard::new().unwrap();
        let ctx = Context::new("My system prompt says: You are a helpful assistant");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn detects_internal_config_leak() {
        let guard = LlmOutputGuard::new().unwrap();
        let ctx = Context::new("The internal api key = sk-1234567890");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn allows_normal_output() {
        let guard = LlmOutputGuard::new().unwrap();
        let ctx = Context::new("The weather in New York is sunny today.");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }
}
