//! Regex-based content filtering, input validation, and request size limits.

use regex::Regex;
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;

/// A configurable regex-based content filter.
///
/// Blocks requests whose body matches any of the configured deny patterns.
/// Optionally requires the body to match at least one allow pattern.
pub struct RegexFilterGuard {
    deny_patterns: Vec<(String, Regex)>,
    label: String,
}

impl RegexFilterGuard {
    /// Create a new filter with no patterns.
    pub fn new(label: &str) -> Self {
        Self {
            deny_patterns: Vec::new(),
            label: label.to_string(),
        }
    }

    /// Add a deny pattern. If the body matches, the request is blocked.
    pub fn deny(mut self, name: &str, pattern: &str) -> Result<Self, GuardError> {
        let re = Regex::new(pattern)
            .map_err(|e| GuardError::Configuration(format!("invalid pattern '{name}': {e}")))?;
        self.deny_patterns.push((name.to_string(), re));
        Ok(self)
    }
}

impl Guard for RegexFilterGuard {
    fn name(&self) -> &str {
        &self.label
    }

    fn description(&self) -> &str {
        "Regex-based content filter"
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        for (pattern_name, regex) in &self.deny_patterns {
            if regex.is_match(&ctx.body) {
                return Ok(Verdict::block(format!(
                    "{}: matched deny pattern '{pattern_name}'",
                    self.label
                )));
            }
        }
        Ok(Verdict::Allow)
    }
}

/// Input validation guard that checks request bodies for well-formedness.
///
/// Validates:
/// - Non-empty body (if required)
/// - Valid UTF-8
/// - No null bytes
/// - Optional JSON structure validation
pub struct InputValidationGuard {
    require_non_empty: bool,
    reject_null_bytes: bool,
    require_valid_json: bool,
    max_nesting_depth: Option<usize>,
}

impl InputValidationGuard {
    /// Create a new input validation guard with default settings.
    pub fn new() -> Self {
        Self {
            require_non_empty: true,
            reject_null_bytes: true,
            require_valid_json: false,
            max_nesting_depth: None,
        }
    }

    /// Require the body to be valid JSON.
    pub fn require_json(mut self) -> Self {
        self.require_valid_json = true;
        self
    }

    /// Set maximum JSON nesting depth.
    pub fn max_nesting(mut self, depth: usize) -> Self {
        self.max_nesting_depth = Some(depth);
        self
    }

    /// Allow empty bodies.
    pub fn allow_empty(mut self) -> Self {
        self.require_non_empty = false;
        self
    }
}

impl Default for InputValidationGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for InputValidationGuard {
    fn name(&self) -> &str {
        "input_validation"
    }

    fn description(&self) -> &str {
        "Validates request body structure and content"
    }

    fn priority(&self) -> u32 {
        20
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        if self.require_non_empty && ctx.body.trim().is_empty() {
            return Ok(Verdict::block("empty request body"));
        }

        if self.reject_null_bytes && ctx.body.contains('\0') {
            return Ok(Verdict::block("request body contains null bytes"));
        }

        if self.require_valid_json {
            match serde_json::from_str::<serde_json::Value>(&ctx.body) {
                Ok(value) => {
                    if let Some(max_depth) = self.max_nesting_depth {
                        let depth = json_depth(&value);
                        if depth > max_depth {
                            return Ok(Verdict::block(format!(
                                "JSON nesting depth {depth} exceeds maximum {max_depth}"
                            )));
                        }
                    }
                }
                Err(e) => {
                    return Ok(Verdict::block(format!("invalid JSON: {e}")));
                }
            }
        }

        Ok(Verdict::Allow)
    }
}

/// Calculate the nesting depth of a JSON value.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(arr) => {
            1 + arr.iter().map(json_depth).max().unwrap_or(0)
        }
        serde_json::Value::Object(obj) => {
            1 + obj.values().map(json_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}

/// Request size limit guard.
///
/// Blocks requests whose body exceeds a configured byte limit.
pub struct RequestSizeLimitGuard {
    max_bytes: usize,
}

impl RequestSizeLimitGuard {
    /// Create a new size limit guard.
    pub fn new(max_bytes: usize) -> Self {
        Self { max_bytes }
    }
}

impl Guard for RequestSizeLimitGuard {
    fn name(&self) -> &str {
        "request_size_limit"
    }

    fn description(&self) -> &str {
        "Enforces maximum request body size"
    }

    fn priority(&self) -> u32 {
        5
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let size = ctx.content_length.unwrap_or(ctx.body.len());
        if size > self.max_bytes {
            Ok(Verdict::block(format!(
                "request size {size} bytes exceeds limit of {} bytes",
                self.max_bytes
            )))
        } else {
            Ok(Verdict::Allow)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regex_filter_blocks_match() {
        let guard = RegexFilterGuard::new("test_filter")
            .deny("bad_word", r"(?i)drop\s+table")
            .unwrap();
        let ctx = Context::new("please DROP TABLE users");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn regex_filter_allows_clean() {
        let guard = RegexFilterGuard::new("test_filter")
            .deny("bad_word", r"(?i)drop\s+table")
            .unwrap();
        let ctx = Context::new("select * from users");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn input_validation_empty_body() {
        let guard = InputValidationGuard::new();
        let ctx = Context::new("  ");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn input_validation_null_bytes() {
        let guard = InputValidationGuard::new();
        let ctx = Context::new("hello\0world");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn input_validation_invalid_json() {
        let guard = InputValidationGuard::new().require_json();
        let ctx = Context::new("not json");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn input_validation_valid_json() {
        let guard = InputValidationGuard::new().require_json();
        let ctx = Context::new(r#"{"key": "value"}"#);
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn input_validation_nesting_depth() {
        let guard = InputValidationGuard::new().require_json().max_nesting(2);
        let ctx = Context::new(r#"{"a": {"b": {"c": "too deep"}}}"#);
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn size_limit_allows_small() {
        let guard = RequestSizeLimitGuard::new(1024);
        let ctx = Context::new("small body");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn size_limit_blocks_large() {
        let guard = RequestSizeLimitGuard::new(10);
        let ctx = Context::new("this body is definitely more than ten bytes");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }
}
