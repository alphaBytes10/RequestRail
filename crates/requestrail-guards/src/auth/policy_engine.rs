//! Rule-based policy engine guard.

use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;
use serde::{Deserialize, Serialize};

/// A declarative rule-based policy engine.
///
/// Evaluates a list of rules in order. The first matching rule determines
/// the verdict. If no rule matches, the default action is applied.
pub struct PolicyEngineGuard {
    rules: Vec<PolicyRule>,
    default_action: PolicyAction,
}

/// A single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Human-readable name.
    pub name: String,
    /// Conditions that must all be true for this rule to match.
    pub conditions: Vec<Condition>,
    /// Action to take if the rule matches.
    pub action: PolicyAction,
}

/// A condition to check against the request context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Match if the request path starts with this prefix.
    PathPrefix(String),
    /// Match if the caller's role is in this set.
    RoleIn(Vec<String>),
    /// Match if the HTTP method matches.
    Method(String),
    /// Match if the caller source matches.
    SourceIs(String),
    /// Match if a metadata key exists with a specific value.
    MetadataEquals(String, String),
    /// Match if the body contains this substring.
    BodyContains(String),
}

/// The action to take when a rule matches.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PolicyAction {
    Allow,
    Block(String),
}

impl PolicyEngineGuard {
    /// Create a new policy engine with a default-deny policy.
    pub fn deny_by_default() -> Self {
        Self {
            rules: Vec::new(),
            default_action: PolicyAction::Block("no matching policy rule".to_string()),
        }
    }

    /// Create a new policy engine with a default-allow policy.
    pub fn allow_by_default() -> Self {
        Self {
            rules: Vec::new(),
            default_action: PolicyAction::Allow,
        }
    }

    /// Add a rule to the engine.
    pub fn with_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Check if a condition matches the context.
    fn matches_condition(condition: &Condition, ctx: &Context) -> bool {
        match condition {
            Condition::PathPrefix(prefix) => {
                ctx.path.as_deref().unwrap_or("").starts_with(prefix.as_str())
            }
            Condition::RoleIn(roles) => {
                ctx.role.as_deref()
                    .map(|r| roles.iter().any(|allowed| allowed == r))
                    .unwrap_or(false)
            }
            Condition::Method(method) => {
                ctx.method.as_deref().unwrap_or("") == method.as_str()
            }
            Condition::SourceIs(source) => {
                ctx.source.as_deref() == Some(source.as_str())
            }
            Condition::MetadataEquals(key, value) => {
                ctx.metadata.get(key).map(|v| v == value).unwrap_or(false)
            }
            Condition::BodyContains(substr) => {
                ctx.body.contains(substr.as_str())
            }
        }
    }
}

impl Guard for PolicyEngineGuard {
    fn name(&self) -> &str {
        "policy_engine"
    }

    fn description(&self) -> &str {
        "Rule-based policy decision engine"
    }

    fn priority(&self) -> u32 {
        30
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        for rule in &self.rules {
            let all_match = rule.conditions.iter().all(|c| Self::matches_condition(c, ctx));
            if all_match {
                return match &rule.action {
                    PolicyAction::Allow => Ok(Verdict::Allow),
                    PolicyAction::Block(reason) => Ok(Verdict::block(format!(
                        "policy '{}': {reason}", rule.name
                    ))),
                };
            }
        }

        // No rule matched — apply default
        match &self.default_action {
            PolicyAction::Allow => Ok(Verdict::Allow),
            PolicyAction::Block(reason) => Ok(Verdict::block(reason.clone())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_rule_matches() {
        let guard = PolicyEngineGuard::deny_by_default()
            .with_rule(PolicyRule {
                name: "allow_api".into(),
                conditions: vec![
                    Condition::PathPrefix("/api/".into()),
                    Condition::RoleIn(vec!["user".into(), "admin".into()]),
                ],
                action: PolicyAction::Allow,
            });

        let ctx = Context::new("test")
            .with_path("/api/data")
            .with_role("user");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn deny_by_default_no_match() {
        let guard = PolicyEngineGuard::deny_by_default();
        let ctx = Context::new("test");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn block_rule() {
        let guard = PolicyEngineGuard::allow_by_default()
            .with_rule(PolicyRule {
                name: "block_admin".into(),
                conditions: vec![
                    Condition::PathPrefix("/admin".into()),
                    Condition::RoleIn(vec!["user".into()]),
                ],
                action: PolicyAction::Block("users cannot access admin".into()),
            });

        let ctx = Context::new("test")
            .with_path("/admin/settings")
            .with_role("user");
        let verdict = guard.evaluate(&ctx).unwrap();
        assert!(verdict.is_block());
    }

    #[test]
    fn first_matching_rule_wins() {
        let guard = PolicyEngineGuard::deny_by_default()
            .with_rule(PolicyRule {
                name: "block_first".into(),
                conditions: vec![Condition::Method("POST".into())],
                action: PolicyAction::Block("POST blocked".into()),
            })
            .with_rule(PolicyRule {
                name: "allow_all".into(),
                conditions: vec![],
                action: PolicyAction::Allow,
            });

        let ctx = Context::new("test").with_method("POST");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }
}
