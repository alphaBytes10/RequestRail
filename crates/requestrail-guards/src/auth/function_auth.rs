//! Function-level authorization guard.

use std::collections::{HashMap, HashSet};
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;

/// Prevents Broken Function Level Authorization (BFLA).
///
/// Restricts access to specific API functions (method + path combinations)
/// based on the caller's role. Prevents normal users from calling admin
/// endpoints.
pub struct FunctionAuthGuard {
    /// (method, path_prefix) -> set of allowed roles
    function_permissions: HashMap<(String, String), HashSet<String>>,
}

impl FunctionAuthGuard {
    /// Create a new function authorization guard.
    pub fn new() -> Self {
        Self {
            function_permissions: HashMap::new(),
        }
    }

    /// Grant a role access to a function (method + path prefix).
    pub fn grant(mut self, method: &str, path_prefix: &str, role: &str) -> Self {
        self.function_permissions
            .entry((method.to_uppercase(), path_prefix.to_string()))
            .or_default()
            .insert(role.to_string());
        self
    }
}

impl Default for FunctionAuthGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for FunctionAuthGuard {
    fn name(&self) -> &str {
        "function_auth"
    }

    fn description(&self) -> &str {
        "Function-level authorization (BFLA protection)"
    }

    fn priority(&self) -> u32 {
        26
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let method = ctx.method.as_deref().unwrap_or("GET").to_uppercase();
        let path = ctx.path.as_deref().unwrap_or("/");
        let role = ctx.role.as_deref().unwrap_or("anonymous");

        // Find the most specific matching function permission
        for ((perm_method, perm_path), allowed_roles) in &self.function_permissions {
            if *perm_method == method && path.starts_with(perm_path.as_str()) {
                if allowed_roles.contains(role) {
                    return Ok(Verdict::Allow);
                } else {
                    return Ok(Verdict::block(format!(
                        "function access denied: role '{role}' cannot {method} '{path}'"
                    )));
                }
            }
        }

        // No matching function permission — allow by default
        // (use PolicyEngine for deny-by-default behavior)
        Ok(Verdict::Allow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_can_delete() {
        let guard = FunctionAuthGuard::new()
            .grant("DELETE", "/api/users", "admin");

        let ctx = Context::new("test")
            .with_method("DELETE")
            .with_path("/api/users/123")
            .with_role("admin");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn user_cannot_delete() {
        let guard = FunctionAuthGuard::new()
            .grant("DELETE", "/api/users", "admin");

        let ctx = Context::new("test")
            .with_method("DELETE")
            .with_path("/api/users/123")
            .with_role("user");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn unregistered_function_allows() {
        let guard = FunctionAuthGuard::new();
        let ctx = Context::new("test")
            .with_method("GET")
            .with_path("/api/data");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }
}
