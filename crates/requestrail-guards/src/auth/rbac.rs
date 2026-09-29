//! Role-Based Access Control (RBAC) guard.

use std::collections::{HashMap, HashSet};
use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;

/// Enforces role-based access control on request paths.
///
/// Maps roles to sets of allowed path prefixes. A request is allowed if
/// the caller's role grants access to the requested path.
pub struct RbacGuard {
    /// role -> set of allowed path prefixes
    role_permissions: HashMap<String, HashSet<String>>,
    /// Paths that are accessible to all roles.
    public_paths: HashSet<String>,
}

impl RbacGuard {
    /// Create a new RBAC guard.
    pub fn new() -> Self {
        Self {
            role_permissions: HashMap::new(),
            public_paths: HashSet::new(),
        }
    }

    /// Grant a role access to a path prefix.
    pub fn grant(mut self, role: &str, path: &str) -> Self {
        self.role_permissions
            .entry(role.to_string())
            .or_default()
            .insert(path.to_string());
        self
    }

    /// Mark a path prefix as public (accessible to all roles).
    pub fn public(mut self, path: &str) -> Self {
        self.public_paths.insert(path.to_string());
        self
    }

    /// Check if a role has access to a path.
    fn has_access(&self, role: &str, path: &str) -> bool {
        // Check public paths
        for public in &self.public_paths {
            if path.starts_with(public.as_str()) {
                return true;
            }
        }

        // Check role-specific paths
        if let Some(allowed) = self.role_permissions.get(role) {
            for prefix in allowed {
                if path.starts_with(prefix.as_str()) {
                    return true;
                }
            }
        }

        false
    }
}

impl Default for RbacGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for RbacGuard {
    fn name(&self) -> &str {
        "rbac"
    }

    fn description(&self) -> &str {
        "Role-based access control on request paths"
    }

    fn priority(&self) -> u32 {
        15
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        let path = ctx.path.as_deref().unwrap_or("/");
        let role = ctx.role.as_deref().unwrap_or("anonymous");

        if self.has_access(role, path) {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::block(format!(
                "role '{role}' does not have access to '{path}'"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_full_access() {
        let guard = RbacGuard::new()
            .grant("admin", "/")
            .grant("user", "/api/")
            .public("/health");

        let ctx = Context::new("test")
            .with_role("admin")
            .with_path("/admin/settings");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn user_limited_access() {
        let guard = RbacGuard::new()
            .grant("admin", "/")
            .grant("user", "/api/");

        let ctx = Context::new("test")
            .with_role("user")
            .with_path("/admin/settings");
        assert!(guard.evaluate(&ctx).unwrap().is_block());

        let ctx = Context::new("test")
            .with_role("user")
            .with_path("/api/data");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn public_paths() {
        let guard = RbacGuard::new()
            .public("/health")
            .public("/status");

        let ctx = Context::new("test")
            .with_role("anonymous")
            .with_path("/health");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn unknown_role_blocked() {
        let guard = RbacGuard::new()
            .grant("admin", "/");

        let ctx = Context::new("test")
            .with_role("intruder")
            .with_path("/secret");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }
}
