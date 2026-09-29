//! Object-level authorization guard (BOLA protection).

use requestrail_core::context::Context;
use requestrail_core::error::GuardError;
use requestrail_core::guard::Guard;
use requestrail_core::verdict::Verdict;

/// Prevents Broken Object Level Authorization (BOLA) attacks.
///
/// Ensures that user A cannot access user B's objects. Checks that
/// `ctx.source` (the caller) matches `ctx.resource_owner`, or that
/// the caller has an admin role that bypasses ownership checks.
pub struct ObjectAuthGuard {
    admin_roles: Vec<String>,
}

impl ObjectAuthGuard {
    /// Create a new object-level authorization guard.
    pub fn new() -> Self {
        Self {
            admin_roles: vec!["admin".to_string(), "superadmin".to_string()],
        }
    }

    /// Add a role that can bypass object ownership checks.
    pub fn with_admin_role(mut self, role: &str) -> Self {
        self.admin_roles.push(role.to_string());
        self
    }
}

impl Default for ObjectAuthGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Guard for ObjectAuthGuard {
    fn name(&self) -> &str {
        "object_auth"
    }

    fn description(&self) -> &str {
        "Object-level authorization (BOLA protection)"
    }

    fn priority(&self) -> u32 {
        25
    }

    fn evaluate(&self, ctx: &Context) -> Result<Verdict, GuardError> {
        // If no resource_owner is specified, skip this check
        let owner = match ctx.resource_owner.as_deref() {
            Some(o) => o,
            None => return Ok(Verdict::Allow),
        };

        // Admin roles bypass ownership checks
        if let Some(role) = ctx.role.as_deref() {
            if self.admin_roles.iter().any(|r| r == role) {
                return Ok(Verdict::Allow);
            }
        }

        // Check if caller is the owner
        let caller = ctx.source.as_deref().unwrap_or("anonymous");
        if caller == owner {
            Ok(Verdict::Allow)
        } else {
            Ok(Verdict::block(format!(
                "object access denied: caller '{caller}' is not the owner '{owner}'"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_can_access() {
        let guard = ObjectAuthGuard::new();
        let ctx = Context::new("test")
            .with_source("user-123")
            .with_resource_owner("user-123");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn non_owner_blocked() {
        let guard = ObjectAuthGuard::new();
        let ctx = Context::new("test")
            .with_source("user-456")
            .with_resource_owner("user-123");
        assert!(guard.evaluate(&ctx).unwrap().is_block());
    }

    #[test]
    fn admin_bypasses() {
        let guard = ObjectAuthGuard::new();
        let ctx = Context::new("test")
            .with_source("admin-user")
            .with_role("admin")
            .with_resource_owner("user-123");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }

    #[test]
    fn no_owner_allows() {
        let guard = ObjectAuthGuard::new();
        let ctx = Context::new("test").with_source("anyone");
        assert!(guard.evaluate(&ctx).unwrap().is_allow());
    }
}
