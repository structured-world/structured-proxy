//! Route-level access policies.
//!
//! Each policy matches requests by path glob and HTTP method, and declares
//! whether authentication is required and which roles the caller must hold.

use globset::GlobMatcher;

use crate::config::RoutePolicyConfig;

/// A compiled route policy.
pub struct RoutePolicy {
    matcher: GlobMatcher,
    methods: Vec<String>,
    /// Whether a valid token is required to reach the route.
    pub require_auth: bool,
    /// Roles the caller must all hold (AND semantics).
    pub required_roles: Vec<String>,
}

impl RoutePolicy {
    fn matches_method(&self, method: &str) -> bool {
        self.methods.iter().any(|m| m == "*" || m == method)
    }
}

/// A compiled set of route policies, matched in declaration order.
#[derive(Default)]
pub struct Policies {
    rules: Vec<RoutePolicy>,
}

impl Policies {
    /// Compile policy config; the first matching rule wins at request time.
    ///
    /// # Errors
    /// Returns an error when a path glob fails to compile.
    pub fn compile(configs: &[RoutePolicyConfig]) -> Result<Self, String> {
        let rules = configs
            .iter()
            .map(|c| {
                let matcher = globset::GlobBuilder::new(&c.path)
                    .literal_separator(true)
                    .build()
                    .map(|g| g.compile_matcher())
                    .map_err(|e| format!("invalid policy path {:?}: {e}", c.path))?;
                Ok(RoutePolicy {
                    matcher,
                    methods: c.methods.iter().map(|m| m.to_uppercase()).collect(),
                    require_auth: c.require_auth,
                    required_roles: c.required_roles.clone(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self { rules })
    }

    /// First policy matching `path` and `method` (method already uppercased).
    pub fn match_rule(&self, path: &str, method: &str) -> Option<&RoutePolicy> {
        self.rules
            .iter()
            .find(|r| r.matcher.is_match(path) && r.matches_method(method))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(
        path: &str,
        methods: &[&str],
        require_auth: bool,
        roles: &[&str],
    ) -> RoutePolicyConfig {
        RoutePolicyConfig {
            path: path.to_string(),
            methods: methods.iter().map(|s| s.to_string()).collect(),
            require_auth,
            required_roles: roles.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn matches_path_and_method() {
        let p = Policies::compile(&[policy("/v1/admin/**", &["GET", "POST"], true, &["admin"])])
            .unwrap();
        assert!(p.match_rule("/v1/admin/users", "GET").is_some());
        assert!(p.match_rule("/v1/admin/users", "POST").is_some());
        // Method not listed → no match.
        assert!(p.match_rule("/v1/admin/users", "DELETE").is_none());
        // Path outside the glob → no match.
        assert!(p.match_rule("/v1/public", "GET").is_none());
    }

    #[test]
    fn wildcard_method_matches_any() {
        let p = Policies::compile(&[policy("/v1/**", &["*"], true, &[])]).unwrap();
        assert!(p.match_rule("/v1/x", "PATCH").is_some());
    }

    #[test]
    fn first_matching_rule_wins() {
        let p = Policies::compile(&[
            policy("/v1/health", &["*"], false, &[]),
            policy("/v1/**", &["*"], true, &["admin"]),
        ])
        .unwrap();
        // Health rule comes first and does not require auth.
        assert!(!p.match_rule("/v1/health", "GET").unwrap().require_auth);
        // Everything else falls to the catch-all.
        assert!(p.match_rule("/v1/secret", "GET").unwrap().require_auth);
    }
}
