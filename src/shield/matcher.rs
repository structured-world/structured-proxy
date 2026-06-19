//! Compile Shield config patterns into runtime path matchers.

use globset::GlobMatcher;

use super::rate::Rate;
use crate::config::{EndpointClassConfig, IdentifierEndpointConfig};
use std::time::Duration;

/// A compiled endpoint-class rule: requests whose path matches `matcher` are
/// limited per client at `rate`, grouped under `class`.
pub struct EndpointClass {
    pub matcher: GlobMatcher,
    pub class: String,
    pub rate: Rate,
}

/// A compiled per-identifier rule: requests to a matching path are limited by a
/// value read from the request body field `body_field`.
pub struct IdentifierEndpoint {
    pub matcher: GlobMatcher,
    pub body_field: String,
    pub rate: Rate,
}

/// Build a glob matcher where `*` stays within a path segment and `**` spans
/// segments, matching the `google.api.http` / maintenance path convention.
fn path_glob(pattern: &str) -> Result<GlobMatcher, String> {
    globset::GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| format!("invalid glob pattern {pattern:?}: {e}"))
}

/// Compile endpoint-class rules, parsing each rate against `default_window`.
pub fn compile_endpoint_classes(
    configs: &[EndpointClassConfig],
    default_window: Duration,
) -> Result<Vec<EndpointClass>, String> {
    configs
        .iter()
        .map(|c| {
            Ok(EndpointClass {
                matcher: path_glob(&c.pattern)?,
                class: c.class.clone(),
                rate: Rate::parse(&c.rate, default_window)?,
            })
        })
        .collect()
}

/// Compile per-identifier rules, parsing each rate against `default_window`.
pub fn compile_identifier_endpoints(
    configs: &[IdentifierEndpointConfig],
    default_window: Duration,
) -> Result<Vec<IdentifierEndpoint>, String> {
    configs
        .iter()
        .map(|c| {
            Ok(IdentifierEndpoint {
                matcher: path_glob(&c.path)?,
                body_field: c.body_field.clone(),
                rate: Rate::parse(&c.rate, default_window)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ec(pattern: &str, class: &str, rate: &str) -> EndpointClassConfig {
        EndpointClassConfig {
            pattern: pattern.to_string(),
            class: class.to_string(),
            rate: rate.to_string(),
        }
    }

    #[test]
    fn endpoint_class_glob_respects_segments() {
        let classes = compile_endpoint_classes(
            &[ec("/api/v1/heavy-*", "heavy", "10/min")],
            Duration::from_secs(60),
        )
        .unwrap();
        let m = &classes[0].matcher;
        assert!(m.is_match("/api/v1/heavy-export"));
        // `*` does not cross a path separator.
        assert!(!m.is_match("/api/v1/heavy-export/sub"));
        assert!(!m.is_match("/api/v1/light"));
    }

    #[test]
    fn double_star_spans_segments() {
        let classes = compile_endpoint_classes(
            &[ec("/v1/auth/**", "auth", "20/min")],
            Duration::from_secs(60),
        )
        .unwrap();
        let m = &classes[0].matcher;
        assert!(m.is_match("/v1/auth/login"));
        assert!(m.is_match("/v1/auth/opaque/start"));
    }

    #[test]
    fn invalid_rate_fails_compilation() {
        let err = compile_endpoint_classes(&[ec("/x", "c", "nonsense")], Duration::from_secs(60));
        assert!(err.is_err());
    }
}
