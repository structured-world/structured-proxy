//! Compile Shield config into runtime matchers, limiters, and rules.

use std::collections::HashMap;
use std::time::Duration;

use globset::GlobMatcher;

use super::gcra::{Gcra, Profile};
use crate::config::{KeySourceConfig, LimitProfileConfig, RateRuleConfig};

/// Bare rate counts (`"20"` with no unit) are interpreted per this window.
const BARE_COUNT_WINDOW: Duration = Duration::from_secs(60);

/// A compiled limit tier: the GCRA shaper, the per-window count reported in the
/// `RateLimit-Limit` header, and the window itself (the fleet-gate epoch length).
#[derive(Debug, Clone, Copy)]
pub struct CompiledProfile {
    pub gcra: Gcra,
    /// Sustained request count per window (for `RateLimit-Limit`).
    pub limit: u64,
    /// Length of the sustained-rate window.
    pub window: Duration,
}

/// How a rule derives its limit key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    /// Client IP (trusted-proxy aware).
    Ip,
    /// A named request-header value (API-key style); IP fallback when absent.
    Header(String),
    /// A validated-JWT claim value; IP fallback for anonymous traffic.
    JwtClaim(String),
}

/// Whether a rule can be decided before auth runs, or needs validated claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No validated claims needed: run before auth so floods are shed cheaply.
    PreAuth,
    /// Needs validated claims (key derived from the JWT): run after auth.
    PostAuth,
}

/// A compiled rate-limit rule.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub matcher: GlobMatcher,
    pub key: KeySource,
    /// Static profile name, if the rule pins one.
    pub profile: Option<String>,
    pub phase: Phase,
    /// Stable identifier for this rule, derived from its shape (pattern + key +
    /// profile) rather than its position. Namespaces store keys so reordering
    /// rules or a rolling deploy does not reset budgets.
    pub fingerprint: String,
}

/// A short, stable, non-reversible hash (128-bit hex) of `input`. Used both to
/// fingerprint rules and to de-identify key values before they reach the shared
/// store, and deterministic across instances so reconciliation keys agree.
pub fn short_hash(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
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

/// Compile a single limit profile from its config.
pub fn compile_profile(cfg: &LimitProfileConfig) -> Result<CompiledProfile, String> {
    let rate = super::rate::Rate::parse(&cfg.rate, BARE_COUNT_WINDOW)?;
    // Reject non-positive limits explicitly rather than silently clamping them
    // to 1, which would hide a misconfigured (effectively unlimited or dead) tier.
    if rate.limit == 0 {
        return Err(format!(
            "profile rate must be greater than 0, got {:?}",
            cfg.rate
        ));
    }
    if cfg.burst == Some(0) {
        return Err("profile burst must be greater than 0".to_string());
    }
    // Default burst = one full window of the sustained rate.
    let burst = cfg.burst.unwrap_or(rate.limit);
    let gcra = Gcra::from_profile(Profile {
        rate: rate.limit,
        window: rate.window,
        burst,
    });
    Ok(CompiledProfile {
        gcra,
        limit: rate.limit,
        window: rate.window,
    })
}

/// Compile every named profile.
pub fn compile_profiles(
    configs: &HashMap<String, LimitProfileConfig>,
) -> Result<HashMap<String, CompiledProfile>, String> {
    configs
        .iter()
        .map(|(name, cfg)| Ok((name.clone(), compile_profile(cfg)?)))
        .collect()
}

/// Compile rules, validating that any pinned `profile` names an existing tier.
/// Each rule's phase is derived from its key: a `jwt_claim` key needs validated
/// claims and runs after auth; every other key runs before auth.
pub fn compile_rules(
    configs: &[RateRuleConfig],
    profiles: &HashMap<String, CompiledProfile>,
) -> Result<Vec<CompiledRule>, String> {
    configs
        .iter()
        .map(|c| {
            if let Some(name) = &c.profile {
                if !profiles.contains_key(name) {
                    return Err(format!(
                        "rule {:?} references unknown profile {name:?}",
                        c.pattern
                    ));
                }
            }
            let key = match &c.key {
                KeySourceConfig::Ip => KeySource::Ip,
                KeySourceConfig::Header { name } => {
                    // Reject an invalid header name at build time: a typo (e.g.
                    // whitespace) would never match a real header, silently
                    // downgrading a per-API-key limit into a per-IP one.
                    http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                        format!("rule {:?} has invalid header name {name:?}", c.pattern)
                    })?;
                    KeySource::Header(name.clone())
                }
                KeySourceConfig::JwtClaim { claim } => KeySource::JwtClaim(claim.clone()),
            };
            let phase = match &key {
                KeySource::JwtClaim(_) => Phase::PostAuth,
                KeySource::Ip | KeySource::Header(_) => Phase::PreAuth,
            };
            let key_repr = match &key {
                KeySource::Ip => "ip".to_string(),
                KeySource::Header(name) => format!("hdr:{name}"),
                KeySource::JwtClaim(claim) => format!("jwt:{claim}"),
            };
            let fingerprint = short_hash(&format!(
                "{}\u{1f}{}\u{1f}{}",
                c.pattern,
                key_repr,
                c.profile.as_deref().unwrap_or("")
            ));
            Ok(CompiledRule {
                matcher: path_glob(&c.pattern)?,
                key,
                profile: c.profile.clone(),
                phase,
                fingerprint,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles() -> HashMap<String, CompiledProfile> {
        let mut cfg = HashMap::new();
        cfg.insert(
            "auth".to_string(),
            LimitProfileConfig {
                rate: "20/min".to_string(),
                burst: Some(5),
            },
        );
        compile_profiles(&cfg).unwrap()
    }

    #[test]
    fn profile_defaults_burst_to_rate_count() {
        let p = compile_profile(&LimitProfileConfig {
            rate: "100/min".to_string(),
            burst: None,
        })
        .unwrap();
        assert_eq!(p.limit, 100);
    }

    #[test]
    fn zero_rate_or_burst_is_rejected() {
        assert!(compile_profile(&LimitProfileConfig {
            rate: "0/min".to_string(),
            burst: None,
        })
        .is_err());
        assert!(compile_profile(&LimitProfileConfig {
            rate: "100/min".to_string(),
            burst: Some(0),
        })
        .is_err());
    }

    #[test]
    fn glob_respects_and_spans_segments() {
        let rules = compile_rules(
            &[
                RateRuleConfig {
                    pattern: "/api/v1/heavy-*".to_string(),
                    key: KeySourceConfig::Ip,
                    profile: Some("auth".to_string()),
                },
                RateRuleConfig {
                    pattern: "/v1/auth/**".to_string(),
                    key: KeySourceConfig::Ip,
                    profile: None,
                },
            ],
            &profiles(),
        )
        .unwrap();
        assert!(rules[0].matcher.is_match("/api/v1/heavy-export"));
        assert!(!rules[0].matcher.is_match("/api/v1/heavy-export/sub"));
        assert!(rules[1].matcher.is_match("/v1/auth/opaque/start"));
    }

    #[test]
    fn phase_is_derived_from_key() {
        let rules = compile_rules(
            &[
                RateRuleConfig {
                    pattern: "/a".to_string(),
                    key: KeySourceConfig::Ip,
                    profile: None,
                },
                RateRuleConfig {
                    pattern: "/b".to_string(),
                    key: KeySourceConfig::JwtClaim {
                        claim: "sub".to_string(),
                    },
                    profile: None,
                },
            ],
            &profiles(),
        )
        .unwrap();
        assert_eq!(rules[0].phase, Phase::PreAuth);
        assert_eq!(rules[1].phase, Phase::PostAuth);
    }

    #[test]
    fn unknown_profile_reference_fails() {
        let err = compile_rules(
            &[RateRuleConfig {
                pattern: "/x".to_string(),
                key: KeySourceConfig::Ip,
                profile: Some("nope".to_string()),
            }],
            &profiles(),
        );
        assert!(err.is_err());
    }
}
