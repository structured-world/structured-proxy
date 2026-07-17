//! Limit resolution: derive a key's `{rate, burst}` from the JWT itself or from
//! an external service, on top of the static config profiles.
//!
//! The resolution chain is `jwt → service → rule profile → default`. JWT
//! resolution is synchronous (the validated claims ride on the request). Service
//! resolution never blocks the request path: a lookup is cached and refreshed in
//! the background (stale-while-revalidate), so a request either uses a cached
//! limit or falls through to the static profile while the fetch happens.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;
use serde::Deserialize;
use serde_json::Value;

use super::gcra::{Gcra, Profile};
use super::matcher::CompiledProfile;
use crate::config::{JwtLimitConfig, LimitServiceConfig};

/// Bare / per-minute rates use this window.
const PER_MINUTE: Duration = Duration::from_secs(60);

/// Resolve a (possibly dotted) claim path to a scalar string value.
pub(super) fn claim_str(claims: &Value, path: &str) -> Option<String> {
    match claim_at(claims, path)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Resolve a (possibly dotted) claim path to an unsigned integer, accepting a
/// numeric or a numeric-string value.
fn claim_u64(claims: &Value, path: &str) -> Option<u64> {
    match claim_at(claims, path)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn claim_at<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = claims;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Build a limit tier from explicit per-minute numbers.
fn profile_from_numbers(rpm: u64, burst: u64) -> CompiledProfile {
    let rate = rpm.max(1);
    let gcra = Gcra::from_profile(Profile {
        rate,
        window: PER_MINUTE,
        burst: burst.max(1),
    });
    CompiledProfile {
        gcra,
        limit: rate,
        window: PER_MINUTE,
    }
}

/// Compiled JWT-based limit resolution: the claim names to read from the token.
#[derive(Debug, Clone)]
pub struct JwtLimits {
    tier_claim: String,
    rpm_claim: String,
    burst_claim: String,
}

impl JwtLimits {
    /// Compile from config.
    pub fn from_config(cfg: &JwtLimitConfig) -> Self {
        Self {
            tier_claim: cfg.tier_claim.clone(),
            rpm_claim: cfg.rpm_claim.clone(),
            burst_claim: cfg.burst_claim.clone(),
        }
    }

    /// Resolve a limit from the validated claims: a tier-name claim naming a
    /// profile takes precedence, then explicit `rpm` (+ optional `burst`)
    /// numbers. `None` when the token carries no limit hints.
    pub fn resolve(
        &self,
        claims: &Value,
        profiles: &HashMap<String, CompiledProfile>,
    ) -> Option<CompiledProfile> {
        if let Some(tier) = claim_str(claims, &self.tier_claim) {
            if let Some(profile) = profiles.get(&tier) {
                return Some(*profile);
            }
        }
        if let Some(rpm) = claim_u64(claims, &self.rpm_claim) {
            let burst = claim_u64(claims, &self.burst_claim).unwrap_or(rpm);
            return Some(profile_from_numbers(rpm, burst));
        }
        None
    }
}

/// External limit-service response: a tier name or explicit numbers.
#[derive(Debug, Deserialize)]
struct LimitResponse {
    #[serde(default)]
    tier: Option<String>,
    #[serde(default)]
    rate_per_min: Option<u64>,
    #[serde(default)]
    burst: Option<u64>,
}

/// A cached resolution. `profile` is `None` when the service reported no limit
/// for the key (a negative cache entry stops us re-querying every request).
#[derive(Clone, Copy)]
struct Cached {
    profile: Option<CompiledProfile>,
    /// When the value was last fetched (drives staleness / refresh age).
    at: Instant,
    /// When the entry was last read (drives idle eviction). Advances on every
    /// access, including stale hits, so an actively-used key is not evicted
    /// during a service outage that keeps `at` from advancing.
    last_access: Instant,
}

/// Sweep the cache of long-idle keys at most once per this interval.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// External limit-resolution service with an async, non-blocking cache.
pub struct LimitService {
    endpoint: String,
    ttl: Duration,
    /// Drop cache entries not refreshed within this window (a key that stopped
    /// receiving requests), so client-controlled key cardinality can't grow the
    /// cache without bound.
    evict_after: Duration,
    client: reqwest::Client,
    /// Profiles for mapping a returned tier name to a compiled limit.
    profiles: HashMap<String, CompiledProfile>,
    cache: dashmap::DashMap<String, Cached>,
    /// Keys with a background fetch already in flight (dedupes refreshes).
    inflight: dashmap::DashMap<String, ()>,
    base: Instant,
    last_sweep_ms: std::sync::atomic::AtomicU64,
}

impl LimitService {
    /// Build the service client from config and the compiled profiles.
    ///
    /// # Errors
    /// Returns an error string when the HTTP client cannot be constructed.
    pub fn build(
        cfg: &LimitServiceConfig,
        profiles: HashMap<String, CompiledProfile>,
    ) -> Result<Arc<Self>, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(cfg.timeout_ms.max(1)))
            .tls_backend_preconfigured(crate::auth::jwks::build_tls_config())
            .build()
            .map_err(|e| format!("invalid limit_service client: {e}"))?;
        let ttl = Duration::from_secs(cfg.ttl_secs.max(1));
        Ok(Arc::new(Self {
            endpoint: cfg.endpoint.clone(),
            ttl,
            // Keep an idle entry for a few refresh cycles, at least 5 minutes.
            evict_after: (ttl * 4).max(Duration::from_secs(300)),
            client,
            profiles,
            cache: dashmap::DashMap::new(),
            inflight: dashmap::DashMap::new(),
            base: Instant::now(),
            last_sweep_ms: std::sync::atomic::AtomicU64::new(0),
        }))
    }

    /// Evict cache entries not refreshed within `evict_after`, at most once per
    /// [`SWEEP_INTERVAL`]; the first caller past the interval claims the sweep.
    fn maybe_sweep(&self) {
        use std::sync::atomic::Ordering;
        let now_ms = u64::try_from(self.base.elapsed().as_millis()).unwrap_or(u64::MAX);
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < SWEEP_INTERVAL.as_millis() as u64 {
            return;
        }
        if self
            .last_sweep_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.sweep();
        }
    }

    /// Drop entries not accessed within `evict_after` (idle keys), keyed on last
    /// access rather than last fetch so an active-but-unrefreshable key survives.
    fn sweep(&self) {
        let evict_after = self.evict_after;
        self.cache
            .retain(|_, c| c.last_access.elapsed() < evict_after);
    }

    /// Resolve `key`'s limit from the cache, serving a stale value while a
    /// background refresh runs. Returns `None` (fall through to the static
    /// profile) only when nothing is cached yet. Never blocks the request.
    pub fn resolve(self: &Arc<Self>, key: &str) -> Option<CompiledProfile> {
        self.maybe_sweep();
        // Bump last-access (even for a stale hit) so an actively-used key is kept
        // through an outage, then read the cached value.
        let cached = self.cache.get_mut(key).map(|mut c| {
            c.last_access = Instant::now();
            *c
        });
        match cached {
            Some(c) if c.at.elapsed() < self.ttl => c.profile,
            Some(c) => {
                // Stale: serve the last value and refresh in the background.
                self.trigger_refresh(key.to_string());
                c.profile
            }
            None => {
                self.trigger_refresh(key.to_string());
                None
            }
        }
    }

    /// Spawn a single background fetch for `key` (deduped by `inflight`).
    fn trigger_refresh(self: &Arc<Self>, key: String) {
        match self.inflight.entry(key.clone()) {
            Entry::Occupied(_) => return,
            Entry::Vacant(v) => {
                v.insert(());
            }
        }
        let this = self.clone();
        tokio::spawn(async move {
            if let Ok(resolved) = this.fetch(&key).await {
                let now = Instant::now();
                this.cache.insert(
                    key.clone(),
                    Cached {
                        profile: resolved,
                        at: now,
                        last_access: now,
                    },
                );
            }
            // On error, leave any stale entry in place (fail-static, not fail-open).
            this.inflight.remove(&key);
        });
    }

    /// Query the service for `key` and map the response to a limit. `Ok(None)`
    /// means the service reported no limit; `Err` means the lookup failed and the
    /// cache should be left untouched.
    async fn fetch(&self, key: &str) -> Result<Option<CompiledProfile>, ()> {
        let url = reqwest::Url::parse_with_params(&self.endpoint, &[("key", key)])
            .map_err(|e| tracing::warn!("invalid limit-service endpoint: {e}"))?;
        let resp = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| tracing::warn!("limit-service fetch failed: {e}"))?;
        if !resp.status().is_success() {
            // A 404 is a definitive "no limit for this key": cache it negatively.
            if resp.status() == reqwest::StatusCode::NOT_FOUND {
                return Ok(None);
            }
            tracing::warn!("limit-service returned {}", resp.status());
            return Err(());
        }
        let body: LimitResponse = resp
            .json()
            .await
            .map_err(|e| tracing::warn!("limit-service response parse failed: {e}"))?;
        Ok(self.map_response(body))
    }

    /// Map a service response to a compiled limit: a tier name resolves against
    /// the configured profiles; otherwise explicit numbers apply.
    fn map_response(&self, body: LimitResponse) -> Option<CompiledProfile> {
        if let Some(tier) = body.tier {
            return self.profiles.get(&tier).copied();
        }
        body.rate_per_min
            .map(|rpm| profile_from_numbers(rpm, body.burst.unwrap_or(rpm)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles() -> HashMap<String, CompiledProfile> {
        let mut m = HashMap::new();
        m.insert(
            "premium".to_string(),
            profile_from_numbers(1000, 100), // limit 1000
        );
        m
    }

    fn jwt_limits() -> JwtLimits {
        JwtLimits::from_config(&JwtLimitConfig {
            tier_claim: "ratelimit_tier".to_string(),
            rpm_claim: "ratelimit_rpm".to_string(),
            burst_claim: "ratelimit_burst".to_string(),
        })
    }

    #[test]
    fn jwt_tier_name_maps_to_profile() {
        let claims = serde_json::json!({ "ratelimit_tier": "premium" });
        let p = jwt_limits().resolve(&claims, &profiles()).unwrap();
        assert_eq!(p.limit, 1000);
    }

    #[test]
    fn jwt_direct_numbers_build_a_profile() {
        let claims = serde_json::json!({ "ratelimit_rpm": 300, "ratelimit_burst": 30 });
        let p = jwt_limits().resolve(&claims, &profiles()).unwrap();
        assert_eq!(p.limit, 300);
    }

    #[test]
    fn jwt_tier_takes_precedence_over_numbers() {
        let claims = serde_json::json!({ "ratelimit_tier": "premium", "ratelimit_rpm": 5 });
        let p = jwt_limits().resolve(&claims, &profiles()).unwrap();
        assert_eq!(p.limit, 1000);
    }

    #[test]
    fn jwt_unknown_tier_falls_through_to_numbers_then_none() {
        // Unknown tier + no numbers → no resolution.
        let claims = serde_json::json!({ "ratelimit_tier": "gold" });
        assert!(jwt_limits().resolve(&claims, &profiles()).is_none());
        // Unknown tier + numbers → numbers win.
        let claims = serde_json::json!({ "ratelimit_tier": "gold", "ratelimit_rpm": 42 });
        assert_eq!(
            jwt_limits().resolve(&claims, &profiles()).unwrap().limit,
            42
        );
    }

    #[tokio::test]
    async fn actively_used_stale_entry_survives_eviction() {
        use crate::config::LimitServiceConfig;
        let svc = LimitService::build(
            &LimitServiceConfig {
                endpoint: "http://127.0.0.1:0/".to_string(),
                ttl_secs: 1,
                timeout_ms: 50,
            },
            profiles(),
        )
        .unwrap();
        // Simulate a service outage: the last successful fetch was long ago, so
        // `at` is stale and well past evict_after, but the key is still in active
        // use right now.
        let old = Instant::now()
            .checked_sub(Duration::from_secs(600))
            .expect("clock supports the offset");
        svc.cache.insert(
            "k".to_string(),
            Cached {
                profile: Some(profile_from_numbers(10, 10)),
                at: old,
                last_access: old,
            },
        );
        let _ = svc.resolve("k");
        svc.sweep();
        assert!(
            svc.cache.contains_key("k"),
            "an actively-used stale entry must not be evicted during an outage"
        );
    }

    #[test]
    fn numeric_string_claims_are_accepted() {
        let claims = serde_json::json!({ "ratelimit_rpm": "250" });
        assert_eq!(
            jwt_limits().resolve(&claims, &profiles()).unwrap().limit,
            250
        );
    }
}
