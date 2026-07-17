//! Shield: request rate limiting.
//!
//! The proxy runs embedded on each service instance, so every decision is made
//! locally with a per-instance GCRA shaper ([`store::GcraStore`]) that adds no
//! blocking latency to the request path. When a shared store is configured, a
//! background task reconciles counters across instances asynchronously to
//! approximate a fleet-wide limit; the request path never blocks on it.
//!
//! A request is limited by the first [rule](matcher::CompiledRule) whose glob
//! matches its path. The rule's key selects *who* is limited (client IP, a
//! header value, or a validated JWT claim) and its profile selects *how much*.

pub mod gcra;
#[cfg(feature = "redis")]
pub mod global;
pub mod matcher;
pub mod rate;
pub mod resolve;
pub mod store;
pub mod window;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::config::ShieldConfig;
use gcra::Verdict;
use matcher::{CompiledProfile, CompiledRule, KeySource, Phase};
use store::GcraStore;

/// Compiled Shield rules, limit tiers, and the local GCRA store.
pub struct Shield {
    rules: Vec<CompiledRule>,
    profiles: HashMap<String, CompiledProfile>,
    /// Applied when a matched rule resolves no other limit.
    default_profile: Option<CompiledProfile>,
    /// Resolve a key's limit from validated JWT claims, when configured.
    jwt_limits: Option<resolve::JwtLimits>,
    /// Resolve a key's limit from an external service (cached, async).
    limit_service: Option<Arc<resolve::LimitService>>,
    /// Cross-instance reconciliation of the fleet-wide view (async, off the hot
    /// path). Present only when a shared store is configured and compiled in.
    #[cfg(feature = "redis")]
    global: Option<Arc<global::GlobalCounters>>,
    store: GcraStore,
    /// CIDR ranges whose `X-Forwarded-For` / `X-Real-IP` headers we trust.
    trusted_proxies: Vec<ipnet::IpNet>,
}

impl Shield {
    /// Build a Shield from config, or `None` when disabled / has no rules.
    ///
    /// # Errors
    /// Returns an error string when a glob pattern, rate, profile reference, or
    /// trusted-proxy CIDR fails to compile.
    pub fn build(config: &ShieldConfig) -> Result<Option<Arc<Self>>, String> {
        if !config.enabled {
            return Ok(None);
        }
        if config.rules.is_empty() {
            // Fail loud rather than silently running unmetered: an upgrade that
            // left an old `shield` schema (endpoint_classes / identifier_endpoints
            // / redis_url) in place deserializes to zero rules, which would
            // otherwise disable this security control while `enabled` is true.
            return Err(
                "shield.enabled is true but no rules are configured (note the schema: \
                 profiles + rules + sync, not the older endpoint_classes/identifier_endpoints)"
                    .to_string(),
            );
        }

        let profiles = matcher::compile_profiles(&config.profiles)?;
        let rules = matcher::compile_rules(&config.rules, &profiles)?;

        let default_profile =
            match &config.default_profile {
                Some(name) => Some(*profiles.get(name).ok_or_else(|| {
                    format!("default_profile references unknown profile {name:?}")
                })?),
                None => None,
            };

        let trusted_proxies = config
            .trusted_proxies
            .iter()
            .map(|s| parse_cidr(s))
            .collect::<Result<Vec<_>, _>>()?;

        let jwt_limits = config
            .jwt_limits
            .as_ref()
            .map(resolve::JwtLimits::from_config);
        let limit_service = match &config.limit_service {
            Some(cfg) => Some(resolve::LimitService::build(cfg, profiles.clone())?),
            None => None,
        };

        #[cfg(feature = "redis")]
        let global = match &config.sync {
            Some(sync) => {
                let g = global::GlobalCounters::build(
                    &sync.redis_url,
                    Duration::from_millis(sync.interval_ms),
                )?;
                // Keep the fleet gate only if reconciliation actually started;
                // otherwise fall back to per-instance limiting rather than gating
                // on an estimate that would never be refreshed.
                g.spawn().then_some(g)
            }
            None => None,
        };
        #[cfg(not(feature = "redis"))]
        if config.sync.is_some() {
            tracing::warn!(
                "shield.sync is set but the `redis` feature is not compiled in; \
                 staying local-only (per-instance limits)"
            );
        }

        Ok(Some(Arc::new(Self {
            rules,
            profiles,
            default_profile,
            jwt_limits,
            limit_service,
            #[cfg(feature = "redis")]
            global,
            store: GcraStore::new(),
            trusted_proxies,
        })))
    }

    /// The first rule in `phase` whose glob matches `path`. A path may match one
    /// rule per phase; each phase enforces independently (two-phase by design:
    /// a pre-auth IP/header rule and a post-auth claim rule can both apply).
    fn match_rule(&self, path: &str, phase: Phase) -> Option<&CompiledRule> {
        self.rules
            .iter()
            .find(|r| r.phase == phase && r.matcher.is_match(path))
    }

    /// Resolve the limit tier for a matched rule, in priority order: the JWT
    /// itself (validated claims), then the external service (cached), then the
    /// rule's pinned profile, then the default profile. `None` means no limit
    /// applies and the request passes unmetered.
    fn resolve_limit(
        &self,
        rule: &CompiledRule,
        claims: Option<&serde_json::Value>,
        identity: &str,
    ) -> Option<CompiledProfile> {
        if let (Some(jwt), Some(claims)) = (&self.jwt_limits, claims) {
            if let Some(profile) = jwt.resolve(claims, &self.profiles) {
                return Some(profile);
            }
        }
        if let Some(service) = &self.limit_service {
            if let Some(profile) = service.resolve(identity) {
                return Some(profile);
            }
        }
        self.static_profile(rule)
    }

    /// The rule's pinned profile, else the default profile.
    fn static_profile(&self, rule: &CompiledRule) -> Option<CompiledProfile> {
        rule.profile
            .as_ref()
            .and_then(|name| self.profiles.get(name))
            .or(self.default_profile.as_ref())
            .copied()
    }
}

/// Pre-auth middleware: enforces rules that need no validated claims (IP /
/// header keys). Layered outside auth so anonymous floods are shed before any
/// signature verification.
pub async fn pre_auth_middleware(
    axum::extract::State(shield): axum::extract::State<Arc<Shield>>,
    request: Request,
    next: Next,
) -> Response {
    enforce(&shield, Phase::PreAuth, request, next).await
}

/// Post-auth middleware: enforces rules keyed by a validated JWT claim. Layered
/// inside auth so the verified claims are available on the request.
pub async fn post_auth_middleware(
    axum::extract::State(shield): axum::extract::State<Arc<Shield>>,
    request: Request,
    next: Next,
) -> Response {
    enforce(&shield, Phase::PostAuth, request, next).await
}

/// Match a phase's rule for the request, apply its limit, and attach headers.
async fn enforce(shield: &Shield, phase: Phase, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let Some(rule) = shield.match_rule(path, phase) else {
        return next.run(request).await;
    };

    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    let client = client_ip(peer, request.headers(), &shield.trusted_proxies);
    let claims = request
        .extensions()
        .get::<crate::auth::ValidatedClaims>()
        .map(|c| c.0.as_ref());
    let key = rule_key(
        &rule.fingerprint,
        &rule.key,
        &client,
        request.headers(),
        claims,
    );

    // The limit service resolves per-principal, so it needs the real identity;
    // the store / shared counter only need the de-identified `store` key.
    let Some(profile) = shield.resolve_limit(rule, claims, &key.identity) else {
        // No limit resolves for this rule (JWT/service/profile/default all
        // absent): allow the request unmetered.
        return next.run(request).await;
    };

    // Fleet gate first (read-only, cached), so the local shaper is not charged
    // for a request the fleet-wide budget will reject. The fleet budget is the
    // sustained rate (`profile.limit`); `burst` is deliberately a per-instance
    // smoothing allowance, not a fleet-wide entitlement (honouring it fleet-wide
    // would multiply the effective limit by N). A single instance's burst is
    // therefore capped by the shared budget when the fleet is near it.
    //
    // Consequence for a `burst > limit` profile (e.g. `rate: "1/min", burst: 5`):
    // under reconciliation the shared counter caps the key at the sustained
    // `limit`, so the extra burst headroom that a local-only deployment would
    // allow is not granted fleet-wide. This is intentional, not an oversight:
    // gating on `burst` instead would let the fleet sustain `burst`-per-window,
    // loosening the sustained cap by the burst factor. The conservative choice
    // (never over-admit the fleet's sustained budget) wins; the local GCRA still
    // smooths per-instance traffic.
    #[cfg(feature = "redis")]
    let fleet_remaining = shield
        .global
        .as_ref()
        .map(|g| g.fleet_remaining(&key.store, profile.limit, profile.window));
    #[cfg(feature = "redis")]
    if fleet_remaining == Some(0) {
        return global_reject(profile.limit, profile.window);
    }

    // The store key intentionally excludes the profile's numbers, so if a key's
    // resolved tier changes (a JWT/service tier upgrade), the existing TAT is
    // reused with the new emission interval. The TAT is an absolute time, so this
    // only causes a brief transient at the change and self-corrects within one
    // window. Keying by the tier's numbers instead would reset the budget on
    // every tier flip, which a client could exploit to shed its own limit.
    let verdict = shield.store.check(&key.store, &profile.gcra);
    if !verdict.allowed {
        return too_many_requests(profile.limit, verdict.remaining, &verdict);
    }

    // Report the tighter of the local and (when reconciled) fleet budgets, so a
    // client near the fleet cap isn't told it has ample local room. This admit
    // consumes one, hence the `- 1`.
    #[cfg(not(feature = "redis"))]
    let reported = verdict.remaining;
    #[cfg(feature = "redis")]
    let reported = {
        let mut r = verdict.remaining;
        if let Some(fr) = fleet_remaining {
            r = r.min(fr.saturating_sub(1));
            // Record the admit for the next reconciliation push.
            if let Some(global) = &shield.global {
                global.record(&key.store, profile.window);
            }
        }
        r
    };

    let mut response = next.run(request).await;
    // Report the tightest budget across phases. With defense-in-depth (a pre-auth
    // and a post-auth rule on the same path), an inner limiter may already have
    // set headers on the way out; overwrite them only when this (outer) phase's
    // remaining is smaller, so the client always sees the budget that will bite
    // first. An inner rejection carries remaining 0, so it is never overwritten.
    maybe_tighten_rate_headers(response.headers_mut(), profile.limit, reported, &verdict);
    response
}

/// Set the `RateLimit-*` headers unless an inner limiter already advertised a
/// tighter (smaller `remaining`) budget, which must reach the client intact.
fn maybe_tighten_rate_headers(
    headers: &mut HeaderMap,
    limit: u64,
    remaining: u64,
    verdict: &Verdict,
) {
    let existing = headers
        .get("ratelimit-remaining")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    match existing {
        Some(inner) if inner <= remaining => {} // inner budget is tighter (or equal): keep it
        _ => attach_rate_headers(headers, limit, remaining, verdict),
    }
}

/// A `429` for a request rejected by the fleet-wide gate. The sliding-window
/// estimate decays continuously (it does not free capacity at the epoch
/// boundary), so `Retry-After` is a modest poll interval rather than the time to
/// the boundary, which a client could wait out and still be rejected.
#[cfg(feature = "redis")]
fn global_reject(limit: u64, window: Duration) -> Response {
    // A tenth of the window (at least 1s): long enough not to hammer, short
    // enough to retry as the window decays or other instances free budget.
    let backoff = (window / 10).max(Duration::from_secs(1));
    let verdict = Verdict {
        allowed: false,
        new_tat: Duration::ZERO,
        remaining: 0,
        retry_after: backoff,
        reset_after: backoff,
    };
    too_many_requests(limit, 0, &verdict)
}

/// The keys a matched rule derives for one request.
struct RuleKey {
    /// De-identified key for the local store and shared counter: the rule's
    /// stable fingerprint, the source tag, and a hash of the value. Raw client
    /// values (API keys, principals, IPs) never reach the shared store or its
    /// logs. Deterministic across instances so reconciliation keys agree.
    store: String,
    /// The raw identity for per-principal limit-service resolution (the service
    /// must see the real principal to resolve its tier). Not persisted.
    identity: String,
}

/// Derive the store key and resolution identity for a matched rule. Every source
/// falls back to the client IP when its value is absent, so a limit can't be
/// dodged by omitting a header or authenticating anonymously (subject to the
/// rule's phase: a `jwt_claim` rule only runs post-auth).
fn rule_key(
    fingerprint: &str,
    key: &KeySource,
    client: &str,
    headers: &HeaderMap,
    claims: Option<&serde_json::Value>,
) -> RuleKey {
    let (tag, identity) = match key {
        KeySource::Ip => ("ip", client.to_string()),
        KeySource::Header(name) => match header_str(headers, name) {
            Some(v) => ("hdr", v),
            None => ("ip", client.to_string()),
        },
        KeySource::JwtClaim(claim) => match claims.and_then(|c| resolve::claim_str(c, claim)) {
            Some(v) => ("jwt", v),
            None => ("ip", client.to_string()),
        },
    };
    RuleKey {
        store: format!("{fingerprint}:{tag}:{}", matcher::short_hash(&identity)),
        identity,
    }
}

/// Parse a trusted-proxy entry as a CIDR range, accepting a bare IP as a /32
/// or /128 host range.
fn parse_cidr(s: &str) -> Result<ipnet::IpNet, String> {
    if let Ok(net) = s.parse::<ipnet::IpNet>() {
        return Ok(net);
    }
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return ipnet::IpNet::new(ip, prefix)
            .map_err(|e| format!("invalid trusted_proxies entry {s:?}: {e}"));
    }
    Err(format!("invalid trusted_proxies CIDR/IP: {s:?}"))
}

/// Resolve the client identity for keying.
///
/// `X-Forwarded-For` is trusted only when the direct `peer` is a configured
/// trusted proxy, and even then the *rightmost* hop outside the trusted ranges
/// is used: appending load balancers (nginx, ALB, GCP) add the connecting IP on
/// the right, so the leftmost entries are attacker-controlled. Without connection
/// info (a server not wired with `ConnectInfo`) we fail closed to a single
/// `"unknown"` bucket rather than trusting client-supplied forwarding headers,
/// which an attacker could otherwise rotate to dodge the limit.
fn client_ip(
    peer: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    trusted: &[ipnet::IpNet],
) -> String {
    match peer {
        Some(ip) => {
            if trusted.iter().any(|net| net.contains(&ip)) {
                if let Some(client) = rightmost_untrusted(headers, trusted) {
                    return client;
                }
            }
            ip.to_string()
        }
        None => "unknown".to_string(),
    }
}

/// Rightmost `X-Forwarded-For` hop that is not within a trusted range, i.e. the
/// last address appended by an untrusted party. Falls back to `X-Real-IP`.
fn rightmost_untrusted(headers: &HeaderMap, trusted: &[ipnet::IpNet]) -> Option<String> {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        for hop in xff.split(',').rev() {
            let hop = hop.trim();
            if hop.is_empty() {
                continue;
            }
            let trusted_hop = hop
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| trusted.iter().any(|net| net.contains(&ip)));
            if !trusted_hop {
                return Some(hop.to_string());
            }
        }
    }
    // X-Real-IP is set by the proxy to the single real client address.
    header_str(headers, "x-real-ip")
}

/// Trimmed, non-empty value of a header.
fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Attach the draft-ietf `RateLimit-*` headers describing the remaining budget.
/// `remaining` is passed explicitly (rather than read from the verdict) so the
/// caller can report the tighter of the local and fleet budgets.
fn attach_rate_headers(headers: &mut HeaderMap, limit: u64, remaining: u64, verdict: &Verdict) {
    if let Ok(v) = limit.to_string().parse() {
        headers.insert("ratelimit-limit", v);
    }
    if let Ok(v) = remaining.to_string().parse() {
        headers.insert("ratelimit-remaining", v);
    }
    if let Ok(v) = secs_ceil(verdict.reset_after).to_string().parse() {
        headers.insert("ratelimit-reset", v);
    }
}

/// A `429` response carrying the rate-limit headers plus `Retry-After`.
fn too_many_requests(limit: u64, remaining: u64, verdict: &Verdict) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "RESOURCE_EXHAUSTED",
            "message": "rate limit exceeded",
        })),
    )
        .into_response();
    let headers = response.headers_mut();
    attach_rate_headers(headers, limit, remaining, verdict);
    if let Ok(v) = secs_ceil(verdict.retry_after).to_string().parse() {
        headers.insert("retry-after", v);
    }
    response
}

/// Whole seconds, rounded up, for `Retry-After` / `RateLimit-Reset` (never report
/// `0` for a non-zero wait).
fn secs_ceil(d: Duration) -> u64 {
    // Round up from nanoseconds, not truncated millis: a sub-millisecond wait
    // must still report at least one second, never zero.
    let nanos = d.as_nanos();
    u64::try_from(nanos.div_ceil(1_000_000_000)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests;
