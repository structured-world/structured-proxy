//! Shield: request rate limiting.
//!
//! Enforces the `shield` config as an axum middleware. Two rule kinds are
//! supported: endpoint *classes* (glob path → per-client limit) and per
//! *identifier* endpoints (limit by a value read from the request body). The
//! counter backend is pluggable via [`RateLimitStore`]; the default is an
//! in-process store, with an optional Redis store for multi-instance setups.

pub mod matcher;
pub mod rate;
pub mod store;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::config::ShieldConfig;
use matcher::{EndpointClass, IdentifierEndpoint};
use store::{Decision, MemoryStore, RateLimitStore};

/// Maximum request body buffered to read an identifier field (256 KiB).
const MAX_IDENTIFIER_BODY: usize = 256 * 1024;

/// Compiled Shield rules plus the counter store.
pub struct Shield {
    store: Arc<dyn RateLimitStore>,
    classes: Vec<EndpointClass>,
    identifiers: Vec<IdentifierEndpoint>,
    /// CIDR ranges whose `X-Forwarded-For` / `X-Real-IP` headers we trust.
    trusted_proxies: Vec<ipnet::IpNet>,
}

impl Shield {
    /// Build a Shield from config, or `None` when disabled / has no rules.
    ///
    /// Uses a Redis store when `redis_url` is set and the `redis` feature is
    /// compiled in; otherwise an in-process [`MemoryStore`].
    ///
    /// # Errors
    /// Returns an error string when a glob pattern or rate fails to compile, or
    /// when the configured Redis backend cannot be reached.
    pub fn build(config: &ShieldConfig) -> Result<Option<Arc<Self>>, String> {
        if !config.enabled {
            return Ok(None);
        }
        if config.endpoint_classes.is_empty() && config.identifier_endpoints.is_empty() {
            tracing::warn!("shield enabled but no endpoint_classes or identifier_endpoints set");
            return Ok(None);
        }

        let default_window = Duration::from_secs(config.window_secs.max(1));
        let classes = matcher::compile_endpoint_classes(&config.endpoint_classes, default_window)?;
        let identifiers =
            matcher::compile_identifier_endpoints(&config.identifier_endpoints, default_window)?;

        let trusted_proxies = config
            .trusted_proxies
            .iter()
            .map(|s| parse_cidr(s))
            .collect::<Result<Vec<_>, _>>()?;

        let store = build_store(config)?;
        Ok(Some(Arc::new(Self {
            store,
            classes,
            identifiers,
            trusted_proxies,
        })))
    }

    fn match_class(&self, path: &str) -> Option<&EndpointClass> {
        self.classes.iter().find(|c| c.matcher.is_match(path))
    }

    fn match_identifier(&self, path: &str) -> Option<&IdentifierEndpoint> {
        self.identifiers.iter().find(|i| i.matcher.is_match(path))
    }
}

/// Select the counter store from config.
fn build_store(config: &ShieldConfig) -> Result<Arc<dyn RateLimitStore>, String> {
    match &config.redis_url {
        Some(url) => open_redis(url),
        None => Ok(Arc::new(MemoryStore::new())),
    }
}

#[cfg(feature = "redis")]
fn open_redis(url: &str) -> Result<Arc<dyn RateLimitStore>, String> {
    store::RedisStore::open(url)
        .map(|s| Arc::new(s) as Arc<dyn RateLimitStore>)
        .map_err(|e| format!("invalid Redis URL for rate-limit store: {e}"))
}

#[cfg(not(feature = "redis"))]
fn open_redis(_url: &str) -> Result<Arc<dyn RateLimitStore>, String> {
    tracing::warn!(
        "shield.redis_url is set but the `redis` feature is not compiled in; \
         falling back to the in-process store (per-replica limits only)"
    );
    Ok(Arc::new(MemoryStore::new()))
}

/// Axum middleware enforcing the compiled Shield rules.
pub async fn middleware(
    State(shield): State<Arc<Shield>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let peer = request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|ci| ci.0.ip());
    let client = client_ip(peer, request.headers(), &shield.trusted_proxies);

    // The decision whose budget we surface to the client via headers.
    let mut report = None;

    // Endpoint-class limit (per client IP), no body needed.
    if let Some(class) = shield.match_class(&path) {
        let key = format!("class:{}:{client}", class.class);
        let decision = shield.store.hit(&key, &class.rate).await;
        if !decision.allowed {
            return too_many_requests(decision);
        }
        report = Some(decision);
    }

    // Per-identifier limit: buffer the body, read the field, then restore it.
    let request = if let Some(id_ep) = shield.match_identifier(&path) {
        let (parts, body) = request.into_parts();
        let bytes = match axum::body::to_bytes(body, MAX_IDENTIFIER_BODY).await {
            Ok(b) => b,
            Err(_) => return payload_too_large(),
        };
        // Key by the identifier value, or fall back to the client IP when the
        // field is absent so the limit can't be bypassed by omitting it.
        let key = match extract_body_field(&bytes, &id_ep.body_field) {
            Some(ident) => format!("id:{path}:{}:{ident}", id_ep.body_field),
            None => format!("id:{path}:{}:ip:{client}", id_ep.body_field),
        };
        let decision = shield.store.hit(&key, &id_ep.rate).await;
        if !decision.allowed {
            return too_many_requests(decision);
        }
        // The identifier rule is more specific than a class rule, so report it.
        report = Some(decision);
        Request::from_parts(parts, Body::from(bytes))
    } else {
        request
    };

    let mut response = next.run(request).await;
    if let Some(decision) = report {
        attach_rate_headers(response.headers_mut(), &decision);
    }
    response
}

/// Convenience alias for the axum request type used by the middleware.
type Request = axum::extract::Request;

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
/// `X-Forwarded-For` / `X-Real-IP` are trusted only when the direct `peer` is a
/// configured trusted proxy (so a direct client can't spoof them). Without
/// connection info (e.g. a custom server that does not provide it) the headers
/// are taken as a best effort.
fn client_ip(
    peer: Option<std::net::IpAddr>,
    headers: &HeaderMap,
    trusted: &[ipnet::IpNet],
) -> String {
    let trust_headers = match peer {
        Some(ip) => trusted.iter().any(|net| net.contains(&ip)),
        None => true,
    };
    if trust_headers {
        if let Some(forwarded) = forwarded_for(headers) {
            return forwarded;
        }
    }
    match peer {
        Some(ip) => ip.to_string(),
        None => "unknown".to_string(),
    }
}

/// First hop of `X-Forwarded-For`, falling back to `X-Real-IP`.
fn forwarded_for(headers: &HeaderMap) -> Option<String> {
    let first = |name: &str, split: bool| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                if split {
                    v.split(',').next().unwrap_or(v)
                } else {
                    v
                }
            })
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    first("x-forwarded-for", true).or_else(|| first("x-real-ip", false))
}

/// Read a (possibly dotted) field from a JSON body as a string identifier.
fn extract_body_field(bytes: &[u8], field: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let mut cur = &value;
    for seg in field.split('.') {
        cur = cur.get(seg)?;
    }
    match cur {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Add `X-RateLimit-*` headers describing the remaining budget.
fn attach_rate_headers(headers: &mut HeaderMap, decision: &Decision) {
    if let Ok(v) = decision.limit.to_string().parse() {
        headers.insert("x-ratelimit-limit", v);
    }
    if let Ok(v) = decision.remaining.to_string().parse() {
        headers.insert("x-ratelimit-remaining", v);
    }
}

fn too_many_requests(decision: Decision) -> Response {
    let retry = decision.retry_after.unwrap_or(Duration::ZERO).as_secs();
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "RESOURCE_EXHAUSTED",
            "message": "rate limit exceeded",
        })),
    )
        .into_response();
    let headers = response.headers_mut();
    attach_rate_headers(headers, &decision);
    if let Ok(v) = retry.to_string().parse() {
        headers.insert("retry-after", v);
    }
    response
}

fn payload_too_large() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        Json(serde_json::json!({
            "error": "INVALID_ARGUMENT",
            "message": "request body too large for rate-limit identifier extraction",
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_trusts_headers_only_from_trusted_peer() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        let trusted = vec![parse_cidr("10.0.0.0/8").unwrap()];
        let lb: std::net::IpAddr = "10.0.0.1".parse().unwrap();
        let direct: std::net::IpAddr = "198.51.100.9".parse().unwrap();

        // From a trusted proxy: trust the forwarded first hop.
        assert_eq!(client_ip(Some(lb), &h, &trusted), "203.0.113.7");
        // From an untrusted direct client: ignore the spoofable header, key by peer.
        assert_eq!(client_ip(Some(direct), &h, &trusted), "198.51.100.9");
    }

    #[test]
    fn client_ip_without_peer_info_uses_headers_then_unknown() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "198.51.100.2".parse().unwrap());
        assert_eq!(client_ip(None, &h, &[]), "198.51.100.2");
        assert_eq!(client_ip(None, &HeaderMap::new(), &[]), "unknown");
    }

    #[test]
    fn extract_body_field_reads_string_and_dotted() {
        let body = br#"{"email":"a@b.com","nested":{"id":42}}"#;
        assert_eq!(
            extract_body_field(body, "email"),
            Some("a@b.com".to_string())
        );
        assert_eq!(
            extract_body_field(body, "nested.id"),
            Some("42".to_string())
        );
        assert_eq!(extract_body_field(body, "missing"), None);
        assert_eq!(extract_body_field(b"not json", "email"), None);
    }

    // --- middleware enforcement (real router) ---

    use crate::config::{EndpointClassConfig, IdentifierEndpointConfig, ShieldConfig};
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    fn shield_config(
        classes: Vec<EndpointClassConfig>,
        ids: Vec<IdentifierEndpointConfig>,
    ) -> ShieldConfig {
        ShieldConfig {
            enabled: true,
            endpoint_classes: classes,
            identifier_endpoints: ids,
            window_secs: 60,
            redis_url: None,
            trusted_proxies: Vec::new(),
        }
    }

    fn app(shield: Arc<Shield>) -> axum::Router {
        axum::Router::new()
            .route("/limited", axum::routing::get(|| async { "ok" }))
            .route("/login", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(shield, middleware))
    }

    #[tokio::test]
    async fn middleware_blocks_after_endpoint_class_limit() {
        let shield = Shield::build(&shield_config(
            vec![EndpointClassConfig {
                pattern: "/limited".into(),
                class: "t".into(),
                rate: "2/min".into(),
            }],
            vec![],
        ))
        .unwrap()
        .unwrap();
        let app = app(shield);

        let get = || HttpRequest::get("/limited").body(Body::empty()).unwrap();
        // Two allowed (no client IP header → all share the "unknown" bucket).
        assert_eq!(app.clone().oneshot(get()).await.unwrap().status(), 200);
        let second = app.clone().oneshot(get()).await.unwrap();
        assert_eq!(second.status(), 200);
        assert_eq!(second.headers()["x-ratelimit-remaining"], "0");
        // Third over the limit → 429 with Retry-After.
        let third = app.clone().oneshot(get()).await.unwrap();
        assert_eq!(third.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(third.headers().contains_key("retry-after"));
    }

    #[tokio::test]
    async fn middleware_limits_per_identifier_value() {
        let shield = Shield::build(&shield_config(
            vec![],
            vec![IdentifierEndpointConfig {
                path: "/login".into(),
                body_field: "email".into(),
                rate: "1/min".into(),
            }],
        ))
        .unwrap()
        .unwrap();
        let app = app(shield);

        let post = |email: &str| {
            HttpRequest::post("/login")
                .header("content-type", "application/json")
                .body(Body::from(format!(r#"{{"email":"{email}"}}"#)))
                .unwrap()
        };

        // First request for alice is allowed, second is blocked.
        assert_eq!(
            app.clone().oneshot(post("alice")).await.unwrap().status(),
            200
        );
        assert_eq!(
            app.clone().oneshot(post("alice")).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        // A different identifier has its own budget.
        assert_eq!(
            app.clone().oneshot(post("bob")).await.unwrap().status(),
            200
        );
    }

    #[tokio::test]
    async fn identifier_response_carries_ratelimit_headers() {
        let shield = Shield::build(&shield_config(
            vec![],
            vec![IdentifierEndpointConfig {
                path: "/login".into(),
                body_field: "email".into(),
                rate: "5/min".into(),
            }],
        ))
        .unwrap()
        .unwrap();
        let app = app(shield);

        let resp = app
            .oneshot(
                HttpRequest::post("/login")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"email":"a"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        // Headers come from the identifier decision, not just class decisions.
        assert_eq!(resp.headers()["x-ratelimit-limit"], "5");
        assert_eq!(resp.headers()["x-ratelimit-remaining"], "4");
    }

    #[tokio::test]
    async fn identifier_limit_not_bypassed_when_field_absent() {
        // Omitting the identifier field must not skip the limit: requests with
        // no extractable identifier fall back to a client-keyed counter.
        let shield = Shield::build(&shield_config(
            vec![],
            vec![IdentifierEndpointConfig {
                path: "/login".into(),
                body_field: "email".into(),
                rate: "1/min".into(),
            }],
        ))
        .unwrap()
        .unwrap();
        let app = app(shield);

        let post_no_email = || {
            HttpRequest::post("/login")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap()
        };
        assert_eq!(
            app.clone().oneshot(post_no_email()).await.unwrap().status(),
            200
        );
        // Second request without the field is still counted → blocked.
        assert_eq!(
            app.clone().oneshot(post_no_email()).await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn middleware_ignores_unmatched_paths() {
        let shield = Shield::build(&shield_config(
            vec![EndpointClassConfig {
                pattern: "/limited".into(),
                class: "t".into(),
                rate: "1/min".into(),
            }],
            vec![],
        ))
        .unwrap()
        .unwrap();
        let app = app(shield);

        // /login is not covered by any rule → never limited.
        for _ in 0..5 {
            let resp = app
                .clone()
                .oneshot(HttpRequest::post("/login").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), 200);
        }
    }
}
