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

        let store = build_store(config)?;
        Ok(Some(Arc::new(Self {
            store,
            classes,
            identifiers,
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

    // Endpoint-class limit (per client IP), no body needed.
    let mut class_decision = None;
    if let Some(class) = shield.match_class(&path) {
        let ip = client_ip(request.headers());
        let key = format!("class:{}:{ip}", class.class);
        let decision = shield.store.hit(&key, &class.rate).await;
        if !decision.allowed {
            return too_many_requests(decision);
        }
        class_decision = Some(decision);
    }

    // Per-identifier limit: buffer the body, read the field, then restore it.
    let request = if let Some(id_ep) = shield.match_identifier(&path) {
        let (parts, body) = request.into_parts();
        let bytes = match axum::body::to_bytes(body, MAX_IDENTIFIER_BODY).await {
            Ok(b) => b,
            Err(_) => return payload_too_large(),
        };
        if let Some(ident) = extract_body_field(&bytes, &id_ep.body_field) {
            let key = format!("id:{path}:{}:{ident}", id_ep.body_field);
            let decision = shield.store.hit(&key, &id_ep.rate).await;
            if !decision.allowed {
                return too_many_requests(decision);
            }
        }
        Request::from_parts(parts, Body::from(bytes))
    } else {
        request
    };

    let mut response = next.run(request).await;
    if let Some(decision) = class_decision {
        attach_rate_headers(response.headers_mut(), &decision);
    }
    response
}

/// Convenience alias for the axum request type used by the middleware.
type Request = axum::extract::Request;

/// Extract the client IP from forwarding headers, falling back to `unknown`.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))
        .unwrap_or("unknown")
        .to_string()
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
    fn client_ip_prefers_forwarded_for_first_hop() {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "203.0.113.7, 10.0.0.1".parse().unwrap());
        assert_eq!(client_ip(&h), "203.0.113.7");
    }

    #[test]
    fn client_ip_falls_back_to_real_ip_then_unknown() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", "198.51.100.2".parse().unwrap());
        assert_eq!(client_ip(&h), "198.51.100.2");
        assert_eq!(client_ip(&HeaderMap::new()), "unknown");
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
