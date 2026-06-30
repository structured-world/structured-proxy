//! End-to-end test of the embedded Tier-2 hooks through the public API.
//!
//! Acceptance-criterion guard: the hook implementations below are written using
//! only `http`, `bytes`, `serde_json`, and `async-trait` (the crates a real
//! embedder uses), and reference **no `axum` type**. The proxy wires them into
//! its router via [`ProxyServer`]; the test then drives that router with axum +
//! tower purely as the assertion harness (that is the proxy's concern, not the
//! embedder's).

use std::sync::Arc;

use async_trait::async_trait;
use http::{HeaderMap, Method, StatusCode};
use structured_proxy::config::ProxyConfig;
use structured_proxy::hooks::{
    AuthDecider, Decision, ExtraRoute, ExtraRouteHandler, MetadataDocument, OidcBackend,
    RequestParts, RouteRequest, RouteResponse,
};
use structured_proxy::ProxyServer;

// --- embedder-supplied hook impls (axum-free) ----------------------------

/// Allows `/v1/public/**`, injects a verified `x-user` for everything else, and
/// redirects an explicit `/login`. Mirrors a real PDP shape (path + headers in,
/// decision out) without any framework types.
struct DemoDecider;

#[async_trait]
impl AuthDecider for DemoDecider {
    async fn decide(&self, req: &RequestParts<'_>) -> Decision {
        if req.path == "/login" {
            return Decision::Redirect {
                location: "https://login.example.com".to_string(),
            };
        }
        if req.path.starts_with("/v1/public/") {
            return Decision::Allow {
                inject_headers: HeaderMap::new(),
            };
        }
        if req.headers.get("authorization").is_some() {
            let mut h = HeaderMap::new();
            h.insert("x-user", "verified-user".parse().unwrap());
            Decision::Allow { inject_headers: h }
        } else {
            Decision::Deny {
                status: StatusCode::UNAUTHORIZED,
                body: bytes::Bytes::from_static(b"{\"error\":\"unauthenticated\"}"),
            }
        }
    }
}

struct DemoOidc;

#[async_trait]
impl OidcBackend for DemoOidc {
    fn metadata_documents(&self) -> Vec<MetadataDocument> {
        vec![MetadataDocument::new(
            "/.well-known/openid-configuration",
            serde_json::json!({ "issuer": "https://idp.example.com" }),
        )]
    }
    fn jwks(&self) -> MetadataDocument {
        MetadataDocument::new("/.well-known/jwks.json", serde_json::json!({ "keys": [] }))
    }
    async fn userinfo(&self, bearer: &str) -> Option<serde_json::Value> {
        (bearer == "token-123").then(|| serde_json::json!({ "sub": "user-1", "email": "u@x" }))
    }
}

struct PingHandler;

#[async_trait]
impl ExtraRouteHandler for PingHandler {
    async fn handle(&self, _req: RouteRequest) -> RouteResponse {
        RouteResponse::new(StatusCode::OK, bytes::Bytes::from_static(b"pong"))
    }
}

// --- harness (axum + tower) ----------------------------------------------

use axum::body::Body;
use tower::ServiceExt;

fn server() -> ProxyServer {
    let config = ProxyConfig::from_yaml_str(
        r#"
upstream:
  default: "http://127.0.0.1:50051"
service:
  name: "hooks-test"
"#,
    )
    .unwrap();

    ProxyServer::from_config(config)
        .with_auth_decider(Arc::new(DemoDecider))
        .with_oidc_backend(Arc::new(DemoOidc))
        .with_verify_path("/auth/verify")
        .with_extra_routes([ExtraRoute::new(Method::GET, "/ping", Arc::new(PingHandler))])
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn verify_endpoint_is_backed_by_the_decider() {
    let app = server().router().unwrap();

    // Authenticated original request → 200 with the injected identity.
    let ok = app
        .clone()
        .oneshot(
            axum::http::Request::get("/auth/verify")
                .header("x-forwarded-method", "GET")
                .header("x-forwarded-uri", "/v1/things")
                .header("authorization", "Bearer whatever")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(ok.headers()["x-user"], "verified-user");

    // No credentials → the decider denies.
    let denied = app
        .oneshot(
            axum::http::Request::get("/auth/verify")
                .header("x-forwarded-method", "GET")
                .header("x-forwarded-uri", "/v1/things")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_redirect_becomes_401_with_location() {
    let app = server().router().unwrap();
    let resp = app
        .oneshot(
            axum::http::Request::get("/auth/verify")
                .header("x-forwarded-method", "GET")
                .header("x-forwarded-uri", "/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers()["location"], "https://login.example.com");
}

#[tokio::test]
async fn oidc_backend_surface_is_served() {
    let app = server().router().unwrap();

    let disc = app
        .clone()
        .oneshot(
            axum::http::Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disc.status(), StatusCode::OK);
    assert!(body_string(disc).await.contains("idp.example.com"));

    let jwks = app
        .clone()
        .oneshot(
            axum::http::Request::get("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
    assert_eq!(jwks.headers()["content-type"], "application/jwk-set+json");

    let userinfo = app
        .oneshot(
            axum::http::Request::get("/userinfo")
                .header("authorization", "Bearer token-123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(userinfo.status(), StatusCode::OK);
    assert!(body_string(userinfo).await.contains("user-1"));
}

#[tokio::test]
async fn verify_path_defaults_when_not_configured() {
    // No with_verify_path and no JWT forward_auth config: the decider still
    // answers at the default /auth/verify.
    let config =
        ProxyConfig::from_yaml_str("upstream:\n  default: \"http://127.0.0.1:50051\"\n").unwrap();
    let app = ProxyServer::from_config(config)
        .with_auth_decider(Arc::new(DemoDecider))
        .router()
        .unwrap();
    let resp = app
        .oneshot(
            axum::http::Request::get("/auth/verify")
                .header("x-forwarded-uri", "/v1/public/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_and_metrics_paths_are_configurable() {
    // Relocate the probes and metrics, and confirm the defaults no longer exist.
    let config = ProxyConfig::from_yaml_str(
        r#"
upstream:
  default: "http://127.0.0.1:50051"
health:
  path: "/internal/health"
  live_path: "/internal/health/live"
metrics:
  path: "/internal/metrics"
"#,
    )
    .unwrap();
    let app = ProxyServer::from_config(config).router().unwrap();

    for path in [
        "/internal/health",
        "/internal/health/live",
        "/internal/metrics",
    ] {
        let resp = app
            .clone()
            .oneshot(axum::http::Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "expected route at {path}");
    }

    // The default paths are gone now that they were relocated.
    let default_health = app
        .oneshot(
            axum::http::Request::get("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(default_health.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn health_and_metrics_can_be_disabled() {
    let config = ProxyConfig::from_yaml_str(
        r#"
upstream:
  default: "http://127.0.0.1:50051"
health:
  enabled: false
metrics:
  enabled: false
"#,
    )
    .unwrap();
    let app = ProxyServer::from_config(config).router().unwrap();

    for path in ["/health", "/health/live", "/metrics"] {
        let resp = app
            .clone()
            .oneshot(axum::http::Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} should be unmounted when disabled"
        );
    }
}

#[tokio::test]
async fn config_forward_auth_path_colliding_with_probe_is_a_clean_error() {
    // The same collision guard must cover plain JWT forward-auth (no decider):
    // a forward_auth.path equal to a built-in GET path is a clean error, not an
    // axum duplicate-route panic.
    const PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEARCMxEnaM2/dblLuPNgBZpTvSUXO5ir+XQ1nyzJm4CFw=\n\
        -----END PUBLIC KEY-----\n";
    let pem_path = std::env::temp_dir().join(format!("sp_hooks_fa_{}.pem", std::process::id()));
    std::fs::write(&pem_path, PUB_PEM).unwrap();

    let config = ProxyConfig::from_yaml_str(&format!(
        r#"
upstream:
  default: "http://127.0.0.1:50051"
auth:
  mode: "jwt"
  jwt:
    public_key_pem_file: "{}"
  forward_auth:
    enabled: true
    path: "/health"
"#,
        pem_path.display()
    ))
    .unwrap();
    let result = ProxyServer::from_config(config).router();
    let _ = std::fs::remove_file(&pem_path);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("collides with an already-mounted route"));
}

#[tokio::test]
async fn verify_path_colliding_with_openapi_docs_is_a_clean_error() {
    // The collision guard must cover every built-in GET route mounted before
    // verify, including the OpenAPI spec/docs paths (not just health/metrics).
    let config = ProxyConfig::from_yaml_str(
        r#"
upstream:
  default: "http://127.0.0.1:50051"
openapi:
  enabled: true
"#,
    )
    .unwrap();
    let result = ProxyServer::from_config(config)
        .with_auth_decider(Arc::new(DemoDecider))
        .with_verify_path("/docs")
        .router();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("collides with an already-mounted route"));
}

#[tokio::test]
async fn verify_path_colliding_with_oidc_route_is_a_clean_error() {
    // The reserved-path set must include OIDC backend routes; a verify path on
    // top of the discovery document is a clean error, not a panic.
    let config =
        ProxyConfig::from_yaml_str("upstream:\n  default: \"http://127.0.0.1:50051\"\n").unwrap();
    let result = ProxyServer::from_config(config)
        .with_oidc_backend(Arc::new(DemoOidc))
        .with_auth_decider(Arc::new(DemoDecider))
        .with_verify_path("/.well-known/openid-configuration")
        .router();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("collides with an already-mounted route"));
}

#[tokio::test]
async fn malformed_verify_path_is_a_clean_error() {
    let config =
        ProxyConfig::from_yaml_str("upstream:\n  default: \"http://127.0.0.1:50051\"\n").unwrap();
    let result = ProxyServer::from_config(config)
        .with_auth_decider(Arc::new(DemoDecider))
        .with_verify_path("auth/verify") // missing leading '/'
        .router();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("must start with '/'"));
}

#[tokio::test]
async fn verify_path_colliding_with_probe_is_a_clean_error() {
    // A verify path that collides with a built-in GET route must surface a
    // config error, not an axum duplicate-route panic.
    let config =
        ProxyConfig::from_yaml_str("upstream:\n  default: \"http://127.0.0.1:50051\"\n").unwrap();
    let result = ProxyServer::from_config(config)
        .with_auth_decider(Arc::new(DemoDecider))
        .with_verify_path("/health")
        .router();
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("collides with an already-mounted route"));
}

#[tokio::test]
async fn relocated_paths_stay_exempt_under_maintenance() {
    // With maintenance enabled, relocated probe / metrics / verify paths must
    // stay reachable (they were exempt at their default locations).
    let config = ProxyConfig::from_yaml_str(
        r#"
upstream:
  default: "http://127.0.0.1:50051"
maintenance:
  enabled: true
health:
  path: "/internal/health"
metrics:
  path: "/internal/metrics"
"#,
    )
    .unwrap();
    let app = ProxyServer::from_config(config)
        .with_auth_decider(Arc::new(DemoDecider))
        .with_verify_path("/internal/verify")
        .router()
        .unwrap();

    // Probe + metrics reachable despite maintenance.
    for path in ["/internal/health", "/internal/metrics"] {
        let resp = app
            .clone()
            .oneshot(axum::http::Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{path} blocked by maintenance"
        );
    }

    // Relocated verify endpoint is exempt and answers the decider's decision.
    let verify = app
        .clone()
        .oneshot(
            axum::http::Request::get("/internal/verify")
                .header("x-forwarded-uri", "/v1/public/info")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(verify.status(), StatusCode::OK);

    // A non-exempt proxied path still gets the 503 maintenance response.
    let blocked = app
        .oneshot(
            axum::http::Request::get("/v1/anything")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(blocked.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn extra_route_is_mounted() {
    let app = server().router().unwrap();
    let resp = app
        .oneshot(
            axum::http::Request::get("/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "pong");
}
