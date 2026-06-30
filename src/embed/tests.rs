//! Tests for the axum glue bridging the framework-agnostic embedding hooks.

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use tower::ServiceExt;

use super::*;
use crate::hooks::{
    AuthDecider, Decision, ExtraRoute, ExtraRouteHandler, MetadataDocument, OidcBackend,
    RequestParts, RouteRequest, RouteResponse,
};

// --- helpers -------------------------------------------------------------

async fn body_string(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn allow_with(name: &'static str, value: &'static str) -> Decision {
    let mut h = HeaderMap::new();
    h.insert(name, value.parse().unwrap());
    Decision::Allow { inject_headers: h }
}

/// An [`AuthDecider`] whose decision is computed from the request by a closure,
/// so tests can assert behaviour against method/path/headers.
struct FnDecider<F>(F);

#[async_trait]
impl<F> AuthDecider for FnDecider<F>
where
    F: Fn(&RequestParts<'_>) -> Decision + Send + Sync,
{
    async fn decide(&self, req: &RequestParts<'_>) -> Decision {
        (self.0)(req)
    }
}

fn decider<F>(f: F) -> Arc<dyn AuthDecider>
where
    F: Fn(&RequestParts<'_>) -> Decision + Send + Sync + 'static,
{
    Arc::new(FnDecider(f))
}

// --- helper unit tests ---------------------------------------------------

#[test]
fn bearer_token_parses_either_case_and_rejects_other_schemes() {
    let mut h = HeaderMap::new();
    h.insert("authorization", "Bearer abc.def".parse().unwrap());
    assert_eq!(bearer_token(&h).as_deref(), Some("abc.def"));

    let mut lower = HeaderMap::new();
    lower.insert("authorization", "bearer xyz".parse().unwrap());
    assert_eq!(bearer_token(&lower).as_deref(), Some("xyz"));

    // Scheme name is case-insensitive (RFC 7235).
    let mut upper = HeaderMap::new();
    upper.insert("authorization", "BEARER tok".parse().unwrap());
    assert_eq!(bearer_token(&upper).as_deref(), Some("tok"));

    let mut basic = HeaderMap::new();
    basic.insert("authorization", "Basic xyz".parse().unwrap());
    assert_eq!(bearer_token(&basic), None);
    assert_eq!(bearer_token(&HeaderMap::new()), None);
}

#[test]
fn original_method_and_target_read_forwarding_headers() {
    let mut h = HeaderMap::new();
    h.insert("x-forwarded-method", "post".parse().unwrap());
    h.insert(
        "x-forwarded-uri",
        "/v1/admin/things?page=2".parse().unwrap(),
    );
    assert_eq!(original_method(&h), Some(Method::POST));
    assert_eq!(
        original_target(&h),
        Some(("/v1/admin/things".to_string(), Some("page=2".to_string())))
    );

    // Falls back to x-original-* and tolerates a missing query.
    let mut alt = HeaderMap::new();
    alt.insert("x-original-method", "GET".parse().unwrap());
    alt.insert("x-original-uri", "/v1/public".parse().unwrap());
    assert_eq!(original_method(&alt), Some(Method::GET));
    assert_eq!(
        original_target(&alt),
        Some(("/v1/public".to_string(), None))
    );

    assert_eq!(original_method(&HeaderMap::new()), None);
    assert_eq!(original_target(&HeaderMap::new()), None);
}

#[test]
fn strip_then_insert_overrides_client_supplied_values() {
    let mut dst = HeaderMap::new();
    dst.insert("x-user", "forged".parse().unwrap());
    dst.insert("x-other", "keep".parse().unwrap());

    let mut inject = HeaderMap::new();
    inject.insert("x-user", "verified".parse().unwrap());

    strip_then_insert(&mut dst, &inject);

    // The forged value is gone, only the verified one remains.
    let users: Vec<_> = dst.get_all("x-user").iter().collect();
    assert_eq!(users.len(), 1);
    assert_eq!(dst["x-user"], "verified");
    // Unrelated client headers are untouched.
    assert_eq!(dst["x-other"], "keep");
}

// --- auth_decider_gate (inline gate) ------------------------------------

/// Build a tiny app with the gate in front of a handler that echoes the
/// `x-user` header the upstream would have received.
fn gated_app(decider: Arc<dyn AuthDecider>) -> Router {
    let echo = |headers: HeaderMap| async move {
        headers
            .get("x-user")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    Router::new()
        .route("/x", get(echo))
        .layer(axum::middleware::from_fn_with_state(
            decider,
            auth_decider_gate,
        ))
}

#[tokio::test]
async fn gate_allow_injects_headers_and_reaches_handler() {
    let app = gated_app(decider(|_| allow_with("x-user", "alice")));
    let resp = app
        .oneshot(Request::get("/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "alice");
}

#[tokio::test]
async fn gate_allow_strips_client_forged_inject_header() {
    // The decider injects x-user; a client-supplied x-user must not survive.
    let app = gated_app(decider(|_| allow_with("x-user", "real")));
    let resp = app
        .oneshot(
            Request::get("/x")
                .header("x-user", "forged")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "real");
}

#[tokio::test]
async fn gate_deny_short_circuits_with_status_and_body() {
    let app = gated_app(decider(|_| Decision::Deny {
        status: StatusCode::FORBIDDEN,
        body: Bytes::from_static(b"{\"error\":\"nope\"}"),
    }));
    let resp = app
        .oneshot(Request::get("/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(resp.headers()["content-type"], "application/json");
    assert_eq!(body_string(resp).await, "{\"error\":\"nope\"}");
}

#[tokio::test]
async fn gate_redirect_is_302_with_location() {
    let app = gated_app(decider(|_| Decision::Redirect {
        location: "https://login.example.com".to_string(),
    }));
    let resp = app
        .oneshot(Request::get("/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert_eq!(resp.headers()["location"], "https://login.example.com");
}

#[tokio::test]
async fn gate_sees_request_path() {
    // Allow only /x; the gate must observe the real path.
    let app = gated_app(decider(|req| {
        if req.path == "/x" {
            allow_with("x-user", "ok")
        } else {
            Decision::Deny {
                status: StatusCode::FORBIDDEN,
                body: Bytes::new(),
            }
        }
    }));
    let resp = app
        .oneshot(Request::get("/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// --- verify_via_decider (/verify endpoint) ------------------------------

fn verify_app(decider: Arc<dyn AuthDecider>) -> Router {
    Router::new().route(
        "/auth/verify",
        axum::routing::any(move |req: axum::extract::Request| {
            let decider = decider.clone();
            async move { verify_via_decider(decider, req).await }
        }),
    )
}

#[tokio::test]
async fn verify_allow_returns_200_with_verified_headers() {
    let app = verify_app(decider(|_| allow_with("x-forwarded-user", "alice")));
    let resp = app
        .oneshot(
            Request::get("/auth/verify")
                .header("x-forwarded-method", "GET")
                .header("x-forwarded-uri", "/v1/admin/things")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-forwarded-user"], "alice");
}

#[tokio::test]
async fn verify_uses_original_method_and_path_from_forwarding_headers() {
    // The sub-request verb is GET to /auth/verify, but the decision must be
    // taken on the original POST /v1/admin/things.
    let app = verify_app(decider(|req| {
        if req.method == Method::POST && req.path == "/v1/admin/things" {
            allow_with("x-ok", "1")
        } else {
            Decision::Deny {
                status: StatusCode::FORBIDDEN,
                body: Bytes::new(),
            }
        }
    }));
    let resp = app
        .oneshot(
            Request::get("/auth/verify")
                .header("x-forwarded-method", "POST")
                .header("x-forwarded-uri", "/v1/admin/things")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-ok"], "1");
}

#[tokio::test]
async fn verify_redirect_is_401_with_location() {
    // A fronting proxy wants 401 (+ Location), not a 302 to follow.
    let app = verify_app(decider(|_| Decision::Redirect {
        location: "https://login.example.com".to_string(),
    }));
    let resp = app
        .oneshot(Request::get("/auth/verify").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers()["location"], "https://login.example.com");
}

// --- oidc_backend_routes -------------------------------------------------

struct TestOidc;

#[async_trait]
impl OidcBackend for TestOidc {
    fn metadata_documents(&self) -> Vec<MetadataDocument> {
        vec![MetadataDocument::new(
            "/.well-known/openid-configuration",
            serde_json::json!({ "issuer": "https://idp.example.com" }),
        )]
    }
    fn jwks(&self) -> MetadataDocument {
        MetadataDocument::new(
            "/.well-known/jwks.json",
            serde_json::json!({ "keys": [{ "kty": "OKP" }] }),
        )
    }
    async fn userinfo(&self, bearer: &str) -> Option<serde_json::Value> {
        (bearer == "good").then(|| serde_json::json!({ "sub": "user-1" }))
    }
}

fn oidc_app() -> Router {
    oidc_backend_routes(Arc::new(TestOidc)).with_state(crate::test_state())
}

#[tokio::test]
async fn oidc_serves_discovery_and_jwks() {
    let app = oidc_app();
    let disc = app
        .clone()
        .oneshot(
            Request::get("/.well-known/openid-configuration")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(disc.status(), StatusCode::OK);

    let jwks = app
        .oneshot(
            Request::get("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
    assert_eq!(jwks.headers()["content-type"], "application/jwk-set+json");
}

#[tokio::test]
async fn oidc_userinfo_requires_valid_bearer() {
    let app = oidc_app();
    let ok = app
        .clone()
        .oneshot(
            Request::get("/userinfo")
                .header("authorization", "Bearer good")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    assert!(body_string(ok).await.contains("user-1"));

    let bad = app
        .oneshot(
            Request::get("/userinfo")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
}

// --- extra_routes_router -------------------------------------------------

struct EchoHandler(&'static str);

#[async_trait]
impl ExtraRouteHandler for EchoHandler {
    async fn handle(&self, req: RouteRequest) -> RouteResponse {
        let body = format!("{} {} {}", self.0, req.method, req.uri.path());
        RouteResponse::new(StatusCode::OK, Bytes::from(body))
    }
}

#[tokio::test]
async fn extra_route_get_handler_runs() {
    let routes = vec![ExtraRoute::new(
        Method::GET,
        "/custom",
        Arc::new(EchoHandler("hit")),
    )];
    let app = extra_routes_router(&routes).with_state(crate::test_state());
    let resp = app
        .oneshot(Request::get("/custom").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "hit GET /custom");
}

#[tokio::test]
async fn extra_routes_merge_methods_on_same_path() {
    // GET and POST on the same path must both work (merged MethodRouter), not
    // panic on overlapping route registration.
    let routes = vec![
        ExtraRoute::new(Method::GET, "/c", Arc::new(EchoHandler("g"))),
        ExtraRoute::new(Method::POST, "/c", Arc::new(EchoHandler("p"))),
    ];
    let app = extra_routes_router(&routes).with_state(crate::test_state());

    let g = app
        .clone()
        .oneshot(Request::get("/c").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(body_string(g).await, "g GET /c");

    let p = app
        .oneshot(Request::post("/c").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(body_string(p).await, "p POST /c");
}

// --- edge cases: extra routes -------------------------------------------

#[tokio::test]
async fn extra_route_unsupported_method_is_skipped() {
    // A non-standard extension method has no MethodFilter; the route is skipped
    // (logged), not panicked, so the path is simply left unmounted.
    let purge = Method::from_bytes(b"PURGE").unwrap();
    let routes = vec![ExtraRoute::new(
        purge.clone(),
        "/c",
        Arc::new(EchoHandler("x")),
    )];
    let app = extra_routes_router(&routes).with_state(crate::test_state());
    let resp = app
        .oneshot(
            Request::builder()
                .method(purge)
                .uri("/c")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Echoes a request header and the body, to prove both reach the handler.
struct EchoBodyHandler;

#[async_trait]
impl ExtraRouteHandler for EchoBodyHandler {
    async fn handle(&self, req: RouteRequest) -> RouteResponse {
        let hdr = req
            .headers
            .get("x-in")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let body = format!("{hdr}|{}", String::from_utf8_lossy(&req.body));
        RouteResponse::new(StatusCode::OK, Bytes::from(body))
    }
}

#[tokio::test]
async fn extra_route_handler_receives_body_and_headers() {
    let routes = vec![ExtraRoute::new(
        Method::POST,
        "/echo",
        Arc::new(EchoBodyHandler),
    )];
    let app = extra_routes_router(&routes).with_state(crate::test_state());
    let resp = app
        .oneshot(
            Request::post("/echo")
                .header("x-in", "hdr-val")
                .body(Body::from("payload"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_string(resp).await, "hdr-val|payload");
}

// --- edge cases: verify + redirect --------------------------------------

#[tokio::test]
async fn verify_without_forwarding_headers_uses_request_target() {
    // With no x-forwarded-*/x-original-*, the decision falls back to the verify
    // request's own method and path.
    let app = verify_app(decider(|req| {
        if req.method == Method::GET && req.path == "/auth/verify" {
            allow_with("x-ok", "1")
        } else {
            Decision::Deny {
                status: StatusCode::FORBIDDEN,
                body: Bytes::new(),
            }
        }
    }));
    let resp = app
        .oneshot(Request::get("/auth/verify").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["x-ok"], "1");
}

#[tokio::test]
async fn gate_redirect_with_invalid_location_omits_header() {
    // A location that is not a valid header value yields the bare status, never
    // a panic or a malformed header.
    let app = gated_app(decider(|_| Decision::Redirect {
        location: "bad\nlocation".to_string(),
    }));
    let resp = app
        .oneshot(Request::get("/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    assert!(!resp.headers().contains_key("location"));
}

// --- edge cases: OIDC backend (consumer-configurable paths) --------------

/// A backend with a non-default userinfo path and two metadata documents, to
/// prove every OIDC path is supplied by the consumer, not hardcoded.
struct CustomPathOidc;

#[async_trait]
impl OidcBackend for CustomPathOidc {
    fn metadata_documents(&self) -> Vec<MetadataDocument> {
        vec![
            MetadataDocument::new(
                "/.well-known/openid-configuration",
                serde_json::json!({ "issuer": "https://idp" }),
            ),
            MetadataDocument::new(
                "/.well-known/sid-configuration",
                serde_json::json!({ "custom": true }),
            ),
        ]
    }
    fn jwks(&self) -> MetadataDocument {
        MetadataDocument::new("/oauth/keys", serde_json::json!({ "keys": [] }))
    }
    fn userinfo_path(&self) -> String {
        "/oauth/userinfo".to_string()
    }
    async fn userinfo(&self, _bearer: &str) -> Option<serde_json::Value> {
        Some(serde_json::json!({ "sub": "s" }))
    }
}

#[tokio::test]
async fn oidc_paths_are_consumer_configurable() {
    let app = oidc_backend_routes(Arc::new(CustomPathOidc)).with_state(crate::test_state());

    // Both metadata documents are served at their consumer-chosen paths.
    for path in [
        "/.well-known/openid-configuration",
        "/.well-known/sid-configuration",
    ] {
        let resp = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "missing metadata at {path}");
    }

    // JWKS at the consumer's custom path (not the default well-known path).
    let jwks = app
        .clone()
        .oneshot(Request::get("/oauth/keys").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(jwks.status(), StatusCode::OK);
    assert_eq!(jwks.headers()["content-type"], "application/jwk-set+json");

    // UserInfo at the consumer's custom path; the default /userinfo is unmounted.
    let custom = app
        .clone()
        .oneshot(Request::get("/oauth/userinfo").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(custom.status(), StatusCode::OK);

    let default = app
        .oneshot(Request::get("/userinfo").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(default.status(), StatusCode::NOT_FOUND);
}

// --- edge cases: userinfo WWW-Authenticate challenge --------------------

#[tokio::test]
async fn userinfo_401_carries_bearer_challenge() {
    let app = oidc_backend_routes(Arc::new(TestOidc)).with_state(crate::test_state());

    // No credentials → plain `Bearer` challenge.
    let missing = app
        .clone()
        .oneshot(Request::get("/userinfo").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(missing.headers()["www-authenticate"], "Bearer");

    // Presented-but-rejected token → invalid_token challenge.
    let bad = app
        .oneshot(
            Request::get("/userinfo")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        bad.headers()["www-authenticate"],
        "Bearer error=\"invalid_token\""
    );
}

// --- edge cases: extra-route oversized body -----------------------------

#[tokio::test]
async fn extra_route_oversized_body_is_rejected_not_emptied() {
    // A body past MAX_EXTRA_ROUTE_BODY must yield 413, never reach the handler
    // as an empty payload (which a body-parsing handler would misread).
    let routes = vec![ExtraRoute::new(
        Method::POST,
        "/echo",
        Arc::new(EchoBodyHandler),
    )];
    let app = extra_routes_router(&routes).with_state(crate::test_state());
    let oversized = vec![b'x'; MAX_EXTRA_ROUTE_BODY + 1];
    let resp = app
        .oneshot(
            Request::post("/echo")
                .header("x-in", "h")
                .body(Body::from(oversized))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // The handler's echo body ("h|...") must NOT appear: it never ran.
    assert!(!body_string(resp).await.starts_with("h|"));
}
