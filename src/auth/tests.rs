//! Auth middleware tests: token handling, route policies, claim forwarding,
//! and the two verifier sources (built-in and injected).

use super::*;

use crate::config::{AuthConfig, ForwardAuthConfig, JwtConfig, RoutePolicyConfig};
use axum::http::Request as HttpRequest;
use tower::ServiceExt;

#[test]
fn bearer_token_parsing() {
    let mut h = HeaderMap::new();
    h.insert("authorization", "Bearer abc.def.ghi".parse().unwrap());
    assert_eq!(bearer_token(&h), Some("abc.def.ghi"));

    let mut h2 = HeaderMap::new();
    h2.insert("authorization", "Basic xyz".parse().unwrap());
    assert_eq!(bearer_token(&h2), None);
    assert_eq!(bearer_token(&HeaderMap::new()), None);
}

#[test]
fn extract_roles_reads_array_and_dotted_path() {
    let claims = serde_json::json!({
        "roles": ["admin", "billing"],
        "realm_access": { "roles": ["nested"] }
    });
    assert!(extract_roles(&claims, "roles").contains("admin"));
    assert!(extract_roles(&claims, "realm_access.roles").contains("nested"));
    assert!(extract_roles(&claims, "missing").is_empty());
}

#[test]
fn inject_claim_headers_renders_scalars() {
    let claims = serde_json::json!({ "sub": "u-1", "n": 7, "obj": {"x": 1} });
    let mapping = HashMap::from([
        ("sub".to_string(), "x-user-id".to_string()),
        ("n".to_string(), "x-n".to_string()),
        ("obj".to_string(), "x-obj".to_string()),
    ]);
    let mut headers = HeaderMap::new();
    inject_claim_headers(&mut headers, &claims, &mapping);
    assert_eq!(headers["x-user-id"], "u-1");
    assert_eq!(headers["x-n"], "7");
    // Object claim is skipped (not a scalar).
    assert!(!headers.contains_key("x-obj"));
}

// --- shared harness ---

/// A router whose routes echo the `x-user` header the upstream would receive,
/// behind the auth middleware.
fn app(auth: Arc<Auth>) -> axum::Router {
    let echo = |headers: HeaderMap| async move {
        headers
            .get("x-user")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    axum::Router::new()
        .route("/secure", axum::routing::get(echo))
        .route("/open", axum::routing::get(echo))
        .layer(axum::middleware::from_fn_with_state(auth, middleware))
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// An `auth.jwt` block carrying only the claim-forwarding settings: no key
/// source, since an injected verifier owns its own keys.
fn jwt_claims_only() -> JwtConfig {
    JwtConfig {
        jwks_uri: None,
        issuer: None,
        audience: None,
        public_key_pem_file: None,
        claims_headers: HashMap::from([("sub".to_string(), "x-user".to_string())]),
        roles_claim: "roles".into(),
    }
}

/// Policies for `/secure`: auth required, plus `roles` when given.
fn secure_policy(roles: &[&str]) -> ForwardAuthConfig {
    ForwardAuthConfig {
        enabled: true,
        path: "/auth/verify".into(),
        policies: vec![RoutePolicyConfig {
            path: "/secure".into(),
            methods: vec!["*".into()],
            require_auth: true,
            required_roles: roles.iter().map(|s| s.to_string()).collect(),
        }],
        login_url: None,
        applications_path: None,
    }
}

// --- injected verifier (no crypto backend needed) ---

/// A verifier that accepts exactly one token and answers with fixed claims, so
/// the middleware can be exercised in a build with no JWT crypto at all.
struct StubVerifier {
    accepts: &'static str,
    claims: Value,
}

#[async_trait::async_trait]
impl TokenVerifier for StubVerifier {
    async fn verify(&self, token: &str) -> Option<Value> {
        (token == self.accepts).then(|| self.claims.clone())
    }
}

fn auth_with_stub(roles: &[&str], jwt: Option<JwtConfig>) -> Arc<Auth> {
    let cfg = AuthConfig {
        mode: "jwt".into(),
        jwt,
        forward_auth: Some(secure_policy(roles)),
        authz: None,
    };
    let stub = StubVerifier {
        accepts: "good-token",
        claims: serde_json::json!({ "sub": "stub-user", "roles": ["admin"] }),
    };
    Auth::build(&cfg, Some(Arc::new(stub))).unwrap().unwrap()
}

#[tokio::test]
async fn injected_verifier_decides_authentication() {
    let auth = auth_with_stub(&[], Some(jwt_claims_only()));

    // The token the injected verifier accepts passes, and its claims are
    // forwarded through the configured claims_headers mapping.
    let resp = app(auth.clone())
        .oneshot(
            HttpRequest::get("/secure")
                .header("authorization", "Bearer good-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "stub-user");

    // Anything else is rejected: a verifier returning None is a 401, never a
    // pass-through.
    let resp = app(auth)
        .oneshot(
            HttpRequest::get("/secure")
                .header("authorization", "Bearer other-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn injected_verifier_claims_drive_role_policy() {
    // Roles come from the injected verifier's claims, so the policy applies the
    // same way it does to built-in verification.
    let resp = app(auth_with_stub(&["admin"], Some(jwt_claims_only())))
        .oneshot(
            HttpRequest::get("/secure")
                .header("authorization", "Bearer good-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let resp = app(auth_with_stub(&["superuser"], Some(jwt_claims_only())))
        .oneshot(
            HttpRequest::get("/secure")
                .header("authorization", "Bearer good-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn injected_verifier_works_without_a_jwt_block() {
    // `auth.jwt` exists only to configure keys and claim forwarding; with an
    // injected verifier and no claim headers, it can be omitted entirely.
    let auth = auth_with_stub(&["admin"], None);
    let resp = app(auth)
        .oneshot(
            HttpRequest::get("/secure")
                .header("authorization", "Bearer good-token")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // The role policy still applies (default roles_claim), and no claim header
    // is injected because none was configured.
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "");
}

#[test]
fn injected_verifier_supersedes_a_configured_key_source() {
    // A config that also names a key source is accepted (the verifier wins);
    // it must not fail the build, nor read the non-existent PEM file.
    let cfg = AuthConfig {
        mode: "jwt".into(),
        jwt: Some(JwtConfig {
            public_key_pem_file: Some("/nonexistent/key.pem".into()),
            ..jwt_claims_only()
        }),
        forward_auth: None,
        authz: None,
    };
    let stub = StubVerifier {
        accepts: "good-token",
        claims: serde_json::json!({}),
    };
    assert!(Auth::build(&cfg, Some(Arc::new(stub))).unwrap().is_some());
}

#[test]
fn no_auth_when_mode_is_not_jwt() {
    let cfg = AuthConfig {
        mode: "none".into(),
        jwt: None,
        forward_auth: None,
        authz: None,
    };
    assert!(Auth::build(&cfg, None).unwrap().is_none());
}

/// Without a crypto backend there is no built-in verifier, so a JWT config that
/// supplies none must fail loudly rather than silently accept every token.
#[cfg(not(feature = "builtin_jwt"))]
#[test]
fn jwt_mode_without_a_verifier_is_rejected() {
    let cfg = AuthConfig {
        mode: "jwt".into(),
        jwt: Some(jwt_claims_only()),
        forward_auth: None,
        authz: None,
    };
    let Err(err) = Auth::build(&cfg, None) else {
        panic!("a jwt config with no verifier must not build");
    };
    assert!(
        err.contains("with_token_verifier"),
        "unexpected error: {err}"
    );
}

// --- built-in verifier: end-to-end JWT validation + policy enforcement ---

#[cfg(feature = "builtin_jwt")]
mod builtin {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use std::sync::atomic::{AtomicU32, Ordering};

    // Ed25519 test keypair (generated for tests only; not a secret).
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIEVVO7H+T5tERRn/dzukOc8i9iYEKKtPh//qcrES+dCt\n\
        -----END PRIVATE KEY-----\n";
    const TEST_PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEARCMxEnaM2/dblLuPNgBZpTvSUXO5ir+XQ1nyzJm4CFw=\n\
        -----END PUBLIC KEY-----\n";

    fn temp_pub_pem() -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "sp_auth_{}_{}.pem",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, TEST_PUB_PEM).unwrap();
        path
    }

    fn sign(claims: serde_json::Value) -> String {
        let key = EncodingKey::from_ed_pem(TEST_PRIV_PEM.as_bytes()).unwrap();
        encode(&Header::new(Algorithm::EdDSA), &claims, &key).unwrap()
    }

    fn future_exp() -> i64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        now + 3600
    }

    fn auth_with_policy(roles: &[&str]) -> Arc<Auth> {
        let cfg = AuthConfig {
            mode: "jwt".into(),
            jwt: Some(JwtConfig {
                issuer: Some("test-iss".into()),
                audience: Some("test-aud".into()),
                public_key_pem_file: Some(temp_pub_pem()),
                ..jwt_claims_only()
            }),
            forward_auth: Some(secure_policy(roles)),
            authz: None,
        };
        Auth::build(&cfg, None).unwrap().unwrap()
    }

    #[tokio::test]
    async fn strips_client_supplied_claim_headers() {
        // A client forges x-user on an unprotected route with no token; the
        // proxy must not forward the forged value to the upstream.
        let app = app(auth_with_policy(&[]));
        let resp = app
            .oneshot(
                HttpRequest::get("/open")
                    .header("x-user", "forged-admin")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(body_string(resp).await, "");
    }

    #[tokio::test]
    async fn unauthenticated_role_check_is_401_not_403() {
        // Policy requires a role but not auth; a request with no token is
        // unauthenticated, so it must get 401, not 403.
        let cfg = AuthConfig {
            mode: "jwt".into(),
            jwt: Some(JwtConfig {
                jwks_uri: None,
                issuer: None,
                audience: None,
                public_key_pem_file: Some(temp_pub_pem()),
                claims_headers: HashMap::new(),
                roles_claim: "roles".into(),
            }),
            forward_auth: Some(ForwardAuthConfig {
                policies: vec![RoutePolicyConfig {
                    path: "/secure".into(),
                    methods: vec!["*".into()],
                    require_auth: false,
                    required_roles: vec!["admin".into()],
                }],
                ..secure_policy(&[])
            }),
            authz: None,
        };
        let auth = Auth::build(&cfg, None).unwrap().unwrap();
        let resp = app(auth)
            .oneshot(
                HttpRequest::get("/secure")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_missing_token_on_protected_route() {
        let app = app(auth_with_policy(&[]));
        let resp = app
            .oneshot(
                HttpRequest::get("/secure")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn accepts_valid_token_and_injects_claim_header() {
        let app = app(auth_with_policy(&["admin"]));
        let token = sign(serde_json::json!({
            "iss": "test-iss", "aud": "test-aud", "exp": future_exp(),
            "sub": "user-42", "roles": ["admin"]
        }));
        let resp = app
            .oneshot(
                HttpRequest::get("/secure")
                    .header("authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        // The sub claim was forwarded to the handler as x-user.
        assert_eq!(&body[..], b"user-42");
    }

    #[tokio::test]
    async fn forbids_when_required_role_missing() {
        let app = app(auth_with_policy(&["admin"]));
        let token = sign(serde_json::json!({
            "iss": "test-iss", "aud": "test-aud", "exp": future_exp(),
            "sub": "user-42", "roles": ["viewer"]
        }));
        let resp = app
            .oneshot(
                HttpRequest::get("/secure")
                    .header("authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_expired_and_wrong_issuer() {
        let app = app(auth_with_policy(&[]));
        let expired = sign(serde_json::json!({
            "iss": "test-iss", "aud": "test-aud", "exp": 1, "sub": "u", "roles": ["admin"]
        }));
        let resp = app
            .clone()
            .oneshot(
                HttpRequest::get("/secure")
                    .header("authorization", format!("Bearer {expired}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let wrong_iss = sign(serde_json::json!({
            "iss": "evil", "aud": "test-aud", "exp": future_exp(), "sub": "u", "roles": ["admin"]
        }));
        let resp = app
            .oneshot(
                HttpRequest::get("/secure")
                    .header("authorization", format!("Bearer {wrong_iss}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn built_in_verifier_requires_a_key_source() {
        // No jwks_uri and no PEM: the built-in verifier has nothing to verify
        // against, which is a config error, not a permissive default.
        let cfg = AuthConfig {
            mode: "jwt".into(),
            jwt: Some(jwt_claims_only()),
            forward_auth: None,
            authz: None,
        };
        let Err(err) = Auth::build(&cfg, None) else {
            panic!("a built-in verifier with no key source must not build");
        };
        assert!(err.contains("jwks_uri"), "unexpected error: {err}");
    }

    /// A build with both crypto backends linked (feature unification, or
    /// `--all-features`) must verify tokens like any other. `jsonwebtoken` can
    /// then not pick a provider from its own features and installs one that
    /// panics on first use, so the verifier has to select one itself.
    #[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
    #[tokio::test]
    async fn verifies_with_both_crypto_backends_linked() {
        let app = app(auth_with_policy(&["admin"]));
        let token = sign(serde_json::json!({
            "iss": "test-iss", "aud": "test-aud", "exp": future_exp(),
            "sub": "user-42", "roles": ["admin"]
        }));
        let resp = app
            .oneshot(
                HttpRequest::get("/secure")
                    .header("authorization", format!("Bearer {token}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
}
