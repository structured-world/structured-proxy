//! Forward-auth verification endpoint.
//!
//! Exposes `forward_auth.path` (default `/auth/verify`) so a fronting reverse
//! proxy (nginx `auth_request`, Traefik `forwardAuth`) can delegate auth to this
//! proxy: it validates the request's `Bearer` token against the configured route
//! policies and answers 200 (with the verified claim headers) or 401/403.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::header::{HeaderValue, LOCATION};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;

use super::{forbidden, unauthorized, Auth, AuthDecision};
use crate::config::AuthConfig;

/// A verification endpoint backed by the shared [`Auth`] machinery.
pub struct ForwardAuth {
    auth: Arc<Auth>,
    path: String,
    login_url: Option<String>,
}

impl ForwardAuth {
    /// Build the endpoint, or `None` when forward-auth is disabled.
    ///
    /// Shares the already-built [`Auth`], so the verify endpoint and the JWT
    /// middleware evaluate identical keys and policies.
    pub fn build(config: &AuthConfig, auth: Arc<Auth>) -> Option<Arc<Self>> {
        let fa = config.forward_auth.as_ref()?;
        if !fa.enabled {
            return None;
        }
        Some(Arc::new(Self {
            auth,
            path: fa.path.clone(),
            login_url: fa.login_url.clone(),
        }))
    }

    /// The verification route, mounted at `forward_auth.path`.
    pub fn routes<S>(self: &Arc<Self>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let fa = self.clone();
        // Any method: the fronting proxy issues its own sub-request verb; the
        // original verb arrives via the forwarding headers.
        Router::new().route(
            &self.path,
            any(move |req: Request| {
                let fa = fa.clone();
                async move { fa.verify(req).await }
            }),
        )
    }

    async fn verify(&self, request: Request) -> Response {
        let headers = request.headers();
        let method = original_method(headers)
            .unwrap_or_else(|| request.method().as_str().to_ascii_uppercase());
        let path = original_path(headers).unwrap_or_else(|| request.uri().path().to_string());

        match self.auth.decide(headers, &path, &method).await {
            // 200 carries the verified claim headers for the fronting proxy to
            // copy upstream.
            AuthDecision::Allow(claim_headers, _) => {
                (StatusCode::OK, claim_headers).into_response()
            }
            AuthDecision::Unauthenticated(msg) => self.deny(msg),
            AuthDecision::Forbidden(msg) => forbidden(msg),
        }
    }

    /// A 401, adding `Location: login_url` when configured so a fronting proxy
    /// can drive an error-page redirect to the login flow.
    fn deny(&self, msg: &'static str) -> Response {
        let mut response = unauthorized(msg);
        if let Some(url) = &self.login_url {
            if let Ok(value) = HeaderValue::try_from(url.as_str()) {
                response.headers_mut().insert(LOCATION, value);
            }
        }
        response
    }
}

/// The original request method, from the fronting proxy's forwarding headers.
fn original_method(headers: &HeaderMap) -> Option<String> {
    forwarded(headers, &["x-forwarded-method", "x-original-method"]).map(|m| m.to_ascii_uppercase())
}

/// The original request path (query stripped), from the forwarding headers.
fn original_path(headers: &HeaderMap) -> Option<String> {
    let raw = forwarded(headers, &["x-forwarded-uri", "x-original-uri"])?;
    let path = raw.split_once('?').map_or(raw.as_str(), |(p, _)| p);
    Some(path.to_string())
}

/// First non-empty value among `names`.
fn forwarded(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    names
        .iter()
        .filter_map(|n| headers.get(*n).and_then(|v| v.to_str().ok()))
        .find(|v| !v.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, ForwardAuthConfig, JwtConfig, RoutePolicyConfig};
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::HashMap;
    use tower::ServiceExt;

    // A fixed Ed25519 keypair so tests can sign tokens the proxy will accept.
    fn keypair() -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let spki_prefix: [u8; 12] = [
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let mut der = spki_prefix.to_vec();
        der.extend_from_slice(sk.verifying_key().as_bytes());
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&der);
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n");
        (sk, pem)
    }

    fn sign(sk: &SigningKey, claims: &serde_json::Value) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let sig = sk.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn write_pem(pem: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "sp_fa_{}_{}.pem",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, pem).unwrap();
        p
    }

    fn forward_auth(pem_path: std::path::PathBuf, login_url: Option<String>) -> Arc<ForwardAuth> {
        let mut claims_headers = HashMap::new();
        claims_headers.insert("sub".to_string(), "x-forwarded-user".to_string());
        let config = AuthConfig {
            mode: "jwt".into(),
            jwt: Some(JwtConfig {
                issuer: None,
                audience: None,
                jwks_uri: None,
                public_key_pem_file: Some(pem_path),
                claims_headers,
                roles_claim: "roles".into(),
            }),
            forward_auth: Some(ForwardAuthConfig {
                enabled: true,
                path: "/auth/verify".into(),
                policies: vec![RoutePolicyConfig {
                    path: "/v1/admin/**".into(),
                    methods: vec!["*".into()],
                    require_auth: true,
                    required_roles: vec!["admin".into()],
                }],
                login_url,
                applications_path: None,
            }),
            authz: None,
        };
        let auth = Auth::build(&config).unwrap().unwrap();
        ForwardAuth::build(&config, auth).unwrap()
    }

    async fn call(fa: &Arc<ForwardAuth>, req: HttpRequest<Body>) -> Response {
        let app: Router = fa.routes();
        app.oneshot(req).await.unwrap()
    }

    fn verify_request(method: &str, uri: &str, token: Option<&str>) -> HttpRequest<Body> {
        let mut b = HttpRequest::get("/auth/verify")
            .header("x-forwarded-method", method)
            .header("x-forwarded-uri", uri);
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn allows_and_echoes_claim_header() {
        let (sk, pem) = keypair();
        let fa = forward_auth(write_pem(&pem), None);
        let token = sign(
            &sk,
            &serde_json::json!({ "sub": "alice", "roles": ["admin"], "exp": 9999999999u64 }),
        );
        let resp = call(&fa, verify_request("GET", "/v1/admin/things", Some(&token))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // The verified identity is echoed for the fronting proxy to copy upstream.
        assert_eq!(resp.headers()["x-forwarded-user"], "alice");
    }

    #[tokio::test]
    async fn denies_without_token_and_sets_login_location() {
        let (_sk, pem) = keypair();
        let fa = forward_auth(write_pem(&pem), Some("https://login.example.com".into()));
        let resp = call(&fa, verify_request("GET", "/v1/admin/things", None)).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(resp.headers()[LOCATION], "https://login.example.com");
    }

    #[tokio::test]
    async fn forbids_when_role_missing() {
        let (sk, pem) = keypair();
        let fa = forward_auth(write_pem(&pem), None);
        let token = sign(
            &sk,
            &serde_json::json!({ "sub": "bob", "roles": ["user"], "exp": 9999999999u64 }),
        );
        let resp = call(&fa, verify_request("GET", "/v1/admin/things", Some(&token))).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn denies_invalid_token() {
        // A token signed by a different key fails verification; the endpoint
        // must reject it (401), never leak it through as authenticated.
        let (_sk, pem) = keypair();
        let fa = forward_auth(write_pem(&pem), None);
        let wrong_key = SigningKey::from_bytes(&[9u8; 32]);
        let token = sign(
            &wrong_key,
            &serde_json::json!({ "sub": "mallory", "roles": ["admin"], "exp": 9999999999u64 }),
        );
        let resp = call(&fa, verify_request("GET", "/v1/admin/things", Some(&token))).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn allows_unprotected_original_path() {
        // The verify sub-request hits /auth/verify, but the original path is a
        // public route, so no token is required.
        let (_sk, pem) = keypair();
        let fa = forward_auth(write_pem(&pem), None);
        let resp = call(&fa, verify_request("GET", "/v1/public/info", None)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
