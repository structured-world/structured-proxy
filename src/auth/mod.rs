//! JWT authentication and route-level authorization.
//!
//! Validates `Authorization: Bearer` JWTs against a configured key source (an
//! Ed25519 PEM file or a JWKS endpoint), enforces per-route policies
//! (`require_auth` / `required_roles`), and forwards selected claims to the
//! upstream as request headers. Active only when `auth.mode == "jwt"`.

pub mod jwks;
pub mod policy;

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use crate::config::AuthConfig;
use jwks::JwksCache;
use policy::Policies;

/// Where verifying keys come from.
enum KeySource {
    /// A single Ed25519 public key (EdDSA).
    Pem(Arc<DecodingKey>),
    /// Keys discovered from a JWKS endpoint, selected by `kid`.
    Jwks(JwksCache),
}

/// Compiled auth configuration: keys, expected claims, and route policies.
pub struct Auth {
    keys: KeySource,
    issuer: Option<String>,
    audience: Option<String>,
    claims_headers: HashMap<String, String>,
    roles_claim: String,
    policies: Policies,
}

impl Auth {
    /// Build auth from config, or `None` when `auth.mode` is not `"jwt"`.
    ///
    /// # Errors
    /// Returns an error string when the JWT config is missing a key source, the
    /// PEM file cannot be read, or a policy glob fails to compile.
    pub fn build(config: &AuthConfig) -> Result<Option<Arc<Self>>, String> {
        if config.mode != "jwt" {
            return Ok(None);
        }
        let jwt = config
            .jwt
            .as_ref()
            .ok_or("auth.mode is \"jwt\" but auth.jwt is not set")?;

        let keys = if let Some(uri) = &jwt.jwks_uri {
            KeySource::Jwks(JwksCache::new(uri.clone()))
        } else if let Some(pem_path) = &jwt.public_key_pem_file {
            let pem = std::fs::read(pem_path)
                .map_err(|e| format!("failed to read auth.jwt.public_key_pem_file: {e}"))?;
            let key = DecodingKey::from_ed_pem(&pem)
                .map_err(|e| format!("invalid Ed25519 public key PEM: {e}"))?;
            KeySource::Pem(Arc::new(key))
        } else {
            return Err("auth.jwt requires either jwks_uri or public_key_pem_file".to_string());
        };

        let policies = match &config.forward_auth {
            Some(fa) => Policies::compile(&fa.policies)?,
            None => Policies::default(),
        };

        Ok(Some(Arc::new(Self {
            keys,
            issuer: jwt.issuer.clone(),
            audience: jwt.audience.clone(),
            claims_headers: jwt.claims_headers.clone(),
            roles_claim: jwt.roles_claim.clone(),
            policies,
        })))
    }

    /// Verify a token and return its claims, or `None` if invalid.
    async fn verify(&self, token: &str) -> Option<Value> {
        let header = decode_header(token).ok()?;
        let (key, algorithm) = match &self.keys {
            KeySource::Pem(k) => (k.clone(), Algorithm::EdDSA),
            KeySource::Jwks(cache) => {
                let kid = header.kid.as_deref()?;
                let vk = cache.key_for(kid).await?;
                (vk.key, vk.algorithm)
            }
        };
        // Reject algorithm confusion: the token must use the key's algorithm.
        if header.alg != algorithm {
            return None;
        }

        let mut validation = Validation::new(algorithm);
        if let Some(iss) = &self.issuer {
            validation.set_issuer(&[iss]);
        }
        match &self.audience {
            Some(aud) => validation.set_audience(&[aud]),
            None => validation.validate_aud = false,
        }

        decode::<Value>(token, &key, &validation)
            .ok()
            .map(|data| data.claims)
    }
}

/// Axum middleware enforcing JWT auth and route policies.
pub async fn middleware(
    State(auth): State<Arc<Auth>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let method = request.method().as_str().to_ascii_uppercase();
    let policy = auth.policies.match_rule(&path, &method);

    // A token that is present but invalid is always a 401, regardless of policy.
    let claims = match bearer_token(request.headers()) {
        Some(token) => match auth.verify(&token).await {
            Some(c) => Some(c),
            None => return unauthorized("invalid or expired token"),
        },
        None => None,
    };

    if let Some(policy) = policy {
        if policy.require_auth && claims.is_none() {
            return unauthorized("authentication required");
        }
        if !policy.required_roles.is_empty() {
            let roles = claims
                .as_ref()
                .map(|c| extract_roles(c, &auth.roles_claim))
                .unwrap_or_default();
            if !policy.required_roles.iter().all(|r| roles.contains(r)) {
                return forbidden("insufficient role");
            }
        }
    }

    if let Some(claims) = &claims {
        inject_claim_headers(request.headers_mut(), claims, &auth.claims_headers);
    }
    next.run(request).await
}

/// Extract the bearer token from the `Authorization` header.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// Resolve a (possibly dotted) claim path to a JSON value.
fn claim_at<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = claims;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Collect the caller's roles from the configured claim (an array of strings).
fn extract_roles(claims: &Value, roles_claim: &str) -> HashSet<String> {
    claim_at(claims, roles_claim)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Inject configured claims as request headers forwarded to the upstream.
fn inject_claim_headers(
    headers: &mut HeaderMap,
    claims: &Value,
    mapping: &HashMap<String, String>,
) {
    for (claim, header) in mapping {
        let Some(value) = claim_at(claims, claim) else {
            continue;
        };
        let rendered = match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            // Skip arrays/objects/null: not meaningful as a single header value.
            _ => continue,
        };
        if let (Ok(name), Ok(val)) = (
            HeaderName::try_from(header.as_str()),
            HeaderValue::try_from(rendered),
        ) {
            headers.insert(name, val);
        }
    }
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "UNAUTHENTICATED", "message": message })),
    )
        .into_response()
}

fn forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "PERMISSION_DENIED", "message": message })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_parsing() {
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer abc.def.ghi".parse().unwrap());
        assert_eq!(bearer_token(&h).as_deref(), Some("abc.def.ghi"));

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

    // --- end-to-end JWT validation + policy enforcement ---

    use crate::config::{AuthConfig, ForwardAuthConfig, JwtConfig, RoutePolicyConfig};
    use axum::http::Request as HttpRequest;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tower::ServiceExt;

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
                jwks_uri: None,
                issuer: Some("test-iss".into()),
                audience: Some("test-aud".into()),
                public_key_pem_file: Some(temp_pub_pem()),
                claims_headers: HashMap::from([("sub".to_string(), "x-user".to_string())]),
                roles_claim: "roles".into(),
            }),
            forward_auth: Some(ForwardAuthConfig {
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
            }),
            authz: None,
            bff: None,
        };
        Auth::build(&cfg).unwrap().unwrap()
    }

    fn app(auth: Arc<Auth>) -> axum::Router {
        axum::Router::new()
            .route(
                "/secure",
                axum::routing::get(|headers: HeaderMap| async move {
                    // Echo the injected claim header so tests can assert it.
                    headers
                        .get("x-user")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string()
                }),
            )
            .layer(axum::middleware::from_fn_with_state(auth, middleware))
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
}
