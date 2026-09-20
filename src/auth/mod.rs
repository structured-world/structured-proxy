//! JWT authentication and route-level authorization.
//!
//! Validates `Authorization: Bearer` JWTs, enforces per-route policies
//! (`require_auth` / `required_roles`), and forwards selected claims to the
//! upstream as request headers. Active only when `auth.mode == "jwt"`.
//!
//! Verification itself sits behind [`TokenVerifier`]: by default the built-in
//! one (keys from `auth.jwt` — an Ed25519 PEM file or a JWKS endpoint, checked
//! with `jsonwebtoken`), or an embedder-supplied one injected through
//! [`ProxyServer::with_token_verifier`](crate::ProxyServer::with_token_verifier).
//! Everything else here — policies, roles, claim headers — is independent of
//! which one verified the token.

pub mod authz;
#[cfg(feature = "builtin_jwt")]
pub(crate) mod crypto;
pub mod forward;
#[cfg(feature = "builtin_jwt")]
pub mod jwks;
pub mod policy;
#[cfg(feature = "builtin_jwt")]
mod verifier;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::Value;

use crate::config::{default_roles_claim, AuthConfig};
use crate::hooks::TokenVerifier;
use policy::Policies;

/// Which implementation checks a token's signature and claims.
enum Verifier {
    /// The built-in one, called directly: the default path pays no dynamic
    /// dispatch and allocates no boxed future per verification. Boxed only to
    /// keep the enum small — it holds an inline JWKS cache, and this costs one
    /// pointer hop at build time, not per request.
    #[cfg(feature = "builtin_jwt")]
    Builtin(Box<verifier::ConfigVerifier>),
    /// The embedder's, behind the public hook.
    Injected(Arc<dyn TokenVerifier>),
}

/// Compiled auth configuration: the verifier, the claims to forward, and the
/// route policies.
pub struct Auth {
    verifier: Verifier,
    claims_headers: HashMap<String, String>,
    roles_claim: String,
    policies: Policies,
}

impl Auth {
    /// Build auth from config, or `None` when `auth.mode` is not `"jwt"`.
    ///
    /// `verifier` is the embedder-supplied token verifier, if any. With `None`
    /// the built-in one is built from `auth.jwt`, which then must name a key
    /// source. With `Some`, the key source in config is unused (the verifier
    /// owns its own keys) and `auth.jwt` may be omitted entirely; the rest of
    /// the block (`claims_headers`, `roles_claim`) still applies.
    ///
    /// # Errors
    /// Returns an error string when the built-in verifier is required but this
    /// build has no crypto backend, when its key source is missing or unusable,
    /// or when a policy glob fails to compile.
    pub fn build(
        config: &AuthConfig,
        verifier: Option<Arc<dyn TokenVerifier>>,
    ) -> Result<Option<Arc<Self>>, String> {
        if config.mode != "jwt" {
            return Ok(None);
        }

        let verifier = match verifier {
            Some(v) => {
                if let Some(jwt) = &config.jwt {
                    if jwt.jwks_uri.is_some() || jwt.public_key_pem_file.is_some() {
                        tracing::warn!(
                            "auth.jwt names a key source, but an injected TokenVerifier is in use; \
                             the configured keys are ignored"
                        );
                    }
                }
                Verifier::Injected(v)
            }
            None => builtin_verifier(config)?,
        };

        let policies = match &config.forward_auth {
            Some(fa) => Policies::compile(&fa.policies)?,
            None => Policies::default(),
        };

        // With an injected verifier `auth.jwt` is optional, so the claim
        // forwarding settings fall back to the same defaults the deserializer
        // would have applied.
        let (claims_headers, roles_claim) = match &config.jwt {
            Some(jwt) => (jwt.claims_headers.clone(), jwt.roles_claim.clone()),
            None => (HashMap::new(), default_roles_claim()),
        };

        Ok(Some(Arc::new(Self {
            verifier,
            claims_headers,
            roles_claim,
            policies,
        })))
    }

    /// Verify a token and return its claims, or `None` if invalid.
    async fn verify(&self, token: &str) -> Option<Value> {
        match &self.verifier {
            #[cfg(feature = "builtin_jwt")]
            Verifier::Builtin(v) => v.verify(token).await,
            Verifier::Injected(v) => v.verify(token).await,
        }
    }
}

/// The built-in verifier, built from `auth.jwt`.
#[cfg(feature = "builtin_jwt")]
fn builtin_verifier(config: &AuthConfig) -> Result<Verifier, String> {
    let jwt = config
        .jwt
        .as_ref()
        .ok_or("auth.mode is \"jwt\" but auth.jwt is not set")?;
    Ok(Verifier::Builtin(Box::new(
        verifier::ConfigVerifier::build(jwt)?,
    )))
}

/// Without a crypto backend there is no built-in verifier to build: a JWT
/// deployment must inject one.
#[cfg(not(feature = "builtin_jwt"))]
fn builtin_verifier(_config: &AuthConfig) -> Result<Verifier, String> {
    Err(
        "auth.mode is \"jwt\" but this build has no JWT crypto backend: enable the \
         `rust_crypto` or `aws_lc_rs` feature, or inject a verifier with \
         ProxyServer::with_token_verifier"
            .to_string(),
    )
}

/// The outcome of an auth check for a request.
pub(crate) enum AuthDecision {
    /// Allowed; forward these (verified) claim headers to the upstream, and the
    /// verified claims themselves (`None` for anonymous access) for downstream
    /// consumers such as per-principal rate limiting.
    Allow(HeaderMap, Option<Value>),
    /// Rejected: no/invalid credentials (HTTP 401).
    Unauthenticated(&'static str),
    /// Rejected: authenticated but lacking a required role (HTTP 403).
    Forbidden(&'static str),
}

/// Verified JWT claims attached to the request by the auth middleware. Present
/// only when a valid token was supplied, and set exclusively from a verified
/// token (never from client input), so downstream consumers may safely key
/// security decisions (e.g. rate limits) on it.
#[derive(Clone)]
pub(crate) struct ValidatedClaims(pub(crate) std::sync::Arc<Value>);

impl Auth {
    /// Evaluate auth for a request: validate the bearer token, apply the route
    /// policy, and render the claim headers to forward. This is the single
    /// source of truth shared by the middleware and the forward-auth endpoint.
    pub(crate) async fn decide(
        &self,
        headers: &HeaderMap,
        path: &str,
        method: &str,
    ) -> AuthDecision {
        // A token that is present but invalid is always a 401, regardless of policy.
        let claims = match bearer_token(headers) {
            Some(token) => match self.verify(token).await {
                Some(c) => Some(c),
                None => return AuthDecision::Unauthenticated("invalid or expired token"),
            },
            None => None,
        };

        if let Some(policy) = self.policies.match_rule(path, method) {
            if policy.require_auth && claims.is_none() {
                return AuthDecision::Unauthenticated("authentication required");
            }
            if !policy.required_roles.is_empty() {
                // An unauthenticated caller is told to authenticate (401), not
                // that they lack a role (403).
                let Some(claims) = claims.as_ref() else {
                    return AuthDecision::Unauthenticated("authentication required");
                };
                let roles = extract_roles(claims, &self.roles_claim);
                if !policy.required_roles.iter().all(|r| roles.contains(r)) {
                    return AuthDecision::Forbidden("insufficient role");
                }
            }
        }

        let mut claim_headers = HeaderMap::new();
        if let Some(claims) = &claims {
            inject_claim_headers(&mut claim_headers, claims, &self.claims_headers);
        }
        AuthDecision::Allow(claim_headers, claims)
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

    // Strip any client-supplied values for proxy-controlled claim headers, so a
    // client can never forge them onto the upstream (only verified claims set
    // them below).
    strip_claim_headers(request.headers_mut(), &auth.claims_headers);

    match auth.decide(request.headers(), &path, &method).await {
        AuthDecision::Unauthenticated(msg) => unauthorized(msg),
        AuthDecision::Forbidden(msg) => forbidden(msg),
        AuthDecision::Allow(claim_headers, claims) => {
            let dst = request.headers_mut();
            for (name, value) in &claim_headers {
                dst.insert(name.clone(), value.clone());
            }
            // Expose the verified claims to inner layers (e.g. per-principal rate
            // limiting) as a typed extension a client cannot forge.
            if let Some(claims) = claims {
                request
                    .extensions_mut()
                    .insert(ValidatedClaims(std::sync::Arc::new(claims)));
            }
            next.run(request).await
        }
    }
}

/// Extract the bearer token from the `Authorization` header.
///
/// Borrowed from the header, not copied: the token is read and dropped within
/// the request's own auth decision, so there is nothing to own.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    (!token.is_empty()).then_some(token)
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

/// Remove any incoming values for the proxy-controlled claim headers, so a
/// client cannot forge them onto the upstream.
fn strip_claim_headers(headers: &mut HeaderMap, mapping: &HashMap<String, String>) {
    for header in mapping.values() {
        if let Ok(name) = HeaderName::try_from(header.as_str()) {
            while headers.remove(&name).is_some() {}
        }
    }
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
