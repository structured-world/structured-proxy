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

// The endpoint is exercised end to end against the built-in verifier, so these
// tests need a crypto backend; the `Auth` seam itself is covered in `tests.rs`.
#[cfg(all(test, feature = "builtin_jwt"))]
mod tests;
