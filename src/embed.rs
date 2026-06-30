//! Axum glue for the framework-agnostic embedding hooks.
//!
//! This module is the *only* place that bridges the `axum`-free public hook
//! traits ([`crate::hooks`]) to the running axum server: it converts live axum
//! requests into the borrowed/owned hook views, runs the embedder's trait
//! impls, and renders their results back into axum responses. Keeping the
//! conversion here is what lets an embedder depend on the hook traits without
//! ever naming `axum`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, on, MethodFilter, MethodRouter};
use axum::{Json, Router};

use crate::hooks::{AuthDecider, Decision, ExtraRoute, OidcBackend, RequestParts, RouteRequest};
use crate::ProxyState;

/// Cap on the body an extra-route handler will buffer (16 MiB). Extra routes are
/// a stateless escape hatch, not a bulk-upload path; a bounded buffer keeps a
/// single request from exhausting memory.
const MAX_EXTRA_ROUTE_BODY: usize = 16 * 1024 * 1024;

/// Fallback peer when the listener was not configured with `ConnectInfo`
/// (e.g. in `oneshot` tests). Real serving always supplies the connecting peer.
fn unknown_peer() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
}

/// The connecting peer, or [`unknown_peer`] when `ConnectInfo` is absent.
fn peer_of(req: &Request) -> SocketAddr {
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or_else(unknown_peer)
}

/// Inline gate: run the embedder's [`AuthDecider`] on every proxied request.
///
/// On `Allow`, the decider-controlled headers are injected onto the request
/// after stripping any client-supplied copies (so a client cannot forge them),
/// then the request proceeds upstream.
pub(crate) async fn auth_decider_gate(
    State(decider): State<Arc<dyn AuthDecider>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = peer_of(&request);
    let decision = {
        let uri = request.uri();
        let parts = RequestParts {
            method: request.method(),
            path: uri.path(),
            query: uri.query(),
            headers: request.headers(),
            peer,
        };
        decider.decide(&parts).await
    };

    match decision {
        Decision::Allow { inject_headers } => {
            let dst = request.headers_mut();
            strip_then_insert(dst, &inject_headers);
            next.run(request).await
        }
        Decision::Deny { status, body } => deny_response(status, body),
        // Inline (browser-facing) path: drive a real redirect.
        Decision::Redirect { location } => redirect_response(StatusCode::FOUND, &location),
    }
}

/// The `/verify` forward-auth endpoint, backed by the same [`AuthDecider`].
///
/// A fronting proxy (nginx `auth_request`, Traefik `forwardAuth`, Envoy
/// ext-authz HTTP) sub-requests this path; the original method/URI arrive via
/// `x-forwarded-*` / `x-original-*` headers. `Allow` answers `200` with the
/// verified headers for the fronting proxy to copy upstream.
pub(crate) async fn verify_via_decider(
    decider: Arc<dyn AuthDecider>,
    request: Request,
) -> Response {
    let peer = peer_of(&request);
    let headers = request.headers().clone();
    let method = original_method(&headers).unwrap_or_else(|| request.method().clone());
    let (path, query) = original_target(&headers).unwrap_or_else(|| {
        let uri = request.uri();
        (uri.path().to_string(), uri.query().map(str::to_string))
    });

    let decision = {
        let parts = RequestParts {
            method: &method,
            path: &path,
            query: query.as_deref(),
            headers: &headers,
            peer,
        };
        decider.decide(&parts).await
    };

    match decision {
        Decision::Allow { inject_headers } => (StatusCode::OK, inject_headers).into_response(),
        Decision::Deny { status, body } => deny_response(status, body),
        // Forward-auth path: a fronting proxy expects 401 (+ Location to drive
        // its own error-page redirect), not a 302 it would have to follow.
        Decision::Redirect { location } => redirect_response(StatusCode::UNAUTHORIZED, &location),
    }
}

/// Routes for the stateless OIDC surface supplied by an [`OidcBackend`].
pub(crate) fn oidc_backend_routes(backend: Arc<dyn OidcBackend>) -> Router<ProxyState> {
    let mut router = Router::new();

    // Static metadata documents (openid-configuration, provider-specific docs).
    for doc in backend.metadata_documents() {
        let json = doc.json;
        router = router.route(
            &doc.path,
            get(move || {
                let json = json.clone();
                async move { Json(json) }
            }),
        );
    }

    // JWKS, with the RFC 7517 media type.
    let jwks = backend.jwks();
    let jwks_body =
        serde_json::to_string(&jwks.json).unwrap_or_else(|_| "{\"keys\":[]}".to_string());
    router = router.route(
        &jwks.path,
        get(move || {
            let body = jwks_body.clone();
            async move { ([(CONTENT_TYPE, "application/jwk-set+json")], body) }
        }),
    );

    // UserInfo: bearer token in, claims out (401 when the backend rejects it).
    let userinfo_path = backend.userinfo_path();
    let userinfo_backend = backend.clone();
    router.route(
        &userinfo_path,
        get(move |headers: HeaderMap| {
            let backend = userinfo_backend.clone();
            async move {
                let token = bearer_token(&headers).unwrap_or_default();
                match backend.userinfo(&token).await {
                    Some(claims) => Json(claims).into_response(),
                    None => deny_response(
                        StatusCode::UNAUTHORIZED,
                        bytes::Bytes::from_static(
                            br#"{"error":"invalid_token","message":"invalid or expired token"}"#,
                        ),
                    ),
                }
            }
        }),
    )
}

/// Build a router for the embedder's extra stateless routes.
///
/// Routes that share a path but differ in method are merged into one
/// [`MethodRouter`], so registering `GET /x` and `POST /x` does not panic.
pub(crate) fn extra_routes_router(routes: &[ExtraRoute]) -> Router<ProxyState> {
    use std::collections::HashMap;

    let mut by_path: HashMap<String, MethodRouter<ProxyState>> = HashMap::new();
    for route in routes {
        let Ok(filter) = MethodFilter::try_from(route.method.clone()) else {
            tracing::warn!(
                method = %route.method,
                path = %route.path,
                "skipping extra route: unsupported HTTP method"
            );
            continue;
        };
        let handler = route.handler.clone();
        let service = on(filter, move |request: Request| {
            let handler = handler.clone();
            async move {
                let peer = peer_of(&request);
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, MAX_EXTRA_ROUTE_BODY)
                    .await
                    .unwrap_or_default();
                let resp = handler
                    .handle(RouteRequest {
                        method: parts.method,
                        uri: parts.uri,
                        headers: parts.headers,
                        body,
                        peer,
                    })
                    .await;
                let mut response = Response::new(Body::from(resp.body));
                *response.status_mut() = resp.status;
                *response.headers_mut() = resp.headers;
                response
            }
        });
        match by_path.remove(&route.path) {
            Some(existing) => {
                by_path.insert(route.path.clone(), existing.merge(service));
            }
            None => {
                by_path.insert(route.path.clone(), service);
            }
        }
    }

    let mut router = Router::new();
    for (path, method_router) in by_path {
        router = router.route(&path, method_router);
    }
    router
}

/// Remove any incoming copies of the soon-to-be-injected header names, then
/// insert the decider's values, so a client cannot forge them onto the upstream.
fn strip_then_insert(dst: &mut HeaderMap, inject: &HeaderMap) {
    for name in inject.keys() {
        while dst.remove(name).is_some() {}
    }
    for (name, value) in inject {
        dst.append(name.clone(), value.clone());
    }
}

/// Render a `Decision::Deny` as a JSON response.
fn deny_response(status: StatusCode, body: bytes::Bytes) -> Response {
    (status, [(CONTENT_TYPE, "application/json")], body).into_response()
}

/// Render a `Decision::Redirect` at the given status with a `Location` header.
/// A malformed `location` (not a valid header value) yields the bare status.
fn redirect_response(status: StatusCode, location: &str) -> Response {
    let mut response = status.into_response();
    if let Ok(value) = location.parse() {
        response.headers_mut().insert(LOCATION, value);
    }
    response
}

/// The bearer token from an `Authorization` header (prefix stripped), if present.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    (!token.is_empty()).then(|| token.to_string())
}

/// The original request method from a fronting proxy's forwarding headers.
fn original_method(headers: &HeaderMap) -> Option<axum::http::Method> {
    let raw = forwarded(headers, &["x-forwarded-method", "x-original-method"])?;
    axum::http::Method::from_bytes(raw.to_ascii_uppercase().as_bytes()).ok()
}

/// The original request path and query from a fronting proxy's forwarding headers.
fn original_target(headers: &HeaderMap) -> Option<(String, Option<String>)> {
    let raw = forwarded(headers, &["x-forwarded-uri", "x-original-uri"])?;
    Some(match raw.split_once('?') {
        Some((path, query)) => (path.to_string(), Some(query.to_string())),
        None => (raw, None),
    })
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
mod tests;
