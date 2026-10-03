//! Axum glue for the framework-agnostic embedding hooks.
//!
//! This module is the *only* place that bridges the `axum`-free public hook
//! traits ([`crate::hooks`]) to the running axum server: it converts live axum
//! requests into the borrowed/owned hook views, runs the embedder's trait
//! impls, and renders their results back into axum responses. Keeping the
//! conversion here is what lets an embedder depend on the hook traits without
//! ever naming `axum`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{CONTENT_TYPE, LOCATION, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, on, MethodFilter, MethodRouter};
use axum::{Json, Router};

use crate::client_address::ClientAddress;
use crate::guard::{http_to_grpc_code, mark_rejection};
use crate::hooks::{AuthDecider, Decision, ExtraRoute, OidcBackend, RequestParts, RouteRequest};

/// Cap on the body an extra-route handler will buffer (16 MiB). Extra routes are
/// a stateless escape hatch, not a bulk-upload path; a bounded buffer keeps a
/// single request from exhausting memory.
const MAX_EXTRA_ROUTE_BODY: usize = 16 * 1024 * 1024;

/// The client address the proxy resolved for `req`. A hook's route used
/// outside the proxy's router (in tests) has none: it gets what resolution
/// with no trusted proxy gives, the peer an axum server recorded, if any.
fn client_of(req: &Request) -> ClientAddress {
    match req.extensions().get::<ClientAddress>() {
        Some(client) => client.clone(),
        None => unresolved(req),
    }
}

/// [`client_of`] a request the proxy did not resolve.
fn unresolved(req: &Request) -> ClientAddress {
    ClientAddress::from_peer(
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0),
    )
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
    // Borrowed when the proxy resolved it, as on every request it serves.
    let fallback;
    let client = match request.extensions().get::<ClientAddress>() {
        Some(client) => client,
        None => {
            fallback = unresolved(&request);
            &fallback
        }
    };
    let decision = {
        let uri = request.uri();
        let parts = RequestParts {
            method: request.method(),
            path: uri.path(),
            query: uri.query(),
            headers: request.headers(),
            client,
        };
        decider.decide(&parts).await
    };

    match decision {
        Decision::Allow { inject_headers } => {
            let dst = request.headers_mut();
            strip_then_insert(dst, &inject_headers);
            next.run(request).await
        }
        // The decider owns the HTTP answer; a gRPC caller gets the code its
        // status maps to.
        Decision::Deny { status, body } => mark_rejection(
            deny_response(status, body),
            http_to_grpc_code(status),
            "denied by the auth decider",
        ),
        // Inline (browser-facing) path: drive a real redirect. A gRPC client
        // cannot follow one; it is told to authenticate, `Location` in its
        // metadata.
        Decision::Redirect { location } => mark_rejection(
            redirect_response(StatusCode::FOUND, &location),
            tonic::Code::Unauthenticated,
            "authentication required",
        ),
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
    let client = client_of(&request);
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
            client: &client,
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
pub(crate) fn oidc_backend_routes<S>(backend: Arc<dyn OidcBackend>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
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
                // RFC 6750 §3 Bearer challenge lets clients classify the failure.
                // No credentials: answer `Bearer` without invoking the backend at
                // all (never call it with an empty token).
                let Some(token) = bearer_token(&headers) else {
                    return unauthorized_with_challenge(
                        bytes::Bytes::from_static(
                            br#"{"error":"invalid_request","message":"missing bearer token"}"#,
                        ),
                        "Bearer",
                    );
                };
                match backend.userinfo(&token).await {
                    Some(claims) => Json(claims).into_response(),
                    // Presented token rejected by the backend.
                    None => unauthorized_with_challenge(
                        bytes::Bytes::from_static(
                            br#"{"error":"invalid_token","message":"invalid or expired token"}"#,
                        ),
                        r#"Bearer error="invalid_token""#,
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
pub(crate) fn extra_routes_router<S>(routes: &[ExtraRoute]) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    use std::collections::HashMap;

    let mut by_path: HashMap<String, MethodRouter<S>> = HashMap::new();
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
                let client = client_of(&request);
                let (parts, body) = request.into_parts();
                // A failed/oversized read must NOT reach the handler as an empty
                // body: a handler that verifies or parses the body would treat
                // the truncation as a real empty payload. Reject instead.
                let body = match axum::body::to_bytes(body, MAX_EXTRA_ROUTE_BODY).await {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return deny_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            bytes::Bytes::from_static(
                                br#"{"error":"payload_too_large","message":"request body exceeded limit or could not be read"}"#,
                            ),
                        )
                    }
                };
                let resp = handler
                    .handle(RouteRequest {
                        method: parts.method,
                        uri: parts.uri,
                        headers: parts.headers,
                        body,
                        client,
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
/// A client-address header is left alone: the proxy sets those from the
/// resolved address, and the decider's copy would contradict it.
fn strip_then_insert(dst: &mut HeaderMap, inject: &HeaderMap) {
    for name in inject.keys() {
        if crate::client_address::owns(name.as_str()) {
            tracing::warn!(header = %name, "auth decider header ignored: the proxy sets it from the client address");
            continue;
        }
        while dst.remove(name).is_some() {}
        for value in inject.get_all(name) {
            dst.append(name.clone(), value.clone());
        }
    }
}

/// Render a `Decision::Deny` as a JSON response.
fn deny_response(status: StatusCode, body: bytes::Bytes) -> Response {
    (status, [(CONTENT_TYPE, "application/json")], body).into_response()
}

/// A `401` JSON response carrying an RFC 6750 `WWW-Authenticate` Bearer challenge.
fn unauthorized_with_challenge(body: bytes::Bytes, challenge: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [
            (CONTENT_TYPE, "application/json"),
            (WWW_AUTHENTICATE, challenge),
        ],
        body,
    )
        .into_response()
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
/// The `Bearer` scheme name is matched case-insensitively per RFC 7235.
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = rest.trim();
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
