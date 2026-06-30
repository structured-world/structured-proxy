//! Framework-agnostic extension points for embedding the proxy.
//!
//! These traits let an embedding crate inject *stateless* service-specific logic
//! (a forward-auth/PDP decision, an OIDC discovery/JWKS/userinfo backing, extra
//! routes) without naming an HTTP framework in its own code or `Cargo.toml`.
//! All signatures use the foundational [`http`] crate (already in the tree via
//! both `axum` and `tonic`), [`bytes::Bytes`], and `serde_json::Value` (never an
//! `axum` type), so `cargo tree -i axum` in an embedder shows axum only under
//! `structured-proxy`.
//!
//! Stateful concerns (BFF sessions, OIDC `authorize`/`token`) are deliberately
//! absent: the default build is a stateless data plane (see the crate README
//! Non-goals). They are planned behind an opt-in `bff` feature.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};

/// Borrowed view of an incoming request, passed to an [`AuthDecider`].
///
/// All fields borrow from the live request: building this is allocation-free, so
/// the per-request gate stays cheap. The body is intentionally absent: an auth
/// decision is taken from method, path, query, headers, and peer alone.
#[derive(Debug)]
pub struct RequestParts<'a> {
    /// Request method (the *original* method on the `/verify` path, recovered
    /// from the fronting proxy's forwarding headers).
    pub method: &'a Method,
    /// Request path, query stripped.
    pub path: &'a str,
    /// Raw query string, if any (without the leading `?`).
    pub query: Option<&'a str>,
    /// Request headers.
    pub headers: &'a HeaderMap,
    /// Direct peer socket address (the connecting client, or the fronting proxy).
    pub peer: SocketAddr,
}

/// The outcome of an [`AuthDecider`] evaluation.
pub enum Decision {
    /// Allow the request; merge these (decider-controlled) headers onto it before
    /// it continues upstream. The proxy strips any client-supplied copies of
    /// these header names first, so a client cannot forge them.
    Allow {
        /// Headers to inject for the upstream (e.g. a verified `x-user-id`).
        inject_headers: HeaderMap,
    },
    /// Reject the request with this status and body (served as `application/json`).
    Deny {
        /// HTTP status to return (e.g. 401 / 403).
        status: StatusCode,
        /// Response body bytes.
        body: Bytes,
    },
    /// Redirect the client (e.g. to a login URL); returned as `302 Found`.
    Redirect {
        /// Absolute or relative `Location` URL.
        location: String,
    },
}

/// The per-request authorization gate.
///
/// Implemented by the embedder for its forward-auth / policy-decision logic
/// (e.g. JWT verification + a policy engine + header translation). Called inline
/// on every proxied request *and* by the `/verify` forward-auth endpoint: same
/// trait, two call sites.
#[async_trait]
pub trait AuthDecider: Send + Sync {
    /// Decide whether to allow, deny, or redirect the request.
    async fn decide(&self, req: &RequestParts<'_>) -> Decision;
}

/// A static JSON document served at a fixed path (an OIDC metadata document or a
/// JWKS document).
#[derive(Debug, Clone)]
pub struct MetadataDocument {
    /// Path to serve at (e.g. `/.well-known/openid-configuration`).
    pub path: String,
    /// JSON body.
    pub json: serde_json::Value,
}

impl MetadataDocument {
    /// Construct a metadata document.
    pub fn new(path: impl Into<String>, json: serde_json::Value) -> Self {
        Self {
            path: path.into(),
            json,
        }
    }
}

/// Backing for the *stateless* OIDC surface the proxy hosts.
///
/// The proxy owns the HTTP routes (discovery, JWKS, userinfo); the embedder
/// supplies their content from its own key/client metadata. No `authorize` /
/// `token` here: those are stateful and out of scope for the data plane.
#[async_trait]
pub trait OidcBackend: Send + Sync {
    /// Static metadata documents to serve as `GET` routes, e.g. the
    /// `openid-configuration` and any provider-specific discovery document.
    fn metadata_documents(&self) -> Vec<MetadataDocument>;

    /// The JWKS document and the path it is advertised at.
    fn jwks(&self) -> MetadataDocument;

    /// The path of the UserInfo endpoint. Defaults to `/userinfo`.
    fn userinfo_path(&self) -> String {
        "/userinfo".to_string()
    }

    /// Resolve UserInfo claims for a verified bearer token. `None` yields `401`.
    /// `bearer` is the raw token (the `Bearer ` prefix already stripped), or an
    /// empty string when no credentials were presented.
    async fn userinfo(&self, bearer: &str) -> Option<serde_json::Value>;
}

/// Owned view of a request handed to an [`ExtraRouteHandler`].
///
/// Unlike [`RequestParts`], this owns its data (including the full body), since
/// an extra route may consume the body to produce a response.
#[derive(Debug)]
pub struct RouteRequest {
    /// Request method.
    pub method: Method,
    /// Full request URI (path + query).
    pub uri: http::Uri,
    /// Request headers.
    pub headers: HeaderMap,
    /// Request body bytes.
    pub body: Bytes,
    /// Direct peer socket address.
    pub peer: SocketAddr,
}

/// Response produced by an [`ExtraRouteHandler`].
pub struct RouteResponse {
    /// HTTP status.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Response body bytes.
    pub body: Bytes,
}

impl RouteResponse {
    /// A response with the given status and body and no extra headers.
    pub fn new(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
        }
    }
}

/// A stateless handler for an extra route registered via
/// [`ProxyServer::with_extra_routes`](crate::ProxyServer::with_extra_routes).
///
/// The framework-agnostic seam (request parts in, response parts out) the
/// embedder uses for service-specific endpoints without naming `axum`.
#[async_trait]
pub trait ExtraRouteHandler: Send + Sync {
    /// Handle a request and produce a response.
    async fn handle(&self, req: RouteRequest) -> RouteResponse;
}

/// A single extra route: a method, a path, and the handler to run.
#[derive(Clone)]
pub struct ExtraRoute {
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) handler: Arc<dyn ExtraRouteHandler>,
}

impl ExtraRoute {
    /// Register `handler` for `method` requests to `path`.
    pub fn new(
        method: Method,
        path: impl Into<String>,
        handler: Arc<dyn ExtraRouteHandler>,
    ) -> Self {
        Self {
            method,
            path: path.into(),
            handler,
        }
    }
}
