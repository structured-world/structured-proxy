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

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};

use crate::client_address::ClientAddress;

/// Borrowed view of an incoming request, passed to an [`AuthDecider`].
///
/// All fields borrow from the live request: building this is allocation-free, so
/// the per-request gate stays cheap. The body is intentionally absent: an auth
/// decision is taken from method, path, query, headers, and client alone.
///
/// # Examples
///
/// ```
/// use structured_proxy::hooks::RequestParts;
/// use structured_proxy::ClientAddress;
///
/// // The view a decider's own tests build.
/// let client = ClientAddress::from_peer(Some("203.0.113.7:51234".parse().unwrap()));
/// let headers = http::HeaderMap::new();
/// let parts = RequestParts::new(&http::Method::GET, "/v1/things", None, &headers, &client);
/// assert_eq!(parts.client.ip(), Some("203.0.113.7".parse().unwrap()));
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub struct RequestParts<'a> {
    /// Request method (the *original* method on the `/verify` path, recovered
    /// from the fronting proxy's forwarding headers).
    pub method: &'a Method,
    /// Request path, query stripped.
    pub path: &'a str,
    /// Raw query string, if any (without the leading `?`).
    pub query: Option<&'a str>,
    /// Request headers. Their `X-Forwarded-For` and `X-Real-IP` hold the
    /// resolved client address and nothing the client sent.
    pub headers: &'a HeaderMap,
    /// The client address the proxy resolved, with the connection's peer
    /// (the client, or the fronting proxy).
    pub client: &'a ClientAddress,
}

impl<'a> RequestParts<'a> {
    /// The view of a request: what the proxy hands a decider, and what a
    /// decider's own tests build.
    pub fn new(
        method: &'a Method,
        path: &'a str,
        query: Option<&'a str>,
        headers: &'a HeaderMap,
        client: &'a ClientAddress,
    ) -> Self {
        Self {
            method,
            path,
            query,
            headers,
            client,
        }
    }
}

/// The outcome of an [`AuthDecider`] evaluation.
#[non_exhaustive]
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

/// Verifies a bearer token and yields its claims.
///
/// This is the seam the JWT middleware validates through. The built-in
/// implementation (`jsonwebtoken`, keys from `auth.jwt`) is what a plain
/// config-driven deployment gets; an embedder injects its own through
/// [`ProxyServer::with_token_verifier`](crate::ProxyServer::with_token_verifier)
/// when it needs a different signature backend — a validated / FIPS module, an
/// HSM, a shared verifier it already owns.
///
/// Injecting one is what makes the crypto backend a property of the *binary*
/// rather than of the dependency graph: Cargo unifies features across the whole
/// resolution, so two consumers of this crate that want different built-in
/// backends cannot coexist, while two consumers that inject their own verifiers
/// can. A build that injects one needs no crypto backend feature at all
/// (`default-features = false`), and then links no JWT crypto.
///
/// Everything around verification stays with the proxy: route policies
/// (`require_auth` / `required_roles`), the roles claim, and the claim→header
/// forwarding all operate on the returned claims.
#[async_trait]
pub trait TokenVerifier: Send + Sync {
    /// Verify `token` and return its claims, or `None` to reject the request
    /// with `401`.
    ///
    /// `token` is the raw JWT from the `Authorization: Bearer` header, already
    /// stripped of the prefix and guaranteed non-empty. The implementation owns
    /// the whole check — signature, `exp`/`nbf`, issuer, audience — since only
    /// it knows which of those its keys and policy imply. Returning claims for
    /// a token whose signature was not verified would hand a forged identity to
    /// the upstream.
    async fn verify(&self, token: &str) -> Option<serde_json::Value>;
}

/// A static JSON document served at a fixed path (an OIDC metadata document or a
/// JWKS document).
#[derive(Debug, Clone)]
#[non_exhaustive]
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

    /// Resolve UserInfo claims for a bearer token. `None` yields `401`.
    ///
    /// `bearer` is always a present, non-empty token (the `Bearer ` prefix
    /// already stripped): a request with no credentials is rejected with a
    /// `401` Bearer challenge before this method is called, so implementations
    /// never receive an empty string.
    async fn userinfo(&self, bearer: &str) -> Option<serde_json::Value>;
}

/// Owned view of a request handed to an [`ExtraRouteHandler`].
///
/// Unlike [`RequestParts`], this owns its data (including the full body), since
/// an extra route may consume the body to produce a response.
#[derive(Debug)]
#[non_exhaustive]
pub struct RouteRequest {
    /// Request method.
    pub method: Method,
    /// Full request URI (path + query).
    pub uri: http::Uri,
    /// Request headers.
    pub headers: HeaderMap,
    /// Request body bytes.
    pub body: Bytes,
    /// The client address the proxy resolved, with the connection's peer.
    pub client: ClientAddress,
}

impl RouteRequest {
    /// The request a handler gets: what the proxy builds, and what a
    /// handler's own tests build.
    pub fn new(
        method: Method,
        uri: http::Uri,
        headers: HeaderMap,
        body: Bytes,
        client: ClientAddress,
    ) -> Self {
        Self {
            method,
            uri,
            headers,
            body,
            client,
        }
    }
}

/// Response produced by an [`ExtraRouteHandler`].
#[non_exhaustive]
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
