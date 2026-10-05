//! The HTTP request a transcoded call was made from.
//!
//! A transcoded call reaches the upstream as a gRPC call to the RPC its
//! binding selected; the client's HTTP method and request target are no
//! longer part of it, and one RPC may be bound to several paths (additional
//! bindings, aliases), so the RPC path cannot be turned back into them. An
//! upstream served in process gets them as a [`ReceivedRequest`] in the
//! request extensions. The proxy records them and checks nothing about them.
//! A remote upstream never sees request extensions.

use axum::http::uri::PathAndQuery;
use axum::http::Method;

/// The HTTP request a transcoded gRPC call was made from, as the proxy
/// received it: its method, its path and query, and the gRPC path of the RPC
/// the matched binding selected.
///
/// The path is the one on the request line, before a router the proxy is
/// nested in strips its prefix, so an alias or a public prefix stays visible.
/// An absolute-form target (any HTTP/2 request, an HTTP/1.1 request through a
/// forward proxy) records its path and query alone, so one request records the
/// same value over either protocol. No header the client sends
/// (`x-original-uri`, forwarding headers) changes it.
///
/// # Examples
///
/// ```
/// use structured_proxy::ReceivedRequest;
///
/// // What a tonic handler behind the proxy does with it.
/// fn target(request: &tonic::Request<()>) -> Option<String> {
///     let received = request.extensions().get::<ReceivedRequest>()?;
///     Some(format!("{} {}", received.method(), received.path_and_query()))
/// }
///
/// let received = ReceivedRequest::new(
///     http::Method::POST,
///     http::uri::PathAndQuery::from_static("/v1/orgs/42:suspend?dry=1"),
///     http::uri::PathAndQuery::from_static("/acme.v1.Orgs/Suspend"),
/// );
/// let mut request = tonic::Request::new(());
/// request.extensions_mut().insert(received);
/// assert_eq!(target(&request).as_deref(), Some("POST /v1/orgs/42:suspend?dry=1"));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ReceivedRequest {
    method: Method,
    path_and_query: PathAndQuery,
    rpc: PathAndQuery,
}

impl ReceivedRequest {
    /// A request received as `method` `path_and_query`, transcoded to the RPC
    /// at the gRPC path `rpc`. The view an upstream's own tests hand it.
    pub fn new(method: Method, path_and_query: PathAndQuery, rpc: PathAndQuery) -> Self {
        Self {
            method,
            path_and_query,
            rpc,
        }
    }

    /// The HTTP method as received: `HEAD` on a route bound to `GET` stays
    /// `HEAD`, and a `custom` binding's method is itself.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The path and query as received, percent-encoding untouched.
    pub fn path_and_query(&self) -> &PathAndQuery {
        &self.path_and_query
    }

    /// The gRPC path of the RPC the matched binding selected
    /// (`/package.Service/Method`).
    pub fn rpc(&self) -> &str {
        self.rpc.path()
    }
}

#[cfg(test)]
mod tests;
