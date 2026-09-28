//! The gRPC service the proxy calls.
//!
//! An upstream is any tower service that speaks gRPC over `http` types: a
//! remote [`tonic::transport::Channel`], or an embedder's own services in
//! process, such as [`tonic::service::Routes`]. The transcoder calls it for
//! every transcoded request, and [`ProxyService`](crate::ProxyService) hands it
//! native gRPC requests unchanged.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::Bytes;
use pin_project_lite::pin_project;
use tonic::client::GrpcService;

/// The error type a gRPC service hands back through tonic.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A gRPC service the proxy can call: a remote
/// [`Channel`](tonic::transport::Channel), [`tonic::service::Routes`], or any
/// other `tower::Service<http::Request<tonic::body::Body>>` answering with a
/// gRPC response. Implemented for every such service; there is nothing to
/// implement by hand.
///
/// An in-process upstream sees a transcoded call exactly as it sees a native
/// gRPC request: through its whole stack, interceptors and layers included.
///
/// # Examples
///
/// ```
/// use structured_proxy::upstream::Upstream;
///
/// fn accepts<U: Upstream>(_upstream: U) {}
///
/// // An empty set of tonic services answers every call with UNIMPLEMENTED.
/// accepts(tonic::service::Routes::default());
/// ```
pub trait Upstream:
    GrpcService<
        tonic::body::Body,
        ResponseBody: http_body::Body<Data = Bytes, Error: Into<BoxError> + Send> + Send + 'static,
        Error: Into<BoxError>,
        Future: Send,
    > + Clone
    + Send
    + Sync
    + 'static
{
}

impl<T> Upstream for T where
    T: GrpcService<
            tonic::body::Body,
            ResponseBody: http_body::Body<Data = Bytes, Error: Into<BoxError> + Send>
                              + Send
                              + 'static,
            Error: Into<BoxError>,
            Future: Send,
        > + Clone
        + Send
        + Sync
        + 'static
{
}

pin_project! {
    /// One native gRPC request on its way through an upstream: waits for the
    /// upstream to be ready, calls it, and answers with its response. A
    /// failure of the upstream itself (a remote one that cannot be reached)
    /// becomes a trailers-only gRPC error, so the client gets a status rather
    /// than a broken connection.
    ///
    /// No proxy timer runs here and `grpc-timeout` travels unchanged: the
    /// caller is a gRPC client, which enforces its own deadline (gRPC
    /// PROTOCOL-HTTP2, "Timeout") by cancelling the stream, and that drops
    /// this future wherever it waits, readiness included. A transcoded call is
    /// different: there the proxy is the gRPC client and bounds the call itself.
    #[project = PassThroughProj]
    #[project_replace = PassThroughReplace]
    pub(crate) enum PassThrough<U: Upstream> {
        Ready {
            upstream: U,
            request: http::Request<tonic::body::Body>,
            protocol: GrpcProtocol,
        },
        Call {
            #[pin]
            future: U::Future,
            protocol: GrpcProtocol,
        },
        Done,
    }
}

impl<U: Upstream> PassThrough<U> {
    pub(crate) fn new(
        upstream: U,
        request: http::Request<tonic::body::Body>,
        protocol: GrpcProtocol,
    ) -> Self {
        Self::Ready {
            upstream,
            request,
            protocol,
        }
    }
}

impl<U: Upstream> Future for PassThrough<U> {
    type Output = Result<http::Response<axum::body::Body>, Infallible>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.as_mut().project() {
                PassThroughProj::Ready {
                    upstream, protocol, ..
                } => {
                    let protocol = *protocol;
                    if let Err(e) = ready!(upstream.poll_ready(cx)) {
                        self.set(Self::Done);
                        return Poll::Ready(Ok(failure(e.into(), protocol)));
                    }
                    let PassThroughReplace::Ready {
                        mut upstream,
                        request,
                        ..
                    } = self.as_mut().project_replace(Self::Done)
                    else {
                        unreachable!("the state was just matched as Ready");
                    };
                    // The returned future owns what it needs; the service
                    // handle is dropped, as tower's `Oneshot` does.
                    let future = upstream.call(request);
                    self.set(Self::Call { future, protocol });
                }
                PassThroughProj::Call { future, protocol } => {
                    let protocol = *protocol;
                    let result = ready!(future.poll(cx));
                    self.set(Self::Done);
                    return Poll::Ready(Ok(match result {
                        Ok(response) => response.map(axum::body::Body::new),
                        Err(e) => failure(e.into(), protocol),
                    }));
                }
                PassThroughProj::Done => panic!("PassThrough polled after completion"),
            }
        }
    }
}

/// The trailers-only answer to an upstream that failed to take the call, in
/// the request's protocol: gRPC-Web carries a trailers-only status in its
/// headers too, but its client reads it only under a gRPC-Web content type
/// (gRPC PROTOCOL-WEB).
fn failure(error: BoxError, protocol: GrpcProtocol) -> http::Response<axum::body::Body> {
    let mut response: http::Response<axum::body::Body> =
        tonic::Status::from_error(error).into_http();
    if protocol != GrpcProtocol::Grpc {
        response.headers_mut().insert(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static(protocol.content_type()),
        );
    }
    response
}

/// The gRPC protocol a request speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GrpcProtocol {
    /// gRPC over HTTP/2 (gRPC PROTOCOL-HTTP2).
    Grpc,
    /// Binary gRPC-Web (gRPC PROTOCOL-WEB).
    Web,
    /// Base64 gRPC-Web, `-text` (gRPC PROTOCOL-WEB).
    WebText,
}

impl GrpcProtocol {
    /// The content type of an answer the proxy writes itself: the protocol
    /// with gRPC's default protobuf codec.
    fn content_type(self) -> &'static str {
        match self {
            Self::Grpc => "application/grpc",
            Self::Web => "application/grpc-web+proto",
            Self::WebText => "application/grpc-web-text+proto",
        }
    }
}

/// The gRPC protocol `headers` announce, if any: a media type of
/// `application/grpc` or `application/grpc+<codec>` (gRPC PROTOCOL-HTTP2,
/// "Content-Type"), or `application/grpc-web[-text][+<codec>]` (gRPC
/// PROTOCOL-WEB). Media types compare without case (RFC 9110 §8.3.1).
pub(crate) fn grpc_protocol(headers: &http::HeaderMap) -> Option<GrpcProtocol> {
    let value = headers.get(http::header::CONTENT_TYPE)?.as_bytes();
    let media = match value.iter().position(|&b| b == b';') {
        Some(end) => &value[..end],
        None => value,
    }
    .trim_ascii();
    let rest = strip_prefix_ignore_case(media, b"application/grpc")?;
    match rest {
        [] | [b'+', ..] => Some(GrpcProtocol::Grpc),
        _ => web_protocol(strip_prefix_ignore_case(rest, b"-web")?),
    }
}

/// Whether a request is a browser's CORS preflight for a gRPC-Web call: an
/// `OPTIONS` with an `Origin` (Fetch §3.2.2) whose
/// `Access-Control-Request-Headers` names `x-grpc-web`, the header gRPC-Web
/// clients send with every call (gRPC PROTOCOL-WEB). It carries no gRPC
/// content type, so only these headers tell it apart from a REST preflight.
pub(crate) fn is_grpc_web_preflight(method: &http::Method, headers: &http::HeaderMap) -> bool {
    method == http::Method::OPTIONS
        && headers.contains_key(http::header::ORIGIN)
        && headers
            .get_all(http::header::ACCESS_CONTROL_REQUEST_HEADERS)
            .iter()
            .flat_map(|value| value.as_bytes().split(|&b| b == b','))
            .any(|name| name.trim_ascii().eq_ignore_ascii_case(b"x-grpc-web"))
}

/// What follows `application/grpc-web`: nothing or `+<codec>` for binary,
/// `-text` with an optional `+<codec>` for base64.
fn web_protocol(rest: &[u8]) -> Option<GrpcProtocol> {
    let (protocol, rest) = match strip_prefix_ignore_case(rest, b"-text") {
        Some(rest) => (GrpcProtocol::WebText, rest),
        None => (GrpcProtocol::Web, rest),
    };
    matches!(rest, [] | [b'+', ..]).then_some(protocol)
}

/// `bytes` after `prefix`, compared without ASCII case.
fn strip_prefix_ignore_case<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let (head, rest) = bytes.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}

#[cfg(test)]
mod tests;
