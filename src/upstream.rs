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
    #[project = PassThroughProj]
    #[project_replace = PassThroughReplace]
    pub(crate) enum PassThrough<U: Upstream> {
        Ready {
            upstream: U,
            request: http::Request<tonic::body::Body>,
        },
        Call {
            #[pin]
            future: U::Future,
        },
        Done,
    }
}

impl<U: Upstream> PassThrough<U> {
    pub(crate) fn new(upstream: U, request: http::Request<tonic::body::Body>) -> Self {
        Self::Ready { upstream, request }
    }
}

impl<U: Upstream> Future for PassThrough<U> {
    type Output = Result<http::Response<axum::body::Body>, Infallible>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.as_mut().project() {
                PassThroughProj::Ready { upstream, .. } => {
                    if let Err(e) = ready!(upstream.poll_ready(cx)) {
                        self.set(Self::Done);
                        return Poll::Ready(Ok(failure(e.into())));
                    }
                    let PassThroughReplace::Ready {
                        mut upstream,
                        request,
                    } = self.as_mut().project_replace(Self::Done)
                    else {
                        unreachable!("the state was just matched as Ready");
                    };
                    // The returned future owns what it needs; the service
                    // handle is dropped, as tower's `Oneshot` does.
                    let future = upstream.call(request);
                    self.set(Self::Call { future });
                }
                PassThroughProj::Call { future } => {
                    let result = ready!(future.poll(cx));
                    self.set(Self::Done);
                    return Poll::Ready(Ok(match result {
                        Ok(response) => response.map(axum::body::Body::new),
                        Err(e) => failure(e.into()),
                    }));
                }
                PassThroughProj::Done => panic!("PassThrough polled after completion"),
            }
        }
    }
}

/// The trailers-only gRPC answer to an upstream that failed to take the call.
fn failure(error: BoxError) -> http::Response<axum::body::Body> {
    tonic::Status::from_error(error).into_http()
}

/// Whether `headers` announce a gRPC or gRPC-Web request: a media type of
/// `application/grpc` or `application/grpc+<codec>` (gRPC PROTOCOL-HTTP2,
/// "Content-Type"), or `application/grpc-web[-text][+<codec>]` (gRPC
/// PROTOCOL-WEB). Media types compare without case (RFC 9110 §8.3.1).
pub(crate) fn is_grpc(headers: &http::HeaderMap) -> bool {
    let Some(value) = headers.get(http::header::CONTENT_TYPE) else {
        return false;
    };
    let value = value.as_bytes();
    let media = match value.iter().position(|&b| b == b';') {
        Some(end) => &value[..end],
        None => value,
    }
    .trim_ascii();
    const GRPC: &[u8] = b"application/grpc";
    if media.len() < GRPC.len() || !media[..GRPC.len()].eq_ignore_ascii_case(GRPC) {
        return false;
    }
    match &media[GRPC.len()..] {
        [] => true,
        [b'+', ..] => true,
        rest => {
            const WEB: &[u8] = b"-web";
            rest.len() >= WEB.len()
                && rest[..WEB.len()].eq_ignore_ascii_case(WEB)
                && is_web_suffix(&rest[WEB.len()..])
        }
    }
}

/// What may follow `application/grpc-web`: nothing, `+<codec>`, or `-text`
/// with an optional `+<codec>`.
fn is_web_suffix(rest: &[u8]) -> bool {
    const TEXT: &[u8] = b"-text";
    let rest = if rest.len() >= TEXT.len() && rest[..TEXT.len()].eq_ignore_ascii_case(TEXT) {
        &rest[TEXT.len()..]
    } else {
        rest
    };
    matches!(rest, [] | [b'+', ..])
}

#[cfg(test)]
mod tests;
