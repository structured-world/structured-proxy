//! Guard rejections on the gRPC path, answered in gRPC.

use alloc::string::ToString;
use core::convert::Infallible;
use core::future::Future;
use core::pin::Pin;
use core::task::{ready, Context, Poll};

use axum::extract::Request;
use axum::response::Response;
use pin_project_lite::pin_project;
use tower::Service;

use super::{http_to_grpc_code, BoxedService, Rejection};
use crate::upstream::{grpc_protocol, trailers_only, GrpcProtocol};

/// The guarded gRPC path of one protocol: a guard's HTTP rejection becomes a
/// trailers-only status in `protocol` (gRPC PROTOCOL-HTTP2, "Responses"), the
/// only answer a gRPC client reads. The upstream's own answers pass as they
/// are.
#[derive(Clone)]
pub(crate) struct GrpcRejections {
    pub(crate) inner: BoxedService,
    pub(crate) protocol: GrpcProtocol,
}

impl Service<Request> for GrpcRejections {
    type Response = Response;
    type Error = Infallible;
    type Future = RejectionFuture;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        RejectionFuture {
            future: self.inner.call(request),
            protocol: self.protocol,
        }
    }
}

pin_project! {
    /// The response future of [`GrpcRejections`].
    pub(crate) struct RejectionFuture {
        #[pin]
        future: <BoxedService as Service<Request>>::Future,
        protocol: GrpcProtocol,
    }
}

impl Future for RejectionFuture {
    type Output = Result<Response, Infallible>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let response = ready!(this.future.poll(cx))?;
        Poll::Ready(Ok(in_grpc(response, *this.protocol)))
    }
}

/// Headers of an HTTP rejection that describe the body, not the rejection,
/// and so do not become gRPC metadata.
const BODY_HEADERS: [http::HeaderName; 3] = [
    http::header::CONTENT_TYPE,
    http::header::CONTENT_LENGTH,
    http::header::TRANSFER_ENCODING,
];

/// `response` as a gRPC client reads it: a guard's rejection (marked, or any
/// answer without a gRPC content type) as a trailers-only status, carrying the
/// guard's headers (`Retry-After`, `RateLimit-*`, `WWW-Authenticate`,
/// `Location`) as metadata.
fn in_grpc(response: Response, protocol: GrpcProtocol) -> Response {
    let (code, message) = match response.extensions().get::<Rejection>() {
        Some(rejection) => (rejection.code, rejection.message.to_string()),
        None if grpc_protocol(response.headers()).is_some() => return response,
        None => (
            http_to_grpc_code(response.status()),
            response
                .status()
                .canonical_reason()
                .unwrap_or_default()
                .to_string(),
        ),
    };
    let (parts, _) = response.into_parts();
    let mut answer = trailers_only(tonic::Status::new(code, message), protocol);
    let headers = answer.headers_mut();
    let mut previous = None;
    for (name, value) in parts.headers {
        // `HeaderMap::into_iter` names a header once, before all its values.
        if let Some(name) = name {
            previous = Some(name);
        }
        let Some(name) = &previous else { continue };
        if BODY_HEADERS.contains(name) {
            continue;
        }
        headers.append(name.clone(), value);
    }
    answer
}
