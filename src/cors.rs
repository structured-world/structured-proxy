//! CORS, answering only real preflight requests.
//!
//! The Fetch standard (§3.2.2, CORS request and CORS-preflight request) makes
//! a preflight an `OPTIONS` request carrying both `Origin` and
//! `Access-Control-Request-Method`; any other `OPTIONS` is an ordinary request
//! and goes on to the routes like any other, so a `custom` rule, a `*` rule or
//! the forward-auth endpoint (whose sub-request carries the original method)
//! can serve it.
//!
//! The policy is one of two: every origin, as a development default, or the
//! configured origins with credentials. Every header value it can send is
//! built once; a request costs a reference count and the headers it gets.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use axum::http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
    ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD, ORIGIN, VARY,
};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response};
use pin_project_lite::pin_project;
use tower::{Layer, Service};

/// A CORS policy, as a layer.
#[derive(Clone, Debug)]
pub(crate) struct CorsLayer(Arc<Policy>);

#[derive(Debug)]
struct Policy {
    /// `None` for every origin: `*` for the origin, the methods and the
    /// exposed headers, the request headers a preflight asks for named back,
    /// and no credentials. Otherwise the
    /// origins answered, with credentials, whose preflight gets back the
    /// method and headers it asked for (the Fetch standard, §3.2.5, forbids
    /// `*` with credentials).
    origins: Option<Vec<HeaderValue>>,
    /// The response headers a browser may read, for the listed origins.
    exposed: Option<HeaderValue>,
    /// How long a browser may cache a preflight's answer.
    max_age: Option<HeaderValue>,
}

const WILDCARD: HeaderValue = HeaderValue::from_static("*");
const TRUE: HeaderValue = HeaderValue::from_static("true");
/// What an answer for the listed origins depends on (RFC 9110 §12.5.5).
const VARY_REQUEST: HeaderValue = HeaderValue::from_static(
    "origin, access-control-request-method, access-control-request-headers",
);
/// What a preflight's answer for every origin depends on.
const VARY_REQUEST_HEADERS: HeaderValue =
    HeaderValue::from_static("access-control-request-headers");

impl CorsLayer {
    /// Every origin, every method and header.
    pub(crate) fn any(max_age: Option<u64>) -> Self {
        Self(Arc::new(Policy {
            origins: None,
            exposed: None,
            max_age: max_age.map(HeaderValue::from),
        }))
    }

    /// `origins`, with credentials, reading `exposed`.
    pub(crate) fn listed(
        origins: Vec<HeaderValue>,
        exposed: &[HeaderName],
        max_age: Option<u64>,
    ) -> Self {
        let exposed = (!exposed.is_empty()).then(|| {
            let names: Vec<&str> = exposed.iter().map(HeaderName::as_str).collect();
            HeaderValue::from_str(&names.join(",")).expect("header names are header values")
        });
        Self(Arc::new(Policy {
            origins: Some(origins),
            exposed,
            max_age: max_age.map(HeaderValue::from),
        }))
    }
}

impl<S> Layer<S> for CorsLayer {
    type Service = Cors<S>;

    fn layer(&self, inner: S) -> Cors<S> {
        Cors {
            policy: self.0.clone(),
            inner,
        }
    }
}

/// The service of a [`CorsLayer`].
#[derive(Clone, Debug)]
pub(crate) struct Cors<S> {
    policy: Arc<Policy>,
    inner: S,
}

impl Policy {
    /// The `Access-Control-Allow-Origin` an `origin` gets: `*`, or the origin
    /// itself when it is listed.
    fn allow_origin(&self, origin: Option<&HeaderValue>) -> Option<HeaderValue> {
        match &self.origins {
            None => Some(WILDCARD),
            Some(listed) => origin.filter(|origin| listed.contains(origin)).cloned(),
        }
    }

    /// The answer to a preflight with `headers`.
    fn preflight<B: Default>(&self, headers: &HeaderMap) -> Response<B> {
        let mut response = Response::new(B::default());
        let answer = response.headers_mut();
        match &self.origins {
            None => {
                answer.insert(ACCESS_CONTROL_ALLOW_METHODS, WILDCARD);
                // `*` does not cover `Authorization` (Fetch §3.2.3, the
                // CORS-preflight fetch): the headers asked for are named back,
                // which no credentials make unsafe here.
                match headers.get(ACCESS_CONTROL_REQUEST_HEADERS) {
                    Some(requested) => {
                        answer.insert(ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
                        answer.insert(VARY, VARY_REQUEST_HEADERS);
                    }
                    None => {
                        answer.insert(ACCESS_CONTROL_ALLOW_HEADERS, WILDCARD);
                    }
                }
            }
            Some(_) => {
                answer.insert(ACCESS_CONTROL_ALLOW_CREDENTIALS, TRUE);
                answer.insert(VARY, VARY_REQUEST);
                if let Some(method) = headers.get(ACCESS_CONTROL_REQUEST_METHOD) {
                    answer.insert(ACCESS_CONTROL_ALLOW_METHODS, method.clone());
                }
                if let Some(requested) = headers.get(ACCESS_CONTROL_REQUEST_HEADERS) {
                    answer.insert(ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
                }
            }
        }
        if let Some(max_age) = &self.max_age {
            answer.insert(ACCESS_CONTROL_MAX_AGE, max_age.clone());
        }
        if let Some(origin) = self.allow_origin(headers.get(ORIGIN)) {
            answer.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        }
        response
    }

    /// Put the headers of an ordinary CORS request on `headers`, those of
    /// the response, over its own: `Vary` alongside the response's.
    fn answer(&self, headers: &mut HeaderMap, allow_origin: Option<HeaderValue>) {
        match &self.origins {
            None => {
                headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, WILDCARD);
                headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, WILDCARD);
            }
            Some(_) => {
                headers.append(VARY, VARY_REQUEST);
                headers.insert(ACCESS_CONTROL_ALLOW_CREDENTIALS, TRUE);
                if let Some(origin) = allow_origin {
                    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                }
                if let Some(exposed) = &self.exposed {
                    headers.insert(ACCESS_CONTROL_EXPOSE_HEADERS, exposed.clone());
                }
            }
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for Cors<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Default,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = CorsFuture<S::Future, ResBody>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let headers = request.headers();
        // A CORS-preflight request (Fetch §3.2.2); any other OPTIONS is an
        // ordinary one.
        if request.method() == Method::OPTIONS
            && headers.contains_key(ORIGIN)
            && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD)
        {
            return CorsFuture::Preflight {
                response: Some(self.policy.preflight(headers)),
            };
        }
        let allow_origin = self.policy.allow_origin(headers.get(ORIGIN));
        CorsFuture::Call {
            future: self.inner.call(request),
            policy: Some(self.policy.clone()),
            allow_origin,
        }
    }
}

pin_project! {
    /// The response future of [`Cors`].
    #[project = CorsProjection]
    pub(crate) enum CorsFuture<F, B> {
        Call {
            #[pin]
            future: F,
            policy: Option<Arc<Policy>>,
            allow_origin: Option<HeaderValue>,
        },
        Preflight { response: Option<Response<B>> },
    }
}

impl<F, B, E> Future for CorsFuture<F, B>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            CorsProjection::Call {
                future,
                policy,
                allow_origin,
            } => {
                let mut response = ready!(future.poll(cx))?;
                let policy = policy.take().expect("polled after completion");
                policy.answer(response.headers_mut(), allow_origin.take());
                Poll::Ready(Ok(response))
            }
            CorsProjection::Preflight { response } => {
                Poll::Ready(Ok(response.take().expect("polled after completion")))
            }
        }
    }
}

#[cfg(test)]
mod tests;
