//! CORS around the router that answers only real preflight requests.
//!
//! tower-http's `CorsLayer` answers every `OPTIONS` request as a preflight, so
//! no route could serve `OPTIONS`: not a `custom` rule, not a `*` rule, not the
//! forward-auth endpoint, whose sub-request carries the original request's
//! method and would be allowed through by that `200`. The Fetch standard (§3.2.2,
//! CORS request and CORS-preflight request) makes a preflight an `OPTIONS`
//! request carrying both `Origin` and `Access-Control-Request-Method`; any other
//! `OPTIONS` is an ordinary request. Such a request passes the CORS layer under a
//! stand-in method, so it gets the response headers of an ordinary CORS request,
//! and has its method restored before anything else sees it.

use std::task::{Context, Poll};

use axum::http::header::{ACCESS_CONTROL_REQUEST_METHOD, ORIGIN};
use axum::http::{Method, Request};
use tower::{Layer, Service};
use tower_http::cors::CorsLayer;

/// Marks a request whose method the outer layer replaced with [`stand_in`].
#[derive(Clone, Copy)]
struct OrdinaryOptions;

/// The method an ordinary `OPTIONS` request carries through the CORS layer
/// (short enough for `http` to store inline, without allocating). A client
/// sending it itself gets no special treatment: without the marker it is left
/// as it is and matches no route.
fn stand_in() -> Method {
    Method::from_bytes(STAND_IN.as_bytes()).expect("a valid method token")
}

const STAND_IN: &str = "X-SP-OPTIONS";

/// `cors`, with only real preflights answered by it, outermost first: one
/// layer stack, so a router applying it boxes each route once.
pub(crate) fn layers(cors: CorsLayer) -> (Disguise, CorsLayer, Restore) {
    (Disguise, cors, Restore)
}

/// Outermost: hides an ordinary `OPTIONS` from the CORS layer.
#[derive(Clone, Copy)]
pub(crate) struct Disguise;

impl<S> Layer<S> for Disguise {
    type Service = DisguiseOptions<S>;

    fn layer(&self, inner: S) -> DisguiseOptions<S> {
        DisguiseOptions(inner)
    }
}

/// The service of [`Disguise`].
#[derive(Clone)]
pub(crate) struct DisguiseOptions<S>(S);

impl<S: Service<Request<B>>, B> Service<Request<B>> for DisguiseOptions<S> {
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> S::Future {
        if request.method() == Method::OPTIONS {
            let headers = request.headers();
            let preflight =
                headers.contains_key(ORIGIN) && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD);
            if !preflight {
                *request.method_mut() = stand_in();
                request.extensions_mut().insert(OrdinaryOptions);
            }
        }
        self.0.call(request)
    }
}

/// Right inside the CORS layer: gives the request its method back.
#[derive(Clone, Copy)]
pub(crate) struct Restore;

impl<S> Layer<S> for Restore {
    type Service = RestoreOptions<S>;

    fn layer(&self, inner: S) -> RestoreOptions<S> {
        RestoreOptions(inner)
    }
}

/// The service of [`Restore`].
#[derive(Clone)]
pub(crate) struct RestoreOptions<S>(S);

impl<S: Service<Request<B>>, B> Service<Request<B>> for RestoreOptions<S> {
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), S::Error>> {
        self.0.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> S::Future {
        // Only the stand-in carries the marker: no map lookup otherwise.
        if request.method().as_str() == STAND_IN
            && request
                .extensions_mut()
                .remove::<OrdinaryOptions>()
                .is_some()
        {
            *request.method_mut() = Method::OPTIONS;
        }
        self.0.call(request)
    }
}

#[cfg(test)]
mod tests;
