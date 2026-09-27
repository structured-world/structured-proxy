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

use axum::extract::Request;
use axum::http::header::{ACCESS_CONTROL_REQUEST_METHOD, ORIGIN};
use axum::http::Method;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use tower_http::cors::CorsLayer;

/// Marks a request whose method the outer layer replaced with [`stand_in`].
#[derive(Clone, Copy)]
struct OrdinaryOptions;

/// The method an ordinary `OPTIONS` request carries through the CORS layer
/// (short enough for `http` to store inline, without allocating). A client
/// sending it itself gets no special treatment: without the marker it is left
/// as it is and matches no route.
fn stand_in() -> Method {
    Method::from_bytes(b"X-SP-OPTIONS").expect("a valid method token")
}

/// `router` wrapped in `cors`, with only real preflights answered by it.
pub(crate) fn layer<S>(router: Router<S>, cors: CorsLayer) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(middleware::from_fn(restore_options))
        .layer(cors)
        .layer(middleware::from_fn(disguise_options))
}

/// Outermost: hide an ordinary `OPTIONS` from the CORS layer.
async fn disguise_options(mut request: Request, next: Next) -> Response {
    let headers = request.headers();
    let preflight =
        headers.contains_key(ORIGIN) && headers.contains_key(ACCESS_CONTROL_REQUEST_METHOD);
    if request.method() == Method::OPTIONS && !preflight {
        *request.method_mut() = stand_in();
        request.extensions_mut().insert(OrdinaryOptions);
    }
    next.run(request).await
}

/// Right inside the CORS layer: give the request its method back.
async fn restore_options(mut request: Request, next: Next) -> Response {
    if request
        .extensions_mut()
        .remove::<OrdinaryOptions>()
        .is_some()
    {
        *request.method_mut() = Method::OPTIONS;
    }
    next.run(request).await
}

#[cfg(test)]
mod tests;
