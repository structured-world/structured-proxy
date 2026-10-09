//! Guards: the checks that may turn a request away before it reaches a route,
//! the upstream or the fallback (maintenance, concurrency, rate limits, JWT,
//! ext_authz, the auth decider). Each covers the traffic its scope names, and
//! each rejects through [`reject`] or [`mark_rejection`], so a rejection
//! reaches a REST client as its HTTP answer and a gRPC client as a gRPC
//! status ([`GrpcRejections`]).

mod concurrency;
mod gate;
mod grpc;

use std::borrow::Cow;
use std::convert::Infallible;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use futures::future::Either;
use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use http::{Method, StatusCode};
use tower::util::{BoxCloneSyncService, Oneshot};
use tower::{Layer, Service, ServiceExt};

use crate::config::{ScopeConfig, Traffic};
use crate::transcode::error::{grpc_to_http_status, guard_error_body};

pub(crate) use concurrency::Concurrency;
pub(crate) use grpc::GrpcRejections;

/// What a guard's rejection means in gRPC terms, attached to its response so a
/// gRPC request is answered with a status instead of the HTTP body.
#[derive(Clone, Debug)]
pub(crate) struct Rejection {
    pub(crate) code: tonic::Code,
    pub(crate) message: Cow<'static, str>,
}

/// A guard's rejection: the `google.rpc.Status` JSON body the transcoder's
/// own errors use, with the HTTP status `code` maps to, carrying the
/// [`Rejection`] for a gRPC request.
pub(crate) fn reject(code: tonic::Code, message: impl Into<Cow<'static, str>>) -> Response {
    let message = message.into();
    let body = guard_error_body(code, &message);
    mark_rejection(
        (grpc_to_http_status(code), Json(body)).into_response(),
        code,
        message,
    )
}

/// Mark a guard's own HTTP answer (a decider's body, an ext_authz denial, a
/// redirect) with the gRPC status a gRPC request gets instead.
pub(crate) fn mark_rejection(
    mut response: Response,
    code: tonic::Code,
    message: impl Into<Cow<'static, str>>,
) -> Response {
    response.extensions_mut().insert(Rejection {
        code,
        message: message.into(),
    });
    response
}

/// The gRPC code of an HTTP status, by the HTTP mapping of
/// `google/rpc/code.proto`: the inverse of the transcoder's own mapping, so a
/// code survives the round trip.
pub(crate) fn http_to_grpc_code(status: StatusCode) -> tonic::Code {
    match status.as_u16() {
        400 => tonic::Code::InvalidArgument,
        401 => tonic::Code::Unauthenticated,
        403 => tonic::Code::PermissionDenied,
        404 => tonic::Code::NotFound,
        409 => tonic::Code::Aborted,
        429 => tonic::Code::ResourceExhausted,
        499 => tonic::Code::Cancelled,
        501 => tonic::Code::Unimplemented,
        503 => tonic::Code::Unavailable,
        504 => tonic::Code::DeadlineExceeded,
        500..=599 => tonic::Code::Internal,
        _ => tonic::Code::Unknown,
    }
}

/// A class of traffic a guard stack is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    Transcoded,
    Endpoints,
    /// The forward-auth endpoint: an endpoint that answers the JWT and decider
    /// gates, so it is never behind them.
    Verify,
    Grpc,
    Fallback,
}

const TRANSCODED: u8 = 1;
const ENDPOINTS: u8 = 1 << 1;
const GRPC: u8 = 1 << 2;
const FALLBACK: u8 = 1 << 3;

impl Class {
    fn bit(self) -> u8 {
        match self {
            Self::Transcoded => TRANSCODED,
            Self::Endpoints | Self::Verify => ENDPOINTS,
            Self::Grpc => GRPC,
            Self::Fallback => FALLBACK,
        }
    }

    /// Whether the authenticating guards (JWT, ext_authz, the decider) may
    /// run on this class.
    fn authenticates(self) -> bool {
        self != Self::Verify
    }
}

fn traffic_bits(traffic: Traffic) -> u8 {
    match traffic {
        Traffic::Transcoded => TRANSCODED,
        Traffic::Endpoints => ENDPOINTS,
        Traffic::Grpc => GRPC,
        Traffic::Fallback => FALLBACK,
        Traffic::All => TRANSCODED | ENDPOINTS | GRPC | FALLBACK,
    }
}

/// A compiled [`ScopeConfig`]: the classes a guard is mounted on, and the
/// paths and methods it is narrowed to within them.
#[derive(Debug)]
pub(crate) struct Scope {
    classes: u8,
    paths: Option<GlobSet>,
    methods: Option<Vec<Method>>,
}

impl Scope {
    /// Compile `config` for the guard named `what`, with `default` traffic
    /// when the config names none; `routed` are the methods the proxy's
    /// routes answer beyond the standard ones.
    ///
    /// # Errors
    /// A scope that covers no traffic, a path glob that is relative or does
    /// not compile, `*` or a method no request can carry (see
    /// [`scope_method`]).
    pub(crate) fn compile(
        config: Option<&ScopeConfig>,
        default: &[Traffic],
        what: &str,
        routed: Routed<'_>,
    ) -> Result<Arc<Self>, String> {
        let traffic = config.and_then(|c| c.traffic.as_deref()).unwrap_or(default);
        let classes = traffic.iter().fold(0, |acc, t| acc | traffic_bits(*t));
        if classes == 0 {
            return Err(format!("{what}.scope.traffic covers no traffic"));
        }
        let patterns = config.map(|c| c.paths.as_slice()).unwrap_or_default();
        let paths = if patterns.is_empty() {
            None
        } else {
            let mut set = GlobSetBuilder::new();
            for pattern in patterns {
                // Paths always start with `/`; a relative pattern is a typo
                // that would silently never match.
                if !pattern.starts_with('/') {
                    return Err(format!(
                        "{what}.scope.paths entry {pattern:?} must start with '/'"
                    ));
                }
                let glob = GlobBuilder::new(pattern)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| format!("{what}.scope.paths entry {pattern:?} is invalid: {e}"))?;
                set.add(glob);
            }
            Some(
                set.build()
                    .map_err(|e| format!("{what}.scope.paths: {e}"))?,
            )
        };
        let names = config.map(|c| c.methods.as_slice()).unwrap_or_default();
        let methods = if names.is_empty() {
            None
        } else {
            Some(
                names
                    .iter()
                    .map(|name| scope_method(name, what, classes, routed))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        };
        Ok(Arc::new(Self {
            classes,
            paths,
            methods,
        }))
    }

    fn covers(&self, class: Class) -> bool {
        self.classes & class.bit() != 0
    }

    fn narrows(&self) -> bool {
        self.paths.is_some() || self.methods.is_some()
    }

    /// Whether the guard applies to `request`, within a class it covers.
    fn matches<B>(&self, request: &http::Request<B>) -> bool {
        self.methods
            .as_ref()
            .is_none_or(|methods| methods.contains(request.method()))
            && self
                .paths
                .as_ref()
                .is_none_or(|paths| paths.is_match(request.uri().path()))
    }
}

/// The methods of RFC 9110 §9.3 and PATCH (RFC 5789).
const STANDARD_METHODS: [Method; 9] = [
    Method::GET,
    Method::HEAD,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::CONNECT,
    Method::OPTIONS,
    Method::TRACE,
    Method::PATCH,
];

/// The methods the proxy's routes answer beyond the standard ones.
#[derive(Clone, Copy)]
pub(crate) struct Routed<'a> {
    /// The methods routes name: `custom` rules, extra routes.
    methods: &'a [Method],
    /// The classes with a route answering every method.
    every: u8,
}

impl<'a> Routed<'a> {
    /// Routes that answer `methods`.
    pub(crate) fn new(methods: &'a [Method]) -> Self {
        Self { methods, every: 0 }
    }

    /// With a route of `class` that answers every method: a `custom` `*`
    /// rule, the verify endpoint. It answers only a scope covering its class.
    #[must_use]
    pub(crate) fn every(mut self, class: Class) -> Self {
        self.every |= class.bit();
        self
    }
}

/// One `scope.methods` entry of the guard `what`, whose scope covers
/// `classes`: a method some request can carry, or an error. A method no route
/// answers would match no request and leave the guard covering nothing,
/// unless the scope covers the fallback, whose methods are the embedder's.
fn scope_method(name: &str, what: &str, classes: u8, routed: Routed<'_>) -> Result<Method, String> {
    if name == "*" {
        return Err(format!(
            "{what}.scope.methods entry \"*\" is not a method: leave methods out to cover every one"
        ));
    }
    let method = Method::from_bytes(name.to_ascii_uppercase().as_bytes())
        .map_err(|_| format!("{what}.scope.methods entry {name:?} is not a method"))?;
    if classes & (FALLBACK | routed.every) != 0
        || STANDARD_METHODS.contains(&method)
        || routed.methods.contains(&method)
    {
        Ok(method)
    } else {
        Err(format!(
            "{what}.scope.methods entry {name:?} is neither a standard method nor one a route answers"
        ))
    }
}

/// A guard layer `L` applied only to the requests its scope's paths and
/// methods select; the others go straight to the inner service.
#[derive(Clone)]
struct Scoped<L> {
    layer: L,
    scope: Arc<Scope>,
}

impl<L: Layer<S>, S: Clone> Layer<S> for Scoped<L> {
    type Service = ScopedService<L::Service, S>;

    fn layer(&self, inner: S) -> Self::Service {
        ScopedService {
            guarded: self.layer.layer(inner.clone()),
            plain: inner,
            scope: self.scope.clone(),
        }
    }
}

#[derive(Clone)]
struct ScopedService<G, S> {
    guarded: G,
    plain: S,
    scope: Arc<Scope>,
}

impl<G, S> Service<Request> for ScopedService<G, S>
where
    G: Service<Request, Response = Response, Error = Infallible> + Clone,
    S: Service<Request, Response = Response, Error = Infallible> + Clone,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Either<Oneshot<G, Request>, Oneshot<S, Request>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        // Which branch serves a request is known only from the request, so
        // readiness is waited for per request, on the chosen branch's clone
        // (as axum's `Route` does): polling both here would hold a
        // reservation of the other one, such as a concurrency permit.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        if self.scope.matches(&request) {
            Either::Left(self.guarded.clone().oneshot(request))
        } else {
            Either::Right(self.plain.clone().oneshot(request))
        }
    }
}

/// A gRPC-path or fallback service with its guards around it.
pub(crate) type BoxedService = BoxCloneSyncService<Request, Response, Infallible>;

/// The guards the proxy runs, each with its scope, and the client-address
/// resolution that runs before all of them.
#[derive(Default)]
pub(crate) struct Guards {
    /// Shared with the resolution layers of the routes and the fallback.
    pub(crate) client_address: Arc<crate::client_address::Resolver>,
    /// `client_address.required`: the guard refusing a request whose address
    /// did not resolve, over every class.
    pub(crate) require_client: Option<Arc<Scope>>,
    pub(crate) maintenance: Option<(Arc<Maintenance>, Arc<Scope>)>,
    pub(crate) concurrency: Option<(Arc<Concurrency>, Arc<Scope>)>,
    pub(crate) shield: Option<(Arc<crate::shield::Shield>, Arc<Scope>)>,
    pub(crate) auth: Option<(Arc<crate::auth::Auth>, Arc<Scope>)>,
    pub(crate) authz: Option<(Arc<crate::auth::authz::Authz>, Arc<Scope>)>,
    pub(crate) decider: Option<(Arc<crate::embed::DeciderGate>, Arc<Scope>)>,
}

/// Put the guards that cover `$class` around `$target`, in pipeline order
/// (outermost first): a required client address, maintenance, concurrency,
/// rate limits before auth, JWT, rate limits after auth (keyed by verified
/// claims), ext_authz, the decider.
/// `$wrap` applies one layer to the target type at hand; a macro, since each
/// guard's layer is its own type.
macro_rules! guard_stack {
    ($guards:expr, $target:expr, $class:expr, $wrap:ident) => {{
        let guards: &Guards = $guards;
        let class: Class = $class;
        let mut target = $target;
        // Built inside out: the first layer added runs last.
        if class.authenticates() {
            if let Some((decider, scope)) = &guards.decider {
                target = $wrap!(
                    target,
                    class,
                    scope,
                    from_fn_with_state(decider.clone(), crate::embed::auth_decider_gate)
                );
            }
            if let Some((authz, scope)) = &guards.authz {
                target = $wrap!(
                    target,
                    class,
                    scope,
                    from_fn_with_state(authz.clone(), crate::auth::authz::middleware)
                );
            }
        }
        if class.authenticates() {
            // Keyed by claims only the JWT gate verifies.
            if let Some((shield, scope)) = guards
                .shield
                .as_ref()
                .filter(|(shield, _)| shield.enforces(crate::shield::matcher::Phase::PostAuth))
            {
                target = $wrap!(
                    target,
                    class,
                    scope,
                    from_fn_with_state(shield.clone(), crate::shield::post_auth_middleware)
                );
            }
            if let Some((auth, scope)) = &guards.auth {
                target = $wrap!(
                    target,
                    class,
                    scope,
                    from_fn_with_state(auth.clone(), crate::auth::middleware)
                );
            }
        }
        // A required client address, maintenance, concurrency and the rate
        // limits before auth decide as the request arrives: one layer.
        if let Some(gate) = gate::Gate::layer(guards, class) {
            target = $wrap!(@all target, gate);
        }
        target
    }};
}

/// One guard layer on a router, when its scope covers the class; with `@all`,
/// a layer that applies its scopes itself.
macro_rules! wrap_router {
    (@all $target:expr, $layer:expr) => {
        $target.layer($layer)
    };
    ($target:expr, $class:expr, $scope:expr, $layer:expr) => {{
        let scope: &Arc<Scope> = $scope;
        if !scope.covers($class) {
            $target
        } else if scope.narrows() {
            $target.layer(Scoped {
                layer: $layer,
                scope: scope.clone(),
            })
        } else {
            $target.layer($layer)
        }
    }};
}

/// One guard layer on a boxed service, when its scope covers the class; with
/// `@all`, a layer that applies its scopes itself.
macro_rules! wrap_service {
    (@all $target:expr, $layer:expr) => {
        BoxedService::new($layer.layer($target))
    };
    ($target:expr, $class:expr, $scope:expr, $layer:expr) => {{
        let scope: &Arc<Scope> = $scope;
        let target: BoxedService = $target;
        if !scope.covers($class) {
            target
        } else if scope.narrows() {
            BoxedService::new(
                Scoped {
                    layer: $layer,
                    scope: scope.clone(),
                }
                .layer(target),
            )
        } else {
            BoxedService::new($layer.layer(target))
        }
    }};
}

impl Guards {
    /// Whether any guard covers `class`.
    pub(crate) fn cover(&self, class: Class) -> bool {
        fn on<T>(guard: &Option<(T, Arc<Scope>)>, class: Class) -> bool {
            guard.as_ref().is_some_and(|(_, scope)| scope.covers(class))
        }
        self.require_client
            .as_ref()
            .is_some_and(|scope| scope.covers(class))
            || on(&self.maintenance, class)
            || on(&self.concurrency, class)
            || on(&self.shield, class)
            || (class.authenticates()
                && (on(&self.auth, class) || on(&self.authz, class) || on(&self.decider, class)))
    }

    /// `router`, all of class `class`, behind the guards that cover it.
    pub(crate) fn router<S>(&self, router: Router<S>, class: Class) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        guard_stack!(self, router, class, wrap_router)
    }

    /// `service`, of class `class`, behind the guards that cover it.
    pub(crate) fn service(&self, service: BoxedService, class: Class) -> BoxedService {
        guard_stack!(self, service, class, wrap_service)
    }
}

/// Maintenance mode: every request outside the exempt paths gets a `503`.
#[derive(Debug)]
pub(crate) struct Maintenance {
    pub(crate) exempt: Vec<String>,
    pub(crate) message: String,
}

impl Maintenance {
    /// Whether `path` stays reachable: an exact exempt path, or `prefix` and
    /// what lies below it for a `prefix/**` one (a sibling that only shares
    /// the prefix, `/healthz` for `/health/**`, does not).
    pub(crate) fn exempts(&self, path: &str) -> bool {
        self.exempt
            .iter()
            .any(|pattern| match pattern.strip_suffix("/**") {
                Some(prefix) => path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with('/')),
                None => path == pattern,
            })
    }
}

#[cfg(test)]
mod tests;
