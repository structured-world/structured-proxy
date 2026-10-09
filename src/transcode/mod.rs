//! REST→gRPC transcoding layer.
//!
//! Reads `google.api.http` annotations from proto service descriptors
//! and builds axum routes that proxy JSON/form requests to gRPC upstream.
//! The upstream decides the HTTP answer beyond the JSON body where it needs
//! to: its response metadata becomes response headers, `x-http-code` sets the
//! status of a successful unary call, and `google.api.HttpBody` carries a raw
//! body in either direction.
//!
//! Generic: works with ANY proto descriptor set. No product-specific code.

pub mod body;
pub mod codec;
pub mod error;
pub(crate) mod httpbody;
pub mod metadata;
pub(crate) mod path;
pub mod request;
pub(crate) mod response;
pub(crate) mod rule;
mod select;
mod table;

pub use path::proto_path_to_axum;
pub use select::RpcSelection;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, FromRequestParts, OriginalUri, RawPathParams, Request, State};
use axum::http::header::{ALLOW, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Router;
use futures::{StreamExt, TryStreamExt};
use prost_reflect::{
    DescriptorPool, DynamicMessage, FieldDescriptor, MessageDescriptor, MethodDescriptor,
    SerializeOptions,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tonic::client::Grpc;
use tonic::metadata::MetadataMap;

use crate::client_address::ClientAddress;
use crate::config::AliasConfig;
use crate::guard::BoxedService;
use crate::received::ReceivedRequest;
use crate::service::ConnectionInfo;
use crate::upstream::Upstream;
use error::{ErrorDetailsPolicy, StatusDetails};
use path::MountedPath;
use response::UpstreamHeaders;
use rule::RouteMethod;
use table::{Choice, PathTable, Routes};

/// How long the upstream may take to answer a call with its response headers
/// when the client's `grpc-timeout` asks for no shorter deadline.
pub const UPSTREAM_DEADLINE: Duration = Duration::from_secs(5);

/// Trait for state types that support REST→gRPC transcoding.
///
/// Implement this for your application's state type to use `transcode::routes()`.
/// Provides the minimal interface needed by transcode handlers. Each request
/// works on its own clone of the state, so a clone should be cheap.
pub trait TranscodeState: Clone + Send + Sync + 'static {
    /// The gRPC service transcoded calls go to.
    type Upstream: Upstream;
    /// The upstream, taken out of this request's clone of the state.
    fn into_upstream(self) -> Self::Upstream;
    /// Headers to forward from HTTP to gRPC metadata.
    fn forwarded_headers(&self) -> &[String];
    /// [`forwarded_headers`](Self::forwarded_headers) as header names, when
    /// the state holds them parsed: a request then skips parsing each name.
    /// `None` by default.
    fn forwarded_header_names(&self) -> Option<&[HeaderName]> {
        None
    }
    /// SSE keep-alive interval (seconds) for server-streaming responses.
    fn sse_keep_alive_secs(&self) -> u64;
}

impl<U: Upstream> TranscodeState for crate::ProxyState<U> {
    type Upstream = U;
    fn into_upstream(self) -> U {
        self.upstream
    }
    fn forwarded_headers(&self) -> &[String] {
        &self.forwarded_headers
    }
    fn forwarded_header_names(&self) -> Option<&[HeaderName]> {
        Some(&self.forwarded_names)
    }
    fn sse_keep_alive_secs(&self) -> u64 {
        self.sse_keep_alive_secs
    }
}

/// Path parameters of a matched route, in path order: each name with its
/// value, borrowed from the router's captures and the routes wherever the
/// binding leaves them as they are.
type PathParams<'a> = Vec<(&'a str, Cow<'a, str>)>;

/// How the HTTP request body reaches the RPC's input message.
#[derive(Debug, Clone)]
enum RequestBody {
    /// JSON or a form, mapped as the rule's `body` says.
    Parsed(request::BodyMapping),
    /// Raw bytes and `Content-Type` into the input message, a `google.api.HttpBody`.
    RawRoot,
    /// Raw bytes and `Content-Type` into the HttpBody field `body` names; the
    /// other fields still come from path and query.
    RawField {
        /// The rule's `body` mapping, which keeps the field out of query binding.
        mapping: request::BodyMapping,
        field: FieldDescriptor,
        /// The field's type, a `google.api.HttpBody`.
        http_body: MessageDescriptor,
    },
}

/// What the HTTP response body is made of.
#[derive(Debug, Clone)]
enum ResponseShape {
    /// ProtoJSON of the response message, or of its `response_body` subfield.
    Json(Option<String>),
    /// The raw body of a `google.api.HttpBody`: the response message itself
    /// (empty path) or the field chain `response_body` names.
    HttpBody(Vec<FieldDescriptor>),
}

/// Route entry extracted from proto HTTP annotations.
#[derive(Debug, Clone)]
struct RouteEntry {
    /// HTTP path pattern (e.g., "/v1/auth/opaque/login/start").
    http_path: String,
    /// The HTTP method(s) the binding answers.
    http_method: RouteMethod,
    /// gRPC path (e.g., "/sid.v1.AuthService/OpaqueLoginStart"), parsed once at
    /// route-build time so each request clones a cheap `Bytes` refcount.
    grpc_path: axum::http::uri::PathAndQuery,
    /// Method descriptor for input/output message resolution.
    method: MethodDescriptor,
    /// Server-streaming RPC (NDJSON / SSE, or chunked HttpBody).
    streaming: bool,
    /// How the request body maps onto the gRPC request message.
    request_body: RequestBody,
    /// What the HTTP response body is made of.
    response: ResponseShape,
    /// Renderer for the status details of this route's errors; `None` when the
    /// error-details policy switches them off for the route.
    error_details: Option<Arc<StatusDetails>>,
    /// Wrap NDJSON stream lines in `{"result"}` / `{"error"}` envelopes.
    ndjson_envelope: bool,
    /// [`codec::has_required_fields`] of the response type, computed once so a
    /// request does not walk the descriptor.
    response_has_required: bool,
    /// Response metadata keys the operator keeps off the HTTP response, on top
    /// of the ones that never go there.
    denied_headers: Arc<[HeaderName]>,
}

impl RouteEntry {
    fn codec(&self) -> codec::DynamicCodec {
        codec::DynamicCodec::with_required_check(self.method.output(), self.response_has_required)
    }

    /// The raw body of `message`, on a route that answers with an HttpBody.
    fn raw_body(&self, message: DynamicMessage) -> Option<httpbody::RawBody> {
        match &self.response {
            ResponseShape::HttpBody(path) => Some(httpbody::take(message, path)),
            ResponseShape::Json(_) => None,
        }
    }
}

/// How [`routes_with_options`] builds the transcoded routes.
///
/// # Examples
///
/// ```
/// use axum::http::HeaderName;
/// use structured_proxy::transcode::error::ErrorDetailsPolicy;
/// use structured_proxy::transcode::TranscodeOptions;
///
/// let options = TranscodeOptions::default()
///     .with_error_details(ErrorDetailsPolicy::default().route("/v1/admin/**", false).unwrap())
///     .with_ndjson_envelope(true)
///     .with_denied_response_headers([HeaderName::from_static("x-debug-trace")]);
/// # let _ = options;
/// ```
#[derive(Debug, Clone, Default)]
pub struct TranscodeOptions {
    pub(crate) error_details: ErrorDetailsPolicy,
    pub(crate) ndjson_envelope: bool,
    pub(crate) denied_response_headers: Arc<[HeaderName]>,
    pub(crate) selection: RpcSelection,
}

impl TranscodeOptions {
    /// Transcode only the RPCs `selection` names (every annotated one by
    /// default).
    pub fn with_selection(mut self, selection: RpcSelection) -> Self {
        self.selection = selection;
        self
    }

    /// Which routes return `google.rpc.Status` details in their error bodies
    /// (all of them by default).
    pub fn with_error_details(mut self, policy: ErrorDetailsPolicy) -> Self {
        self.error_details = policy;
        self
    }

    /// Wrap every NDJSON line of a server-streaming response in an envelope:
    /// `{"result": <message>}` for data, `{"error": <error body>}` for the
    /// terminal error (the grpc-gateway stream shape). Off by default, when a
    /// data line is the bare message and the error line carries an
    /// `@type: google.rpc.Status` marker instead. Only the envelope keeps the
    /// two apart for RPCs that stream `google.protobuf.Any`, `Struct`, `Value`
    /// or `ListValue`, whose messages can carry any keys. SSE is unaffected.
    pub fn with_ndjson_envelope(mut self, enabled: bool) -> Self {
        self.ndjson_envelope = enabled;
        self
    }

    /// Response metadata keys that never become HTTP response headers, on top
    /// of gRPC's own keys, hop-by-hop fields and `x-http-code`, which never do.
    /// Replaces any list set before. Use it to keep internal headers (debug
    /// traces, backend names) off a public edge; an upstream key not listed
    /// here reaches the client.
    pub fn with_denied_response_headers(
        mut self,
        names: impl IntoIterator<Item = HeaderName>,
    ) -> Self {
        self.denied_response_headers = names.into_iter().collect();
        self
    }
}

/// Build transcoded REST→gRPC routes from a descriptor pool.
///
/// Takes a `DescriptorPool` and optional path aliases from config.
/// Returns an axum Router that transcodes REST requests to gRPC calls. Error
/// bodies carry `google.rpc.Status` details on every route; use
/// [`routes_with_options`] to choose per route or to frame NDJSON streams.
pub fn routes<S: TranscodeState>(pool: &DescriptorPool, aliases: &[AliasConfig]) -> Router<S> {
    routes_with_options(pool, aliases, &TranscodeOptions::default())
}

/// [`routes`], built as `options` describe.
///
/// A binding answers the requests whose path matches its template, custom verb
/// included (`/v1/{name}:cancel`, google/api/http.proto `Verb`), and whose
/// method is its own; a GET binding answers HEAD too. A request's verb is its
/// last segment from the first unencoded `:`: a verb some binding of its path
/// binds owns the URL, answered by that verb's bindings alone; a verb none
/// binds stays part of the last variable. A URL that bindings answer, but none
/// with the request's method, is `405` with their methods in `Allow`; a path
/// that matches a template but that no binding answers is `404`.
///
/// A second binding for a method, path and verb already taken (or any binding
/// on a path and verb a `custom` `*` rule takes, which answers every method),
/// and a template the router cannot match (text around a variable within one
/// segment, a path that does not start with `/`), are skipped with an error in
/// the log.
pub fn routes_with_options<S: TranscodeState>(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    options: &TranscodeOptions,
) -> Router<S> {
    routes_and_choices(pool, aliases, options).0
}

/// The routes of [`routes_with_options`], with the [`Choices`] among their
/// bindings that the caller makes before its own layers.
pub(crate) fn routes_and_choices<S: TranscodeState>(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    options: &TranscodeOptions,
) -> (Router<S>, Option<Choices>) {
    let tables = path_tables(pool, aliases, options);
    if tables.is_empty() {
        tracing::warn!("No HTTP-annotated RPCs found in proto descriptors");
        return (Router::new(), None);
    }

    let routes = Arc::new(Routes::new(tables));
    let choices = Choices {
        routes: routes.clone(),
        ranked: None,
    };
    let mut router: Router<S> = Router::new();
    for (table, mounted) in routes.tables.iter().enumerate() {
        let routes = routes.clone();
        // Every method goes to the routes, which answer 405 themselves: the
        // URL, not the path alone, decides which methods a path answers. A
        // HEAD a GET binding serves still goes out without a body: axum's
        // route future empties the body of every HEAD response, `any` routes
        // included.
        let handler =
            move |State(state): State<S>, request: Request| dispatch(routes, table, state, request);
        let mut route = axum::routing::any(handler.clone());
        // A binding answering HEAD itself is the path's HEAD route, before
        // the GET of another route merged at the path answers HEAD.
        if mounted.binds_head() {
            route = route.head(handler);
        }
        router = router.route(&mounted.path, route);
    }
    (router, Some(choices))
}

/// The choice of the binding a request reaches among the transcoded routes,
/// made before any layer of the routes runs. A URL no binding answers (its
/// field template, its custom verb) is no transcoded request: it goes to the
/// proxy's other routes instead.
pub(crate) struct Choices {
    routes: Arc<Routes>,
    /// The transcoded paths among the proxy's other routes, when known.
    ranked: Option<Arc<table::Ranked>>,
}

impl Choices {
    /// These choices among `others`: the router paths of the proxy's other
    /// routes, each with the method it answers (`None`: every one). A table
    /// answers a request a better-ranked one refused only when no other
    /// route ranks before it. Ranked among none of them when an other path
    /// is one the proxy cannot rank as the router does.
    pub(crate) fn among(mut self, others: &[(Option<Method>, String)]) -> Self {
        self.ranked = table::Ranked::new(&self.routes, others).map(Arc::new);
        self
    }

    /// These choices, handing a URL no binding answers to `elsewhere`: a
    /// router of the proxy's other routes.
    pub(crate) fn with_elsewhere(self, elsewhere: Router) -> Chooser {
        Chooser(Arc::new(Choosing {
            routes: self.routes,
            ranked: self.ranked,
            elsewhere,
        }))
    }

    /// The transcoded routes served past any router, calling with `state`;
    /// `layered` puts the layers of the transcoded routes around them.
    /// `None` without a ranking among the other routes.
    pub(crate) fn direct<S: TranscodeState>(
        &self,
        state: S,
        layered: impl FnOnce(BoxedService) -> BoxedService,
    ) -> Option<Direct> {
        let ranked = self.ranked.clone()?;
        let dispatcher = BoxedService::new(Dispatcher {
            routes: self.routes.clone(),
            state,
        });
        Some(Direct {
            ranking: Arc::new(Ranking {
                ranked,
                routes: self.routes.clone(),
            }),
            service: layered(dispatcher),
        })
    }
}

/// The transcoded routes served straight from the proxy's own match of a
/// request's path, past any router.
#[derive(Clone)]
pub(crate) struct Direct {
    ranking: Arc<Ranking>,
    /// The routes behind their layers.
    service: BoxedService,
}

struct Ranking {
    ranked: Arc<table::Ranked>,
    routes: Arc<Routes>,
}

impl Direct {
    /// Whether `request` is one of the transcoded routes', whose binding
    /// then rides on it: its path's best match among every route of the
    /// proxy is a transcoded path, the method not another route's there, and
    /// a binding answers the URL. A request for none goes to the other
    /// routes, which a fallback follows, as if the transcoded ones were not
    /// there.
    pub(crate) fn takes<B>(&self, request: &mut http::Request<B>) -> bool {
        let ranking = &*self.ranking;
        match ranking.ranked.table(request.method(), request.uri().path()) {
            Some(table) => choose(&ranking.routes, Some(&ranking.ranked), table, request),
            None => false,
        }
    }

    /// The routes behind their layers, for a request [`takes`](Self::takes)
    /// took.
    pub(crate) fn service(&self) -> &BoxedService {
        &self.service
    }
}

/// The transcoded routes as one service, for requests whose binding rides on
/// them.
#[derive(Clone)]
struct Dispatcher<S> {
    routes: Arc<Routes>,
    state: S,
}

impl<S: TranscodeState> tower::Service<Request> for Dispatcher<S> {
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Response, std::convert::Infallible>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request) -> Self::Future {
        let routes = self.routes.clone();
        let state = self.state.clone();
        Box::pin(async move { Ok(serve(routes, state, request).await) })
    }
}

/// Choose among `routes` for `request`, which the router matches (or
/// matched) to the table at `table`, ranked among the proxy's other routes
/// by `ranked` when known: `false` when no binding answers it, otherwise the
/// choice rides on the request to [`dispatch`].
fn choose<B>(
    routes: &Routes,
    ranked: Option<&table::Ranked>,
    table: usize,
    request: &mut http::Request<B>,
) -> bool {
    let (method, path) = (request.method(), request.uri().path());
    let choice = match ranked {
        Some(ranked) => match routes.choose_ranked(table, method, path, &|other| {
            ranked.ranks_first(other, method, path)
        }) {
            // The other routes at the path answer methods too.
            Choice::MethodNotAllowed(allow) => Choice::MethodNotAllowed(ranked.allow(table, allow)),
            choice => choice,
        },
        None => routes.choose(table, method, path),
    };
    match choice {
        Choice::NotFound => false,
        choice => {
            request.extensions_mut().insert(Chosen(choice));
            true
        }
    }
}

/// [`Choices`] with the routes a URL no binding answers goes to. One
/// reference count: the router clones its routes' layers for every request.
#[derive(Clone)]
pub(crate) struct Chooser(Arc<Choosing>);

struct Choosing {
    routes: Arc<Routes>,
    ranked: Option<Arc<table::Ranked>>,
    elsewhere: Router,
}

impl Chooser {
    /// The other routes, with `fallback` answering what they do not.
    pub(crate) fn with_fallback(self, fallback: BoxedService) -> Self {
        Self(Arc::new(Choosing {
            routes: self.0.routes.clone(),
            ranked: self.0.ranked.clone(),
            elsewhere: self.0.elsewhere.clone().fallback_service(fallback),
        }))
    }

    /// `router`, holding the transcoded routes, choosing outside its layers
    /// for a router that is served on its own, merged or nested: the request
    /// is past the routing then, and the router reports the route it matched
    /// with the paths it is nested at in front.
    pub(crate) fn layer(self, router: Router) -> Router {
        router.layer(self)
    }
}

impl<S> tower::Layer<S> for Chooser {
    type Service = ChooseRouted<S>;

    fn layer(&self, route: S) -> ChooseRouted<S> {
        ChooseRouted {
            chooser: self.clone(),
            route,
        }
    }
}

/// A transcoded route, with the choice among its bindings made before its
/// layers: a request no binding answers goes to the other routes.
#[derive(Clone)]
pub(crate) struct ChooseRouted<S> {
    chooser: Chooser,
    route: S,
}

impl<S> tower::Service<Request> for ChooseRouted<S>
where
    S: tower::Service<Request, Response = Response, Error = std::convert::Infallible>,
{
    type Response = Response;
    type Error = std::convert::Infallible;
    type Future = ChooseFuture<S::Future>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.route.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let choosing = &*self.chooser.0;
        let extensions = request.extensions();
        let matched = extensions
            .get::<axum::extract::MatchedPath>()
            .and_then(|matched| {
                let nested = extensions.get::<axum::extract::NestedPath>();
                local_path(matched.as_str(), nested.map(|nested| nested.as_str()))
            })
            .and_then(|path| choosing.routes.table_at(path));
        let ranked = choosing.ranked.as_deref();
        if matched.is_none_or(|matched| choose(&choosing.routes, ranked, matched, &mut request)) {
            return ChooseFuture::Route {
                future: self.route.call(request),
            };
        }
        // The other routes route it again: the route the first routing
        // matched goes, so theirs is reported. Its captures stay, unread: no
        // other route of the proxy takes path parameters, and an extra
        // route's handler sees no extensions. Routes an application merged
        // after the proxy's are not among them: the router has routed the
        // request to this route and tries no other, so they are reached only
        // as extra routes, or behind a proxy service's fallback.
        request
            .extensions_mut()
            .remove::<axum::extract::MatchedPath>();
        ChooseFuture::Elsewhere {
            future: tower::ServiceExt::oneshot(choosing.elsewhere.clone(), request),
        }
    }
}

pin_project_lite::pin_project! {
    /// The response future of [`ChooseRouted`].
    #[project = ChooseProjection]
    pub(crate) enum ChooseFuture<F> {
        Route { #[pin] future: F },
        Elsewhere { #[pin] future: tower::util::Oneshot<Router, Request> },
    }
}

impl<F> std::future::Future for ChooseFuture<F>
where
    F: std::future::Future<Output = Result<Response, std::convert::Infallible>>,
{
    type Output = Result<Response, std::convert::Infallible>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.project() {
            ChooseProjection::Route { future } => future.poll(cx),
            ChooseProjection::Elsewhere { future } => future.poll(cx),
        }
    }
}

/// The binding chosen for a request before the layers of the routes, for
/// [`dispatch`].
#[derive(Clone)]
struct Chosen(Choice);

/// The router path `matched` names in the router nested at `nested`, which
/// writes the paths it is nested at in front of it.
fn local_path<'p>(matched: &'p str, nested: Option<&str>) -> Option<&'p str> {
    let Some(nested) = nested else {
        return Some(matched);
    };
    // A prefix ending in `/` is joined to the path without its leading `/`,
    // and a path of `/` alone is the prefix itself (axum's nesting).
    let local = matched.strip_prefix(nested.trim_end_matches('/'))?;
    Some(if local.is_empty() { "/" } else { local })
}

/// The tables [`routes_with_options`] mounts, one per router path, each
/// holding every binding of that path in binding order.
fn path_tables(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    options: &TranscodeOptions,
) -> Vec<PathTable> {
    let bindings = route_bindings(pool, aliases, &options.selection, true);
    tracing::info!("Registering {} transcoded REST→gRPC routes", bindings.len());

    // At most two renderers, without and with the opaque-detail extension,
    // each shared by every route that uses it and built only when one does.
    // The second is a copy of the first: the descriptor pool inside is shared.
    let mut status_details: [Option<Arc<StatusDetails>>; 2] = [None, None];
    // The router tells paths apart by shape only, so every binding of one
    // shape goes into one table, whatever its capture names.
    let mut tables: Vec<PathTable> = Vec::new();
    let mut by_shape: HashMap<String, usize> = HashMap::new();
    for mut binding in bindings {
        let policy = &options.error_details;
        let route = binding.mount.display();
        if policy.enabled_for(&route) {
            let opaque = policy.opaque_for(&route);
            let slot = usize::from(opaque);
            if status_details[slot].is_none() {
                let base = status_details
                    .iter()
                    .flatten()
                    .next()
                    .map(|existing| existing.as_ref().clone())
                    .unwrap_or_else(|| StatusDetails::new(pool));
                status_details[slot] = Some(Arc::new(base.with_opaque_details(opaque)));
            }
            binding.entry.error_details = status_details[slot].clone();
        }
        binding.entry.ndjson_envelope = options.ndjson_envelope;
        binding.entry.denied_headers = options.denied_response_headers.clone();
        match by_shape.get(&binding.mount.shape) {
            Some(&index) => tables[index].add(binding.mount, binding.entry),
            None => {
                by_shape.insert(binding.mount.shape.clone(), tables.len());
                tables.push(PathTable::new(binding.mount, binding.entry));
            }
        }
    }

    retain_mountable(
        &mut tables,
        |table| table.path.as_str(),
        |path, error| {
            tracing::error!(
                path = %path,
                %error,
                "transcoded route conflicts with another; skipping its bindings"
            );
        },
    );
    tables
}

/// Keep the items whose router path a router holding the ones kept before
/// accepts, in order; `refused` hears of each left out. axum would panic on
/// such a path, and matchit is the router axum matches with.
fn retain_mountable<T>(
    items: &mut Vec<T>,
    path: impl Fn(&T) -> &str,
    mut refused: impl FnMut(&str, matchit::InsertError),
) {
    let mut router = matchit::Router::new();
    items.retain(|item| match router.insert(path(item), ()) {
        Ok(()) => true,
        Err(error) => {
            refused(path(item), error);
            false
        }
    });
}

/// The shapes of the router paths [`routes_with_options`] mounts for
/// `selection`: what the OpenAPI document may promise.
pub(crate) fn mounted_shapes(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    selection: &RpcSelection,
) -> std::collections::HashSet<String> {
    // One path per shape, the first binding's, as the tables are built.
    let mut seen = std::collections::HashSet::new();
    let mut paths: Vec<MountedPath> = route_bindings(pool, aliases, selection, false)
        .into_iter()
        .filter_map(|binding| {
            seen.insert(binding.mount.shape.clone())
                .then_some(binding.mount)
        })
        .collect();
    retain_mountable(&mut paths, |mount| mount.axum.as_str(), |_, _| {});
    paths.into_iter().map(|mount| mount.shape).collect()
}

/// Serve `request`, which the router matched to the table at `matched`:
/// choose the binding before anything is extracted, so a request no binding
/// answers gets its 404 or 405 without its body being read.
async fn dispatch<S: TranscodeState>(
    routes: Arc<Routes>,
    matched: usize,
    state: S,
    request: Request,
) -> Response {
    let (mut parts, body) = request.into_parts();
    let choice = match parts.extensions.remove::<Chosen>() {
        Some(Chosen(choice)) => choice,
        None => routes.choose(matched, &parts.method, parts.uri.path()),
    };
    let (table, index) = match choice {
        Choice::Route { table, index } => (table, index),
        Choice::MethodNotAllowed(allow) => {
            return (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, allow)]).into_response()
        }
        // Only routes served without a `Chooser` get here.
        Choice::NotFound => return StatusCode::NOT_FOUND.into_response(),
    };
    // The router's captures, decoded, shared with it rather than copied.
    let captured = match RawPathParams::from_request_parts(&mut parts, &state).await {
        Ok(captured) => captured,
        Err(rejection) => return rejection.into_response(),
    };
    let mut path_params: PathParams<'_> = captured
        .iter()
        .map(|(name, value)| (name, Cow::Borrowed(value)))
        .collect();
    let multi_segment = routes.tables[table].multi_segment(index);
    // The path the router matched, kept past the parts going on with the
    // body when the captures are read from it.
    let local;
    if table != matched || !multi_segment.is_empty() {
        // Another path the request matches answers it (a verb bound there, or
        // the only bindings without a verb), or a variable over several
        // segments keeps `%2F` the router decoded: the captures come from the
        // request's path, the router's prefix parameters stay.
        local = parts.uri.clone();
        let captures = &routes.tables[matched].captures;
        path_params.retain(|(name, _)| !captures.iter().any(|capture| capture == name));
        if let Err(rejection) = capture(
            &routes,
            table,
            multi_segment,
            local.path(),
            &mut path_params,
        ) {
            return rejection.into_response(routes.tables[table].entry(index));
        }
    }
    // The target as received, before a router the proxy is nested in strips
    // its prefix; the router records it on every request it routes.
    let uri = match parts.extensions.remove::<OriginalUri>() {
        Some(OriginalUri(uri)) => uri,
        None => parts.uri.clone(),
    };
    let begun = begin(
        &routes,
        (table, index),
        &state,
        (parts, body),
        path_params,
        uri,
    )
    .await;
    serve_begun(begun, routes, table, index).await
}

/// Serve `request`, which the proxy matched to a transcoded binding itself,
/// with no router: the choice rides on it.
async fn serve<S: TranscodeState>(routes: Arc<Routes>, state: S, request: Request) -> Response {
    let (mut parts, body) = request.into_parts();
    let head = parts.method == Method::HEAD;
    let choice = match parts.extensions.remove::<Chosen>() {
        Some(Chosen(choice)) => choice,
        None => Choice::NotFound,
    };
    let mut response = match choice {
        Choice::Route { table, index } => {
            // The path the proxy matched, what the captures are read from.
            let local = parts.uri.clone();
            // The target as received, before a router the proxy is nested in
            // strips its prefix.
            let uri = match parts.extensions.remove::<OriginalUri>() {
                Some(OriginalUri(uri)) => uri,
                None => local.clone(),
            };
            let multi_segment = routes.tables[table].multi_segment(index);
            let mut path_params = Vec::with_capacity(routes.tables[table].captures.len());
            match capture(
                &routes,
                table,
                multi_segment,
                local.path(),
                &mut path_params,
            ) {
                Ok(()) => {
                    let begun = begin(
                        &routes,
                        (table, index),
                        &state,
                        (parts, body),
                        path_params,
                        uri,
                    )
                    .await;
                    serve_begun(begun, routes, table, index).await
                }
                Err(rejection) => rejection.into_response(routes.tables[table].entry(index)),
            }
        }
        Choice::MethodNotAllowed(allow) => {
            (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, allow)]).into_response()
        }
        Choice::NotFound => StatusCode::NOT_FOUND.into_response(),
    };
    // As a router's route answers: the length of a body whose size is known,
    // and none sent for a HEAD. Not on a 204, which has no Content-Length, nor
    // on a 304, whose length could only describe the selected representation
    // (RFC 9110 §8.6), never the empty body sent.
    let status = response.status();
    if status != StatusCode::NO_CONTENT
        && status != StatusCode::NOT_MODIFIED
        && !response
            .headers()
            .contains_key(http::header::CONTENT_LENGTH)
    {
        if let Some(length) = http_body::Body::size_hint(response.body()).exact() {
            response
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, HeaderValue::from(length));
        }
    }
    if head {
        *response.body_mut() = axum::body::Body::empty();
    }
    response
}

/// How far [`begin`] got: the upstream call to make, or the answer already.
enum Begun<U> {
    Call {
        call: Call<U>,
        sse: bool,
        keep_alive_secs: u64,
    },
    Answered(Response),
}

/// Bind the request of `parts` and `body` to the binding at `binding` (table,
/// index) with its path parameters `path_params`, its target as received
/// `uri`: read its body and map it onto the RPC.
async fn begin<S: TranscodeState>(
    routes: &Routes,
    (table, index): (usize, usize),
    state: &S,
    (mut parts, body): (http::request::Parts, axum::body::Body),
    mut path_params: PathParams<'_>,
    uri: Uri,
) -> Begun<S::Upstream> {
    routes.tables[table].bind_params(index, &mut path_params);
    // Taken rather than copied: reading the body needs only its limit, which
    // stays in the extensions.
    let client = Client {
        headers: std::mem::take(&mut parts.headers),
        origin: Origin {
            connection: parts.extensions.remove::<ConnectionInfo>(),
            address: parts.extensions.remove::<ClientAddress>(),
        },
        line: RequestLine {
            method: std::mem::replace(&mut parts.method, Method::GET),
            uri,
        },
    };
    let body = match Bytes::from_request(Request::from_parts(parts, body), state).await {
        Ok(body) => body,
        Err(rejection) => return Begun::Answered(rejection.into_response()),
    };
    let entry = routes.tables[table].entry(index);
    match start(state.clone(), client, &path_params, body, entry) {
        Ok((call, sse, keep_alive_secs)) => Begun::Call {
            call,
            sse,
            keep_alive_secs,
        },
        Err(rejection) => Begun::Answered(rejection.into_response(entry)),
    }
}

/// Make the call [`begin`] got to, the parameters bound: the routes go on
/// with it.
async fn serve_begun<U: crate::upstream::Upstream>(
    begun: Begun<U>,
    routes: Arc<Routes>,
    table: usize,
    index: usize,
) -> Response {
    let (call, sse, keep_alive_secs) = match begun {
        Begun::Call {
            call,
            sse,
            keep_alive_secs,
        } => (call, sse, keep_alive_secs),
        Begun::Answered(response) => return response,
    };
    let entry = RouteRef {
        routes,
        table,
        index,
    };
    if entry.streaming {
        streaming_call(call, entry, sse, keep_alive_secs).await
    } else {
        unary_call(call, &entry).await
    }
}

/// Add the captures of the table at `table` matching `path` to `params`,
/// percent-decoded as the router decodes its own except at the positions of
/// `multi_segment`, which keep `%2F`; borrowed from `path` where nothing is
/// decoded.
fn capture<'p>(
    routes: &'p Routes,
    table: usize,
    multi_segment: &[usize],
    path: &'p str,
    params: &mut PathParams<'p>,
) -> Result<(), Unmappable> {
    let found = routes
        .params_of(table, path)
        .expect("the chosen table was found by matching this path");
    for (position, (name, raw)) in found.iter().enumerate() {
        let decoded: Cow<'p, [u8]> = if multi_segment.contains(&position) {
            path::decode_multi_segment(raw)
        } else {
            percent_encoding::percent_decode_str(raw).into()
        };
        let not_utf8 = || Unmappable(format!("path parameter {name} is not valid UTF-8"));
        let value = match decoded {
            Cow::Borrowed(bytes) => {
                Cow::Borrowed(std::str::from_utf8(bytes).map_err(|_| not_utf8())?)
            }
            Cow::Owned(bytes) => Cow::Owned(String::from_utf8(bytes).map_err(|_| not_utf8())?),
        };
        params.push((name, value));
    }
    Ok(())
}

/// The binding serving a request, held through the routes: they are already
/// shared with the request, so naming the binding takes no refcount of its
/// own.
#[derive(Clone)]
struct RouteRef {
    routes: Arc<Routes>,
    table: usize,
    index: usize,
}

impl std::ops::Deref for RouteRef {
    type Target = RouteEntry;

    fn deref(&self) -> &RouteEntry {
        self.routes.tables[self.table].entry(self.index)
    }
}

/// One transcode route to mount: the RPC entry that serves it and where it is
/// mounted.
struct RouteBinding {
    entry: RouteEntry,
    mount: MountedPath,
}

impl RouteBinding {
    fn claim(&self) -> table::Claim<'_> {
        table::Claim {
            method: &self.entry.http_method,
            verb: self.mount.verb.as_deref(),
            template: self.mount.last_template.as_deref(),
            literals: &self.mount.literals,
        }
    }
}

/// The single source of truth for what [`routes`] mounts: every binding of
/// every unary and server-streaming RPC, plus its config aliases, less the
/// templates the router cannot match. Both [`routes`] (to build handlers) and
/// [`route_paths`] (to enumerate paths for collision checks) consume this, so
/// the mounted set and the enumerated set cannot drift apart. A template left
/// out is logged when `report` is set.
fn route_bindings(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    selection: &RpcSelection,
    report: bool,
) -> Vec<RouteBinding> {
    let mut bindings = Vec::new();
    let mut push = |mount: MountedPath, entry: RouteEntry| match mount.routable() {
        Ok(()) => bindings.push(RouteBinding { entry, mount }),
        Err(_) if !report => {}
        Err(error) => tracing::error!(
            path = %mount.display(),
            rpc = %entry.grpc_path,
            %error,
            "google.api.http path template cannot be routed; skipping this binding"
        ),
    };
    for entry in extract_routes(pool, selection) {
        for alias in aliases {
            if let Some(suffix) = entry.http_path.strip_prefix(&alias.to) {
                if alias.from.ends_with("/{path}") {
                    let prefix = alias.from.trim_end_matches("/{path}");
                    push(
                        MountedPath::new(&format!("{prefix}{suffix}")),
                        entry.clone(),
                    );
                }
            }
        }
        push(MountedPath::new(&entry.http_path), entry);
    }
    bindings
}

/// The axum paths [`routes_with_options`] would register for this pool,
/// aliases and selection.
///
/// Mirrors the registration (every binding of every selected unary and
/// server-streaming RPC, and their config aliases) without building handlers,
/// so callers can detect route collisions before mounting additional routes
/// (e.g. a forward-auth endpoint).
///
/// Each entry is `(method, path)` where `method` is the uppercase HTTP token,
/// or `*` for a route that answers every method, so callers can distinguish
/// same-path/different-method routes from real conflicts. The bindings of one
/// path are listed as the route they share: `*` once when a `custom` `*` rule
/// or a custom verb after a variable is among them (the transcoded routes
/// match the verb, and answer a bound verb's other methods with 405), else
/// each method once. Two bindings that cannot both serve (one method or a `*`
/// rule, one verb) are listed both, so the caller sees the collision.
pub fn route_paths(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    selection: &RpcSelection,
) -> Vec<(String, String)> {
    // The bindings of each route shape, in first-binding order.
    let mut shapes: Vec<Vec<RouteBinding>> = Vec::new();
    let mut by_shape: HashMap<String, usize> = HashMap::new();
    // The routes themselves report a template left out.
    for binding in route_bindings(pool, aliases, selection, false) {
        match by_shape.get(&binding.mount.shape) {
            Some(&index) => shapes[index].push(binding),
            None => {
                by_shape.insert(binding.mount.shape.clone(), shapes.len());
                shapes.push(vec![binding]);
            }
        }
    }
    // Only the routes mounted: a shape the router refuses beside the ones
    // before it is skipped, as the tables are, and reserves nothing.
    retain_mountable(
        &mut shapes,
        |bindings| bindings[0].mount.axum.as_str(),
        |_, _| {},
    );
    let mut paths = Vec::new();
    for bindings in &shapes {
        let listed = |method: &str, path: &str| (method.to_owned(), path.to_owned());
        // A path with a verb after its variable answers every method: one
        // whose verb is bound only for others is told so with 405.
        match bindings
            .iter()
            .find(|b| b.entry.http_method == RouteMethod::Any || b.mount.verb.is_some())
        {
            Some(star) => paths.push(listed("*", &star.mount.axum)),
            None => {
                let mut methods: Vec<&str> = Vec::new();
                for binding in bindings {
                    let method = binding.entry.http_method.as_str();
                    if !methods.contains(&method) {
                        methods.push(method);
                        paths.push(listed(method, &binding.mount.axum));
                    }
                }
            }
        }
        for (at, binding) in bindings.iter().enumerate() {
            let clashes = bindings[..at]
                .iter()
                .any(|earlier| table::clash(&earlier.claim(), &binding.claim()));
            if clashes {
                paths.push(listed(
                    binding.entry.http_method.as_str(),
                    &binding.mount.axum,
                ));
            }
        }
    }
    paths
}

/// The methods the transcoded bindings for one pool, aliases and selection
/// answer: what [`route_paths`] lists under `*` still names methods a route
/// answers, or every one for a `custom` `*` rule.
pub(crate) struct BoundMethods {
    /// The methods the bindings name, each once.
    pub(crate) methods: Vec<Method>,
    /// Whether a `custom` `*` rule answers every method.
    pub(crate) every: bool,
}

/// The [`BoundMethods`] of the transcoded bindings for this pool, aliases
/// and selection.
pub(crate) fn bound_methods(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    selection: &RpcSelection,
) -> BoundMethods {
    let mut bound = BoundMethods {
        methods: Vec::new(),
        every: false,
    };
    for binding in route_bindings(pool, aliases, selection, false) {
        match binding.entry.http_method {
            RouteMethod::One(method) if !bound.methods.contains(&method) => {
                bound.methods.push(method);
            }
            RouteMethod::One(_) => {}
            RouteMethod::Any => bound.every = true,
        }
    }
    bound
}

/// JSON serialization options shared by the unary and streaming response paths,
/// so a given message serializes identically regardless of RPC kind.
fn response_serialize_options() -> SerializeOptions {
    SerializeOptions::new()
        .skip_default_fields(false)
        .stringify_64_bit_integers(true)
}

/// Serialize a message straight to JSON bytes, without an intermediate tree.
fn message_to_json_bytes(
    msg: &DynamicMessage,
    opts: &SerializeOptions,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut buf = Vec::with_capacity(128);
    msg.serialize_with_options(&mut serde_json::Serializer::new(&mut buf), opts)?;
    Ok(buf)
}

/// Serialize one streamed gRPC message to a compact JSON string.
fn message_to_json_string(msg: &DynamicMessage, opts: &SerializeOptions) -> Result<String, String> {
    let buf = message_to_json_bytes(msg, opts).map_err(|e| e.to_string())?;
    // SAFETY: serde_json's serializer writes only valid UTF-8, the same
    // guarantee `serde_json::to_string` relies on.
    Ok(unsafe { String::from_utf8_unchecked(buf) })
}

/// The unary response body as JSON: the whole message, or the subfield
/// `response_body` names (JSON `null` when the path does not exist).
fn json_body(
    msg: &DynamicMessage,
    response_body: Option<&str>,
) -> Result<Vec<u8>, serde_json::Error> {
    let opts = response_serialize_options();
    let Some(path) = response_body else {
        return message_to_json_bytes(msg, &opts);
    };
    // Walk the tree by moving each subtree out, so nothing is copied.
    // `response_body` names proto fields, while the tree is keyed by their
    // JSON names, so each segment is resolved through the descriptor.
    let mut value = Some(msg.serialize_with_options(serde_json::value::Serializer, &opts)?);
    let mut desc = Some(prost_reflect::ReflectMessage::descriptor(msg));
    for segment in path.split('.') {
        let field = desc.as_ref().and_then(|d| d.get_field_by_name(segment));
        desc = match field.as_ref().map(FieldDescriptor::kind) {
            Some(prost_reflect::Kind::Message(inner)) => Some(inner),
            _ => None,
        };
        value = match (value, field) {
            (Some(serde_json::Value::Object(mut fields)), Some(field)) => {
                fields.remove(field.json_name())
            }
            _ => None,
        };
    }
    let value = value.unwrap_or_else(|| {
        tracing::warn!(
            response_body = %path,
            "configured response_body path not found in response; returning null"
        );
        serde_json::Value::Null
    });
    serde_json::to_vec(&value)
}

/// Whether the client negotiated a Server-Sent Events response via `Accept`.
///
/// Considers every `Accept` header line (a client may send more than one) and
/// every comma-separated media range within each. Matches `text/event-stream`
/// case-insensitively and honors the quality factor: per RFC 7231 §5.3.1 a
/// `q=0` weight means the type is explicitly not acceptable, so it does not
/// select the SSE path.
fn wants_sse(headers: &HeaderMap) -> bool {
    headers
        .get_all(axum::http::header::ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|accept| accept.split(','))
        .any(accept_range_selects_sse)
}

/// Whether a single `Accept` media range selects `text/event-stream` with a
/// non-zero quality factor.
fn accept_range_selects_sse(range: &str) -> bool {
    let mut parts = range.split(';');
    let media = parts.next().unwrap_or("").trim();
    if !media.eq_ignore_ascii_case("text/event-stream") {
        return false;
    }
    // Default weight is 1.0; only an explicit `q=0` (or unparseable-as-positive)
    // disqualifies the match. A malformed weight falls back to acceptable.
    for param in parts {
        let mut kv = param.splitn(2, '=');
        if kv.next().unwrap_or("").trim().eq_ignore_ascii_case("q") {
            let q: f32 = kv.next().unwrap_or("").trim().parse().unwrap_or(1.0);
            return q > 0.0;
        }
    }
    true
}

/// Who sent a transcoded request: its headers, where it came from and its
/// request line.
struct Client {
    headers: HeaderMap,
    origin: Origin,
    line: RequestLine,
}

/// The method and target of a transcoded request as it was received: the
/// target before a router the proxy is nested in strips its prefix.
struct RequestLine {
    method: Method,
    uri: Uri,
}

impl RequestLine {
    /// What an upstream in process gets of the request line. An authority-form
    /// target has no path to record (RFC 9110 §7.1); it never matches a route,
    /// whose paths all start with `/`, and is refused rather than recorded as
    /// something it was not.
    fn received(self, entry: &RouteEntry) -> Result<ReceivedRequest, Unmappable> {
        let path_and_query = self
            .uri
            .into_parts()
            .path_and_query
            .ok_or_else(|| Unmappable("the request target has no path".to_string()))?;
        Ok(ReceivedRequest::new(
            self.method,
            path_and_query,
            entry.grpc_path.clone(),
        ))
    }
}

/// Where a transcoded request came from: the connection, when the server
/// recorded one, and the client address the proxy resolved.
struct Origin {
    connection: Option<ConnectionInfo>,
    address: Option<ClientAddress>,
}

/// The upstream call one request on a transcoded route makes, with whether a
/// streamed answer goes out as SSE and its keep-alive; or why the request
/// cannot be mapped onto the RPC.
fn start<S: TranscodeState>(
    proxy_state: S,
    client: Client,
    path_params: &[(&str, Cow<'_, str>)],
    body: Bytes,
    entry: &RouteEntry,
) -> Result<(Call<S::Upstream>, bool, u64), Unmappable> {
    let keep_alive_secs = proxy_state.sse_keep_alive_secs();
    let Client {
        headers,
        origin,
        line,
    } = client;
    // The query is read where it was received, before the request line is
    // handed on.
    let prepared = prepare(
        proxy_state,
        &headers,
        origin,
        path_params,
        line.uri.query(),
        body,
        entry,
    )
    .and_then(|mut call| {
        // Next to the extensions `prepare` sets, for an upstream in process.
        call.request.extensions_mut().insert(line.received(entry)?);
        Ok(call)
    });
    let call = prepared?;
    Ok((
        call,
        entry.streaming && wants_sse(&headers),
        keep_alive_secs,
    ))
}

/// Why a request ends before the upstream is called: it cannot be mapped onto
/// the RPC (`INVALID_ARGUMENT`, 400).
struct Unmappable(String);

impl Unmappable {
    /// The answer, in the error body the upstream's own errors get on the route.
    fn into_response(self, entry: &RouteEntry) -> Response {
        let status = tonic::Status::invalid_argument(self.0);
        error::status_to_response_with_details(&status, entry.error_details.as_deref())
    }
}

/// A call ready to be made: the upstream, the request, and how long the
/// upstream may take to answer it.
struct Call<U> {
    upstream: U,
    request: tonic::Request<DynamicMessage>,
    deadline: Duration,
}

impl<U: Upstream> Call<U> {
    /// Wait for the upstream to take the call, start it, and wait for its
    /// response headers, all within the one deadline: an upstream under
    /// backpressure that never frees a slot answers `DEADLINE_EXCEEDED` like
    /// one that never answers. Every upstream gets the same deadline here, in
    /// process or remote, rather than whatever its transport enforces.
    async fn open(
        self,
        entry: &RouteEntry,
    ) -> Result<tonic::Response<tonic::Streaming<DynamicMessage>>, tonic::Status> {
        let Self {
            upstream,
            request,
            deadline,
        } = self;
        let call = async move {
            let mut client = Grpc::new(upstream);
            if let Err(e) = client.ready().await {
                let e: crate::upstream::BoxError = e.into();
                return Err(tonic::Status::unavailable(format!(
                    "gRPC upstream not ready: {e}"
                )));
            }
            client
                .server_streaming(request, entry.grpc_path.clone(), entry.codec())
                .await
        };
        match tokio::time::timeout(deadline, call).await {
            Ok(result) => result,
            Err(_) => Err(tonic::Status::deadline_exceeded(
                "upstream did not answer within the deadline",
            )),
        }
    }
}

/// Map the request onto the RPC's input message.
fn prepare<S: TranscodeState>(
    proxy_state: S,
    headers: &HeaderMap,
    origin: Origin,
    path_params: &[(&str, Cow<'_, str>)],
    raw_query: Option<&str>,
    body: Bytes,
    entry: &RouteEntry,
) -> Result<Call<S::Upstream>, Unmappable> {
    let Origin {
        connection,
        address,
    } = origin;
    // A request the proxy resolved carries the client-address headers its
    // forwarding policy wrote; one routed here without that resolution
    // carries only what its client asserted, which is never forwarded.
    let forwarded = match proxy_state.forwarded_header_names() {
        Some(names) => metadata::Forwarded::Named(names),
        None => metadata::Forwarded::Listed(proxy_state.forwarded_headers()),
    };
    let request_metadata = metadata::forwarded_metadata(headers, forwarded, address.is_some())
        .map_err(|e| Unmappable(e.to_string()))?;
    let message =
        decode_request(entry, headers, path_params, raw_query, body).map_err(Unmappable)?;
    let mut request = tonic::Request::new(message);
    *request.metadata_mut() = request_metadata;
    // An upstream in process reads the HTTP client's address and TLS
    // certificates with `Request::remote_addr` / `peer_certs`, the resolved
    // client address as a `ClientAddress` and the request line as a
    // `ReceivedRequest`; a remote one never sees request extensions.
    if let Some(connection) = connection {
        connection.into_tonic_extensions(request.extensions_mut());
    }
    if let Some(address) = address {
        request.extensions_mut().insert(address);
    }
    // Only the client's own deadline travels upstream: a default one would
    // cut a long server stream short on an upstream that applies
    // `grpc-timeout` to the whole call.
    let deadline = metadata::apply_request_deadline(&mut request, headers)
        .map_or(UPSTREAM_DEADLINE, |client| client.min(UPSTREAM_DEADLINE));

    Ok(Call {
        upstream: proxy_state.into_upstream(),
        request,
        deadline,
    })
}

/// A successful unary answer with its initial metadata and trailers kept
/// apart.
struct UnaryAnswer {
    initial: MetadataMap,
    message: DynamicMessage,
    trailers: Option<MetadataMap>,
}

/// Call a unary RPC. tonic's `Grpc::unary` merges the trailers over the
/// initial metadata, so a key sent in both keeps only its trailer value; the
/// HTTP response carries both, so the call is made as a one-message stream
/// instead, reading exactly what `Grpc::unary` reads.
async fn call_unary<U: Upstream>(
    call: Call<U>,
    entry: &RouteEntry,
) -> Result<UnaryAnswer, tonic::Status> {
    let (initial, mut stream, _) = call.open(entry).await?.into_parts();
    let message = match stream.message().await {
        Ok(Some(message)) => message,
        Ok(None) => {
            let status = tonic::Status::internal("Missing response message.");
            return Err(with_initial(status, initial));
        }
        Err(status) => return Err(with_initial(status, initial)),
    };
    let trailers = match stream.trailers().await {
        Ok(trailers) => trailers,
        Err(status) => return Err(with_initial(status, initial)),
    };
    Ok(UnaryAnswer {
        initial,
        message,
        trailers,
    })
}

/// A failure that came after the upstream's response headers, with their
/// metadata put ahead of the failure's own: both belong to the error
/// response, as tonic's `Grpc::unary` keeps them.
fn with_initial(mut status: tonic::Status, initial: MetadataMap) -> tonic::Status {
    let own = std::mem::take(status.metadata_mut()).into_headers();
    let mut merged = initial.into_headers();
    let mut last: Option<HeaderName> = None;
    // A header map yields a name only with the first value of each key.
    for (name, value) in own {
        if let Some(name) = name {
            merged.append(&name, value);
            last = Some(name);
        } else if let Some(name) = &last {
            merged.append(name, value);
        }
    }
    *status.metadata_mut() = MetadataMap::from_headers(merged);
    status
}

/// Serve a unary RPC.
async fn unary_call<U: Upstream>(call: Call<U>, entry: &RouteEntry) -> Response {
    match call_unary(call, entry).await {
        Ok(answer) => unary_success(entry, answer),
        Err(status) => upstream_error(status, entry),
    }
}

/// The HTTP response to a successful unary call: the status `x-http-code`
/// sets (200 otherwise), the forwarded response metadata, and the body.
fn unary_success(entry: &RouteEntry, answer: UnaryAnswer) -> Response {
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(answer.initial, &entry.denied_headers);
    if let Some(trailers) = answer.trailers {
        upstream.absorb(trailers, &entry.denied_headers);
    }
    let status = match upstream.status() {
        Ok(status) => status.unwrap_or(StatusCode::OK),
        Err(response::InvalidHttpCode) => {
            tracing::error!(
                rpc = %entry.grpc_path,
                "upstream set x-http-code to something other than one integer in 200-599"
            );
            return error::malformed_response(entry.error_details.as_deref());
        }
    };
    let (content_type, body) = match &entry.response {
        ResponseShape::HttpBody(path) => {
            let raw = httpbody::take(answer.message, path);
            match content_type_header(&raw.content_type) {
                Ok(content_type) => (content_type, Body::from(raw.data)),
                Err(()) => return invalid_content_type(entry),
            }
        }
        ResponseShape::Json(response_body) => {
            match json_body(&answer.message, response_body.as_deref()) {
                Ok(json) => (
                    Some(HeaderValue::from_static("application/json")),
                    Body::from(json),
                ),
                Err(e) => {
                    tracing::error!("Failed to serialize gRPC response: {e}");
                    return error::status_to_response_with_details(
                        &tonic::Status::internal("failed to serialize response"),
                        entry.error_details.as_deref(),
                    );
                }
            }
        }
    };
    response::build(status, upstream.into_headers(), content_type, body)
}

/// The `Content-Type` an HttpBody asks for: none when it left the field empty.
fn content_type_header(content_type: &str) -> Result<Option<HeaderValue>, ()> {
    if content_type.is_empty() {
        return Ok(None);
    }
    HeaderValue::from_str(content_type)
        .map(Some)
        .map_err(|_| ())
}

/// The answer to an HttpBody whose content type cannot be a header value.
fn invalid_content_type(entry: &RouteEntry) -> Response {
    tracing::error!(
        rpc = %entry.grpc_path,
        "upstream HttpBody content_type is not a valid header value"
    );
    error::malformed_response(entry.error_details.as_deref())
}

/// The HTTP response to a failed call, carrying the failure's metadata as
/// headers (a trailers-only response, or the response headers and trailers of
/// a call that failed after them, see [`with_initial`]) unless its details
/// were malformed and the answer is the generic `INTERNAL`, which then carries
/// nothing of the upstream's answer.
fn upstream_error(mut status: tonic::Status, entry: &RouteEntry) -> Response {
    let (response, faithful) = error::render_response(&status, entry.error_details.as_deref());
    let metadata = std::mem::take(status.metadata_mut());
    if !faithful || metadata.is_empty() {
        return response;
    }
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(metadata, &entry.denied_headers);
    response::with_upstream_headers(response, upstream.into_headers())
}

/// Serve a server-streaming RPC.
///
/// A JSON stream is Server-Sent Events when the client sends
/// `Accept: text/event-stream`, otherwise newline-delimited JSON (NDJSON); a
/// gRPC error mid-stream is delivered as an explicit terminal frame before the
/// stream is closed cleanly, rather than truncating the HTTP body. An HttpBody
/// stream is the concatenated `data` of its messages. The upstream's initial
/// metadata becomes response headers; trailers arrive after the headers are
/// sent and are not forwarded.
async fn streaming_call<U: Upstream>(
    call: Call<U>,
    entry: RouteRef,
    use_sse: bool,
    keep_alive_secs: u64,
) -> Response {
    let response = match call.open(&entry).await {
        Ok(response) => response,
        // A trailers-only rejection, or no answer within the deadline.
        Err(status) => return upstream_error(status, &entry),
    };
    let (initial, stream, _) = response.into_parts();
    if matches!(entry.response, ResponseShape::HttpBody(_)) {
        return http_body_stream(stream, entry, initial).await;
    }
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(initial, &entry.denied_headers);
    let headers = upstream.into_headers();
    // Once the upstream accepted the call, the response starts at once rather
    // than waiting for the first item, so headers and SSE keep-alives are not
    // held back; an error that comes before the first message is a terminal
    // frame. The terminal frame renders like the unary error body. The
    // closure takes over this request's route handle, so the stream keeps it
    // alive without another refcount.
    let envelope = entry.ndjson_envelope;
    let render_error =
        move |status: &tonic::Status| error::error_body(status, entry.error_details.as_deref());
    let response = if use_sse {
        sse_response(stream, render_error, keep_alive_secs)
    } else {
        ndjson_response(stream, render_error, envelope)
    };
    response::with_upstream_headers(response, headers)
}

/// A server-streaming HttpBody response: `Content-Type` from the first
/// message, so the headers wait for it, then every message's `data` as it
/// arrives. An error before the first message is an ordinary error response,
/// with the initial metadata the upstream sent before it; after the first
/// message, the raw body has no in-band error frame, so the body is aborted
/// and the client sees a truncated transfer instead of a clean end.
async fn http_body_stream(
    mut stream: tonic::Streaming<DynamicMessage>,
    entry: RouteRef,
    initial: MetadataMap,
) -> Response {
    let first = match stream.message().await {
        Ok(Some(message)) => entry.raw_body(message).unwrap_or_default(),
        Ok(None) => httpbody::RawBody::default(),
        Err(status) => return upstream_error(with_initial(status, initial), &entry),
    };
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(initial, &entry.denied_headers);
    let headers = upstream.into_headers();
    let content_type = match content_type_header(&first.content_type) {
        Ok(content_type) => content_type,
        Err(()) => return invalid_content_type(&entry),
    };
    let rest = stream.map(move |item| match item {
        Ok(message) => Ok(entry.raw_body(message).unwrap_or_default().data),
        Err(status) => {
            tracing::error!(
                rpc = %entry.grpc_path,
                code = ?status.code(),
                "server-streaming HttpBody failed after the response started; aborting the body"
            );
            Err(std::io::Error::other(status))
        }
    });
    let chunks = futures::stream::once(futures::future::ready(Ok(first.data)))
        .chain(rest)
        .try_filter(|chunk| futures::future::ready(!chunk.is_empty()));
    response::build(
        StatusCode::OK,
        headers,
        content_type,
        Body::from_stream(chunks),
    )
}

/// One frame of a streaming response: a serialized message, or the error body
/// (see [`error::error_body`]) that ends the stream.
///
/// `Error` is terminal: [`json_frames`] stops the stream right after yielding
/// it, so an error frame is always the last thing a client sees regardless of
/// whether it came from a gRPC status or a serialization failure. It stays a
/// JSON value so each format can add its own framing before serializing it.
enum StreamFrame {
    Data(String),
    Error(serde_json::Value),
}

/// Type URL marking the terminal error line of an unenveloped NDJSON stream. A
/// data line is the ProtoJSON of a response message, which carries a top-level
/// `@type` only when the RPC streams `google.protobuf.Any`; `Struct`, `Value`
/// and `ListValue` can carry any key at all. For those RPCs no in-band marker
/// is collision-free, which is what the opt-in envelope
/// ([`TranscodeOptions::with_ndjson_envelope`]) is for; the unenveloped shape
/// stays the default so existing NDJSON readers keep working.
const STATUS_TYPE_URL: &str = "type.googleapis.com/google.rpc.Status";

/// Turn a gRPC message stream into a stream of serialized JSON frames, stopping
/// after the first error so error frames are unambiguously terminal.
///
/// Both a gRPC `Status` (rendered by `render_error`) and a per-message
/// serialization failure become a terminal [`StreamFrame::Error`]; downstream
/// messages the upstream might still emit are dropped rather than streamed past
/// the error. The terminal frame drops the upstream along with the stream
/// state, so the body ends at once instead of polling an upstream that may
/// stay open.
fn json_frames<St, R>(
    stream: St,
    render_error: R,
) -> impl futures::Stream<Item = StreamFrame> + Send + 'static
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + Unpin + 'static,
    R: Fn(&tonic::Status) -> serde_json::Value + Send + 'static,
{
    let state = Some((stream, render_error, response_serialize_options()));
    futures::stream::unfold(state, |state| async move {
        let (mut stream, render_error, opts) = state?;
        let error = match stream.next().await? {
            Ok(msg) => match message_to_json_string(&msg, &opts) {
                Ok(s) => return Some((StreamFrame::Data(s), Some((stream, render_error, opts)))),
                Err(e) => tonic::Status::internal(format!("serialization error: {e}")),
            },
            Err(status) => status,
        };
        Some((StreamFrame::Error(render_error(&error)), None))
    })
}

/// Build an NDJSON (`application/x-ndjson`) streaming response.
///
/// With `envelope`, every line is wrapped: `{"result": <message>}` for data and
/// `{"error": <error body>}` for the terminal error. Without it, a data line is
/// the bare message and the error line is the error body plus an
/// `@type: google.rpc.Status` marker (see [`STATUS_TYPE_URL`]).
fn ndjson_response<St, R>(stream: St, render_error: R, envelope: bool) -> Response
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + Unpin + 'static,
    R: Fn(&tonic::Status) -> serde_json::Value + Send + 'static,
{
    let byte_stream = json_frames(stream, render_error).map(move |frame| {
        let mut line = match frame {
            // The message is already serialized; wrap the text instead of
            // parsing it back into a value.
            StreamFrame::Data(s) if envelope => {
                let mut wrapped = String::with_capacity(s.len() + 12);
                wrapped.push_str("{\"result\":");
                wrapped.push_str(&s);
                wrapped.push('}');
                wrapped
            }
            StreamFrame::Data(s) => s,
            StreamFrame::Error(body) if envelope => {
                serde_json::json!({ "error": body }).to_string()
            }
            StreamFrame::Error(mut body) => {
                if let Some(fields) = body.as_object_mut() {
                    fields.insert("@type".into(), STATUS_TYPE_URL.into());
                }
                body.to_string()
            }
        };
        line.push('\n');
        Ok::<Bytes, std::io::Error>(Bytes::from(line))
    });

    let body = Body::from_stream(byte_stream);
    // Body framing (chunked on HTTP/1.1, DATA frames on HTTP/2) is chosen by
    // hyper from the protocol version; setting transfer-encoding by hand would
    // be redundant on HTTP/1.1 and illegal on HTTP/2.
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-ndjson")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Build a Server-Sent Events (`text/event-stream`) streaming response.
fn sse_response<St, R>(stream: St, render_error: R, keep_alive_secs: u64) -> Response
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + Unpin + 'static,
    R: Fn(&tonic::Status) -> serde_json::Value + Send + 'static,
{
    // Terminal errors use the `stream-error` event type, not the reserved
    // `error` type that the browser EventSource dispatches for transport
    // failures — clients listen for it via addEventListener("stream-error").
    let event_stream = json_frames(stream, render_error).map(|frame| {
        let event = match frame {
            StreamFrame::Data(s) => Event::default().data(s),
            StreamFrame::Error(body) => Event::default()
                .event("stream-error")
                .data(body.to_string()),
        };
        Ok::<Event, std::convert::Infallible>(event)
    });

    Sse::new(event_stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(keep_alive_secs)))
        .into_response()
}

/// Request body mapping of the raw-body routes: nothing parsed.
static NO_PARSED_BODY: request::BodyMapping = request::BodyMapping::None;

/// Map the HTTP request onto the RPC's input message: path parameters, query
/// parameters and the route's `body` rule, or the raw body for an HttpBody.
/// Unary and server-streaming routes share it, so both bind a request the same
/// way. The error is the message of the 400 the caller answers with, before
/// the upstream is called.
fn decode_request(
    entry: &RouteEntry,
    headers: &HeaderMap,
    path_params: &[(&str, Cow<'_, str>)],
    raw_query: Option<&str>,
    body_bytes: Bytes,
) -> Result<DynamicMessage, String> {
    // A raw field keeps its `body` mapping with no body read, so query binding
    // leaves that field to the raw body. An HttpBody input with `body: "*"`
    // takes every field from the raw body, so its query binds nothing
    // (google/api/http.proto: with `*` there are no HTTP parameters).
    let (mapping, body, raw_query) = match &entry.request_body {
        RequestBody::Parsed(mapping @ request::BodyMapping::None) => {
            (mapping, request::Body::Absent, raw_query)
        }
        RequestBody::Parsed(mapping) => (
            mapping,
            request::Body::new(body::content_type(headers), &body_bytes),
            raw_query,
        ),
        RequestBody::RawRoot => (&NO_PARSED_BODY, request::Body::Absent, None),
        RequestBody::RawField { mapping, .. } => (mapping, request::Body::Absent, raw_query),
    };

    let mut message =
        request::build_message(&entry.method.input(), mapping, body, path_params, raw_query)?;
    match &entry.request_body {
        RequestBody::Parsed(_) => {}
        RequestBody::RawRoot => {
            httpbody::fill(&mut message, request_content_type(headers)?, body_bytes);
        }
        RequestBody::RawField {
            field, http_body, ..
        } => {
            let mut inner = DynamicMessage::new(http_body.clone());
            httpbody::fill(&mut inner, request_content_type(headers)?, body_bytes);
            message.set_field(field, prost_reflect::Value::Message(inner));
        }
    }
    Ok(message)
}

/// The request's full `Content-Type` value (parameters included) for an
/// HttpBody, empty when absent. `HttpBody.content_type` is a proto string, so
/// a value that is not visible ASCII is rejected rather than altered.
fn request_content_type(headers: &HeaderMap) -> Result<String, String> {
    match headers.get(CONTENT_TYPE) {
        None => Ok(String::new()),
        Some(value) => value
            .to_str()
            .map(str::to_owned)
            .map_err(|_| "request Content-Type is not a visible ASCII string".to_string()),
    }
}

/// Extract the route entries of every HTTP binding of every selected unary
/// and server-streaming RPC. Client-streaming RPCs have no HTTP mapping.
fn extract_routes(pool: &DescriptorPool, selection: &RpcSelection) -> Vec<RouteEntry> {
    let http_ext = match pool.get_extension_by_name("google.api.http") {
        Some(ext) => ext,
        None => {
            tracing::warn!("google.api.http extension not found in descriptor pool");
            return Vec::new();
        }
    };

    let mut entries = Vec::new();

    for service in pool.services() {
        for method in service.methods() {
            if method.is_client_streaming() || !selection.selects(&method) {
                continue;
            }

            let grpc_path = format!("/{}/{}", service.full_name(), method.name());
            let grpc_path: axum::http::uri::PathAndQuery = match grpc_path.parse() {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!("skipping route with invalid gRPC path '{grpc_path}': {e}");
                    continue;
                }
            };

            let input = method.input();
            let output = method.output();
            let streaming = method.is_server_streaming();
            let response_has_required = codec::has_required_fields(&output);
            for binding in rule::http_bindings(&method, &http_ext) {
                if streaming {
                    tracing::info!(
                        "Registering streaming route: {} {} → {}",
                        binding.method.as_str(),
                        binding.path,
                        grpc_path
                    );
                }
                entries.push(RouteEntry {
                    http_path: binding.path,
                    http_method: binding.method,
                    grpc_path: grpc_path.clone(),
                    method: method.clone(),
                    streaming,
                    request_body: request_body(&input, binding.body),
                    response: response_shape(&output, binding.response_body),
                    // Decided per mounted path in `routes_with_options`.
                    error_details: None,
                    ndjson_envelope: false,
                    response_has_required,
                    denied_headers: Arc::default(),
                });
            }
        }
    }

    entries
}

/// How a binding's `body` rule reaches `input`: raw into an HttpBody (the
/// input itself with `body: "*"`, or the HttpBody field `body` names), parsed
/// otherwise. `body` names a field of the input itself, never a dotted path:
/// `google/api/http.proto` requires "the referred field must not be a repeated
/// field and must be present at the top-level of request message type".
fn request_body(input: &MessageDescriptor, mapping: request::BodyMapping) -> RequestBody {
    let raw_field = match &mapping {
        request::BodyMapping::Root if httpbody::is_http_body(input) => return RequestBody::RawRoot,
        request::BodyMapping::Field(name) => httpbody::http_body_field(input, name),
        _ => None,
    };
    match raw_field {
        Some((field, http_body)) => RequestBody::RawField {
            mapping,
            field,
            http_body,
        },
        None => RequestBody::Parsed(mapping),
    }
}

/// What a binding answers with: the raw body of an HttpBody (the output itself,
/// or the HttpBody `response_body` names), JSON otherwise.
fn response_shape(output: &MessageDescriptor, response_body: Option<String>) -> ResponseShape {
    match response_body {
        None if httpbody::is_http_body(output) => ResponseShape::HttpBody(Vec::new()),
        None => ResponseShape::Json(None),
        Some(path) => match httpbody::http_body_path(output, &path) {
            Some(fields) => ResponseShape::HttpBody(fields),
            None => ResponseShape::Json(Some(path)),
        },
    }
}

#[cfg(test)]
mod tests;
