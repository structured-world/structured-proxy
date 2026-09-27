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
pub mod request;
pub(crate) mod response;
pub(crate) mod rule;

use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, State};
use axum::http::header::{ALLOW, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodFilter, MethodRouter};
use axum::Router;
use futures::{StreamExt, TryStreamExt};
use prost_reflect::{
    DescriptorPool, DynamicMessage, FieldDescriptor, MessageDescriptor, MethodDescriptor,
    SerializeOptions,
};
use std::collections::HashMap;
use std::sync::Arc;
use tonic::client::Grpc;
use tonic::metadata::MetadataMap;

use crate::config::AliasConfig;
use error::{ErrorDetailsPolicy, StatusDetails};
use response::UpstreamHeaders;
use rule::RouteMethod;

/// Trait for state types that support REST→gRPC transcoding.
///
/// Implement this for your application's state type to use `transcode::routes()`.
/// Provides the minimal interface needed by transcode handlers.
pub trait TranscodeState: Clone + Send + Sync + 'static {
    /// Lazy gRPC channel to upstream service.
    fn grpc_channel(&self) -> tonic::transport::Channel;
    /// Headers to forward from HTTP to gRPC metadata.
    fn forwarded_headers(&self) -> &[String];
    /// SSE keep-alive interval (seconds) for server-streaming responses.
    fn sse_keep_alive_secs(&self) -> u64;
}

impl TranscodeState for crate::ProxyState {
    fn grpc_channel(&self) -> tonic::transport::Channel {
        self.grpc_channel.clone()
    }
    fn forwarded_headers(&self) -> &[String] {
        &self.forwarded_headers
    }
    fn sse_keep_alive_secs(&self) -> u64 {
        self.sse_keep_alive_secs
    }
}

/// Path parameters of a matched route.
type PathParams = HashMap<String, String>;

/// How the HTTP request body reaches the RPC's input message.
#[derive(Debug, Clone)]
enum RequestBody {
    /// JSON or a form, mapped as the rule's `body` says.
    Parsed(request::BodyMapping),
    /// Raw bytes and `Content-Type` into the input message, a `google.api.HttpBody`.
    RawRoot,
    /// Raw bytes and `Content-Type` into the HttpBody field (of that type) `body`
    /// names; the other fields still come from path and query.
    RawField(FieldDescriptor, MessageDescriptor),
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
}

impl TranscodeOptions {
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
/// A second binding for a method and path already taken (or any binding on a
/// path a `custom` `*` rule takes, which answers every method) is skipped with
/// an error in the log.
pub fn routes_with_options<S: TranscodeState>(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    options: &TranscodeOptions,
) -> Router<S> {
    let bindings = route_bindings(pool, aliases);
    if bindings.is_empty() {
        tracing::warn!("No HTTP-annotated RPCs found in proto descriptors");
        return Router::new();
    }

    tracing::info!("Registering {} transcoded REST→gRPC routes", bindings.len());

    // At most two renderers, without and with the opaque-detail extension,
    // each shared by every route that uses it and built only when one does.
    // The second is a copy of the first: the descriptor pool inside is shared.
    let mut status_details: [Option<Arc<StatusDetails>>; 2] = [None, None];
    // Every binding of one path goes into the same method router, in binding
    // order.
    let mut paths: Vec<PathRoutes> = Vec::new();
    let mut path_index: HashMap<String, usize> = HashMap::new();
    for mut binding in bindings {
        let policy = &options.error_details;
        if policy.enabled_for(&binding.axum_path) {
            let opaque = policy.opaque_for(&binding.axum_path);
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
        let index = match path_index.get(&binding.axum_path) {
            Some(&index) => index,
            None => {
                path_index.insert(binding.axum_path.clone(), paths.len());
                paths.push(PathRoutes {
                    path: binding.axum_path,
                    methods: Vec::new(),
                });
                paths.len() - 1
            }
        };
        paths[index].add(Arc::new(binding.entry));
    }

    let mut router: Router<S> = Router::new();
    for path in &paths {
        router = router.route(&path.path, path.method_router());
    }
    router
}

/// The axum handler serving the route entry `$entry`, for the state type `S`
/// in scope. A macro because the closure's handler type cannot be named.
macro_rules! endpoint {
    ($entry:expr) => {{
        let entry: Arc<RouteEntry> = $entry;
        move |state: State<S>,
              headers: HeaderMap,
              path_params: Path<PathParams>,
              raw_query: RawQuery,
              body: Bytes| handle(state, headers, path_params, raw_query, body, entry)
    }};
}

/// The bindings mounted at one axum path.
struct PathRoutes {
    path: String,
    methods: Vec<Arc<RouteEntry>>,
}

impl PathRoutes {
    /// Add `entry` unless its method is already answered on this path.
    fn add(&mut self, entry: Arc<RouteEntry>) {
        let taken = self.methods.iter().any(|existing| {
            existing.http_method == entry.http_method
                || existing.http_method == RouteMethod::Any
                || entry.http_method == RouteMethod::Any
        });
        if taken {
            tracing::error!(
                method = entry.http_method.as_str(),
                path = %self.path,
                rpc = %entry.grpc_path,
                "HTTP method and path already bound to another RPC; skipping this binding"
            );
            return;
        }
        self.methods.push(entry);
    }

    /// One method router for every binding of the path. Methods axum routes by
    /// itself are registered directly; any other token (a `custom` rule such
    /// as `PROPFIND`) is dispatched by a fallback that answers `405` with the
    /// full `Allow` list (RFC 9110 §15.5.6) for a method nobody binds.
    fn method_router<S: TranscodeState>(&self) -> MethodRouter<S> {
        let mut router = MethodRouter::new();
        let mut extension: Vec<(Method, Arc<RouteEntry>)> = Vec::new();
        let mut allow: Vec<&str> = Vec::new();
        for entry in &self.methods {
            match &entry.http_method {
                // `add` keeps a `*` binding alone on its path.
                RouteMethod::Any => return axum::routing::any(endpoint!(entry.clone())),
                RouteMethod::One(method) => {
                    allow.push(method.as_str());
                    match MethodFilter::try_from(method.clone()) {
                        Ok(filter) => router = router.on(filter, endpoint!(entry.clone())),
                        Err(_) => extension.push((method.clone(), entry.clone())),
                    }
                }
            }
        }
        if extension.is_empty() {
            return router;
        }
        // A GET route answers HEAD too.
        if allow.contains(&"GET") && !allow.contains(&"HEAD") {
            allow.push("HEAD");
        }
        let allow = HeaderValue::from_str(&allow.join(", "))
            .expect("method tokens are valid header value characters");
        let extension: Arc<[(Method, Arc<RouteEntry>)]> = extension.into();
        router.fallback(
            move |method: Method,
                  state: State<S>,
                  headers: HeaderMap,
                  path_params: Path<PathParams>,
                  raw_query: RawQuery,
                  body: Bytes| async move {
                match extension.iter().find(|(bound, _)| *bound == method) {
                    Some((_, entry)) => {
                        handle(state, headers, path_params, raw_query, body, entry.clone()).await
                    }
                    None => (StatusCode::METHOD_NOT_ALLOWED, [(ALLOW, allow)]).into_response(),
                }
            },
        )
    }
}

/// One transcode route to mount: the RPC entry that serves it and the axum path
/// to register it at.
struct RouteBinding {
    entry: RouteEntry,
    axum_path: String,
}

/// The single source of truth for what [`routes`] mounts: every binding of
/// every unary and server-streaming RPC, plus its config aliases. Both
/// [`routes`] (to build handlers) and [`route_paths`] (to enumerate paths for
/// collision checks) consume this, so the mounted set and the enumerated set
/// cannot drift apart.
fn route_bindings(pool: &DescriptorPool, aliases: &[AliasConfig]) -> Vec<RouteBinding> {
    let mut bindings = Vec::new();
    for entry in extract_routes(pool) {
        for alias in aliases {
            if let Some(suffix) = entry.http_path.strip_prefix(&alias.to) {
                if alias.from.ends_with("/{path}") {
                    let prefix = alias.from.trim_end_matches("/{path}");
                    bindings.push(RouteBinding {
                        axum_path: format!("{prefix}{suffix}"),
                        entry: entry.clone(),
                    });
                }
            }
        }
        bindings.push(RouteBinding {
            axum_path: proto_path_to_axum(&entry.http_path),
            entry,
        });
    }
    bindings
}

/// The axum paths [`routes`] would register for this pool and aliases.
///
/// Mirrors the registration in [`routes`] (every binding of every unary and
/// server-streaming RPC, and their config aliases) without building handlers,
/// so callers can detect route collisions before mounting additional routes
/// (e.g. a forward-auth endpoint).
///
/// Each entry is `(method, path)` where `method` is the uppercase HTTP token,
/// or `*` for a `custom` rule that answers every method, so callers can
/// distinguish same-path/different-method routes from real conflicts.
pub fn route_paths(pool: &DescriptorPool, aliases: &[AliasConfig]) -> Vec<(String, String)> {
    route_bindings(pool, aliases)
        .into_iter()
        .map(|b| (b.entry.http_method.as_str().to_string(), b.axum_path))
        .collect()
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
    let mut value = Some(msg.serialize_with_options(serde_json::value::Serializer, &opts)?);
    for segment in path.split('.') {
        value = match value {
            Some(serde_json::Value::Object(mut fields)) => fields.remove(segment),
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

/// Serve one request on a transcoded route.
async fn handle<S: TranscodeState>(
    State(proxy_state): State<S>,
    headers: HeaderMap,
    Path(path_params): Path<PathParams>,
    RawQuery(raw_query): RawQuery,
    body: Bytes,
    entry: Arc<RouteEntry>,
) -> Response {
    let prepared = prepare(
        &proxy_state,
        &headers,
        &path_params,
        raw_query.as_deref(),
        body,
        &entry,
    )
    .await;
    let (client, request) = match prepared {
        Ok(prepared) => prepared,
        Err(rejection) => return rejection.into_response(&entry),
    };
    if entry.streaming {
        let keep_alive_secs = proxy_state.sse_keep_alive_secs();
        streaming_call(client, request, entry, wants_sse(&headers), keep_alive_secs).await
    } else {
        unary_call(client, request, &entry).await
    }
}

/// Why a request ends before the upstream is called.
enum Rejection {
    /// It cannot be mapped onto the RPC (`INVALID_ARGUMENT`, 400).
    Unmappable(String),
    /// The upstream channel is not ready (`UNAVAILABLE`, 503).
    NotReady(String),
}

impl Rejection {
    /// The answer, in the error body the upstream's own errors get on the route.
    fn into_response(self, entry: &RouteEntry) -> Response {
        let status = match self {
            Self::Unmappable(message) => tonic::Status::invalid_argument(message),
            Self::NotReady(message) => tonic::Status::unavailable(message),
        };
        error::status_to_response_with_details(&status, entry.error_details.as_deref())
    }
}

/// Map the request onto the RPC's input message and get a client whose
/// channel is ready.
async fn prepare<S: TranscodeState>(
    proxy_state: &S,
    headers: &HeaderMap,
    path_params: &PathParams,
    raw_query: Option<&str>,
    body: Bytes,
    entry: &RouteEntry,
) -> Result<
    (
        Grpc<tonic::transport::Channel>,
        tonic::Request<DynamicMessage>,
    ),
    Rejection,
> {
    let message = decode_request(entry, headers, path_params, raw_query, body)
        .map_err(Rejection::Unmappable)?;
    let mut request = tonic::Request::new(message);
    *request.metadata_mut() =
        metadata::http_headers_to_grpc_metadata(headers, proxy_state.forwarded_headers());
    metadata::apply_request_deadline(&mut request, headers);

    let mut client = Grpc::new(proxy_state.grpc_channel());
    if let Err(e) = client.ready().await {
        return Err(Rejection::NotReady(format!("gRPC upstream not ready: {e}")));
    }
    Ok((client, request))
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
async fn call_unary(
    client: &mut Grpc<tonic::transport::Channel>,
    request: tonic::Request<DynamicMessage>,
    entry: &RouteEntry,
) -> Result<UnaryAnswer, tonic::Status> {
    let response = client
        .server_streaming(request, entry.grpc_path.clone(), entry.codec())
        .await?;
    let (initial, mut stream, _) = response.into_parts();
    let message = stream
        .message()
        .await?
        .ok_or_else(|| tonic::Status::internal("Missing response message."))?;
    let trailers = stream.trailers().await?;
    Ok(UnaryAnswer {
        initial,
        message,
        trailers,
    })
}

/// Serve a unary RPC.
async fn unary_call(
    mut client: Grpc<tonic::transport::Channel>,
    request: tonic::Request<DynamicMessage>,
    entry: &RouteEntry,
) -> Response {
    match call_unary(&mut client, request, entry).await {
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
/// headers unless its details were malformed and the answer is the generic
/// `INTERNAL`. Only the failure's own metadata is used (a trailers-only
/// response, or the trailers ending the call): a failure the proxy's client
/// raises itself, such as an undecodable message, has none, so nothing of an
/// answer the proxy rejected reaches the client.
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
async fn streaming_call(
    mut client: Grpc<tonic::transport::Channel>,
    request: tonic::Request<DynamicMessage>,
    entry: Arc<RouteEntry>,
    use_sse: bool,
    keep_alive_secs: u64,
) -> Response {
    let response = match client
        .server_streaming(request, entry.grpc_path.clone(), entry.codec())
        .await
    {
        Ok(response) => response,
        // Only a trailers-only rejection lands here.
        Err(status) => return upstream_error(status, &entry),
    };
    let (initial, stream, _) = response.into_parts();
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(initial, &entry.denied_headers);
    let headers = upstream.into_headers();

    if matches!(entry.response, ResponseShape::HttpBody(_)) {
        return http_body_stream(stream, entry, headers).await;
    }
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
/// arrives. An error before the first message is an ordinary error response;
/// after it, the raw body has no in-band error frame, so the body is aborted
/// and the client sees a truncated transfer instead of a clean end.
async fn http_body_stream(
    mut stream: tonic::Streaming<DynamicMessage>,
    entry: Arc<RouteEntry>,
    headers: HeaderMap,
) -> Response {
    let first = match stream.message().await {
        Ok(Some(message)) => entry.raw_body(message).unwrap_or_default(),
        Ok(None) => httpbody::RawBody::default(),
        Err(status) => return upstream_error(status, &entry),
    };
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
    path_params: &PathParams,
    raw_query: Option<&str>,
    body_bytes: Bytes,
) -> Result<DynamicMessage, String> {
    let mapping = match &entry.request_body {
        RequestBody::Parsed(mapping) => mapping,
        RequestBody::RawRoot | RequestBody::RawField(..) => &NO_PARSED_BODY,
    };
    // Only parse the body when the rule maps it onto the message.
    let json_body = match mapping {
        request::BodyMapping::None => serde_json::Value::Null,
        _ => body::parse_body(body::content_type(headers), &body_bytes)
            .map_err(|e| format!("failed to parse request body: {e}"))?,
    };

    // Query string → field bindings (fields not bound by path or body).
    // A malformed query is a client error: reject it rather than silently
    // dropping every query-bound field.
    let query_pairs = request::parse_query(raw_query)?;

    let input_desc = entry.method.input();
    let request_json =
        request::build_request_json(&input_desc, mapping, json_body, path_params, &query_pairs)?;

    let mut message = DynamicMessage::deserialize(input_desc, request_json)
        .map_err(|e| format!("failed to decode request: {e}"))?;
    match &entry.request_body {
        RequestBody::Parsed(_) => {}
        RequestBody::RawRoot => {
            httpbody::fill(&mut message, request_content_type(headers)?, body_bytes);
        }
        RequestBody::RawField(field, http_body) => {
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

/// Extract the route entries of every HTTP binding of every unary and
/// server-streaming RPC. Client-streaming RPCs have no HTTP mapping.
fn extract_routes(pool: &DescriptorPool) -> Vec<RouteEntry> {
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
            if method.is_client_streaming() {
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
/// otherwise.
fn request_body(input: &MessageDescriptor, mapping: request::BodyMapping) -> RequestBody {
    match &mapping {
        request::BodyMapping::Root if httpbody::is_http_body(input) => RequestBody::RawRoot,
        request::BodyMapping::Field(name) => match httpbody::http_body_field(input, name) {
            Some((field, http_body)) => RequestBody::RawField(field, http_body),
            None => RequestBody::Parsed(mapping),
        },
        _ => RequestBody::Parsed(mapping),
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

/// Convert a `google.api.http` path template to axum 0.8 path syntax.
///
/// The proto `{param}` form IS axum 0.8's native capture syntax, so plain
/// single-segment params pass through verbatim. Only field-path templates and
/// bare wildcards need rewriting (axum 0.7 used `:param`; 0.8 uses `{param}`
/// and rejects any segment starting with `:`):
/// - `{name=*}`  (single segment)      -> `{name}`
/// - `{name=**}` (multi-segment) -> `{*name}` (axum catch-all)
/// - bare `*` segment            -> `{wildcardN}`
/// - bare `**` segment           -> `{*wildcardN}` (axum catch-all)
pub fn proto_path_to_axum(path: &str) -> String {
    let mut out = String::with_capacity(path.len());

    let segments = split_top_level(path);
    let last = segments.len().saturating_sub(1);
    for (idx, segment) in segments.iter().enumerate() {
        if idx > 0 {
            out.push('/');
        }
        out.push_str(&convert_segment(segment, idx, idx == last));
    }

    out
}

/// Split a path on `/` boundaries that are NOT inside a `{...}` brace span.
///
/// google.api.http field templates can embed slashes inside a single capture
/// (e.g. the AIP-127 resource name `{name=shelves/*/books/*}`), so a naive
/// `str::split('/')` would fracture the brace span into invalid fragments.
/// Tracking brace depth keeps each capture intact.
fn split_top_level(path: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;

    for (i, ch) in path.char_indices() {
        match ch {
            '{' => depth += 1,
            // Decrement only on a matched brace; a stray `}` (malformed input)
            // is treated as a literal rather than driving depth negative.
            '}' if depth > 0 => depth -= 1,
            '/' if depth == 0 => {
                segments.push(&path[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    segments.push(&path[start..]);
    segments
}

/// Convert a single top-level path segment from proto template to axum 0.8 form.
///
/// `is_last` indicates the terminal segment: axum permits a catch-all capture
/// (`{*name}`) only there, so catch-alls in any other position must degrade.
fn convert_segment(segment: &str, idx: usize, is_last: bool) -> String {
    if let Some(inner) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        // Brace capture, possibly with a `name=template` field path.
        if let Some((name, template)) = inner.split_once('=') {
            return match template {
                // Single-segment field path collapses to a plain capture.
                "*" => format!("{{{name}}}"),
                // Multi-segment catch-all maps to axum's `{*name}` (terminal only).
                "**" => catch_all(name, is_last),
                // Templates with interspersed literals (`{name=shelves/*/books/*}`)
                // have no faithful axum form: axum cannot bind literal segments
                // into one capture. Collapse to a catch-all so routing stays
                // deterministic and the field still binds to the matched tail,
                // and warn so the limitation surfaces instead of mis-routing.
                _ => {
                    tracing::warn!(
                        template = %inner,
                        "google.api.http multi-segment field template is not fully \
                         supported; routing it as a catch-all capture"
                    );
                    catch_all(name, is_last)
                }
            };
        }
        // Plain `{name}` is already valid axum 0.8 syntax.
        return format!("{{{inner}}}");
    }

    // Bare wildcards: name them by position so multiple wildcards never collide.
    match segment {
        "**" => catch_all(&format!("wildcard{idx}"), is_last),
        "*" => format!("{{wildcard{idx}}}"),
        literal => literal.to_string(),
    }
}

/// Emit an axum catch-all `{*name}` when `is_last`, else degrade to a
/// single-segment `{name}` capture.
///
/// axum accepts a catch-all only in the final path segment; a mid-path
/// `{*name}` is rejected at `Router::route()`. A non-terminal catch-all comes
/// from a malformed or unsupported google.api.http template, so we degrade
/// (capturing one segment) and warn rather than panic the whole router.
fn catch_all(name: &str, is_last: bool) -> String {
    if is_last {
        format!("{{*{name}}}")
    } else {
        tracing::warn!(
            capture = %name,
            "catch-all in a non-terminal path segment is unrepresentable in axum; \
             degrading to a single-segment capture"
        );
        format!("{{{name}}}")
    }
}

#[cfg(test)]
mod tests;
