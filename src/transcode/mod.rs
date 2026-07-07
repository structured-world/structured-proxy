//! REST→gRPC transcoding layer.
//!
//! Reads `google.api.http` annotations from proto service descriptors
//! and builds axum routes that proxy JSON/form requests to gRPC upstream.
//!
//! Generic: works with ANY proto descriptor set. No product-specific code.

pub mod body;
pub mod codec;
pub mod error;
pub mod metadata;
pub mod request;

use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put, MethodRouter};
use axum::{Json, Router};
use futures::StreamExt;
use prost_reflect::{DescriptorPool, DynamicMessage, MethodDescriptor, SerializeOptions};
use tonic::client::Grpc;

use crate::config::AliasConfig;

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

/// Route entry extracted from proto HTTP annotations.
#[derive(Debug, Clone)]
struct RouteEntry {
    /// HTTP path pattern (e.g., "/v1/auth/opaque/login/start").
    http_path: String,
    /// HTTP method (GET, POST, PUT, PATCH, DELETE).
    http_method: HttpMethod,
    /// gRPC path (e.g., "/sid.v1.AuthService/OpaqueLoginStart"), parsed once at
    /// route-build time so each request clones a cheap `Bytes` refcount.
    grpc_path: axum::http::uri::PathAndQuery,
    /// Method descriptor for input/output message resolution.
    method: MethodDescriptor,
    /// How the request body maps onto the gRPC request message.
    body: request::BodyMapping,
    /// Optional response subfield to return as the HTTP body (`response_body`).
    response_body: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    /// The uppercase HTTP method token (e.g. `"GET"`).
    fn as_str(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

/// Build transcoded REST→gRPC routes from a descriptor pool.
///
/// Takes a `DescriptorPool` and optional path aliases from config.
/// Returns an axum Router that transcodes REST requests to gRPC calls.
pub fn routes<S: TranscodeState>(pool: &DescriptorPool, aliases: &[AliasConfig]) -> Router<S> {
    let bindings = route_bindings(pool, aliases);
    if bindings.is_empty() {
        tracing::warn!("No HTTP-annotated RPCs found in proto descriptors");
        return Router::new();
    }

    tracing::info!("Registering {} transcoded REST→gRPC routes", bindings.len());

    let mut router: Router<S> = Router::new();
    for binding in bindings {
        let method = binding.entry.http_method;
        let entry = std::sync::Arc::new(binding.entry);
        let method_router: MethodRouter<S> = if binding.streaming {
            let handler = move |proxy_state: State<S>, headers: HeaderMap| {
                streaming_handler(proxy_state, headers, entry)
            };
            match method {
                HttpMethod::Get => get(handler),
                HttpMethod::Post => post(handler),
                // route_bindings only yields GET/POST streaming bindings.
                _ => unreachable!("streaming routes are GET/POST only"),
            }
        } else {
            let handler = move |proxy_state: State<S>,
                                headers: HeaderMap,
                                path_params: Path<std::collections::HashMap<String, String>>,
                                raw_query: RawQuery,
                                body: axum::body::Bytes| {
                transcode_handler(proxy_state, headers, path_params, raw_query, body, entry)
            };
            match method {
                HttpMethod::Get => get(handler),
                HttpMethod::Post => post(handler),
                HttpMethod::Put => put(handler),
                HttpMethod::Patch => patch(handler),
                HttpMethod::Delete => delete(handler),
            }
        };
        router = router.route(&binding.axum_path, method_router);
    }

    router
}

/// One transcode route to mount: the RPC entry that serves it, the axum path to
/// register it at, and whether it is the server-streaming variant.
struct RouteBinding {
    entry: RouteEntry,
    axum_path: String,
    streaming: bool,
}

/// The single source of truth for what [`routes`] mounts: unary RPCs, their
/// config aliases, and server-streaming RPCs. Both [`routes`] (to build handlers)
/// and [`route_paths`] (to enumerate paths for collision checks) consume this, so
/// the mounted set and the enumerated set cannot drift apart.
fn route_bindings(pool: &DescriptorPool, aliases: &[AliasConfig]) -> Vec<RouteBinding> {
    let mut bindings = Vec::new();
    for entry in extract_routes(pool) {
        bindings.push(RouteBinding {
            axum_path: proto_path_to_axum(&entry.http_path),
            entry: entry.clone(),
            streaming: false,
        });
        for alias in aliases {
            if let Some(suffix) = entry.http_path.strip_prefix(&alias.to) {
                if alias.from.ends_with("/{path}") {
                    let prefix = alias.from.trim_end_matches("/{path}");
                    bindings.push(RouteBinding {
                        axum_path: format!("{prefix}{suffix}"),
                        entry: entry.clone(),
                        streaming: false,
                    });
                }
            }
        }
    }
    for entry in extract_streaming_routes(pool) {
        if matches!(entry.http_method, HttpMethod::Get | HttpMethod::Post) {
            bindings.push(RouteBinding {
                axum_path: proto_path_to_axum(&entry.http_path),
                entry,
                streaming: true,
            });
        }
    }
    bindings
}

/// The axum paths [`routes`] would register for this pool and aliases.
///
/// Mirrors the registration in [`routes`] (unary RPCs, their config aliases, and
/// server-streaming RPCs) without building handlers, so callers can detect route
/// collisions before mounting additional routes (e.g. a forward-auth endpoint).
///
/// Each entry is `(method, path)` where `method` is the uppercase HTTP token, so
/// callers can distinguish same-path/different-method routes from real conflicts.
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

/// Serialize one streamed gRPC message to a compact JSON string.
fn message_to_json_string(msg: &DynamicMessage, opts: &SerializeOptions) -> Result<String, String> {
    let value = msg
        .serialize_with_options(serde_json::value::Serializer, opts)
        .map_err(|e| e.to_string())?;
    serde_json::to_string(&value).map_err(|e| e.to_string())
}

/// Terminal error frame for a stream that failed mid-flight. Shared by the
/// NDJSON and SSE paths so a client sees the same shape in either format.
fn stream_error_json(status: &tonic::Status) -> serde_json::Value {
    serde_json::json!({
        "error": error::grpc_code_name(status.code()),
        "message": status.message(),
        "code": status.code() as i32,
    })
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

/// Handler for server-streaming RPCs.
///
/// Returns Server-Sent Events when the client sends `Accept: text/event-stream`,
/// otherwise newline-delimited JSON (NDJSON). In both formats a gRPC error
/// mid-stream is delivered as an explicit terminal frame before the stream is
/// closed cleanly, rather than truncating the HTTP body.
async fn streaming_handler<S: TranscodeState>(
    State(proxy_state): State<S>,
    headers: HeaderMap,
    entry: std::sync::Arc<RouteEntry>,
) -> Response {
    let channel = proxy_state.grpc_channel();

    let input_desc = entry.method.input();
    let request_msg = DynamicMessage::new(input_desc);

    let grpc_metadata =
        metadata::http_headers_to_grpc_metadata(&headers, proxy_state.forwarded_headers());
    let mut grpc_request = tonic::Request::new(request_msg);
    *grpc_request.metadata_mut() = grpc_metadata;
    metadata::apply_request_deadline(&mut grpc_request, &headers);

    let output_desc = entry.method.output();
    let grpc_codec = codec::DynamicCodec::new(output_desc.clone());
    let grpc_path = entry.grpc_path.clone();

    let mut grpc_client = Grpc::new(channel);
    if let Err(e) = grpc_client.ready().await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "UNAVAILABLE",
                "message": format!("gRPC upstream not ready: {e}"),
            })),
        )
            .into_response();
    }

    let use_sse = wants_sse(&headers);

    match grpc_client
        .server_streaming(grpc_request, grpc_path, grpc_codec)
        .await
    {
        Ok(response) => {
            let stream = response.into_inner();
            if use_sse {
                sse_response(stream, proxy_state.sse_keep_alive_secs())
            } else {
                ndjson_response(stream)
            }
        }
        Err(status) => error::status_to_response(status),
    }
}

/// One JSON frame of a streaming response, already serialized.
///
/// `Error` is terminal: [`json_frames`] stops the stream right after yielding
/// it, so an error frame is always the last thing a client sees regardless of
/// whether it came from a gRPC status or a serialization failure.
enum StreamFrame {
    Data(String),
    Error(String),
}

/// Turn a gRPC message stream into a stream of serialized JSON frames, stopping
/// after the first error so error frames are unambiguously terminal.
///
/// Both a gRPC `Status` and a per-message serialization failure become a
/// terminal [`StreamFrame::Error`]; downstream messages the upstream might
/// still emit are dropped rather than streamed past the error.
fn json_frames<St>(stream: St) -> impl futures::Stream<Item = StreamFrame> + Send + 'static
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + 'static,
{
    let opts = response_serialize_options();
    stream.scan(false, move |stopped, result| {
        if *stopped {
            return futures::future::ready(None);
        }
        let frame = match result {
            Ok(msg) => match message_to_json_string(&msg, &opts) {
                Ok(s) => StreamFrame::Data(s),
                Err(e) => {
                    *stopped = true;
                    StreamFrame::Error(
                        serde_json::json!({
                            "error": "INTERNAL",
                            "message": format!("serialization error: {e}"),
                        })
                        .to_string(),
                    )
                }
            },
            Err(status) => {
                *stopped = true;
                StreamFrame::Error(stream_error_json(&status).to_string())
            }
        };
        futures::future::ready(Some(frame))
    })
}

/// Build an NDJSON (`application/x-ndjson`) streaming response.
fn ndjson_response<St>(stream: St) -> Response
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + 'static,
{
    // Data and error frames are both JSON lines; an error is distinguished by
    // its `error` field and by being the final line (see `json_frames`).
    let byte_stream = json_frames(stream).map(|frame| {
        let mut line = match frame {
            StreamFrame::Data(s) | StreamFrame::Error(s) => s,
        };
        line.push('\n');
        Ok::<axum::body::Bytes, std::io::Error>(axum::body::Bytes::from(line))
    });

    let body = axum::body::Body::from_stream(byte_stream);
    // Body framing (chunked on HTTP/1.1, DATA frames on HTTP/2) is chosen by
    // hyper from the protocol version; setting transfer-encoding by hand would
    // be redundant on HTTP/1.1 and illegal on HTTP/2.
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/x-ndjson")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Build a Server-Sent Events (`text/event-stream`) streaming response.
fn sse_response<St>(stream: St, keep_alive_secs: u64) -> Response
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + 'static,
{
    // Terminal errors use the `stream-error` event type, not the reserved
    // `error` type that the browser EventSource dispatches for transport
    // failures — clients listen for it via addEventListener("stream-error").
    let event_stream = json_frames(stream).map(|frame| {
        let event = match frame {
            StreamFrame::Data(s) => Event::default().data(s),
            StreamFrame::Error(s) => Event::default().event("stream-error").data(s),
        };
        Ok::<Event, std::convert::Infallible>(event)
    });

    Sse::new(event_stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(keep_alive_secs)))
        .into_response()
}

/// Generic transcoding handler.
async fn transcode_handler<S: TranscodeState>(
    State(proxy_state): State<S>,
    headers: HeaderMap,
    Path(path_params): Path<std::collections::HashMap<String, String>>,
    RawQuery(raw_query): RawQuery,
    body_bytes: axum::body::Bytes,
    entry: std::sync::Arc<RouteEntry>,
) -> Response {
    let channel = proxy_state.grpc_channel();

    // Only read the body when the rule maps it onto the message.
    let json_body = match entry.body {
        request::BodyMapping::None => serde_json::Value::Null,
        _ => {
            let ct = body::content_type(&headers);
            match body::parse_body(ct, &body_bytes) {
                Ok(v) => v,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": "INVALID_ARGUMENT",
                            "message": format!("failed to parse request body: {e}"),
                        })),
                    )
                        .into_response();
                }
            }
        }
    };

    // Query string → field bindings (fields not bound by path or body).
    // A malformed query is a client error: reject it rather than silently
    // dropping every query-bound field.
    let query_pairs = match request::parse_query(raw_query.as_deref()) {
        Ok(pairs) => pairs,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "INVALID_ARGUMENT",
                    "message": e,
                })),
            )
                .into_response();
        }
    };

    let input_desc = entry.method.input();
    let request_json = match request::build_request_json(
        &input_desc,
        &entry.body,
        json_body,
        &path_params,
        &query_pairs,
    ) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "INVALID_ARGUMENT",
                    "message": e,
                })),
            )
                .into_response();
        }
    };

    let request_msg = match DynamicMessage::deserialize(input_desc, request_json) {
        Ok(msg) => msg,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "INVALID_ARGUMENT",
                    "message": format!("failed to decode request: {e}"),
                })),
            )
                .into_response();
        }
    };

    let grpc_metadata =
        metadata::http_headers_to_grpc_metadata(&headers, proxy_state.forwarded_headers());
    let mut grpc_request = tonic::Request::new(request_msg);
    *grpc_request.metadata_mut() = grpc_metadata;
    metadata::apply_request_deadline(&mut grpc_request, &headers);

    let output_desc = entry.method.output();
    let grpc_codec = codec::DynamicCodec::new(output_desc.clone());
    let grpc_path = entry.grpc_path.clone();

    let mut grpc_client = Grpc::new(channel);
    if let Err(e) = grpc_client.ready().await {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "UNAVAILABLE",
                "message": format!("gRPC upstream not ready: {e}"),
            })),
        )
            .into_response();
    }

    match grpc_client.unary(grpc_request, grpc_path, grpc_codec).await {
        Ok(response) => {
            let response_msg = response.into_inner();
            let serialize_opts = response_serialize_options();
            match response_msg
                .serialize_with_options(serde_json::value::Serializer, &serialize_opts)
            {
                Ok(json_value) => {
                    // `response_body` returns just that subfield as the HTTP body.
                    let out = match &entry.response_body {
                        Some(path) => request::extract_response_body(&json_value, path)
                            .unwrap_or_else(|| {
                                tracing::warn!(
                                    response_body = %path,
                                    "configured response_body path not found in response; \
                                     returning null"
                                );
                                serde_json::Value::Null
                            }),
                        None => json_value,
                    };
                    (StatusCode::OK, Json(out)).into_response()
                }
                Err(e) => {
                    tracing::error!("Failed to serialize gRPC response: {e}");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "error": "INTERNAL",
                            "message": "failed to serialize response",
                        })),
                    )
                        .into_response()
                }
            }
        }
        Err(status) => error::status_to_response(status),
    }
}

/// Extract HTTP route entries from proto descriptors.
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
            if method.is_client_streaming() || method.is_server_streaming() {
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

            for binding in extract_http_bindings(&method, &http_ext) {
                entries.push(RouteEntry {
                    http_path: binding.http_path,
                    http_method: binding.http_method,
                    grpc_path: grpc_path.clone(),
                    method: method.clone(),
                    body: binding.body,
                    response_body: binding.response_body,
                });
            }
        }
    }

    entries
}

/// Extract server-streaming HTTP route entries.
fn extract_streaming_routes(pool: &DescriptorPool) -> Vec<RouteEntry> {
    let http_ext = match pool.get_extension_by_name("google.api.http") {
        Some(ext) => ext,
        None => return Vec::new(),
    };

    let mut entries = Vec::new();

    for service in pool.services() {
        for method in service.methods() {
            if !method.is_server_streaming() || method.is_client_streaming() {
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

            for binding in extract_http_bindings(&method, &http_ext) {
                tracing::info!(
                    "Registering streaming route: {} {} → {}",
                    match binding.http_method {
                        HttpMethod::Get => "GET",
                        HttpMethod::Post => "POST",
                        _ => "OTHER",
                    },
                    binding.http_path,
                    grpc_path
                );
                entries.push(RouteEntry {
                    http_path: binding.http_path,
                    http_method: binding.http_method,
                    grpc_path: grpc_path.clone(),
                    method: method.clone(),
                    body: binding.body,
                    response_body: binding.response_body,
                });
            }
        }
    }

    entries
}

/// A single HTTP binding parsed from a `google.api.http` rule.
struct HttpBinding {
    http_method: HttpMethod,
    http_path: String,
    body: request::BodyMapping,
    response_body: Option<String>,
}

/// Extract all HTTP bindings (the primary rule plus any `additional_bindings`)
/// from a method's `google.api.http` extension.
fn extract_http_bindings(
    method: &MethodDescriptor,
    http_ext: &prost_reflect::ExtensionDescriptor,
) -> Vec<HttpBinding> {
    let options = method.options();
    if !options.has_extension(http_ext) {
        return Vec::new();
    }

    let prost_reflect::Value::Message(rule_msg) = options.get_extension(http_ext).into_owned()
    else {
        return Vec::new();
    };

    collect_bindings(&rule_msg)
}

/// Collect the primary binding plus every `additional_bindings` entry from an
/// `HttpRule` message.
fn collect_bindings(rule_msg: &DynamicMessage) -> Vec<HttpBinding> {
    let mut bindings = Vec::new();
    if let Some(binding) = parse_http_rule(rule_msg) {
        bindings.push(binding);
    }

    // additional_bindings is a repeated HttpRule; each carries its own
    // method/path/body. The proto forbids nesting them further.
    if let Some(field) = rule_msg.get_field_by_name("additional_bindings") {
        if let prost_reflect::Value::List(list) = field.into_owned() {
            for item in list {
                if let prost_reflect::Value::Message(sub) = item {
                    if let Some(binding) = parse_http_rule(&sub) {
                        bindings.push(binding);
                    }
                }
            }
        }
    }

    bindings
}

/// Parse a single `HttpRule` message into a binding (method+path required).
fn parse_http_rule(rule_msg: &DynamicMessage) -> Option<HttpBinding> {
    let (http_method, http_path) = [
        ("get", HttpMethod::Get),
        ("post", HttpMethod::Post),
        ("put", HttpMethod::Put),
        ("delete", HttpMethod::Delete),
        ("patch", HttpMethod::Patch),
    ]
    .into_iter()
    .find_map(
        |(name, http_method)| match rule_msg.get_field_by_name(name)?.into_owned() {
            prost_reflect::Value::String(path) if !path.is_empty() => Some((http_method, path)),
            _ => None,
        },
    )?;

    let body = rule_msg
        .get_field_by_name("body")
        .and_then(|v| match v.into_owned() {
            prost_reflect::Value::String(s) => Some(request::BodyMapping::parse(&s)),
            _ => None,
        })
        .unwrap_or(request::BodyMapping::None);

    let response_body =
        rule_msg
            .get_field_by_name("response_body")
            .and_then(|v| match v.into_owned() {
                prost_reflect::Value::String(s) if !s.is_empty() => Some(s),
                _ => None,
            });

    Some(HttpBinding {
        http_method,
        http_path,
        body,
        response_body,
    })
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
mod tests {
    use super::*;

    /// Build a standalone `HttpRule`-shaped descriptor (self-referential
    /// `additional_bindings`) so the binding parser can be tested without the
    /// google.api extension wiring.
    fn http_rule_descriptor() -> prost_reflect::MessageDescriptor {
        use prost_reflect::prost::Message;
        use prost_reflect::prost_types::{
            field_descriptor_proto::{Label, Type},
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        let str_field = |name: &str, num: i32| FieldDescriptorProto {
            name: Some(name.to_string()),
            number: Some(num),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::String as i32),
            ..Default::default()
        };
        let rule = DescriptorProto {
            name: Some("HttpRule".to_string()),
            field: vec![
                str_field("get", 2),
                str_field("put", 3),
                str_field("post", 4),
                str_field("delete", 5),
                str_field("patch", 6),
                str_field("body", 7),
                str_field("response_body", 12),
                FieldDescriptorProto {
                    name: Some("additional_bindings".to_string()),
                    number: Some(11),
                    label: Some(Label::Repeated as i32),
                    r#type: Some(Type::Message as i32),
                    type_name: Some(".gapi.HttpRule".to_string()),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("http.proto".to_string()),
            package: Some("gapi".to_string()),
            message_type: vec![rule],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };
        let pool = DescriptorPool::decode(fds.encode_to_vec().as_slice()).unwrap();
        pool.get_message_by_name("gapi.HttpRule").unwrap()
    }

    #[test]
    fn collect_bindings_reads_body_response_and_additional() {
        let desc = http_rule_descriptor();

        // additional_bindings entry: POST /v1/items with whole-body mapping.
        let mut extra = DynamicMessage::new(desc.clone());
        extra.set_field_by_name("post", prost_reflect::Value::String("/v1/items".into()));
        extra.set_field_by_name("body", prost_reflect::Value::String("*".into()));

        // primary rule: GET /v1/items/{id}, returns only the `result` subfield.
        let mut rule = DynamicMessage::new(desc);
        rule.set_field_by_name("get", prost_reflect::Value::String("/v1/items/{id}".into()));
        rule.set_field_by_name(
            "response_body",
            prost_reflect::Value::String("result".into()),
        );
        rule.set_field_by_name(
            "additional_bindings",
            prost_reflect::Value::List(vec![prost_reflect::Value::Message(extra)]),
        );

        let bindings = collect_bindings(&rule);
        assert_eq!(bindings.len(), 2);

        // Primary: GET, no body, response_body = result.
        assert!(matches!(bindings[0].http_method, HttpMethod::Get));
        assert_eq!(bindings[0].http_path, "/v1/items/{id}");
        assert_eq!(bindings[0].body, request::BodyMapping::None);
        assert_eq!(bindings[0].response_body.as_deref(), Some("result"));

        // Additional: POST, whole-body mapping, no response_body.
        assert!(matches!(bindings[1].http_method, HttpMethod::Post));
        assert_eq!(bindings[1].http_path, "/v1/items");
        assert_eq!(bindings[1].body, request::BodyMapping::Root);
        assert_eq!(bindings[1].response_body, None);
    }

    #[test]
    fn test_proto_path_to_axum() {
        // axum 0.8: proto `{param}` IS the native capture syntax, pass through verbatim.
        assert_eq!(proto_path_to_axum("/v1/profiles/{id}"), "/v1/profiles/{id}");
        assert_eq!(
            proto_path_to_axum("/v1/admin/profiles/{profile_id}/metadata/{key}"),
            "/v1/admin/profiles/{profile_id}/metadata/{key}"
        );
        assert_eq!(proto_path_to_axum("/v1/auth/login"), "/v1/auth/login");
    }

    #[test]
    fn test_proto_path_to_axum_wildcards() {
        // `{name=*}` single-segment field path collapses to a plain capture.
        assert_eq!(proto_path_to_axum("/v1/{name=*}"), "/v1/{name}");
        // `{name=**}` multi-segment catch-all maps to axum's `{*name}`.
        assert_eq!(
            proto_path_to_axum("/v1/files/{path=**}"),
            "/v1/files/{*path}"
        );
        // Bare wildcards get position-named captures so they never collide.
        // Index is the segment position after splitting on `/` (leading "" = 0).
        assert_eq!(proto_path_to_axum("/v1/*/items"), "/v1/{wildcard2}/items");
        assert_eq!(proto_path_to_axum("/v1/files/**"), "/v1/files/{*wildcard3}");
    }

    #[test]
    fn non_terminal_catch_all_degrades_to_single_capture() {
        // A catch-all `{*name}` is only valid in axum's LAST path segment.
        // An unsupported/multi-segment field template in a NON-terminal position
        // (`/v1/{name=projects/*}/topics`) must NOT emit a mid-path catch-all —
        // axum rejects `/v1/{*name}/topics` at `Router::route()`. It degrades to
        // a single-segment capture instead.
        assert_eq!(
            proto_path_to_axum("/v1/{name=projects/*}/topics"),
            "/v1/{name}/topics"
        );
        let path = proto_path_to_axum("/v1/{name=projects/*}/topics");
        let _router: Router<()> = Router::new().route(&path, get(|| async { "ok" }));

        // The same guard applies to an explicit `**` template in non-terminal
        // position and a terminal one still yields a real catch-all.
        assert_eq!(proto_path_to_axum("/v1/{rest=**}/tail"), "/v1/{rest}/tail");
        assert_eq!(
            proto_path_to_axum("/v1/files/{rest=**}"),
            "/v1/files/{*rest}"
        );
    }

    #[test]
    fn multi_segment_field_template_does_not_fracture() {
        // google.api.http resource-name templates (AIP-127) embed slashes
        // inside a SINGLE brace span: `{name=shelves/*/books/*}`. Splitting on
        // `/` before brace parsing fractured this into invalid fragments and
        // produced a mangled axum path that panicked at `Router::route()`.
        // It must collapse to a single catch-all capture instead.
        assert_eq!(
            proto_path_to_axum("/v1/{name=shelves/*/books/*}"),
            "/v1/{*name}"
        );
        // And the produced path must actually register on axum 0.8.
        let path = proto_path_to_axum("/v1/{name=shelves/*/books/*}");
        let _router: Router<()> = Router::new().route(&path, get(|| async { "ok" }));
    }

    /// Regression for the axum 0.7→0.8 migration bug: `proto_path_to_axum`
    /// emitted `:id` syntax, which axum 0.8 rejects at `Router::route()` with
    /// a startup panic ("Path segments must not start with `:`"). Building the
    /// router over a brace-param path must NOT panic. Pre-fix this panicked.
    #[test]
    fn router_builds_with_brace_path_params_on_axum_0_8() {
        let axum_path = proto_path_to_axum("/v1/profiles/{id}");
        let _router: Router<()> = Router::new().route(&axum_path, get(|| async { "ok" }));

        // Deeper nesting and a catch-all also route without panicking.
        let nested = proto_path_to_axum("/v1/admin/profiles/{profile_id}/metadata/{key}");
        let catch_all = proto_path_to_axum("/v1/files/{path=**}");
        let _router: Router<()> = Router::new()
            .route(&nested, get(|| async { "ok" }))
            .route(&catch_all, get(|| async { "ok" }));
    }

    /// `Item { name: "alice", count: 42 }` — default fixture for the
    /// serialization helpers.
    fn item_message() -> DynamicMessage {
        item_message_named("alice", 42)
    }

    /// Build an `Item { name, count }` message from a freshly-decoded
    /// descriptor pool, used to exercise the streaming serialization helpers.
    fn item_message_named(name: &str, count: i64) -> DynamicMessage {
        use prost_reflect::prost::Message;
        use prost_reflect::prost_types::{
            field_descriptor_proto::{Label, Type},
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        };

        let item = DescriptorProto {
            name: Some("Item".to_string()),
            field: vec![
                FieldDescriptorProto {
                    name: Some("name".to_string()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::String as i32),
                    ..Default::default()
                },
                FieldDescriptorProto {
                    name: Some("count".to_string()),
                    number: Some(2),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::Int64 as i32),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("item.proto".to_string()),
            package: Some("test.v1".to_string()),
            message_type: vec![item],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let mut bytes = Vec::new();
        FileDescriptorSet { file: vec![file] }
            .encode(&mut bytes)
            .unwrap();
        let pool = DescriptorPool::decode(bytes.as_slice()).unwrap();
        let desc = pool.get_message_by_name("test.v1.Item").unwrap();

        let mut msg = DynamicMessage::new(desc);
        msg.set_field_by_name("name", prost_reflect::Value::String(name.to_string()));
        msg.set_field_by_name("count", prost_reflect::Value::I64(count));
        msg
    }

    /// Collect a streaming response body into a single UTF-8 string.
    async fn collect_body(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn ndjson_error_frame_is_terminal() {
        // A gRPC error mid-stream must be the LAST frame: messages the upstream
        // would yield after the error are dropped, so the error line is an
        // unambiguous end-of-stream signal rather than a mid-stream marker.
        let items = vec![
            Ok(item_message_named("alice", 1)),
            Err(tonic::Status::internal("boom")),
            Ok(item_message_named("bob", 2)),
        ];
        let body = collect_body(ndjson_response(futures::stream::iter(items))).await;
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "stream must stop after the error frame");
        assert!(lines[0].contains("alice"));
        assert!(lines[1].contains("INTERNAL") && lines[1].contains("boom"));
        assert!(!body.contains("bob"), "post-error message must be dropped");
    }

    #[tokio::test]
    async fn sse_error_uses_distinct_event_name() {
        // The terminal error is sent as `event: stream-error`, not the reserved
        // `error` type that collides with the browser EventSource onerror.
        let items = vec![
            Ok(item_message_named("alice", 1)),
            Err(tonic::Status::permission_denied("nope")),
            Ok(item_message_named("bob", 2)),
        ];
        let body = collect_body(sse_response(futures::stream::iter(items), 15)).await;
        assert!(body.contains("stream-error"));
        assert!(body.contains("PERMISSION_DENIED"));
        assert!(!body.contains("bob"), "post-error message must be dropped");
    }

    #[test]
    fn wants_sse_detects_event_stream_accept() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/event-stream".parse().unwrap());
        assert!(wants_sse(&headers));
    }

    #[test]
    fn wants_sse_matches_within_list_and_ignores_params() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "accept",
            "application/json, text/event-stream;q=0.9".parse().unwrap(),
        );
        assert!(wants_sse(&headers));
    }

    #[test]
    fn wants_sse_false_for_json_and_missing() {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/json".parse().unwrap());
        assert!(!wants_sse(&headers));
        assert!(!wants_sse(&HeaderMap::new()));
    }

    #[test]
    fn wants_sse_rejects_explicit_q_zero() {
        // RFC 7231 §5.3.1: `q=0` means the media type is explicitly NOT
        // acceptable, so it must not select the SSE path.
        let mut headers = HeaderMap::new();
        headers.insert("accept", "text/event-stream;q=0".parse().unwrap());
        assert!(!wants_sse(&headers));
    }

    #[test]
    fn wants_sse_honors_second_accept_header_line() {
        // A client may send multiple `Accept` header lines; the negotiation
        // must consider all of them, not just the first.
        let mut headers = HeaderMap::new();
        headers.append("accept", "application/json".parse().unwrap());
        headers.append("accept", "text/event-stream".parse().unwrap());
        assert!(wants_sse(&headers));
    }

    #[test]
    fn message_to_json_string_stringifies_64bit() {
        let opts = response_serialize_options();
        let json = message_to_json_string(&item_message(), &opts).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["name"], "alice");
        // 64-bit integers are stringified to survive JS number precision limits.
        assert_eq!(value["count"], "42");
    }

    #[test]
    fn ndjson_response_omits_manual_transfer_encoding() {
        // hyper picks the framing per protocol version; a hand-set
        // transfer-encoding would be illegal on HTTP/2.
        let resp = ndjson_response(futures::stream::empty::<
            Result<DynamicMessage, tonic::Status>,
        >());
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-ndjson"
        );
        assert!(resp.headers().get("transfer-encoding").is_none());
    }

    #[test]
    fn stream_error_json_carries_grpc_code_name() {
        let status = tonic::Status::permission_denied("nope");
        let value = stream_error_json(&status);
        assert_eq!(value["error"], "PERMISSION_DENIED");
        assert_eq!(value["message"], "nope");
        assert_eq!(value["code"], tonic::Code::PermissionDenied as i32);
    }
}
