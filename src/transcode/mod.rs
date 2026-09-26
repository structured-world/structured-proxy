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
use std::sync::Arc;
use tonic::client::Grpc;

use crate::config::AliasConfig;
use error::{ErrorDetailsPolicy, StatusDetails};

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
    /// Renderer for the status details of this route's errors; `None` when the
    /// error-details policy switches them off for the route.
    error_details: Option<Arc<StatusDetails>>,
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
/// Takes a `DescriptorPool`, optional path aliases from config and the policy
/// deciding which routes return `google.rpc.Status` details in their error
/// bodies. Returns an axum Router that transcodes REST requests to gRPC calls.
pub fn routes<S: TranscodeState>(
    pool: &DescriptorPool,
    aliases: &[AliasConfig],
    error_details: &ErrorDetailsPolicy,
) -> Router<S> {
    let bindings = route_bindings(pool, aliases);
    if bindings.is_empty() {
        tracing::warn!("No HTTP-annotated RPCs found in proto descriptors");
        return Router::new();
    }

    tracing::info!("Registering {} transcoded REST→gRPC routes", bindings.len());

    // One renderer shared by every route that returns details, built only if
    // at least one does.
    let mut status_details: Option<Arc<StatusDetails>> = None;
    let mut router: Router<S> = Router::new();
    for mut binding in bindings {
        if error_details.enabled_for(&binding.axum_path) {
            let renderer = status_details.get_or_insert_with(|| Arc::new(StatusDetails::new(pool)));
            binding.entry.error_details = Some(Arc::clone(renderer));
        }
        let method = binding.entry.http_method;
        let entry = Arc::new(binding.entry);
        let method_router: MethodRouter<S> = if binding.streaming {
            let handler = move |proxy_state: State<S>,
                                headers: HeaderMap,
                                path_params: Path<std::collections::HashMap<String, String>>,
                                raw_query: RawQuery,
                                body: axum::body::Bytes| {
                streaming_handler(proxy_state, headers, path_params, raw_query, body, entry)
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
    Path(path_params): Path<std::collections::HashMap<String, String>>,
    RawQuery(raw_query): RawQuery,
    body_bytes: axum::body::Bytes,
    entry: std::sync::Arc<RouteEntry>,
) -> Response {
    let channel = proxy_state.grpc_channel();

    let request_msg = match decode_request(
        &entry,
        &headers,
        &path_params,
        raw_query.as_deref(),
        &body_bytes,
    ) {
        Ok(msg) => msg,
        Err(message) => return bad_request(&entry, message),
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
        let status = tonic::Status::unavailable(format!("gRPC upstream not ready: {e}"));
        return error::status_to_response(&status, entry.error_details.as_deref());
    }

    let use_sse = wants_sse(&headers);

    match grpc_client
        .server_streaming(grpc_request, grpc_path, grpc_codec)
        .await
    {
        Ok(response) => {
            let stream = response.into_inner();
            // The terminal frame renders like the unary error body. The
            // closure takes over this request's route handle, so the stream
            // keeps it alive without another refcount.
            let render_error = move |status: &tonic::Status| {
                error::error_body(status, entry.error_details.as_deref())
            };
            if use_sse {
                sse_response(stream, render_error, proxy_state.sse_keep_alive_secs())
            } else {
                ndjson_response(stream, render_error)
            }
        }
        Err(status) => error::status_to_response(&status, entry.error_details.as_deref()),
    }
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

/// Type URL marking the terminal error line of an NDJSON stream. A data line is
/// the ProtoJSON of a response message, which carries a top-level `@type` only
/// when the RPC streams `google.protobuf.Any` itself.
const STATUS_TYPE_URL: &str = "type.googleapis.com/google.rpc.Status";

/// Turn a gRPC message stream into a stream of serialized JSON frames, stopping
/// after the first error so error frames are unambiguously terminal.
///
/// Both a gRPC `Status` (rendered by `render_error`) and a per-message
/// serialization failure become a terminal [`StreamFrame::Error`]; downstream
/// messages the upstream might still emit are dropped rather than streamed past
/// the error.
fn json_frames<St, R>(
    stream: St,
    render_error: R,
) -> impl futures::Stream<Item = StreamFrame> + Send + 'static
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + 'static,
    R: Fn(&tonic::Status) -> serde_json::Value + Send + 'static,
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
                    StreamFrame::Error(render_error(&tonic::Status::internal(format!(
                        "serialization error: {e}"
                    ))))
                }
            },
            Err(status) => {
                *stopped = true;
                StreamFrame::Error(render_error(&status))
            }
        };
        futures::future::ready(Some(frame))
    })
}

/// Build an NDJSON (`application/x-ndjson`) streaming response.
fn ndjson_response<St, R>(stream: St, render_error: R) -> Response
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + 'static,
    R: Fn(&tonic::Status) -> serde_json::Value + Send + 'static,
{
    // Data and error frames are both JSON lines. The error line is the last
    // one, and carries `@type: google.rpc.Status` next to the error body so a
    // reader can tell it from a data line without guessing from its fields.
    let byte_stream = json_frames(stream, render_error).map(|frame| {
        let mut line = match frame {
            StreamFrame::Data(s) => s,
            StreamFrame::Error(mut body) => {
                if let Some(fields) = body.as_object_mut() {
                    fields.insert("@type".into(), STATUS_TYPE_URL.into());
                }
                body.to_string()
            }
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
fn sse_response<St, R>(stream: St, render_error: R, keep_alive_secs: u64) -> Response
where
    St: futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send + 'static,
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

/// Map the HTTP request onto the RPC's input message: path parameters, query
/// parameters and the route's `body` rule. Unary and server-streaming routes
/// share it, so both bind a request the same way. The error is the message of
/// the 400 the caller answers with, before the upstream is called.
fn decode_request(
    entry: &RouteEntry,
    headers: &HeaderMap,
    path_params: &std::collections::HashMap<String, String>,
    raw_query: Option<&str>,
    body_bytes: &[u8],
) -> Result<DynamicMessage, String> {
    // Only read the body when the rule maps it onto the message.
    let json_body = match entry.body {
        request::BodyMapping::None => serde_json::Value::Null,
        _ => body::parse_body(body::content_type(headers), body_bytes)
            .map_err(|e| format!("failed to parse request body: {e}"))?,
    };

    // Query string → field bindings (fields not bound by path or body).
    // A malformed query is a client error: reject it rather than silently
    // dropping every query-bound field.
    let query_pairs = request::parse_query(raw_query)?;

    let input_desc = entry.method.input();
    let request_json = request::build_request_json(
        &input_desc,
        &entry.body,
        json_body,
        path_params,
        &query_pairs,
    )?;

    DynamicMessage::deserialize(input_desc, request_json)
        .map_err(|e| format!("failed to decode request: {e}"))
}

/// The 400 answer to a request [`decode_request`] could not map, in the same
/// error body the upstream's own errors get on this route.
fn bad_request(entry: &RouteEntry, message: String) -> Response {
    error::status_to_response(
        &tonic::Status::invalid_argument(message),
        entry.error_details.as_deref(),
    )
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

    let request_msg = match decode_request(
        &entry,
        &headers,
        &path_params,
        raw_query.as_deref(),
        &body_bytes,
    ) {
        Ok(msg) => msg,
        Err(message) => return bad_request(&entry, message),
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
        let status = tonic::Status::unavailable(format!("gRPC upstream not ready: {e}"));
        return error::status_to_response(&status, entry.error_details.as_deref());
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
                    error::status_to_response(
                        &tonic::Status::internal("failed to serialize response"),
                        entry.error_details.as_deref(),
                    )
                }
            }
        }
        Err(status) => error::status_to_response(&status, entry.error_details.as_deref()),
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
                    // Decided per mounted path in `routes`.
                    error_details: None,
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
                    // Decided per mounted path in `routes`.
                    error_details: None,
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
mod tests;
