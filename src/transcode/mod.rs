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

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
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
}

impl TranscodeState for crate::ProxyState {
    fn grpc_channel(&self) -> tonic::transport::Channel {
        self.grpc_channel.clone()
    }
    fn forwarded_headers(&self) -> &[String] {
        &self.forwarded_headers
    }
}

/// Route entry extracted from proto HTTP annotations.
#[derive(Debug, Clone)]
struct RouteEntry {
    /// HTTP path pattern (e.g., "/v1/auth/opaque/login/start").
    http_path: String,
    /// HTTP method (GET, POST, PUT, PATCH, DELETE).
    http_method: HttpMethod,
    /// gRPC path (e.g., "/sid.v1.AuthService/OpaqueLoginStart").
    grpc_path: String,
    /// Method descriptor for input/output message resolution.
    method: MethodDescriptor,
}

#[derive(Debug, Clone, Copy)]
enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// Build transcoded REST→gRPC routes from a descriptor pool.
///
/// Takes a `DescriptorPool` and optional path aliases from config.
/// Returns an axum Router that transcodes REST requests to gRPC calls.
pub fn routes<S: TranscodeState>(pool: &DescriptorPool, aliases: &[AliasConfig]) -> Router<S> {
    let entries = extract_routes(pool);
    if entries.is_empty() {
        tracing::warn!("No HTTP-annotated RPCs found in proto descriptors");
        return Router::new();
    }

    tracing::info!("Registering {} transcoded REST→gRPC routes", entries.len());

    let mut router: Router<S> = Router::new();
    for entry in &entries {
        let entry_clone = entry.clone();

        let handler = move |proxy_state: State<S>,
                            headers: HeaderMap,
                            path_params: Path<std::collections::HashMap<String, String>>,
                            body: axum::body::Bytes| {
            transcode_handler(proxy_state, headers, path_params, body, entry_clone)
        };

        let method_router: MethodRouter<S> = match entry.http_method {
            HttpMethod::Get => get(handler),
            HttpMethod::Post => post(handler),
            HttpMethod::Put => put(handler),
            HttpMethod::Patch => patch(handler),
            HttpMethod::Delete => delete(handler),
        };

        let axum_path = proto_path_to_axum(&entry.http_path);
        router = router.route(&axum_path, method_router);

        // Register aliases from config
        for alias in aliases {
            if let Some(suffix) = entry.http_path.strip_prefix(&alias.to) {
                // Build alias path: alias.from with the matched suffix
                let alias_path = if alias.from.ends_with("/{path}") {
                    let prefix = alias.from.trim_end_matches("/{path}");
                    format!("{}{}", prefix, suffix)
                } else {
                    continue;
                };

                let alias_entry = entry.clone();
                let alias_handler =
                    move |proxy_state: State<S>,
                          headers: HeaderMap,
                          path_params: Path<std::collections::HashMap<String, String>>,
                          body: axum::body::Bytes| {
                        transcode_handler(proxy_state, headers, path_params, body, alias_entry)
                    };
                let alias_method: MethodRouter<S> = match entry.http_method {
                    HttpMethod::Get => get(alias_handler),
                    HttpMethod::Post => post(alias_handler),
                    HttpMethod::Put => put(alias_handler),
                    HttpMethod::Patch => patch(alias_handler),
                    HttpMethod::Delete => delete(alias_handler),
                };
                router = router.route(&alias_path, alias_method);
            }
        }
    }

    // Server-streaming RPCs
    let streaming_entries = extract_streaming_routes(pool);
    for entry in &streaming_entries {
        let entry_clone = entry.clone();
        let axum_path = proto_path_to_axum(&entry.http_path);

        let handler = move |proxy_state: State<S>, headers: HeaderMap| {
            streaming_handler(proxy_state, headers, entry_clone)
        };

        let method_router: MethodRouter<S> = match entry.http_method {
            HttpMethod::Get => get(handler),
            HttpMethod::Post => post(handler),
            _ => continue,
        };

        router = router.route(&axum_path, method_router);
    }

    router
}

/// Handler for server-streaming RPCs (NDJSON response).
async fn streaming_handler<S: TranscodeState>(
    State(proxy_state): State<S>,
    headers: HeaderMap,
    entry: RouteEntry,
) -> Response {
    let channel = proxy_state.grpc_channel();

    let input_desc = entry.method.input();
    let request_msg = DynamicMessage::new(input_desc);

    let grpc_metadata =
        metadata::http_headers_to_grpc_metadata(&headers, proxy_state.forwarded_headers());
    let mut grpc_request = tonic::Request::new(request_msg);
    *grpc_request.metadata_mut() = grpc_metadata;

    let output_desc = entry.method.output();
    let grpc_codec = codec::DynamicCodec::new(output_desc.clone());
    let grpc_path: axum::http::uri::PathAndQuery = match entry.grpc_path.parse() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Invalid gRPC path '{}': {e}", entry.grpc_path);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "INTERNAL",
                    "message": "invalid gRPC path configuration",
                })),
            )
                .into_response();
        }
    };

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

    match grpc_client
        .server_streaming(grpc_request, grpc_path, grpc_codec)
        .await
    {
        Ok(response) => {
            let stream = response.into_inner();
            let serialize_opts = SerializeOptions::new()
                .skip_default_fields(false)
                .stringify_64_bit_integers(true);

            let byte_stream = stream.map(move |result| match result {
                Ok(msg) => {
                    match msg.serialize_with_options(serde_json::value::Serializer, &serialize_opts)
                    {
                        Ok(json_value) => {
                            let mut bytes = serde_json::to_vec(&json_value).unwrap_or_default();
                            bytes.push(b'\n');
                            Ok::<axum::body::Bytes, std::io::Error>(axum::body::Bytes::from(bytes))
                        }
                        Err(e) => Err(std::io::Error::other(format!("serialization error: {e}"))),
                    }
                }
                Err(status) => Err(std::io::Error::other(format!(
                    "gRPC stream error: {status}"
                ))),
            });

            let body = axum::body::Body::from_stream(byte_stream);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/x-ndjson")
                .header("transfer-encoding", "chunked")
                .body(body)
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(status) => error::status_to_response(status),
    }
}

/// Generic transcoding handler.
async fn transcode_handler<S: TranscodeState>(
    State(proxy_state): State<S>,
    headers: HeaderMap,
    Path(path_params): Path<std::collections::HashMap<String, String>>,
    body_bytes: axum::body::Bytes,
    entry: RouteEntry,
) -> Response {
    let channel = proxy_state.grpc_channel();

    let ct = body::content_type(&headers);
    let mut json_body = match body::parse_body(ct, &body_bytes) {
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
    };

    if !path_params.is_empty() {
        if let Some(obj) = json_body.as_object_mut() {
            for (key, value) in &path_params {
                obj.insert(key.clone(), serde_json::Value::String(value.clone()));
            }
        }
    }

    let input_desc = entry.method.input();
    let request_msg = match DynamicMessage::deserialize(input_desc, json_body) {
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

    let output_desc = entry.method.output();
    let grpc_codec = codec::DynamicCodec::new(output_desc.clone());
    let grpc_path: axum::http::uri::PathAndQuery = match entry.grpc_path.parse() {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Invalid gRPC path '{}': {e}", entry.grpc_path);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "INTERNAL",
                    "message": "invalid gRPC path configuration",
                })),
            )
                .into_response();
        }
    };

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
            let serialize_opts = SerializeOptions::new()
                .skip_default_fields(false)
                .stringify_64_bit_integers(true);
            match response_msg
                .serialize_with_options(serde_json::value::Serializer, &serialize_opts)
            {
                Ok(json_value) => (StatusCode::OK, Json(json_value)).into_response(),
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

            if let Some((http_method, http_path)) = extract_http_rule(&method, &http_ext) {
                entries.push(RouteEntry {
                    http_path,
                    http_method,
                    grpc_path,
                    method: method.clone(),
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

            if let Some((http_method, http_path)) = extract_http_rule(&method, &http_ext) {
                tracing::info!(
                    "Registering streaming route: {} {} → {}",
                    match http_method {
                        HttpMethod::Get => "GET",
                        HttpMethod::Post => "POST",
                        _ => "OTHER",
                    },
                    http_path,
                    grpc_path
                );
                entries.push(RouteEntry {
                    http_path,
                    http_method,
                    grpc_path,
                    method: method.clone(),
                });
            }
        }
    }

    entries
}

/// Extract the HTTP method and path from a method's `google.api.http` extension.
fn extract_http_rule(
    method: &MethodDescriptor,
    http_ext: &prost_reflect::ExtensionDescriptor,
) -> Option<(HttpMethod, String)> {
    let options = method.options();

    if !options.has_extension(http_ext) {
        return None;
    }

    let http_rule = options.get_extension(http_ext);
    if let prost_reflect::Value::Message(rule_msg) = http_rule.into_owned() {
        for (method_name, http_method) in [
            ("get", HttpMethod::Get),
            ("post", HttpMethod::Post),
            ("put", HttpMethod::Put),
            ("delete", HttpMethod::Delete),
            ("patch", HttpMethod::Patch),
        ] {
            if let Some(val) = rule_msg.get_field_by_name(method_name) {
                if let prost_reflect::Value::String(path) = val.into_owned() {
                    if !path.is_empty() {
                        return Some((http_method, path));
                    }
                }
            }
        }
    }

    None
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

    for (idx, segment) in split_top_level(path).into_iter().enumerate() {
        if idx > 0 {
            out.push('/');
        }
        out.push_str(&convert_segment(segment, idx));
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
fn convert_segment(segment: &str, idx: usize) -> String {
    if let Some(inner) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        // Brace capture, possibly with a `name=template` field path.
        if let Some((name, template)) = inner.split_once('=') {
            return match template {
                // Single-segment field path collapses to a plain capture.
                "*" => format!("{{{name}}}"),
                // Multi-segment catch-all maps to axum's `{*name}`.
                "**" => format!("{{*{name}}}"),
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
                    format!("{{*{name}}}")
                }
            };
        }
        // Plain `{name}` is already valid axum 0.8 syntax.
        return format!("{{{inner}}}");
    }

    // Bare wildcards: name them by position so multiple wildcards never collide.
    match segment {
        "**" => format!("{{*wildcard{idx}}}"),
        "*" => format!("{{wildcard{idx}}}"),
        literal => literal.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
