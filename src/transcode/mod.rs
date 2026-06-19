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
                            raw_query: RawQuery,
                            body: axum::body::Bytes| {
            transcode_handler(
                proxy_state,
                headers,
                path_params,
                raw_query,
                body,
                entry_clone,
            )
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
                          raw_query: RawQuery,
                          body: axum::body::Bytes| {
                        transcode_handler(
                            proxy_state,
                            headers,
                            path_params,
                            raw_query,
                            body,
                            alias_entry,
                        )
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
    RawQuery(raw_query): RawQuery,
    body_bytes: axum::body::Bytes,
    entry: RouteEntry,
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
    let query_pairs: Vec<(String, String)> = raw_query
        .as_deref()
        .map(|q| serde_urlencoded::from_str(q).unwrap_or_default())
        .unwrap_or_default();

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
                Ok(json_value) => {
                    // `response_body` returns just that subfield as the HTTP body.
                    let out = match &entry.response_body {
                        Some(path) => request::extract_response_body(&json_value, path),
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
}
