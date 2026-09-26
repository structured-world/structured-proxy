//! gRPC → HTTP error mapping.
//!
//! Converts `tonic::Status` to appropriate HTTP status codes and JSON error bodies
//! following the gRPC-HTTP status code mapping from the gRPC specification, and
//! renders the typed `google.rpc.Status` details the upstream attached in the
//! `grpc-status-details-bin` trailer.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::Engine as _;
use globset::GlobMatcher;
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, SerializeOptions};
use serde_json::{Map, Value};

/// Full name of `google.rpc.DebugInfo`. It carries stack traces and server
/// internals meant for the service's operators, so it never reaches an HTTP
/// client.
const DEBUG_INFO: &str = "google.rpc.DebugInfo";

/// Map a gRPC status code to the corresponding HTTP status code.
///
/// Based on <https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md>
pub fn grpc_to_http_status(code: tonic::Code) -> StatusCode {
    match code {
        tonic::Code::Ok => StatusCode::OK,
        tonic::Code::Cancelled => StatusCode::from_u16(499).unwrap_or(StatusCode::BAD_REQUEST),
        tonic::Code::Unknown => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists => StatusCode::CONFLICT,
        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
        tonic::Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::OutOfRange => StatusCode::BAD_REQUEST,
        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,
        tonic::Code::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        tonic::Code::DataLoss => StatusCode::INTERNAL_SERVER_ERROR,
        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,
    }
}

/// Message of the `INTERNAL` a client gets instead of an upstream error whose
/// details cannot be rendered faithfully. The cause stays in the proxy's log.
const MALFORMED_STATUS_MESSAGE: &str = "upstream returned a malformed error status";

/// An upstream error status whose details cannot be rendered faithfully: a
/// trailer that is not a `google.rpc.Status`, or a detail of a known type whose
/// bytes do not decode or whose value has no valid JSON form. Its cause is
/// logged where it is detected.
#[derive(Debug)]
struct MalformedStatus;

/// Convert a `tonic::Status` into an axum HTTP response with a JSON error body
/// `{"error", "message", "code"}`, without status details.
///
/// Use [`status_to_response_with_details`] to also render the upstream's
/// `google.rpc.Status` details.
pub fn status_to_response(status: tonic::Status) -> Response {
    status_to_response_with_details(&status, None)
}

/// Convert a `tonic::Status` into an axum HTTP response with a JSON error body.
///
/// The body is `{"error", "message", "code"}`, plus a `details` array when
/// `details` is given (see [`error_body`]). The HTTP status follows the code the
/// body reports, so a malformed upstream status answers 500.
pub fn status_to_response_with_details(
    status: &tonic::Status,
    details: Option<&StatusDetails>,
) -> Response {
    let (code, body) = render(status, details);
    (grpc_to_http_status(code), Json(body)).into_response()
}

/// The JSON error body for a failed call, shared by the unary response and the
/// terminal frame of a stream so a client parses one shape everywhere.
///
/// `error` is the gRPC code name, `code` its number and `message` the status
/// message. With `details`, the body also carries `details`: the upstream's
/// `google.rpc.Status.details` in proto3 JSON form (empty when the upstream sent
/// none), plus `opaqueDetails` for details whose type no descriptor describes;
/// without it, both keys are absent and the trailer is not read. When the
/// details cannot be rendered faithfully the whole body is a generic `INTERNAL`
/// instead, never a partial or reinterpreted set of details.
pub fn error_body(status: &tonic::Status, details: Option<&StatusDetails>) -> Value {
    render(status, details).1
}

/// The error body and the gRPC code it reports: the upstream's own, or
/// `INTERNAL` when its details cannot be rendered faithfully.
fn render(status: &tonic::Status, details: Option<&StatusDetails>) -> (tonic::Code, Value) {
    let Some(details) = details else {
        return (status.code(), body(status.code(), status.message(), None));
    };
    match details.render(status) {
        Ok(rendered) => (
            status.code(),
            body(status.code(), status.message(), Some(rendered)),
        ),
        Err(MalformedStatus) => (
            tonic::Code::Internal,
            body(
                tonic::Code::Internal,
                MALFORMED_STATUS_MESSAGE,
                Some(RenderedDetails::default()),
            ),
        ),
    }
}

/// `opaqueDetails` appears only when a detail went to the extension, so a
/// client that does not handle it sees nothing new otherwise.
fn body(code: tonic::Code, message: &str, details: Option<RenderedDetails>) -> Value {
    let mut body = Map::with_capacity(5);
    body.insert("error".into(), grpc_code_name(code).into());
    body.insert("message".into(), message.into());
    body.insert("code".into(), (code as i32).into());
    if let Some(rendered) = details {
        body.insert("details".into(), Value::Array(rendered.details));
        if !rendered.opaque.is_empty() {
            body.insert("opaqueDetails".into(), Value::Array(rendered.opaque));
        }
    }
    Value::Object(body)
}

/// Human-readable gRPC code name for JSON error responses.
pub(crate) fn grpc_code_name(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::Ok => "OK",
        tonic::Code::Cancelled => "CANCELLED",
        tonic::Code::Unknown => "UNKNOWN",
        tonic::Code::InvalidArgument => "INVALID_ARGUMENT",
        tonic::Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        tonic::Code::NotFound => "NOT_FOUND",
        tonic::Code::AlreadyExists => "ALREADY_EXISTS",
        tonic::Code::PermissionDenied => "PERMISSION_DENIED",
        tonic::Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        tonic::Code::FailedPrecondition => "FAILED_PRECONDITION",
        tonic::Code::Aborted => "ABORTED",
        tonic::Code::OutOfRange => "OUT_OF_RANGE",
        tonic::Code::Unimplemented => "UNIMPLEMENTED",
        tonic::Code::Internal => "INTERNAL",
        tonic::Code::Unavailable => "UNAVAILABLE",
        tonic::Code::DataLoss => "DATA_LOSS",
        tonic::Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

/// Which routes return `details` in their error bodies.
///
/// A global switch plus per-route overrides, checked in the order they were
/// added: the first whose pattern matches the route decides. A pattern is a
/// glob over the mounted route path, where `*` stays within one segment and
/// `**` spans segments; every path parameter counts as one segment, so
/// `/v1/users/*` matches the route `/v1/users/{id}`. Decided once per route
/// when the router is built, so a request pays nothing for it.
///
/// # Examples
///
/// ```
/// use structured_proxy::transcode::error::ErrorDetailsPolicy;
///
/// // Details everywhere except the internal admin surface.
/// let policy = ErrorDetailsPolicy::default()
///     .route("/v1/admin/**", false)
///     .unwrap();
/// assert!(policy.enabled_for("/v1/users/{id}"));
/// assert!(!policy.enabled_for("/v1/admin/users/{id}"));
///
/// // Off by default, back on for one sub-route.
/// let policy = ErrorDetailsPolicy::disabled()
///     .route("/v1/public/**", true)
///     .unwrap();
/// assert!(!policy.enabled_for("/v1/users/{id}"));
/// assert!(policy.enabled_for("/v1/public/items"));
/// ```
#[derive(Debug, Clone)]
pub struct ErrorDetailsPolicy {
    enabled: bool,
    routes: Vec<(GlobMatcher, bool)>,
}

impl ErrorDetailsPolicy {
    /// No details on any route, until a [`route`](Self::route) switches them on.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            routes: Vec::new(),
        }
    }

    /// Add an override for the routes `pattern` matches, checked after the
    /// ones added before it.
    ///
    /// # Errors
    ///
    /// A pattern that does not start with `/` (it could never match a route)
    /// or is not a valid glob.
    pub fn route(mut self, pattern: &str, enabled: bool) -> Result<Self, String> {
        // Route paths always start with `/`; a relative pattern is a
        // missing-slash typo that would silently never apply.
        if !pattern.starts_with('/') {
            return Err(format!(
                "error details route pattern {pattern:?} must start with '/'"
            ));
        }
        self.routes
            .push((crate::shield::matcher::path_glob(pattern)?, enabled));
        Ok(self)
    }

    /// Whether the route mounted at `route_path` (axum form, e.g.
    /// `/v1/users/{id}`) returns details: the first matching rule decides,
    /// otherwise the global switch.
    pub fn enabled_for(&self, route_path: &str) -> bool {
        for (matcher, enabled) in &self.routes {
            if matcher.is_match(route_path) {
                return *enabled;
            }
        }
        self.enabled
    }
}

impl Default for ErrorDetailsPolicy {
    /// Details on every route.
    fn default() -> Self {
        Self {
            enabled: true,
            routes: Vec::new(),
        }
    }
}

/// Whether `full_name` is a well-known type with a special ProtoJSON
/// representation, which an `Any` carries under `value`
/// (<https://protobuf.dev/programming-guides/json/#any>). The same set
/// prost-reflect wraps when it serializes an `Any`.
fn has_special_json(full_name: &str) -> bool {
    matches!(
        full_name,
        "google.protobuf.Any"
            | "google.protobuf.Timestamp"
            | "google.protobuf.Duration"
            | "google.protobuf.Struct"
            | "google.protobuf.FloatValue"
            | "google.protobuf.DoubleValue"
            | "google.protobuf.Int32Value"
            | "google.protobuf.Int64Value"
            | "google.protobuf.UInt32Value"
            | "google.protobuf.UInt64Value"
            | "google.protobuf.BoolValue"
            | "google.protobuf.StringValue"
            | "google.protobuf.BytesValue"
            | "google.protobuf.FieldMask"
            | "google.protobuf.ListValue"
            | "google.protobuf.Value"
            | "google.protobuf.Empty"
    )
}

/// Whether `name` is a protobuf full name: dot-separated identifiers, each a
/// letter or `_` followed by letters, digits or `_`.
fn is_full_name(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|part| {
            let mut chars = part.chars();
            matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
}

/// The rendered details of one status.
#[derive(Debug, Default)]
struct RenderedDetails {
    /// ProtoJSON `Any` entries, in upstream order.
    details: Vec<Value>,
    /// Opaque-detail extension entries, in upstream order.
    opaque: Vec<Value>,
}

/// An entry of the structured-proxy opaque-detail extension, for a detail whose
/// type no descriptor describes: `{"index", "typeUrl", "bytes"}`, where `index`
/// is its position among the forwarded details (so merging `details` and
/// `opaqueDetails` by position restores the upstream order), `typeUrl` the
/// original type URL and `bytes` the standard base64 of the original bytes.
/// It carries no `@type` and lives outside `details`, so it cannot be taken for
/// a ProtoJSON `Any`.
fn opaque_entry(index: usize, type_url: &str, value: &[u8]) -> Value {
    let mut out = Map::with_capacity(3);
    out.insert("index".into(), index.into());
    out.insert("typeUrl".into(), type_url.into());
    out.insert(
        "bytes".into(),
        base64::engine::general_purpose::STANDARD
            .encode(value)
            .into(),
    );
    Value::Object(out)
}

/// Renders the typed details of a gRPC status (`grpc-status-details-bin`) as
/// proto3 JSON.
///
/// A detail type is resolved in the product descriptors first, so a service's
/// own detail messages (and its own `google.rpc` revision) render as it defines
/// them, then in the canonical `google/rpc/status.proto` and
/// `error_details.proto`, which are always available even when the product
/// descriptors do not import them.
///
/// Details use the canonical proto3 JSON mapping (unset fields omitted, 64-bit
/// integers as strings), the form clients of the `google.rpc` model expect.
#[derive(Debug, Clone)]
pub struct StatusDetails {
    product: DescriptorPool,
    canonical: DescriptorPool,
}

impl StatusDetails {
    /// Build a renderer that resolves detail types in `product` first, then in
    /// the canonical `google.rpc` descriptors.
    pub fn new(product: &DescriptorPool) -> Self {
        let mut canonical = DescriptorPool::global();
        canonical
            .decode_file_descriptor_set(tonic_types::pb::FILE_DESCRIPTOR_SET)
            .expect("tonic-types ships a valid google.rpc descriptor set");
        Self {
            product: product.clone(),
            canonical,
        }
    }

    /// The details of `status`, `google.rpc.DebugInfo` left out.
    ///
    /// A detail whose type resolves goes to `details` in its ProtoJSON `Any`
    /// form: `@type` plus the message fields, or `@type` plus `value` for a
    /// well-known type with a special JSON representation. A type no descriptor
    /// describes has no ProtoJSON form (the mapping requires the type), so it
    /// goes to the opaque-detail extension instead (see [`opaque_entry`]).
    ///
    /// # Errors
    ///
    /// [`MalformedStatus`] when the trailer is not a `google.rpc.Status`, or a
    /// detail of a known type does not decode or has no valid JSON form. Such a
    /// detail is never passed on as opaque bytes, since that would present a
    /// broken value as an unknown one.
    fn render(&self, status: &tonic::Status) -> Result<RenderedDetails, MalformedStatus> {
        let mut rendered = RenderedDetails::default();
        let raw = status.details();
        if raw.is_empty() {
            return Ok(rendered);
        }
        let decoded = tonic_types::pb::Status::decode(raw).map_err(|e| {
            tracing::error!("malformed grpc-status-details-bin trailer: {e}");
            MalformedStatus
        })?;
        // The trailer must describe the same error as grpc-status and
        // grpc-message (gRPC richer error model); otherwise its details would
        // be attached to an error they were not written for.
        if decoded.code != status.code() as i32 || decoded.message != status.message() {
            tracing::error!(
                trailer_code = decoded.code,
                status_code = status.code() as i32,
                "grpc-status-details-bin disagrees with grpc-status / grpc-message"
            );
            return Err(MalformedStatus);
        }
        rendered.details.reserve(decoded.details.len());
        // Position among the forwarded details: DebugInfo takes no index, so
        // the numbering does not reveal that one was withheld.
        let mut index = 0usize;
        for any in &decoded.details {
            // ProtoJSON identifies the type by the last `/`-segment of the URL
            // (`type.googleapis.com/google.rpc.ErrorInfo`). A name that is not
            // a protobuf full name (empty after a trailing `/`, a query suffix,
            // an empty segment) could be a disguised DebugInfo, so the whole
            // status is refused rather than its bytes passed on as opaque.
            let type_url = any.type_url.as_str();
            let type_name = type_url.rsplit_once('/').map_or(type_url, |(_, name)| name);
            if !is_full_name(type_name) {
                tracing::error!(%type_url, "error detail with a malformed type URL");
                return Err(MalformedStatus);
            }
            if type_name == DEBUG_INFO {
                continue;
            }
            match self.resolve(type_name) {
                Some(desc) => rendered
                    .details
                    .push(self.typed_entry(type_url, type_name, desc, &any.value)?),
                None => rendered
                    .opaque
                    .push(opaque_entry(index, type_url, &any.value)),
            }
            index += 1;
        }
        Ok(rendered)
    }

    /// The ProtoJSON `Any` form of a detail whose type resolved.
    fn typed_entry(
        &self,
        type_url: &str,
        type_name: &str,
        desc: MessageDescriptor,
        value: &[u8],
    ) -> Result<Value, MalformedStatus> {
        // ProtoJSON puts a well-known type with a special JSON representation
        // under `value` whatever that JSON looks like (a Struct is an object,
        // yet still wrapped), so the choice follows the type, not the shape.
        let wrapped = has_special_json(desc.full_name());
        let json = self.to_json(type_name, desc, value)?;
        let mut out = Map::new();
        out.insert("@type".into(), type_url.into());
        match json {
            Value::Object(fields) if !wrapped => out.extend(fields),
            other => {
                out.insert("value".into(), other);
            }
        }
        Ok(Value::Object(out))
    }

    fn resolve(&self, type_name: &str) -> Option<MessageDescriptor> {
        self.product
            .get_message_by_name(type_name)
            .or_else(|| self.canonical.get_message_by_name(type_name))
    }

    fn to_json(
        &self,
        type_name: &str,
        desc: MessageDescriptor,
        value: &[u8],
    ) -> Result<Value, MalformedStatus> {
        let msg = DynamicMessage::decode(desc, value).map_err(|e| {
            tracing::error!(detail = %type_name, "undecodable error detail: {e}");
            MalformedStatus
        })?;
        msg.serialize_with_options(serde_json::value::Serializer, &SerializeOptions::new())
            .map_err(|e| {
                tracing::error!(detail = %type_name, "error detail has no valid JSON form: {e}");
                MalformedStatus
            })
    }
}

#[cfg(test)]
mod tests;
