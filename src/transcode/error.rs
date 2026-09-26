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

use crate::config::ErrorDetailsConfig;

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

/// Convert a `tonic::Status` into an axum HTTP response with a JSON error body.
///
/// The body is `{"error", "message", "code"}`, plus a `details` array when
/// `details` is given (see [`error_body`]). The HTTP status follows the code the
/// body reports, so a malformed upstream status answers 500.
pub fn status_to_response(status: &tonic::Status, details: Option<&StatusDetails>) -> Response {
    let (code, body) = render(status, details);
    (grpc_to_http_status(code), Json(body)).into_response()
}

/// The JSON error body for a failed call, shared by the unary response and the
/// terminal frame of a stream so a client parses one shape everywhere.
///
/// `error` is the gRPC code name, `code` its number and `message` the status
/// message. With `details`, the body also carries `details`: the upstream's
/// `google.rpc.Status.details` in proto3 JSON form (empty when the upstream sent
/// none); without it, the key is absent and the trailer is not read. When the
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
                Some(Vec::new()),
            ),
        ),
    }
}

fn body(code: tonic::Code, message: &str, details: Option<Vec<Value>>) -> Value {
    let mut body = Map::with_capacity(4);
    body.insert("error".into(), grpc_code_name(code).into());
    body.insert("message".into(), message.into());
    body.insert("code".into(), (code as i32).into());
    if let Some(details) = details {
        body.insert("details".into(), Value::Array(details));
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

/// Which routes return `details` in their error bodies, compiled from
/// [`ErrorDetailsConfig`].
///
/// Decided once per route when the router is built, so a request pays nothing
/// for it.
#[derive(Debug, Clone)]
pub struct ErrorDetailsPolicy {
    enabled: bool,
    routes: Vec<(GlobMatcher, bool)>,
}

impl ErrorDetailsPolicy {
    /// Compile the config, rejecting patterns that could never match a route.
    ///
    /// # Errors
    ///
    /// A pattern that does not start with `/` or is not a valid glob.
    ///
    /// # Examples
    ///
    /// ```
    /// use structured_proxy::config::ErrorDetailsConfig;
    /// use structured_proxy::transcode::error::ErrorDetailsPolicy;
    ///
    /// let policy = ErrorDetailsPolicy::from_config(&ErrorDetailsConfig::default()).unwrap();
    /// assert!(policy.enabled_for("/v1/users/{id}"));
    /// ```
    pub fn from_config(cfg: &ErrorDetailsConfig) -> Result<Self, String> {
        let routes = cfg
            .routes
            .iter()
            .map(|rule| {
                // Route paths always start with `/`; a relative pattern is a
                // missing-slash typo that would silently never apply.
                if !rule.pattern.starts_with('/') {
                    return Err(format!(
                        "error_details route pattern {:?} must start with '/'",
                        rule.pattern
                    ));
                }
                Ok((
                    crate::shield::matcher::path_glob(&rule.pattern)?,
                    rule.enabled,
                ))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            enabled: cfg.enabled,
            routes,
        })
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
    /// A detail whose type resolves is its ProtoJSON `Any` form: `@type` plus
    /// the message fields, or `@type` plus `value` for a well-known type with a
    /// special JSON representation. A type no descriptor describes has no
    /// ProtoJSON form (the mapping requires the type), so it is kept in the
    /// structured-proxy opaque-detail extension instead.
    ///
    /// # Errors
    ///
    /// [`MalformedStatus`] when the trailer is not a `google.rpc.Status`, or a
    /// detail of a known type does not decode or has no valid JSON form. Such a
    /// detail is never passed on as opaque bytes, since that would present a
    /// broken value as an unknown one.
    fn render(&self, status: &tonic::Status) -> Result<Vec<Value>, MalformedStatus> {
        let raw = status.details();
        if raw.is_empty() {
            return Ok(Vec::new());
        }
        let decoded = tonic_types::pb::Status::decode(raw).map_err(|e| {
            tracing::error!("malformed grpc-status-details-bin trailer: {e}");
            MalformedStatus
        })?;
        let mut details = Vec::with_capacity(decoded.details.len());
        for any in &decoded.details {
            if let Some(detail) = self.render_any(&any.type_url, &any.value)? {
                details.push(detail);
            }
        }
        Ok(details)
    }

    /// One `Any`, or `None` for a detail that must not leave the proxy.
    fn render_any(&self, type_url: &str, value: &[u8]) -> Result<Option<Value>, MalformedStatus> {
        // The proto3 JSON mapping identifies the type by the last `/`-segment of
        // the URL (`type.googleapis.com/google.rpc.ErrorInfo`).
        let type_name = type_url.rsplit_once('/').map_or(type_url, |(_, name)| name);
        if type_name == DEBUG_INFO {
            return Ok(None);
        }

        let mut out = Map::new();
        out.insert("@type".into(), type_url.into());
        match self.resolve(type_name) {
            Some(desc) => match self.to_json(type_name, desc, value)? {
                Value::Object(fields) => out.extend(fields),
                // A well-known type with a special JSON representation
                // (`Duration` as "1.5s") goes under `value` (ProtoJSON, `Any`).
                other => {
                    out.insert("value".into(), other);
                }
            },
            // No descriptor for the type: ProtoJSON cannot express it, so the
            // opaque-detail extension keeps the original bytes instead of
            // dropping the detail. Not ProtoJSON; consumers opt into it.
            None => {
                out.insert(
                    "value".into(),
                    base64::engine::general_purpose::STANDARD
                        .encode(value)
                        .into(),
                );
            }
        }
        Ok(Some(Value::Object(out)))
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
