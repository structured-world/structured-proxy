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
use prost_reflect::{
    Cardinality, DescriptorPool, DynamicMessage, Kind, MessageDescriptor, ReflectMessage,
    SerializeOptions, Value as PbValue,
};
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

/// Full name of `google.protobuf.Any`.
const ANY: &str = "google.protobuf.Any";

/// The type name an `Any.type_url` names, or `None` when the URL is malformed.
///
/// The URL must contain a `/`, and the part after the last one is the type's
/// full name (`google/protobuf/any.proto`). Anything else (a bare name, a
/// trailing `/`, a query suffix, an empty segment) could disguise a
/// DebugInfo, so callers refuse the whole status on `None`.
fn any_type_name(type_url: &str) -> Option<&str> {
    let (_, name) = type_url.rsplit_once('/')?;
    is_full_name(name).then_some(name)
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

/// Add to `pool` every top-level message and enum of `canonical` it does not
/// define, per type rather than per file.
///
/// A product may define some canonical types itself: in a file of another name,
/// or in its own revision of the canonical file holding only a subset. Those
/// definitions win. The canonical types it lacks still go in, through a copy
/// of the canonical file renamed under `structured-proxy/canonical/` and
/// reduced to the missing types; the copy also imports the product files that
/// define the types it dropped, so its references resolve to the product's
/// revisions.
fn complete_with_canonical(pool: &mut DescriptorPool, canonical: &DescriptorPool) {
    use std::collections::{BTreeSet, HashMap};

    // Canonical file name → the pool files that now provide its types in its
    // place (its renamed copy, product files defining some of them). A file
    // importing it imports those instead.
    let mut stand_ins: HashMap<String, BTreeSet<String>> = HashMap::new();
    // `files()` lists dependencies before their dependents, so each file finds
    // its imports already merged.
    for file in canonical.files() {
        let mut proto = file.file_descriptor_proto().clone();
        let package = proto.package().to_owned();
        let full = |name: &str| {
            if package.is_empty() {
                name.to_owned()
            } else {
                format!("{package}.{name}")
            }
        };
        // Files of the pool that already define a type of this file.
        let mut defining_files = BTreeSet::new();
        proto.message_type.retain(|message| {
            match pool.get_message_by_name(&full(message.name())) {
                Some(existing) => {
                    defining_files.insert(existing.parent_file().name().to_owned());
                    false
                }
                None => true,
            }
        });
        proto
            .enum_type
            .retain(|en| match pool.get_enum_by_name(&full(en.name())) {
                Some(existing) => {
                    defining_files.insert(existing.parent_file().name().to_owned());
                    false
                }
                None => true,
            });
        let everything_present = proto.message_type.is_empty() && proto.enum_type.is_empty();
        let file_present = pool.get_file_by_name(file.name()).is_some();
        if everything_present {
            // Typically the very same file. When the types live in files of
            // other names, importers of this one import those instead.
            if !file_present {
                stand_ins.insert(file.name().to_owned(), defining_files);
            }
            continue;
        }
        // A copy that leaves types out, or whose name the product already uses,
        // goes in under its own name; importers then need it plus the product
        // files that define the rest.
        let renamed = !defining_files.is_empty() || file_present;
        let mut provided_by = defining_files.clone();
        if renamed {
            let name = format!("structured-proxy/canonical/{}", file.name());
            proto.name = Some(name.clone());
            provided_by.insert(name);
        }
        let mut dependencies = BTreeSet::new();
        for dep in &proto.dependency {
            match stand_ins.get(dep) {
                Some(files) => {
                    // A product revision of the dependency stays importable
                    // next to the copy that completes it.
                    if pool.get_file_by_name(dep).is_some() {
                        dependencies.insert(dep.clone());
                    }
                    dependencies.extend(files.iter().cloned());
                }
                None => {
                    dependencies.insert(dep.clone());
                }
            }
        }
        dependencies.extend(defining_files);
        proto.dependency = dependencies.into_iter().collect();
        // Indexes into the old dependency list; nothing here needs them.
        proto.public_dependency.clear();
        proto.weak_dependency.clear();
        proto.source_code_info = None;
        match pool.add_file_descriptor_proto(proto) {
            Ok(()) => {
                if renamed {
                    stand_ins.insert(file.name().to_owned(), provided_by);
                }
            }
            Err(e) => {
                tracing::debug!(file = %file.name(), "canonical descriptor not merged: {e}");
            }
        }
    }
}

/// Renders the typed details of a gRPC status (`grpc-status-details-bin`) as
/// proto3 JSON.
///
/// Detail types resolve in one pool: the product descriptors, completed with
/// the well-known types and the canonical `google/rpc/status.proto` and
/// `error_details.proto` for whatever the product does not define itself. A
/// service's own detail messages (and its own `google.rpc` revision) render as
/// it defines them, the canonical ones are always available even when the
/// product descriptors do not import them, and a type packed inside another
/// detail resolves from the same pool as the detail itself.
///
/// Details use the canonical proto3 JSON mapping (unset fields omitted, 64-bit
/// integers as strings), the form clients of the `google.rpc` model expect.
#[derive(Debug, Clone)]
pub struct StatusDetails {
    pool: DescriptorPool,
}

impl StatusDetails {
    /// Build a renderer over `product`, completed with the canonical
    /// descriptors it lacks.
    pub fn new(product: &DescriptorPool) -> Self {
        let mut canonical = DescriptorPool::global();
        canonical
            .decode_file_descriptor_set(tonic_types::pb::FILE_DESCRIPTOR_SET)
            .expect("tonic-types ships a valid google.rpc descriptor set");
        let mut pool = product.clone();
        complete_with_canonical(&mut pool, &canonical);
        Self { pool }
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
            let type_url = any.type_url.as_str();
            let Some(type_name) = any_type_name(type_url) else {
                tracing::error!(%type_url, "error detail with a malformed type URL");
                return Err(MalformedStatus);
            };
            if type_name == DEBUG_INFO {
                continue;
            }
            match self.resolve(type_name) {
                Some(desc) => match self.typed_entry(type_url, type_name, desc, &any.value)? {
                    Some(entry) => rendered.details.push(entry),
                    // An Any detail packing DebugInfo, withheld like a direct one.
                    None => continue,
                },
                None => rendered
                    .opaque
                    .push(opaque_entry(index, type_url, &any.value)),
            }
            index += 1;
        }
        Ok(rendered)
    }

    /// The ProtoJSON `Any` form of a detail whose type resolved, with every
    /// DebugInfo packed inside it removed; `None` when the detail is itself an
    /// `Any` packing a DebugInfo.
    fn typed_entry(
        &self,
        type_url: &str,
        type_name: &str,
        desc: MessageDescriptor,
        value: &[u8],
    ) -> Result<Option<Value>, MalformedStatus> {
        // ProtoJSON puts a well-known type with a special JSON representation
        // under `value` whatever that JSON looks like (a Struct is an object,
        // yet still wrapped), so the choice follows the type, not the shape.
        // Empty is one of them (JSON `{}` in the ProtoJSON table), as in Go's
        // protojson and prost-reflect, so it is wrapped too.
        let wrapped = has_special_json(desc.full_name());
        let mut msg = DynamicMessage::decode(desc, value).map_err(|e| {
            tracing::error!(detail = %type_name, "undecodable error detail: {e}");
            MalformedStatus
        })?;
        if self.scrub(&mut msg)?.is_none() {
            return Ok(None);
        }
        let json = msg
            .serialize_with_options(serde_json::value::Serializer, &SerializeOptions::new())
            .map_err(|e| {
                tracing::error!(detail = %type_name, "error detail has no valid JSON form: {e}");
                MalformedStatus
            })?;
        let mut out = Map::new();
        out.insert("@type".into(), type_url.into());
        match json {
            Value::Object(fields) if !wrapped => {
                // A field whose JSON name is `@type` would replace the Any's
                // own type URL, and there is no faithful ProtoJSON form for it.
                if fields.contains_key("@type") {
                    tracing::error!(detail = %type_name, "error detail has a field named @type");
                    return Err(MalformedStatus);
                }
                out.extend(fields);
            }
            other => {
                out.insert("value".into(), other);
            }
        }
        Ok(Some(Value::Object(out)))
    }

    fn resolve(&self, type_name: &str) -> Option<MessageDescriptor> {
        self.pool.get_message_by_name(type_name)
    }

    /// Remove every DebugInfo anywhere below `msg`: a message field typed as
    /// DebugInfo, or an `Any` packing one, whether singular, repeated or a map
    /// value. Only the message types decide, so data such as a `Struct` key
    /// named `@type` is never mistaken for one. Returns `None` when `msg` is
    /// itself a DebugInfo or an `Any` packing one (the caller drops it),
    /// otherwise whether anything changed.
    fn scrub(&self, msg: &mut DynamicMessage) -> Result<Option<bool>, MalformedStatus> {
        let desc = msg.descriptor();
        if desc.full_name() == ANY {
            return self.scrub_any(msg);
        }
        if desc.full_name() == DEBUG_INFO {
            return Ok(None);
        }
        let mut changed = false;
        let mut dropped_fields = Vec::new();
        for (field, value) in msg.fields_mut() {
            if !matches!(field.kind(), Kind::Message(_)) {
                continue;
            }
            if !self.scrub_value(value, &mut changed)? {
                // A proto2 `required` field cannot be cleared without making
                // the message invalid, so the whole message goes instead.
                if field.cardinality() == Cardinality::Required {
                    return Ok(None);
                }
                dropped_fields.push(field);
            }
        }
        // Extensions are not among the message's own fields, yet ProtoJSON
        // renders them (as `[full.name]`), so they are scrubbed the same way.
        let mut dropped_extensions = Vec::new();
        for (extension, value) in msg.extensions_mut() {
            if !matches!(extension.kind(), Kind::Message(_)) {
                continue;
            }
            if !self.scrub_value(value, &mut changed)? {
                dropped_extensions.push(extension);
            }
        }
        for field in dropped_fields {
            msg.clear_field(&field);
            changed = true;
        }
        for extension in dropped_extensions {
            msg.clear_extension(&extension);
            changed = true;
        }
        Ok(Some(changed))
    }

    /// [`scrub`](Self::scrub) applied to one set field or extension value:
    /// repeated elements and map entries that must go are removed in place.
    /// Returns `false` when the value is a singular message that must go, so
    /// the caller clears the field.
    fn scrub_value(
        &self,
        value: &mut PbValue,
        changed: &mut bool,
    ) -> Result<bool, MalformedStatus> {
        match value {
            PbValue::Message(inner) => match self.scrub(inner)? {
                Some(inner_changed) => *changed |= inner_changed,
                None => return Ok(false),
            },
            PbValue::List(items) => {
                let before = items.len();
                let mut failed = None;
                items.retain_mut(|item| match item {
                    PbValue::Message(inner) if failed.is_none() => match self.scrub(inner) {
                        Ok(Some(inner_changed)) => {
                            *changed |= inner_changed;
                            true
                        }
                        Ok(None) => false,
                        Err(e) => {
                            failed = Some(e);
                            true
                        }
                    },
                    _ => true,
                });
                if let Some(e) = failed {
                    return Err(e);
                }
                *changed |= items.len() != before;
            }
            PbValue::Map(entries) => {
                let mut dropped = Vec::new();
                for (key, value) in entries.iter_mut() {
                    if let PbValue::Message(inner) = value {
                        match self.scrub(inner)? {
                            Some(inner_changed) => *changed |= inner_changed,
                            None => dropped.push(key.clone()),
                        }
                    }
                }
                for key in dropped {
                    entries.remove(&key);
                    *changed = true;
                }
            }
            _ => {}
        }
        Ok(true)
    }

    /// [`scrub`](Self::scrub) for an `Any`: its type URL is checked like a
    /// top-level detail's, a DebugInfo is reported for dropping, and a packed
    /// message of a known type is scrubbed and re-packed if it changed.
    fn scrub_any(&self, any: &mut DynamicMessage) -> Result<Option<bool>, MalformedStatus> {
        let type_url = match any.get_field_by_name("type_url").as_deref() {
            Some(PbValue::String(url)) => url.clone(),
            _ => String::new(),
        };
        let Some(type_name) = any_type_name(&type_url) else {
            tracing::error!(%type_url, "packed Any with a malformed type URL");
            return Err(MalformedStatus);
        };
        if type_name == DEBUG_INFO {
            return Ok(None);
        }
        // An unknown packed type has no JSON form; serialization reports it.
        let Some(desc) = self.resolve(type_name) else {
            return Ok(Some(false));
        };
        let bytes = match any.get_field_by_name("value").as_deref() {
            Some(PbValue::Bytes(bytes)) => bytes.clone(),
            _ => Default::default(),
        };
        let mut inner = DynamicMessage::decode(desc, bytes).map_err(|e| {
            tracing::error!(detail = %type_name, "undecodable packed Any: {e}");
            MalformedStatus
        })?;
        match self.scrub(&mut inner)? {
            None => Ok(None),
            Some(false) => Ok(Some(false)),
            Some(true) => {
                any.set_field_by_name("value", PbValue::Bytes(inner.encode_to_vec().into()));
                Ok(Some(true))
            }
        }
    }
}

#[cfg(test)]
mod tests;
