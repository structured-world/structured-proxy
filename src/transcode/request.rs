//! Request message construction for REST→gRPC transcoding.
//!
//! Builds the gRPC request message from three `google.api.http` sources, in
//! precedence order: path parameters (highest), the request body, then query
//! parameters (lowest, fill only). A JSON body is deserialized straight into
//! the message; path and query values arrive as strings and are converted to
//! each field's proto type as they are set.

mod presence;

use std::borrow::Cow;
use std::collections::HashMap;

use prost_reflect::{
    DynamicMessage, FieldDescriptor, Kind, MessageDescriptor, ReflectMessage, SerializeOptions,
    Value,
};
use serde::de::value::StrDeserializer;
use serde::Deserializer;
use serde_json::Value as JsonValue;

use presence::{OneEntry, Presence, Recording};

/// How the HTTP request body maps onto the gRPC request message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyMapping {
    /// No body is read; fields come from path + query (typical for GET/DELETE).
    None,
    /// The entire body maps to the message root (`body: "*"`).
    Root,
    /// The body maps to a single named field of the message (`body: "field"`).
    Field(String),
}

impl BodyMapping {
    /// Parse the `body` value of a `google.api.http` rule.
    ///
    /// `""` (absent) → [`BodyMapping::None`], `"*"` → [`BodyMapping::Root`],
    /// any other string → [`BodyMapping::Field`].
    pub fn parse(raw: &str) -> Self {
        match raw {
            "" => BodyMapping::None,
            "*" => BodyMapping::Root,
            field => BodyMapping::Field(field.to_string()),
        }
    }
}

/// The HTTP request body the [`BodyMapping`] reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body<'a> {
    /// No body is read. Under [`BodyMapping::Field`] the field still belongs
    /// to the body (a raw `google.api.HttpBody` filled afterwards), so query
    /// parameters leave it alone.
    Absent,
    /// A JSON body (ProtoJSON of the mapped message or field). Empty means
    /// `{}`.
    Json(&'a [u8]),
    /// An `application/x-www-form-urlencoded` body, bound field by field like
    /// query parameters.
    Form(&'a [u8]),
}

impl<'a> Body<'a> {
    /// The body as its media type (no parameters) says: a form for
    /// `application/x-www-form-urlencoded`, JSON otherwise.
    ///
    /// # Examples
    ///
    /// ```
    /// use structured_proxy::transcode::request::Body;
    ///
    /// let form = Body::new(Some("application/x-www-form-urlencoded"), b"a=1");
    /// assert_eq!(form, Body::Form(b"a=1"));
    /// assert_eq!(Body::new(None, b"{}"), Body::Json(b"{}"));
    /// ```
    pub fn new(content_type: Option<&str>, bytes: &'a [u8]) -> Self {
        match content_type {
            Some(ct) if ct.starts_with("application/x-www-form-urlencoded") => Body::Form(bytes),
            _ => Body::Json(bytes),
        }
    }
}

/// Build the request message from the body mapping, path params, and query.
///
/// Path-bound fields win over the body, and the body wins over query parameters
/// (query only fills fields the body did not set, even to their default).
/// Unknown query, form and path keys are dropped rather than rejected,
/// matching common transcoder behavior; an unknown key in a JSON body is an
/// error, as ProtoJSON has it.
///
/// # Errors
/// A body that is not the ProtoJSON of the mapped message or field, a form
/// body mapped onto a field that is not a message, or a path, query or form
/// value that is not a valid value of its field. The message is meant for the
/// client, as the text of an `INVALID_ARGUMENT` answer.
///
/// # Examples
///
/// ```
/// use std::collections::HashMap;
/// use prost_reflect::DescriptorPool;
/// use structured_proxy::transcode::request::{build_request_message, Body, BodyMapping};
///
/// # fn run(pool: DescriptorPool) {
/// let input = pool.get_message_by_name("google.protobuf.Duration").unwrap();
/// let message = build_request_message(
///     &input,
///     &BodyMapping::Root,
///     Body::Json(br#"{"seconds": "5"}"#),
///     &HashMap::new(),
///     Some("nanos=7"),
/// )
/// .unwrap();
/// assert_eq!(message.get_field_by_name("nanos").unwrap().as_i32(), Some(7));
/// # }
/// # use prost_reflect::prost::Message;
/// # let file = prost_reflect::prost_types::FileDescriptorProto {
/// #     name: Some("d.proto".into()),
/// #     package: Some("google.protobuf".into()),
/// #     message_type: vec![prost_reflect::prost_types::DescriptorProto {
/// #         name: Some("Duration".into()),
/// #         field: vec![
/// #             prost_reflect::prost_types::FieldDescriptorProto {
/// #                 name: Some("seconds".into()), number: Some(1), label: Some(1), r#type: Some(3),
/// #                 json_name: Some("seconds".into()), ..Default::default()
/// #             },
/// #             prost_reflect::prost_types::FieldDescriptorProto {
/// #                 name: Some("nanos".into()), number: Some(2), label: Some(1), r#type: Some(5),
/// #                 json_name: Some("nanos".into()), ..Default::default()
/// #             },
/// #         ],
/// #         ..Default::default()
/// #     }],
/// #     syntax: Some("proto3".into()),
/// #     ..Default::default()
/// # };
/// # let set = prost_reflect::prost_types::FileDescriptorSet { file: vec![file] };
/// # run(DescriptorPool::decode(set.encode_to_vec().as_slice()).unwrap());
/// ```
pub fn build_request_message(
    input: &MessageDescriptor,
    mapping: &BodyMapping,
    body: Body<'_>,
    path_params: &HashMap<String, String>,
    raw_query: Option<&str>,
) -> Result<DynamicMessage, String> {
    // Parsed without allocating wherever nothing needs unescaping.
    let query: Vec<(Cow<'_, str>, Cow<'_, str>)> = match raw_query {
        Some(q) => url::form_urlencoded::parse(q.as_bytes()).collect(),
        None => Vec::new(),
    };
    let source = match body {
        Body::Absent => Source::Absent,
        Body::Json(bytes) => Source::Json(bytes),
        Body::Form(bytes) => Source::Form(bytes),
    };
    build(input, mapping, source, path_params, &query)
}

/// Build the request-message JSON from the body mapping, path params, and query.
///
/// The request message is built by [`build_request_message`], then serialized
/// back to ProtoJSON (proto field names, 64-bit integers as strings, default
/// values left out).
///
/// # Errors
/// Returns an error string if `body` maps to the message root but is not a
/// JSON object, or for any error of [`build_request_message`].
#[deprecated(
    note = "builds the message and serializes it back to JSON; use build_request_message, \
            which returns the message"
)]
pub fn build_request_json(
    input: &MessageDescriptor,
    body_mapping: &BodyMapping,
    body_json: JsonValue,
    path_params: &HashMap<String, String>,
    query: &[(String, String)],
) -> Result<JsonValue, String> {
    let source = match (body_mapping, body_json) {
        (BodyMapping::Root, JsonValue::Null) => Source::Absent,
        (BodyMapping::Root, body @ JsonValue::Object(_)) => Source::Value(body),
        (BodyMapping::Root, _) => return Err("request body must be a JSON object".to_string()),
        (_, body) => Source::Value(body),
    };
    let query: Vec<(Cow<'_, str>, Cow<'_, str>)> = query
        .iter()
        .map(|(k, v)| (Cow::Borrowed(k.as_str()), Cow::Borrowed(v.as_str())))
        .collect();
    let message = build(input, body_mapping, source, path_params, &query)?;
    let options = SerializeOptions::new().use_proto_field_name(true);
    message
        .serialize_with_options(serde_json::value::Serializer, &options)
        .map_err(|e| format!("failed to serialize request: {e}"))
}

/// Parse a raw query string into ordered key/value pairs.
///
/// `None` and the empty string yield no pairs. A non-empty string must be valid
/// `application/x-www-form-urlencoded`.
///
/// # Errors
/// Returns an error string when the query cannot be parsed, so the caller can
/// reject the request rather than silently dropping every query-bound field.
pub fn parse_query(raw: Option<&str>) -> Result<Vec<(String, String)>, String> {
    match raw {
        None | Some("") => Ok(Vec::new()),
        Some(q) => serde_urlencoded::from_str(q).map_err(|e| format!("invalid query string: {e}")),
    }
}

/// Extract a (possibly dotted) subfield of the response JSON for `response_body`.
///
/// Returns `None` when any path segment is missing, letting the caller
/// distinguish a misconfigured path from a field that is legitimately null.
pub fn extract_response_body(value: &JsonValue, path: &str) -> Option<JsonValue> {
    let mut cur = value;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur.clone())
}

/// Where the body comes from.
enum Source<'a> {
    Absent,
    Json(&'a [u8]),
    Form(&'a [u8]),
    /// An already parsed JSON value.
    Value(JsonValue),
}

/// Which source a string value comes from, and so whether it overwrites.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Binding {
    /// Path parameters and form fields set their field.
    Set,
    /// Query parameters fill only what nothing else set.
    Fill,
}

fn build(
    input: &MessageDescriptor,
    mapping: &BodyMapping,
    source: Source<'_>,
    path_params: &HashMap<String, String>,
    query: &[(Cow<'_, str>, Cow<'_, str>)],
) -> Result<DynamicMessage, String> {
    // What the body and the path set matters only when a query can fill.
    let mut presence = (!query.is_empty()).then(Presence::default);
    // The field numbers of the path being bound, reused across keys.
    let mut path = Vec::new();

    let mut message = match (mapping, source) {
        (BodyMapping::None, _) => DynamicMessage::new(input.clone()),
        (BodyMapping::Field(name), Source::Absent) => {
            if let (Some(presence), Some(field)) = (&mut presence, input.get_field_by_name(name)) {
                presence.record_path(&[field.number()], false);
            }
            DynamicMessage::new(input.clone())
        }
        (BodyMapping::Root, Source::Absent) => DynamicMessage::new(input.clone()),
        // An empty body is `{}`, whatever its media type.
        (_, Source::Json(bytes) | Source::Form(bytes)) if bytes.is_empty() => {
            json_body(input, mapping, b"{}", presence.as_mut())?
        }
        (_, Source::Json(bytes)) => json_body(input, mapping, bytes, presence.as_mut())?,
        (_, Source::Value(value)) => deserialize(input, mapping, value, presence.as_mut())
            .map_err(|e| format!("failed to decode request body: {e}"))?,
        (_, Source::Form(bytes)) => {
            let pairs: Vec<(Cow<'_, str>, Cow<'_, str>)> =
                url::form_urlencoded::parse(bytes).collect();
            form_body(input, mapping, &pairs, presence.as_mut(), &mut path)?
        }
    };

    // Path params win over everything (the router already matched them).
    for (key, raw) in path_params {
        let target = Target {
            prefix: &[],
            key,
            values: &[raw.as_str()],
        };
        bind(
            &mut message,
            target,
            Binding::Set,
            presence.as_mut(),
            &mut path,
        )?;
    }

    if let Some(presence) = &mut presence {
        for_each_group(query, |key, values| {
            let target = Target {
                prefix: &[],
                key,
                values,
            };
            bind(
                &mut message,
                target,
                Binding::Fill,
                Some(&mut *presence),
                &mut path,
            )
        })?;
    }
    Ok(message)
}

/// Where string values go: the field at the dotted proto path `key`, below
/// the field numbers in `prefix`.
#[derive(Clone, Copy)]
struct Target<'a> {
    prefix: &'a [u32],
    key: &'a str,
    /// Every value of the key, in request order.
    values: &'a [&'a str],
}

/// Deserialize a JSON body in one pass.
fn json_body(
    input: &MessageDescriptor,
    mapping: &BodyMapping,
    bytes: &[u8],
    presence: Option<&mut Presence>,
) -> Result<DynamicMessage, String> {
    // A `null` body sets nothing, like `{}`.
    if matches!(mapping, BodyMapping::Root) && trim_json_whitespace(bytes) == b"null" {
        return Ok(DynamicMessage::new(input.clone()));
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let message = deserialize(input, mapping, &mut de, presence)
        .and_then(|message| de.end().map(|()| message))
        .map_err(|e| format!("failed to decode request body: {e}"))?;
    Ok(message)
}

fn trim_json_whitespace(bytes: &[u8]) -> &[u8] {
    let ws = |b: &u8| matches!(b, b' ' | b'\t' | b'\n' | b'\r');
    let start = bytes.iter().position(|b| !ws(b)).unwrap_or(bytes.len());
    let end = bytes.iter().rposition(|b| !ws(b)).map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// Deserialize `body` as the mapping says: the whole input message, or the
/// value of one of its fields.
fn deserialize<'de, D: Deserializer<'de>>(
    input: &MessageDescriptor,
    mapping: &BodyMapping,
    body: D,
    presence: Option<&mut Presence>,
) -> Result<DynamicMessage, D::Error> {
    match mapping {
        BodyMapping::Field(name) => {
            // Keyed by the JSON name, which prost-reflect looks up first, so
            // no other field's JSON name can shadow it.
            let field = input.get_field_by_name(name);
            let key = field.as_ref().map_or(name.as_str(), |f| f.json_name());
            deserialize_input(input, OneEntry { key, value: body }, presence)
        }
        _ => deserialize_input(input, body, presence),
    }
}

fn deserialize_input<'de, D: Deserializer<'de>>(
    input: &MessageDescriptor,
    de: D,
    presence: Option<&mut Presence>,
) -> Result<DynamicMessage, D::Error> {
    let Some(presence) = presence else {
        return DynamicMessage::deserialize(input.clone(), de);
    };
    match Recording::root(de, presence, input) {
        Ok(recording) => DynamicMessage::deserialize(input.clone(), recording),
        Err(de) => DynamicMessage::deserialize(input.clone(), de),
    }
}

/// Bind a form body field by field, into the input message or the message
/// field the mapping names.
fn form_body(
    input: &MessageDescriptor,
    mapping: &BodyMapping,
    pairs: &[(Cow<'_, str>, Cow<'_, str>)],
    mut presence: Option<&mut Presence>,
    path: &mut Vec<u32>,
) -> Result<DynamicMessage, String> {
    let mut message = DynamicMessage::new(input.clone());
    let prefix = match mapping {
        BodyMapping::Field(name) => {
            let field = input
                .get_field_by_name(name)
                .filter(|f| !f.is_list() && !f.is_map() && matches!(f.kind(), Kind::Message(_)))
                .ok_or_else(|| format!("a form body cannot fill field `{name}`"))?;
            // The field is the body's even when the form is empty of it.
            message.get_field_mut(&field);
            if let Some(presence) = presence.as_deref_mut() {
                presence.record_path(&[field.number()], true);
            }
            Some(field.number())
        }
        _ => None,
    };
    let prefix = prefix.as_slice();
    for_each_group(pairs, |key, values| {
        let target = Target {
            prefix,
            key,
            values,
        };
        bind(
            &mut message,
            target,
            Binding::Set,
            presence.as_deref_mut(),
            path,
        )
    })?;
    Ok(message)
}

/// Call `f` once per distinct key of `pairs`, with every value of that key in
/// request order.
fn for_each_group<'p>(
    pairs: &'p [(Cow<'p, str>, Cow<'p, str>)],
    mut f: impl FnMut(&'p str, &[&'p str]) -> Result<(), String>,
) -> Result<(), String> {
    // A stable sort keeps the values of each key in request order.
    let mut order: Vec<usize> = (0..pairs.len()).collect();
    order.sort_by(|&a, &b| pairs[a].0.cmp(&pairs[b].0));
    let mut values = Vec::new();
    for run in order.chunk_by(|&a, &b| pairs[a].0 == pairs[b].0) {
        values.clear();
        values.extend(run.iter().map(|&i| pairs[i].1.as_ref()));
        f(pairs[run[0]].0.as_ref(), &values)?;
    }
    Ok(())
}

/// Set the field `target` names to its values: all of them for a repeated
/// field, the last one otherwise. `path` is a buffer for the field numbers.
///
/// A key that names no field, or passes through a field that is not a
/// singular message, is dropped. A [`Binding::Fill`] leaves a field the body
/// or the path set, or one below a field they set to a non-object, alone.
fn bind(
    message: &mut DynamicMessage,
    target: Target<'_>,
    binding: Binding,
    presence: Option<&mut Presence>,
    path: &mut Vec<u32>,
) -> Result<(), String> {
    let Target {
        prefix,
        key,
        values,
    } = target;
    path.clear();
    path.extend_from_slice(prefix);
    let mut desc = message.descriptor();
    for &number in prefix {
        desc = match desc.get_field(number).map(|f| f.kind()) {
            Some(Kind::Message(inner)) => inner,
            _ => return Ok(()),
        };
    }
    let mut segments = key.split('.');
    let mut leaf = segments.next().unwrap_or_default();
    for next in segments {
        let Some(field) = desc.get_field_by_name(leaf) else {
            return Ok(());
        };
        let Kind::Message(inner) = field.kind() else {
            return Ok(());
        };
        if field.is_list() || field.is_map() {
            return Ok(());
        }
        path.push(field.number());
        desc = inner;
        leaf = next;
    }
    let Some(field) = desc.get_field_by_name(leaf) else {
        return Ok(());
    };
    path.push(field.number());
    if binding == Binding::Fill && presence.as_deref().is_some_and(|p| p.blocks(path)) {
        return Ok(());
    }

    let value = field_value(&field, values)?;
    let (parents, _) = path.split_at(path.len() - 1);
    let mut holder = message;
    for &number in parents {
        let parent = holder
            .descriptor()
            .get_field(number)
            .expect("the path was resolved against these descriptors");
        check_oneof(holder, &parent)?;
        holder = match holder.get_field_mut(&parent) {
            Value::Message(inner) => inner,
            _ => unreachable!("a singular message field holds a message"),
        };
    }
    check_oneof(holder, &field)?;
    holder.set_field(&field, value);
    if binding == Binding::Set {
        if let Some(presence) = presence {
            presence.record_path(path, false);
        }
    }
    Ok(())
}

/// Refuse to set `field` over another member of its oneof, as ProtoJSON
/// refuses a body naming two of them.
fn check_oneof(message: &DynamicMessage, field: &FieldDescriptor) -> Result<(), String> {
    let Some(oneof) = field.containing_oneof() else {
        return Ok(());
    };
    if oneof
        .fields()
        .any(|other| other.number() != field.number() && message.has_field(&other))
    {
        return Err(format!(
            "multiple fields provided for oneof '{}'",
            oneof.name()
        ));
    }
    Ok(())
}

/// The value of `field` from its string forms.
fn field_value(field: &FieldDescriptor, raw: &[&str]) -> Result<Value, String> {
    let invalid = |e: String| format!("invalid value for field `{}`: {e}", field.name());
    if field.is_map() {
        return Err(invalid("a map field cannot be set from a string".into()));
    }
    let kind = field.kind();
    if field.is_list() {
        return raw
            .iter()
            .map(|raw| scalar(&kind, raw))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::List)
            .map_err(invalid);
    }
    let raw = raw.last().expect("a bound key has a value");
    scalar(&kind, raw).map_err(invalid)
}

/// A string as a value of `kind`, read as the ProtoJSON of that value would
/// be: numbers in decimal (floats also `NaN`, `Infinity`, `-Infinity`), bools
/// as `true`/`false`, enums by name, bytes as base64, and a message type from
/// its JSON string form (a `Timestamp`, `Duration`, `FieldMask`, wrapper).
fn scalar(kind: &Kind, raw: &str) -> Result<Value, String> {
    Ok(match kind {
        Kind::Double => Value::F64(parse_f64(raw)?),
        Kind::Float => Value::F32(parse_f32(raw)?),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => Value::I32(parse(raw)?),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => Value::I64(parse(raw)?),
        Kind::Uint32 | Kind::Fixed32 => Value::U32(parse(raw)?),
        Kind::Uint64 | Kind::Fixed64 => Value::U64(parse(raw)?),
        Kind::Bool => Value::Bool(parse(raw)?),
        Kind::String => Value::String(raw.to_owned()),
        Kind::Bytes => Value::Bytes(decode_base64(raw)?.into()),
        Kind::Enum(desc) => Value::EnumNumber(
            desc.get_value_by_name(raw)
                .ok_or_else(|| format!("unrecognized enum value '{raw}'"))?
                .number(),
        ),
        Kind::Message(desc) => Value::Message(
            DynamicMessage::deserialize(
                desc.clone(),
                StrDeserializer::<serde::de::value::Error>::new(raw),
            )
            .map_err(|e| e.to_string())?,
        ),
    })
}

fn parse<T: std::str::FromStr>(raw: &str) -> Result<T, String>
where
    T::Err: std::fmt::Display,
{
    raw.parse().map_err(|e: T::Err| e.to_string())
}

/// Special float names of ProtoJSON.
fn special_float(raw: &str) -> Option<f64> {
    match raw {
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        "NaN" => Some(f64::NAN),
        _ => None,
    }
}

fn parse_f64(raw: &str) -> Result<f64, String> {
    raw.parse::<f64>()
        .or_else(|e| special_float(raw).ok_or(e))
        .map_err(|e| e.to_string())
}

/// A decimal with a finite `f64` value must lie within the `f32` range, as it
/// must in a JSON number; anything else is read as an `f32` literal or a
/// special name.
fn parse_f32(raw: &str) -> Result<f32, String> {
    match raw.parse::<f64>() {
        Ok(wide) if wide.is_finite() => {
            if wide < f64::from(f32::MIN) || wide > f64::from(f32::MAX) {
                Err("float value out of range".to_string())
            } else {
                // In range, so the cast rounds instead of saturating.
                Ok(wide as f32)
            }
        }
        _ => raw
            .parse::<f32>()
            .or_else(|e| special_float(raw).map(|v| v as f32).ok_or(e))
            .map_err(|e| e.to_string()),
    }
}

/// Base64 as ProtoJSON reads it: the standard or the URL-safe alphabet,
/// padded or not.
fn decode_base64(raw: &str) -> Result<Vec<u8>, String> {
    use base64::alphabet;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    use base64::{DecodeError, Engine};

    const CONFIG: GeneralPurposeConfig = GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent);
    const STANDARD: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, CONFIG);
    const URL_SAFE: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, CONFIG);

    let mut buf = Vec::new();
    match STANDARD.decode_vec(raw, &mut buf) {
        Ok(()) => Ok(buf),
        Err(DecodeError::InvalidByte(_, b'-' | b'_')) => {
            buf.clear();
            URL_SAFE
                .decode_vec(raw, &mut buf)
                .map(|()| buf)
                .map_err(|e| format!("invalid base64: {e}"))
        }
        Err(e) => Err(format!("invalid base64: {e}")),
    }
}

#[cfg(test)]
mod tests;
