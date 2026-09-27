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

use prost_reflect::{DynamicMessage, FieldDescriptor, Kind, MessageDescriptor, Value};
use serde::de::value::StrDeserializer;
use serde::Deserializer;
use serde_json::Value as JsonValue;

use presence::{has_special_json, OneEntry, Presence, Recording};

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
/// use prost_reflect::{MessageDescriptor, Value};
/// use structured_proxy::transcode::request::{build_request_message, Body, BodyMapping};
///
/// // message Page { int32 size = 1; string cursor = 2; }
/// # fn page() -> MessageDescriptor {
/// #     use prost_reflect::prost::Message;
/// #     use prost_reflect::prost_types::{
/// #         field_descriptor_proto::{Label, Type},
/// #         DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
/// #     };
/// #     let field = |name: &str, number, ty: Type| FieldDescriptorProto {
/// #         name: Some(name.into()),
/// #         number: Some(number),
/// #         label: Some(Label::Optional as i32),
/// #         r#type: Some(ty as i32),
/// #         ..Default::default()
/// #     };
/// #     let file = FileDescriptorProto {
/// #         name: Some("page.proto".into()),
/// #         package: Some("example".into()),
/// #         message_type: vec![DescriptorProto {
/// #             name: Some("Page".into()),
/// #             field: vec![field("size", 1, Type::Int32), field("cursor", 2, Type::String)],
/// #             ..Default::default()
/// #         }],
/// #         syntax: Some("proto3".into()),
/// #         ..Default::default()
/// #     };
/// #     let set = FileDescriptorSet { file: vec![file] };
/// #     prost_reflect::DescriptorPool::decode(set.encode_to_vec().as_slice())
/// #         .unwrap()
/// #         .get_message_by_name("example.Page")
/// #         .unwrap()
/// # }
/// let message = build_request_message(
///     &page(),
///     &BodyMapping::Root,
///     Body::Json(br#"{"size": 0}"#),
///     &HashMap::new(),
///     Some("size=50&cursor=abc"),
/// )
/// .unwrap();
/// // The body set `size`, to its default: the query cannot replace it.
/// assert_eq!(message.get_field_by_name("size").unwrap().as_i32(), Some(0));
/// // It left `cursor` out: the query fills it.
/// assert_eq!(
///     *message.get_field_by_name("cursor").unwrap(),
///     Value::String("abc".into())
/// );
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
    build(input, mapping, body, path_params, &query)
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
    body: Body<'_>,
    path_params: &HashMap<String, String>,
    query: &[(Cow<'_, str>, Cow<'_, str>)],
) -> Result<DynamicMessage, String> {
    // What the body and the path set matters only when a query can fill.
    let body_len = match body {
        Body::Json(bytes) | Body::Form(bytes) => bytes.len(),
        Body::Absent => 0,
    };
    let mut presence = (!query.is_empty()).then(|| Presence::for_body(body_len));
    // The fields of the path being bound, reused across keys.
    let mut path = Vec::new();

    let mut message = match (mapping, body) {
        (BodyMapping::None, _) => DynamicMessage::new(input.clone()),
        (BodyMapping::Field(name), Body::Absent) => {
            if let (Some(presence), Some(field)) = (&mut presence, input.get_field_by_name(name)) {
                presence.record_path(&[field], false);
            }
            DynamicMessage::new(input.clone())
        }
        (BodyMapping::Root, Body::Absent) => DynamicMessage::new(input.clone()),
        // An empty body is `{}`, whatever its media type.
        (_, Body::Json(bytes) | Body::Form(bytes)) if bytes.is_empty() => {
            json_body(input, mapping, b"{}", path_params, presence.as_mut())?
        }
        (_, Body::Json(bytes)) => json_body(input, mapping, bytes, path_params, presence.as_mut())?,
        (_, Body::Form(bytes)) => {
            let pairs: Vec<(Cow<'_, str>, Cow<'_, str>)> =
                url::form_urlencoded::parse(bytes).collect();
            let form = Form {
                pairs: &pairs,
                path_params,
            };
            form_body(input, mapping, form, presence.as_mut(), &mut path)?
        }
    };

    // A well-known input type is set whole from its JSON form; path and query
    // keys would reach its internal fields.
    if has_special_json(input) {
        return Ok(message);
    }

    // Path params win over everything (the router already matched them).
    for (key, raw) in path_params {
        let target = Target {
            root: input,
            prefix: None,
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
                root: input,
                prefix: None,
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

/// Where string values go: the field at the dotted path `key`, below the
/// message field `prefix` of `root` when there is one, below `root` otherwise.
#[derive(Clone, Copy)]
struct Target<'a> {
    root: &'a MessageDescriptor,
    prefix: Option<&'a FieldDescriptor>,
    key: &'a str,
    /// Every value of the key, in request order.
    values: &'a [&'a str],
}

/// Deserialize a JSON body in one pass.
///
/// The path wins over the body, so a body value for a field the path binds
/// never decides the request, even when it is not a valid value of that field.
/// Such a body fails the one pass; it is then read again without those keys.
/// Only a failing body pays for the second read.
fn json_body(
    input: &MessageDescriptor,
    mapping: &BodyMapping,
    bytes: &[u8],
    path_params: &HashMap<String, String>,
    mut presence: Option<&mut Presence>,
) -> Result<DynamicMessage, String> {
    // A `null` body sets nothing, like `{}`.
    if matches!(mapping, BodyMapping::Root) && trim_json_whitespace(bytes) == b"null" {
        return Ok(DynamicMessage::new(input.clone()));
    }
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let first = deserialize(input, mapping, &mut de, presence.as_deref_mut())
        .and_then(|message| de.end().map(|()| message));
    let error = match first {
        Ok(message) => return Ok(message),
        Err(error) => error,
    };
    let fail = |e: serde_json::Error| format!("failed to decode request body: {e}");
    if path_params.is_empty() {
        return Err(fail(error));
    }
    // Not JSON at all: the path cannot change that.
    let Ok(mut value) = serde_json::from_slice::<JsonValue>(bytes) else {
        return Err(fail(error));
    };
    strip_path_fields(&mut value, input, mapping, path_params);
    if let Some(presence) = presence.as_deref_mut() {
        presence.clear();
    }
    deserialize(input, mapping, value, presence).map_err(fail)
}

/// Remove from `body` every key the path binds, under its JSON or proto name:
/// the path sets those fields whatever the body holds.
fn strip_path_fields(
    body: &mut JsonValue,
    input: &MessageDescriptor,
    mapping: &BodyMapping,
    path_params: &HashMap<String, String>,
) {
    for key in path_params.keys() {
        let mut segments = key.split('.');
        let desc = match mapping {
            BodyMapping::Root => input.clone(),
            // Under `body: "field"` the body is that field's value, so only
            // the path keys below the field reach into it.
            BodyMapping::Field(name) => {
                if segments.next() != Some(name.as_str()) {
                    continue;
                }
                match input.get_field_by_name(name).map(|f| f.kind()) {
                    Some(Kind::Message(inner)) => inner,
                    _ => continue,
                }
            }
            BodyMapping::None => return,
        };
        remove_path(body, desc, segments);
    }
}

/// Remove the field at `segments` below `desc` from the JSON object `value`.
fn remove_path<'k>(
    mut value: &mut JsonValue,
    mut desc: MessageDescriptor,
    segments: impl Iterator<Item = &'k str>,
) {
    let mut segments = segments.peekable();
    while let Some(segment) = segments.next() {
        let Some(field) = field_named(&desc, segment) else {
            return;
        };
        let Some(object) = value.as_object_mut() else {
            return;
        };
        if segments.peek().is_none() {
            object.remove(field.json_name());
            object.remove(field.name());
            return;
        }
        let Kind::Message(inner) = field.kind() else {
            return;
        };
        let key = if object.contains_key(field.json_name()) {
            field.json_name()
        } else {
            field.name()
        };
        let Some(next) = object.get_mut(key) else {
            return;
        };
        value = next;
        desc = inner;
    }
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
    if has_special_json(input) {
        presence.record_whole();
        return DynamicMessage::deserialize(input.clone(), de);
    }
    DynamicMessage::deserialize(input.clone(), Recording::root(de, presence))
}

/// Bind a form body field by field, into the input message or the message
/// field the mapping names.
fn form_body(
    input: &MessageDescriptor,
    mapping: &BodyMapping,
    form: Form<'_, '_>,
    mut presence: Option<&mut Presence>,
    path: &mut Vec<FieldDescriptor>,
) -> Result<DynamicMessage, String> {
    let Form { pairs, path_params } = form;
    let mut message = DynamicMessage::new(input.clone());
    let prefix = match mapping {
        BodyMapping::Field(name) => {
            let field = input
                .get_field_by_name(name)
                .filter(|f| {
                    !f.is_list()
                        && !f.is_map()
                        && matches!(f.kind(), Kind::Message(m) if !has_special_json(&m))
                })
                .ok_or_else(|| format!("a form body cannot fill field `{name}`"))?;
            // The field is the body's even when the form is empty of it.
            message.get_field_mut(&field);
            if let Some(presence) = presence.as_deref_mut() {
                presence.record_path(std::slice::from_ref(&field), true);
            }
            Some(field)
        }
        // Its keys would be the internal fields of a type read only whole.
        _ if has_special_json(input) => {
            return Err(format!("a form body cannot fill `{}`", input.full_name()));
        }
        _ => None,
    };
    for_each_group(pairs, |key, values| {
        let target = Target {
            root: input,
            prefix: prefix.as_ref(),
            key,
            values,
        };
        if !resolve(target, path) {
            return Ok(());
        }
        // The path sets these fields whatever the form holds, so their form
        // values are never decoded, as a JSON body's are not.
        if path_params.keys().any(|bound| covers(bound, path)) {
            return Ok(());
        }
        assign(
            &mut message,
            path,
            values,
            Binding::Set,
            presence.as_deref_mut(),
        )
    })?;
    Ok(message)
}

/// A form body and the path parameters that override it.
#[derive(Clone, Copy)]
struct Form<'p, 'q> {
    pairs: &'p [(Cow<'q, str>, Cow<'q, str>)],
    path_params: &'p HashMap<String, String>,
}

/// Whether the dotted path key `bound` names the field at the end of `path`
/// or one above it. Path keys start at the input message, as `path` does.
fn covers(bound: &str, path: &[FieldDescriptor]) -> bool {
    let mut fields = path.iter();
    bound.split('.').all(|segment| {
        fields
            .next()
            .is_some_and(|f| segment == f.name() || segment == f.json_name())
    })
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

/// Set the field `target` names to its values (see [`resolve`] and
/// [`assign`]). `path` is a buffer for the fields on the way.
fn bind(
    message: &mut DynamicMessage,
    target: Target<'_>,
    binding: Binding,
    presence: Option<&mut Presence>,
    path: &mut Vec<FieldDescriptor>,
) -> Result<(), String> {
    if !resolve(target, path) {
        return Ok(());
    }
    assign(message, path, target.values, binding, presence)
}

/// Resolve the dotted key of `target` into the fields on the way, in `path`.
///
/// Each segment names a field by its proto name or its JSON name, as
/// ProtoJSON reads a key. False when the key is dropped: it names no field,
/// or passes through a field that is not a singular message or is a
/// well-known type. A well-known type is set whole from its validated JSON
/// form, never field by field (a Timestamp's `nanos` alone could hold an
/// invalid value).
fn resolve(target: Target<'_>, path: &mut Vec<FieldDescriptor>) -> bool {
    path.clear();
    let mut owned;
    let mut desc = match target.prefix {
        Some(field) => {
            let Kind::Message(inner) = field.kind() else {
                return false;
            };
            path.push(field.clone());
            owned = inner;
            &owned
        }
        None => target.root,
    };
    let mut segments = target.key.split('.');
    let mut leaf = segments.next().unwrap_or_default();
    for next in segments {
        let Some(field) = field_named(desc, leaf) else {
            return false;
        };
        let Kind::Message(inner) = field.kind() else {
            return false;
        };
        if field.is_list() || field.is_map() || has_special_json(&inner) {
            return false;
        }
        path.push(field);
        owned = inner;
        desc = &owned;
        leaf = next;
    }
    let Some(field) = field_named(desc, leaf) else {
        return false;
    };
    path.push(field);
    true
}

/// The field of `desc` named `name`, by its proto name or else its JSON name.
fn field_named(desc: &MessageDescriptor, name: &str) -> Option<FieldDescriptor> {
    desc.get_field_by_name(name)
        .or_else(|| desc.get_field_by_json_name(name))
}

/// Set the field at the end of `path` to `values`: all of them for a repeated
/// field, the last one otherwise. A [`Binding::Fill`] leaves a field the body
/// or the path set, or one below a field they set to a non-object, alone.
fn assign(
    message: &mut DynamicMessage,
    path: &[FieldDescriptor],
    values: &[&str],
    binding: Binding,
    mut presence: Option<&mut Presence>,
) -> Result<(), String> {
    if binding == Binding::Fill && presence.as_deref_mut().is_some_and(|p| p.blocks(path)) {
        return Ok(());
    }

    let (field, parents) = path
        .split_last()
        .expect("a resolved path ends in its field");
    let value = field_value(field, values)?;
    let mut holder = message;
    for parent in parents {
        check_oneof(holder, parent)?;
        holder = match holder.get_field_mut(parent) {
            Value::Message(inner) => inner,
            _ => unreachable!("a singular message field holds a message"),
        };
    }
    check_oneof(holder, field)?;
    holder.set_field(field, value);
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

/// A ProtoJSON double: one of the special names, or a decimal with a finite
/// value. Rust's parser also reads `inf`, `nan` and `infinity` in any case,
/// and an overflowing decimal as infinity; ProtoJSON has none of those
/// (protobuf JSON mapping, "float, double").
fn parse_f64(raw: &str) -> Result<f64, String> {
    if let Some(special) = special_float(raw) {
        return Ok(special);
    }
    match raw.parse::<f64>() {
        Ok(value) if value.is_finite() => Ok(value),
        Ok(_) => Err("value out of range, or not a decimal number".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// A ProtoJSON float: a special name, or a finite decimal within the `f32`
/// range.
fn parse_f32(raw: &str) -> Result<f32, String> {
    let wide = parse_f64(raw)?;
    if wide.is_finite() && (wide < f64::from(f32::MIN) || wide > f64::from(f32::MAX)) {
        return Err("float value out of range".to_string());
    }
    // A special value casts to itself; a finite one is in range, so the cast
    // rounds instead of saturating.
    Ok(wide as f32)
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
