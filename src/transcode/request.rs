//! Request message construction for REST→gRPC transcoding.
//!
//! Assembles the gRPC request JSON from three `google.api.http` sources, in
//! precedence order: path parameters (highest), the request body, then query
//! parameters (lowest, fill only). Path and query values arrive as strings, so
//! they are coerced to each field's proto type before prost-reflect decodes the
//! message.

use prost_reflect::{FieldDescriptor, Kind, MessageDescriptor};
use serde_json::{Map, Value};
use std::collections::HashMap;

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

/// Build the request-message JSON from the body mapping, path params, and query.
///
/// Path-bound fields win over the body, and the body wins over query parameters
/// (query only fills fields not already set). Unknown query keys are dropped
/// rather than rejected, matching common transcoder behavior.
///
/// # Errors
/// Returns an error string if `body` maps to the message root but the parsed
/// body is not a JSON object.
pub fn build_request_json(
    input: &MessageDescriptor,
    body_mapping: &BodyMapping,
    body_json: Value,
    path_params: &HashMap<String, String>,
    query: &[(String, String)],
) -> Result<Value, String> {
    let mut root = match body_mapping {
        BodyMapping::None => Value::Object(Map::new()),
        BodyMapping::Root => match body_json {
            Value::Object(_) => body_json,
            Value::Null => Value::Object(Map::new()),
            _ => return Err("request body must be a JSON object".to_string()),
        },
        BodyMapping::Field(field) => {
            let mut m = Map::new();
            m.insert(field.clone(), body_json);
            Value::Object(m)
        }
    };

    // Path params win over everything (the router already matched them).
    for (key, raw) in path_params {
        set_field(&mut root, input, key, true, |field| {
            coerce(&field.kind(), raw)
        });
    }

    // Query params: group repeated keys, fill only fields not already present.
    for (key, values) in group_query(query) {
        set_field(&mut root, input, &key, false, |field| {
            if field.is_list() {
                Value::Array(values.iter().map(|v| coerce(&field.kind(), v)).collect())
            } else {
                // A non-repeated field bound multiple times takes the last value.
                coerce(&field.kind(), values.last().expect("group is non-empty"))
            }
        });
    }

    Ok(root)
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
pub fn extract_response_body(value: &Value, path: &str) -> Option<Value> {
    let mut cur = value;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur.clone())
}

/// Group query pairs by key, preserving value order, so repeated keys
/// (`?tag=a&tag=b`) collect into one entry for repeated-field binding.
fn group_query(query: &[(String, String)]) -> Vec<(String, Vec<String>)> {
    let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
    for (k, v) in query {
        if let Some((_, vals)) = grouped.iter_mut().find(|(gk, _)| gk == k) {
            vals.push(v.clone());
        } else {
            grouped.push((k.clone(), vec![v.clone()]));
        }
    }
    grouped
}

/// Resolve a (possibly dotted) field path against the message descriptor and
/// JSON tree, creating intermediate objects, then set the leaf via `make`.
///
/// `overwrite = false` leaves an already-present leaf untouched (query fill).
/// Unknown fields or non-message intermediates are silently skipped.
fn set_field<F>(root: &mut Value, input: &MessageDescriptor, dotted: &str, overwrite: bool, make: F)
where
    F: FnOnce(&FieldDescriptor) -> Value,
{
    let segments: Vec<&str> = dotted.split('.').collect();
    let mut desc = input.clone();
    let mut cur = root;

    for seg in &segments[..segments.len() - 1] {
        let Some(field) = desc.get_field_by_name(seg) else {
            return;
        };
        let Kind::Message(message) = field.kind() else {
            return;
        };
        desc = message;
        let Some(obj) = cur.as_object_mut() else {
            return;
        };
        cur = obj
            .entry((*seg).to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }

    let leaf = segments[segments.len() - 1];
    let Some(field) = desc.get_field_by_name(leaf) else {
        return;
    };
    let Some(obj) = cur.as_object_mut() else {
        return;
    };
    if !overwrite && obj.contains_key(leaf) {
        return;
    }
    obj.insert(leaf.to_string(), make(&field));
}

/// Coerce a path/query string to a JSON value matching the field's proto type,
/// so prost-reflect's proto3-JSON decoder accepts it.
///
/// 32-bit integers and floats become JSON numbers; 64-bit integers stay strings
/// (their canonical proto3-JSON form). Booleans parse to JSON booleans. Anything
/// that fails to parse falls back to the raw string.
fn coerce(kind: &Kind, raw: &str) -> Value {
    match kind {
        Kind::Bool => raw
            .parse::<bool>()
            .map(Value::Bool)
            .unwrap_or_else(|_| Value::String(raw.to_string())),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => raw
            .parse::<i32>()
            .map(|n| Value::Number(n.into()))
            .unwrap_or_else(|_| Value::String(raw.to_string())),
        Kind::Uint32 | Kind::Fixed32 => raw
            .parse::<u32>()
            .map(|n| Value::Number(n.into()))
            .unwrap_or_else(|_| Value::String(raw.to_string())),
        Kind::Double | Kind::Float => raw
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(raw.to_string())),
        // 64-bit ints (canonical proto3 JSON is a string), strings, bytes, enums
        // (name), and anything else pass through as a string.
        _ => Value::String(raw.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost_reflect::prost::Message;
    use prost_reflect::prost_types::{
        field_descriptor_proto::{Label, Type},
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };
    use prost_reflect::DescriptorPool;

    fn field(
        name: &str,
        num: i32,
        ty: Type,
        label: Label,
        type_name: Option<&str>,
    ) -> FieldDescriptorProto {
        FieldDescriptorProto {
            name: Some(name.to_string()),
            number: Some(num),
            label: Some(label as i32),
            r#type: Some(ty as i32),
            type_name: type_name.map(|s| s.to_string()),
            ..Default::default()
        }
    }

    /// Build a small descriptor pool with a typed message for coercion tests.
    fn test_msg() -> MessageDescriptor {
        let nested = DescriptorProto {
            name: Some("Nested".to_string()),
            field: vec![field("city", 1, Type::String, Label::Optional, None)],
            ..Default::default()
        };
        let msg = DescriptorProto {
            name: Some("TestMsg".to_string()),
            field: vec![
                field("name", 1, Type::String, Label::Optional, None),
                field("age", 2, Type::Int32, Label::Optional, None),
                field("active", 3, Type::Bool, Label::Optional, None),
                field("tags", 4, Type::String, Label::Repeated, None),
                field("count", 5, Type::Int64, Label::Optional, None),
                field(
                    "nested",
                    6,
                    Type::Message,
                    Label::Optional,
                    Some(".test.TestMsg.Nested"),
                ),
            ],
            nested_type: vec![nested],
            ..Default::default()
        };
        let file = FileDescriptorProto {
            name: Some("test.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![msg],
            syntax: Some("proto3".to_string()),
            ..Default::default()
        };
        let fds = FileDescriptorSet { file: vec![file] };
        let pool = DescriptorPool::decode(fds.encode_to_vec().as_slice()).unwrap();
        pool.get_message_by_name("test.TestMsg").unwrap()
    }

    fn pp(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn qq(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn coerce_unsigned_32_rejects_out_of_range() {
        // u32 fields must not accept negatives or values above u32::MAX; those
        // fall back to a raw string so prost-reflect rejects them precisely.
        assert_eq!(coerce(&Kind::Uint32, "-1"), Value::String("-1".into()));
        assert_eq!(
            coerce(&Kind::Uint32, "4294967296"),
            Value::String("4294967296".into())
        );
        assert_eq!(coerce(&Kind::Uint32, "42"), Value::Number(42.into()));
        assert_eq!(coerce(&Kind::Fixed32, "-1"), Value::String("-1".into()));
        // Signed 32-bit still accepts negatives.
        assert_eq!(coerce(&Kind::Int32, "-5"), Value::Number((-5).into()));
        // And rejects values outside i32 range.
        assert_eq!(
            coerce(&Kind::Int32, "2147483648"),
            Value::String("2147483648".into())
        );
    }

    #[test]
    fn body_mapping_parse() {
        assert_eq!(BodyMapping::parse(""), BodyMapping::None);
        assert_eq!(BodyMapping::parse("*"), BodyMapping::Root);
        assert_eq!(
            BodyMapping::parse("resource"),
            BodyMapping::Field("resource".into())
        );
    }

    #[test]
    fn body_root_merges_path_and_query() {
        let m = test_msg();
        let body = serde_json::json!({ "name": "alice" });
        let out = build_request_json(
            &m,
            &BodyMapping::Root,
            body,
            &pp(&[("age", "30")]),
            &qq(&[("active", "true")]),
        )
        .unwrap();
        assert_eq!(out["name"], "alice");
        assert_eq!(out["age"], 30); // Int32 coerced to a JSON number
        assert_eq!(out["active"], true); // Bool coerced
    }

    #[test]
    fn body_field_nests_body_under_named_field() {
        let m = test_msg();
        let body = serde_json::json!({ "city": "berlin" });
        let out = build_request_json(
            &m,
            &BodyMapping::Field("nested".into()),
            body,
            &pp(&[]),
            &qq(&[("name", "bob")]),
        )
        .unwrap();
        assert_eq!(out["nested"]["city"], "berlin");
        assert_eq!(out["name"], "bob");
    }

    #[test]
    fn query_repeated_field_becomes_array() {
        let m = test_msg();
        let out = build_request_json(
            &m,
            &BodyMapping::None,
            Value::Null,
            &pp(&[]),
            &qq(&[("tags", "a"), ("tags", "b")]),
        )
        .unwrap();
        assert_eq!(out["tags"], serde_json::json!(["a", "b"]));
    }

    #[test]
    fn query_dotted_path_sets_nested_field() {
        let m = test_msg();
        let out = build_request_json(
            &m,
            &BodyMapping::None,
            Value::Null,
            &pp(&[]),
            &qq(&[("nested.city", "paris")]),
        )
        .unwrap();
        assert_eq!(out["nested"]["city"], "paris");
    }

    #[test]
    fn query_does_not_override_body_or_path() {
        let m = test_msg();
        let body = serde_json::json!({ "name": "from_body" });
        let out = build_request_json(
            &m,
            &BodyMapping::Root,
            body,
            &pp(&[("age", "7")]),
            &qq(&[("name", "from_query"), ("age", "99")]),
        )
        .unwrap();
        assert_eq!(out["name"], "from_body"); // body wins over query
        assert_eq!(out["age"], 7); // path wins over query
    }

    #[test]
    fn int64_field_stays_string() {
        let m = test_msg();
        let out = build_request_json(
            &m,
            &BodyMapping::None,
            Value::Null,
            &pp(&[]),
            &qq(&[("count", "9007199254740993")]),
        )
        .unwrap();
        // 64-bit ints serialize as JSON strings in canonical proto3 JSON.
        assert_eq!(out["count"], "9007199254740993");
    }

    #[test]
    fn unknown_query_field_is_dropped() {
        let m = test_msg();
        let out = build_request_json(
            &m,
            &BodyMapping::None,
            Value::Null,
            &pp(&[]),
            &qq(&[("does_not_exist", "x")]),
        )
        .unwrap();
        assert_eq!(out.get("does_not_exist"), None);
    }

    #[test]
    fn root_body_must_be_object() {
        let m = test_msg();
        let err = build_request_json(
            &m,
            &BodyMapping::Root,
            serde_json::json!("a string"),
            &pp(&[]),
            &qq(&[]),
        );
        assert!(err.is_err());
    }

    #[test]
    fn extract_response_body_walks_dotted_path() {
        let v = serde_json::json!({ "result": { "token": "abc" } });
        assert_eq!(
            extract_response_body(&v, "result.token"),
            Some(serde_json::json!("abc"))
        );
        assert_eq!(
            extract_response_body(&v, "result"),
            Some(serde_json::json!({ "token": "abc" }))
        );
        // A missing path is None (caller can warn), distinct from a null field.
        assert_eq!(extract_response_body(&v, "missing"), None);
    }

    #[test]
    fn parse_query_handles_empty_and_pairs() {
        assert_eq!(parse_query(None).unwrap(), Vec::<(String, String)>::new());
        assert_eq!(
            parse_query(Some("")).unwrap(),
            Vec::<(String, String)>::new()
        );
        assert_eq!(
            parse_query(Some("a=1&b=2")).unwrap(),
            vec![("a".into(), "1".into()), ("b".into(), "2".into())]
        );
    }
}
