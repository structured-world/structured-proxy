use super::*;
use prost_reflect::prost::Message;
use prost_reflect::prost_types::{
    field_descriptor_proto::{Label, Type},
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
};
use prost_reflect::DescriptorPool;
use serde_json::Value;

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

/// Build a `test.TestMsg` and return it as ProtoJSON.
fn build_test_msg(
    mapping: BodyMapping,
    body: Body<'_>,
    path: &[(&str, &str)],
    query: &str,
) -> Result<Value, String> {
    build_request_message(
        &test_msg(),
        &mapping,
        body,
        &pp(path),
        (!query.is_empty()).then_some(query),
    )
    .map(|message| json(&message))
}

#[test]
fn coerce_unsigned_32_rejects_out_of_range() {
    // u32 fields must not accept negatives or values above u32::MAX.
    assert!(scalar(&Kind::Uint32, "-1").is_err());
    assert!(scalar(&Kind::Uint32, "4294967296").is_err());
    assert_eq!(
        scalar(&Kind::Uint32, "42"),
        Ok(prost_reflect::Value::U32(42))
    );
    assert!(scalar(&Kind::Fixed32, "-1").is_err());
    // Signed 32-bit still accepts negatives.
    assert_eq!(
        scalar(&Kind::Int32, "-5"),
        Ok(prost_reflect::Value::I32(-5))
    );
    // And rejects values outside i32 range.
    assert!(scalar(&Kind::Int32, "2147483648").is_err());
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
    let out = build_test_msg(
        BodyMapping::Root,
        Body::Json(br#"{"name": "alice"}"#),
        &[("age", "30")],
        "active=true",
    )
    .unwrap();
    assert_eq!(out["name"], "alice");
    assert_eq!(out["age"], 30); // Int32 from the path
    assert_eq!(out["active"], true); // Bool from the query
}

#[test]
fn body_field_nests_body_under_named_field() {
    let out = build_test_msg(
        BodyMapping::Field("nested".into()),
        Body::Json(br#"{"city": "berlin"}"#),
        &[],
        "name=bob",
    )
    .unwrap();
    assert_eq!(out["nested"]["city"], "berlin");
    assert_eq!(out["name"], "bob");
}

#[test]
fn query_repeated_field_becomes_array() {
    let out = build_test_msg(BodyMapping::None, Body::Absent, &[], "tags=a&tags=b").unwrap();
    assert_eq!(out["tags"], serde_json::json!(["a", "b"]));
}

#[test]
fn query_dotted_path_sets_nested_field() {
    let out = build_test_msg(BodyMapping::None, Body::Absent, &[], "nested.city=paris").unwrap();
    assert_eq!(out["nested"]["city"], "paris");
}

#[test]
fn query_does_not_override_body_or_path() {
    let out = build_test_msg(
        BodyMapping::Root,
        Body::Json(br#"{"name": "from_body"}"#),
        &[("age", "7")],
        "name=from_query&age=99",
    )
    .unwrap();
    assert_eq!(out["name"], "from_body"); // body wins over query
    assert_eq!(out["age"], 7); // path wins over query
}

#[test]
fn int64_field_stays_string() {
    let out = build_test_msg(
        BodyMapping::None,
        Body::Absent,
        &[],
        "count=9007199254740993",
    )
    .unwrap();
    // 64-bit ints serialize as JSON strings in canonical proto3 JSON.
    assert_eq!(out["count"], "9007199254740993");
}

#[test]
fn unknown_query_field_is_dropped() {
    let out = build_test_msg(BodyMapping::None, Body::Absent, &[], "does_not_exist=x").unwrap();
    assert_eq!(out.get("does_not_exist"), None);
}

#[test]
fn root_body_must_be_object() {
    let err = build_test_msg(BodyMapping::Root, Body::Json(br#""a string""#), &[], "");
    assert!(err.is_err());
}

// ---- The message builder ----

const TYPES_PROTO: &str = r#"
syntax = "proto3";
package t;
import "google/protobuf/duration.proto";
import "google/protobuf/timestamp.proto";
import "google/protobuf/wrappers.proto";
import "google/protobuf/struct.proto";

enum Size {
  SIZE_UNSPECIFIED = 0;
  SMALL = 1;
  LARGE = 2;
}

message Address {
  string city = 1;
  string zip = 2;
}

message Req {
  string display_name = 1;
  int32 age = 2;
  int64 count = 3;
  bool active = 4;
  repeated string tags = 5;
  Address address = 6;
  google.protobuf.Timestamp at = 7;
  google.protobuf.Duration ttl = 8;
  Size size = 9;
  repeated Size sizes = 10;
  bytes blob = 11;
  float ratio = 12;
  double score = 13;
  map<string, string> labels = 14;
  repeated Address addresses = 15;
  oneof choice {
    string left = 16;
    string right = 17;
  }
  uint64 big = 18;
  google.protobuf.StringValue note = 19;
  google.protobuf.Struct meta = 20;
  int32 max_items = 21;
  repeated int32 tag_ids = 22;
}
"#;

struct TypesProto;

impl protox::file::FileResolver for TypesProto {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        match name {
            "types.proto" => protox::file::File::from_source(name, TYPES_PROTO),
            _ => protox::file::GoogleFileResolver::new().open_file(name),
        }
    }
}

fn req() -> MessageDescriptor {
    message_type("t.Req")
}

/// A message type of the test pool, the well-known types included.
fn message_type(name: &str) -> MessageDescriptor {
    protox::Compiler::with_file_resolver(TypesProto)
        .open_file("types.proto")
        .unwrap()
        .descriptor_pool()
        .get_message_by_name(name)
        .unwrap()
}

/// Build a `t.Req` from the parts of a request.
fn build_req(
    mapping: BodyMapping,
    body: Body<'_>,
    path: &[(&str, &str)],
    query: &str,
) -> Result<DynamicMessage, String> {
    build_request_message(
        &req(),
        &mapping,
        body,
        &pp(path),
        (!query.is_empty()).then_some(query),
    )
}

/// The message as ProtoJSON, default values left out.
fn json(message: &DynamicMessage) -> Value {
    serde_json::to_value(message).unwrap()
}

#[test]
fn a_default_valued_body_scalar_beats_the_query() {
    // `count: 0`, `active: false` and an empty string read the same as unset
    // on the built message; the body still set them, so the query must not.
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"count": "0", "active": false, "displayName": "", "age": 0}"#),
        &[],
        "count=5&active=true&display_name=q&age=9",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({}));
}

#[test]
fn a_body_key_in_either_naming_beats_the_query() {
    // A body may use the JSON name or the proto name of a field; the query
    // uses the proto name. Both spellings are the same field.
    for body in [
        &br#"{"displayName": "body"}"#[..],
        br#"{"display_name": "body"}"#,
    ] {
        let message = build_req(
            BodyMapping::Root,
            Body::Json(body),
            &[],
            "display_name=query",
        )
        .unwrap();
        assert_eq!(json(&message)["displayName"], "body");
    }
}

#[test]
fn the_query_fills_beside_a_nested_body_object() {
    // The body set `address.city` only: the query cannot replace it, but can
    // fill `address.zip`.
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"address": {"city": "paris"}}"#),
        &[],
        "address.city=rome&address.zip=75001",
    )
    .unwrap();
    assert_eq!(
        json(&message)["address"],
        serde_json::json!({"city": "paris", "zip": "75001"})
    );
}

#[test]
fn a_body_field_set_to_null_keeps_the_query_out_of_it() {
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"address": null}"#),
        &[],
        "address.city=rome&age=3",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({"age": 3}));
}

#[test]
fn the_query_fills_what_the_body_left_out() {
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"displayName": "body"}"#),
        &[],
        "age=3&tags=a&tags=b&size=LARGE",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"displayName": "body", "age": 3, "tags": ["a", "b"], "size": "LARGE"})
    );
}

#[test]
fn the_path_wins_over_body_and_query() {
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"displayName": "body", "address": {"city": "paris"}}"#),
        &[("display_name", "path"), ("address.city", "rome")],
        "display_name=query&address.city=oslo",
    )
    .unwrap();
    assert_eq!(json(&message)["displayName"], "path");
    assert_eq!(json(&message)["address"]["city"], "rome");
}

#[test]
fn a_body_bound_to_a_field_fills_that_field_only() {
    // `body: "address"`: the body is the Address, the query binds the rest
    // and whatever of the Address the body left out.
    let message = build_req(
        BodyMapping::Field("address".into()),
        Body::Json(br#"{"city": "paris"}"#),
        &[],
        "address.city=rome&address.zip=75001&age=4",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"age": 4, "address": {"city": "paris", "zip": "75001"}})
    );
}

#[test]
fn a_body_bound_to_a_scalar_field_takes_its_json_value() {
    let message = build_req(
        BodyMapping::Field("display_name".into()),
        Body::Json(br#""from the body""#),
        &[],
        "display_name=query",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"displayName": "from the body"})
    );
}

#[test]
fn a_field_reserved_for_a_raw_body_is_left_to_it() {
    // A raw HttpBody field is filled after the message is built; the query
    // must not bind it or anything below it.
    let message = build_req(
        BodyMapping::Field("address".into()),
        Body::Absent,
        &[],
        "address.city=rome&age=4",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({"age": 4}));
}

#[test]
fn well_known_types_come_from_path_and_query_strings() {
    let message = build_req(
        BodyMapping::None,
        Body::Absent,
        &[("at", "2026-01-02T03:04:05Z")],
        "ttl=1.5s",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"at": "2026-01-02T03:04:05Z", "ttl": "1.500s"})
    );
}

#[test]
fn a_malformed_well_known_type_string_is_an_error() {
    let err = build_req(BodyMapping::None, Body::Absent, &[], "ttl=soon").unwrap_err();
    assert!(err.contains("`ttl`"), "{err}");
}

#[test]
fn an_enum_binds_by_name_and_an_unknown_name_is_an_error() {
    let message = build_req(
        BodyMapping::None,
        Body::Absent,
        &[],
        "size=SMALL&sizes=LARGE&sizes=SMALL",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"size": "SMALL", "sizes": ["LARGE", "SMALL"]})
    );
    let err = build_req(BodyMapping::None, Body::Absent, &[], "size=HUGE").unwrap_err();
    assert!(err.contains("HUGE"), "{err}");
}

#[test]
fn a_form_body_binds_typed_fields() {
    // Form values are strings; each becomes its field's type, repeated keys
    // collect, dotted keys reach nested fields, and the form is the body, so
    // the query only fills around it.
    let message = build_req(
        BodyMapping::Root,
        Body::Form(b"active=true&age=41&tags=a&tags=b&address.city=paris&unknown=x"),
        &[],
        "age=9&address.zip=75001",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({
            "active": true, "age": 41, "tags": ["a", "b"],
            "address": {"city": "paris", "zip": "75001"}
        })
    );
}

#[test]
fn a_form_body_bound_to_a_message_field_fills_it() {
    let message = build_req(
        BodyMapping::Field("address".into()),
        Body::Form(b"city=paris"),
        &[],
        "address.city=rome&age=2",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"age": 2, "address": {"city": "paris"}})
    );
}

#[test]
fn a_form_body_cannot_fill_a_scalar_field() {
    let err = build_req(
        BodyMapping::Field("display_name".into()),
        Body::Form(b"a=b"),
        &[],
        "",
    )
    .unwrap_err();
    assert!(err.contains("display_name"), "{err}");
}

#[test]
fn a_malformed_body_is_an_error() {
    let err = build_req(BodyMapping::Root, Body::Json(b"{not json"), &[], "").unwrap_err();
    assert!(err.starts_with("failed to decode request body"), "{err}");
    // Trailing data after the object is malformed too.
    assert!(build_req(BodyMapping::Root, Body::Json(b"{} {}"), &[], "").is_err());
}

#[test]
fn a_body_value_of_the_wrong_type_is_an_error() {
    for body in [
        &br#"{"age": "old"}"#[..],
        br#"{"active": "yes"}"#,
        br#"{"address": "paris"}"#,
        br#"{"tags": "a"}"#,
        br#""a string""#,
        b"[]",
    ] {
        let result = build_req(BodyMapping::Root, Body::Json(body), &[], "");
        assert!(result.is_err(), "{}", String::from_utf8_lossy(body));
    }
}

#[test]
fn an_unknown_body_key_is_an_error() {
    let err = build_req(BodyMapping::Root, Body::Json(br#"{"nope": 1}"#), &[], "").unwrap_err();
    assert!(err.contains("nope"), "{err}");
}

#[test]
fn an_empty_or_null_body_sets_nothing() {
    for body in [&b""[..], b"null", b" null\n", b"{}"] {
        let message = build_req(BodyMapping::Root, Body::Json(body), &[], "age=1").unwrap();
        assert_eq!(json(&message), serde_json::json!({"age": 1}));
    }
    // An empty form is an empty body too.
    let message = build_req(BodyMapping::Root, Body::Form(b""), &[], "").unwrap();
    assert_eq!(json(&message), serde_json::json!({}));
}

#[test]
fn a_path_or_query_value_of_the_wrong_type_is_an_error() {
    for query in [
        "age=old",
        "age=2147483648",
        "active=yes",
        "count=1.5",
        "big=-1",
        "ratio=1e39",
        "blob=***",
    ] {
        let err = build_req(BodyMapping::None, Body::Absent, &[], query).unwrap_err();
        let name = query.split('=').next().unwrap();
        assert!(err.contains(&format!("`{name}`")), "{query}: {err}");
    }
    assert!(build_req(BodyMapping::None, Body::Absent, &[("age", "x")], "").is_err());
}

#[test]
fn numbers_read_as_protojson_reads_them() {
    let message = build_req(
        BodyMapping::None,
        Body::Absent,
        &[],
        "score=NaN&ratio=-Infinity&big=18446744073709551615&count=-9007199254740993",
    )
    .unwrap();
    let json = json(&message);
    assert_eq!(json["score"], "NaN");
    assert_eq!(json["ratio"], "-Infinity");
    assert_eq!(json["big"], "18446744073709551615");
    assert_eq!(json["count"], "-9007199254740993");
}

#[test]
fn bytes_read_standard_and_url_safe_base64() {
    // A query spells `+` as `%2B`: a bare `+` is a space in a form.
    for encoded in ["-_8", "%2B%2F8%3D", "%2B%2F8"] {
        let message = build_req(
            BodyMapping::None,
            Body::Absent,
            &[],
            &format!("blob={encoded}"),
        )
        .unwrap();
        assert_eq!(
            message
                .get_field_by_name("blob")
                .unwrap()
                .as_bytes()
                .unwrap()
                .as_ref(),
            [0xfb, 0xff],
            "{encoded}"
        );
    }
}

#[test]
fn a_map_field_cannot_be_bound_from_a_string() {
    let err = build_req(BodyMapping::None, Body::Absent, &[], "labels=a").unwrap_err();
    assert!(err.contains("`labels`"), "{err}");
}

#[test]
fn keys_below_a_repeated_or_map_field_are_dropped() {
    let message = build_req(
        BodyMapping::None,
        Body::Absent,
        &[],
        "addresses.city=paris&labels.a=b&age.x=1&age=2",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({"age": 2}));
}

#[test]
fn an_unknown_nested_key_sets_nothing_on_the_way() {
    // The key is dropped whole: `address` is not created for it.
    let message = build_req(BodyMapping::None, Body::Absent, &[], "address.nope=x").unwrap();
    assert!(!message.has_field_by_name("address"));
}

#[test]
fn two_members_of_a_oneof_are_an_error() {
    let err = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"left": "l"}"#),
        &[("right", "r")],
        "",
    )
    .unwrap_err();
    assert!(err.contains("choice"), "{err}");
    // The query cannot pick the other member either.
    let err = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"left": "l"}"#),
        &[],
        "right=r",
    )
    .unwrap_err();
    assert!(err.contains("choice"), "{err}");
    // Setting the same member again is fine.
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"left": "l"}"#),
        &[("left", "p")],
        "",
    )
    .unwrap();
    assert_eq!(json(&message)["left"], "p");
}

#[test]
fn a_body_that_is_a_well_known_type_beats_the_query() {
    // A well-known input type reads its body as a whole (a string, not a map
    // of fields), so the body sets the whole message and the query nothing.
    let note = build_request_message(
        &message_type("google.protobuf.StringValue"),
        &BodyMapping::Root,
        Body::Json(br#""from the body""#),
        &HashMap::new(),
        Some("value=query"),
    )
    .unwrap();
    assert_eq!(json(&note), serde_json::json!("from the body"));
    let at = build_request_message(
        &message_type("google.protobuf.Timestamp"),
        &BodyMapping::Root,
        Body::Json(br#""2026-01-02T03:04:05Z""#),
        &HashMap::new(),
        Some("seconds=0&nanos=5"),
    )
    .unwrap();
    assert_eq!(json(&at), serde_json::json!("2026-01-02T03:04:05Z"));
}

#[test]
fn only_protojson_float_spellings_are_accepted() {
    // ProtoJSON: a finite number, or exactly `NaN`, `Infinity`, `-Infinity`.
    // Rust's parser also reads `inf`, `nan` and `infinity`, and an overflowing
    // decimal as infinity; those are not the client's values.
    for field in ["score", "ratio"] {
        for raw in [
            "inf", "-inf", "nan", "infinity", "INFINITY", "1e400", "-1e400",
        ] {
            let query = format!("{field}={raw}");
            let err = build_req(BodyMapping::None, Body::Absent, &[], &query).unwrap_err();
            assert!(err.contains(&format!("`{field}`")), "{query}: {err}");
        }
        for raw in ["Infinity", "-Infinity", "NaN", "1.5", "-0", "1e3"] {
            let query = format!("{field}={raw}");
            assert!(
                build_req(BodyMapping::None, Body::Absent, &[], &query).is_ok(),
                "{query}"
            );
        }
    }
}

#[test]
fn a_path_bound_field_is_taken_from_the_path_whatever_the_body_holds() {
    // The path wins over the body, so a body value of the wrong type for a
    // field the path binds does not decide the request.
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"displayName": 123, "address": {"city": 5, "zip": "z"}, "age": 2}"#),
        &[("display_name", "path"), ("address.city", "rome")],
        "age=9",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({
            "displayName": "path", "age": 2,
            "address": {"city": "rome", "zip": "z"}
        })
    );
    // Without a query too, and with the proto name as the body key.
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"display_name": [1]}"#),
        &[("display_name", "path")],
        "",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({"displayName": "path"}));
    // A body field bound to one field: a path key below it is taken the same way.
    let message = build_req(
        BodyMapping::Field("address".into()),
        Body::Json(br#"{"city": false, "zip": "z"}"#),
        &[("address.city", "rome")],
        "",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"address": {"city": "rome", "zip": "z"}})
    );
    // A wrong value in a field the path does not bind is still an error.
    let err = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"displayName": 123, "age": "old"}"#),
        &[("display_name", "path")],
        "",
    )
    .unwrap_err();
    assert!(err.starts_with("failed to decode request body"), "{err}");
}

#[test]
fn a_path_bound_form_field_is_taken_from_the_path_whatever_the_form_holds() {
    // The form is the body, so the path wins over it as over a JSON body.
    let message = build_req(
        BodyMapping::Root,
        Body::Form(b"age=old&count=3"),
        &[("age", "7")],
        "",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({"age": 7, "count": "3"}));
    // Under `body: "address"` the form keys sit below the field.
    let message = build_req(
        BodyMapping::Field("address".into()),
        Body::Form(b"city=x&zip=z"),
        &[("address.city", "rome")],
        "",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"address": {"city": "rome", "zip": "z"}})
    );
    // A wrong value in a field the path does not bind is still an error.
    let err = build_req(
        BodyMapping::Root,
        Body::Form(b"age=old&count=many"),
        &[("age", "7")],
        "",
    )
    .unwrap_err();
    assert!(err.contains("`count`"), "{err}");
}

#[test]
fn a_nested_well_known_type_in_the_body_is_set_whole() {
    // A Struct reads its body object as its own keys, not as its fields, so
    // the body sets the whole Struct and the query cannot reach into it.
    let message = build_req(
        BodyMapping::Root,
        Body::Json(br#"{"meta": {"k": "v"}}"#),
        &[],
        "meta.fields=x&age=1",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"meta": {"k": "v"}, "age": 1})
    );
}

#[test]
fn a_well_known_type_bound_field_by_field_is_kept_and_must_be_valid() {
    // Path, query and form keys reach the fields of a Timestamp, Duration or
    // wrapper, so none of the client's values is lost.
    let message = build_req(
        BodyMapping::None,
        Body::Absent,
        &[("ttl.seconds", "9")],
        "at.seconds=5&at.nanos=7&note.value=x&age=1",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({
            "at": "1970-01-01T00:00:05.000000007Z", "ttl": "9s",
            "note": "x", "age": 1
        })
    );
    // A form body too, at the root or bound to a well-known type field.
    let message = build_req(
        BodyMapping::Root,
        Body::Form(b"at.seconds=5&age=2"),
        &[],
        "",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"at": "1970-01-01T00:00:05Z", "age": 2})
    );
    let message = build_req(
        BodyMapping::Field("note".into()),
        Body::Form(b"value=hello"),
        &[],
        "",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({"note": "hello"}));
    // A path parameter sets one field of it; the query may fill another, as
    // beside a path-bound field of any message.
    let message = build_req(
        BodyMapping::None,
        Body::Absent,
        &[("at.seconds", "5")],
        "at.nanos=7&at.seconds=9",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"at": "1970-01-01T00:00:05.000000007Z"})
    );
    // The result must still be a value its JSON form could hold: nanos past
    // 999999999, or seconds and nanos of opposite sign, are not.
    for (path, query) in [
        (&[][..], "at.nanos=2000000000"),
        (&[("ttl.seconds", "5")][..], "ttl.nanos=-1"),
        (&[][..], "at.seconds=253402300800"),
    ] {
        let err = build_req(BodyMapping::None, Body::Absent, path, query).unwrap_err();
        assert!(err.starts_with("invalid value"), "{query}: {err}");
    }
    let err = build_req(
        BodyMapping::Field("at".into()),
        Body::Form(b"nanos=-5"),
        &[],
        "",
    )
    .unwrap_err();
    assert!(err.starts_with("invalid value"), "{err}");
}

#[test]
fn a_root_well_known_type_bound_field_by_field_must_be_valid() {
    // The same holds when the input message itself is a well-known type.
    let at = message_type("google.protobuf.Timestamp");
    let message = build_request_message(
        &at,
        &BodyMapping::None,
        Body::Absent,
        &pp(&[("seconds", "5")]),
        Some("nanos=7"),
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!("1970-01-01T00:00:05.000000007Z")
    );
    let message = build_request_message(
        &at,
        &BodyMapping::Root,
        Body::Form(b"seconds=5"),
        &HashMap::new(),
        None,
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!("1970-01-01T00:00:05Z"));
    let err = build_request_message(
        &at,
        &BodyMapping::None,
        Body::Absent,
        &pp(&[("seconds", "5")]),
        Some("nanos=2000000000"),
    )
    .unwrap_err();
    assert!(err.starts_with("invalid value"), "{err}");
}

#[test]
fn form_and_query_keys_bind_by_proto_or_json_name() {
    // ProtoJSON reads a field under either name, and so do form and query keys.
    let message = build_req(
        BodyMapping::Root,
        Body::Form(b"displayName=Alice&maxItems=3"),
        &[],
        "",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"displayName": "Alice", "maxItems": 3})
    );
    let message = build_req(BodyMapping::None, Body::Absent, &[], "maxItems=4").unwrap();
    assert_eq!(json(&message), serde_json::json!({"maxItems": 4}));
    // The path wins over a form key in either naming, whatever it holds.
    let message = build_req(
        BodyMapping::Root,
        Body::Form(b"maxItems=many&age=1"),
        &[("max_items", "7")],
        "",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({"maxItems": 7, "age": 1}));
}

#[test]
fn both_names_of_one_field_bind_as_one_key_in_request_order() {
    // `tag_ids` and `tagIds` are one field: a repeated one gets every value in
    // request order, a singular one the last value sent, whichever name it
    // came under.
    let message = build_req(
        BodyMapping::None,
        Body::Absent,
        &[],
        "tag_ids=1&tagIds=2&tag_ids=3&maxItems=5&max_items=6",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"tagIds": [1, 2, 3], "maxItems": 6})
    );
    let message = build_req(
        BodyMapping::None,
        Body::Absent,
        &[],
        "max_items=6&maxItems=5",
    )
    .unwrap();
    assert_eq!(json(&message), serde_json::json!({"maxItems": 5}));
    let message = build_req(
        BodyMapping::Root,
        Body::Form(b"tagIds=1&tag_ids=2&maxItems=5&max_items=6"),
        &[],
        "",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"tagIds": [1, 2], "maxItems": 6})
    );
}

#[test]
fn the_query_fills_a_form_bound_well_known_field_the_form_left_out() {
    // A form bound to a Timestamp field sets it field by field, like any
    // message field, so the query fills what the form did not send.
    let message = build_req(
        BodyMapping::Field("at".into()),
        Body::Form(b"seconds=5"),
        &[],
        "at.nanos=7&at.seconds=9",
    )
    .unwrap();
    assert_eq!(
        json(&message),
        serde_json::json!({"at": "1970-01-01T00:00:05.000000007Z"})
    );
}

#[test]
fn a_body_media_type_picks_json_or_form() {
    assert_eq!(
        Body::new(Some("application/x-www-form-urlencoded"), b"a"),
        Body::Form(b"a")
    );
    assert_eq!(Body::new(Some("application/json"), b"a"), Body::Json(b"a"));
    assert_eq!(Body::new(Some("text/plain"), b"a"), Body::Json(b"a"));
    assert_eq!(Body::new(None, b"a"), Body::Json(b"a"));
}
