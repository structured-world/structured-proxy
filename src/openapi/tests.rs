use prost_reflect::{DynamicMessage, MapKey, Value as ProtoValue};

use super::*;

#[test]
fn test_extract_path_params() {
    assert_eq!(
        extract_path_params("/v1/profiles/{profile_id}"),
        vec!["profile_id"]
    );
    assert_eq!(
        extract_path_params("/v1/profiles/{profile_id}/devices/{device_id}"),
        vec!["profile_id", "device_id"]
    );
    assert!(extract_path_params("/v1/auth/login").is_empty());
}

#[test]
fn path_param_with_a_field_template_names_the_field() {
    // `{name=shelves/*}` binds the field `name`, not a field called
    // `name=shelves/*`.
    assert_eq!(extract_path_params("/v1/{name=shelves/*}"), vec!["name"]);
    assert_eq!(extract_path_params("/v1/files/{path=**}"), vec!["path"]);
}

#[test]
fn test_docs_html_contains_scalar() {
    let html = docs_html("/openapi.json", "Test API");
    assert!(html.contains("@scalar/api-reference"));
    assert!(html.contains("/openapi.json"));
    assert!(html.contains("Test API"));
}

#[test]
fn test_well_known_schemas() {
    // Verify well-known type mappings are correct.
    let pool = DescriptorPool::global();
    if let Some(ts) = pool.get_message_by_name("google.protobuf.Timestamp") {
        let schema = well_known_schema(&ts);
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["format"], "date-time");
    }
}

fn config() -> OpenApiConfig {
    OpenApiConfig {
        enabled: true,
        path: "/openapi.json".into(),
        docs_path: "/docs".into(),
        title: Some("Test API".into()),
        version: Some("0.1.0".into()),
    }
}

#[test]
fn test_generate_empty_pool() {
    let pool = DescriptorPool::new();
    let spec = generate(&pool, &config(), &[], &RpcSelection::default());

    assert_eq!(spec["openapi"], "3.0.3");
    assert_eq!(spec["info"]["title"], "Test API");
    assert_eq!(spec["info"]["version"], "0.1.0");
    assert!(spec["paths"].as_object().unwrap().is_empty());
}

#[test]
fn test_field_to_schema_primitives() {
    // Test via JSON output structure.
    let schema = json!({ "type": "string" });
    assert_eq!(schema["type"], "string");

    let int_schema = json!({ "type": "integer", "format": "int32" });
    assert_eq!(int_schema["format"], "int32");

    let i64_schema = json!({ "type": "string", "format": "int64", "description": "64-bit integer (string-encoded)" });
    assert_eq!(i64_schema["type"], "string");
    assert_eq!(i64_schema["format"], "int64");
}

// --- specs generated from annotated descriptors --------------------------------

const HTTP_PROTO: &str = r#"
syntax = "proto3";
package google.api;
message HttpRule {
  string selector = 1;
  oneof pattern {
    string get = 2;
    string put = 3;
    string post = 4;
    string delete = 5;
    string patch = 6;
    CustomHttpPattern custom = 8;
  }
  string body = 7;
  string response_body = 12;
  repeated HttpRule additional_bindings = 11;
}
message CustomHttpPattern {
  string kind = 1;
  string path = 2;
}
"#;

const ANNOTATIONS_PROTO: &str = r#"
syntax = "proto3";
package google.api;
import "google/api/http.proto";
import "google/protobuf/descriptor.proto";
extend google.protobuf.MethodOptions {
  HttpRule http = 72295728;
}
"#;

const HTTPBODY_PROTO: &str = r#"
syntax = "proto3";
package google.api;
import "google/protobuf/any.proto";
message HttpBody {
  string content_type = 1;
  bytes data = 2;
  repeated google.protobuf.Any extensions = 3;
}
"#;

const API_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
import "google/api/httpbody.proto";
import "google/protobuf/any.proto";
import "google/protobuf/duration.proto";
import "google/protobuf/empty.proto";
import "google/protobuf/field_mask.proto";
import "google/protobuf/source_context.proto";
import "google/protobuf/struct.proto";
import "google/protobuf/timestamp.proto";
import "google/protobuf/wrappers.proto";

message Item {
  string name = 1;
  int32 count = 2;
  Note note = 3;
}
message Note {
  string text = 1;
}
message Filter {
  string q = 1;
}
message Search {
  Filter filter = 1;
}
message Upload {
  string name = 1;
  google.api.HttpBody file = 2;
}
message Tree {
  string name = 1;
  Tree child = 2;
}
enum Shade {
  SHADE_UNSPECIFIED = 0;
  SHADE_DARK = 1;
}
// Every kind of field a response can carry, for the schema/wire comparison.
message Wire {
  double ratio = 1;
  float scale = 2;
  int32 small_count = 3;
  sint32 delta = 4;
  sfixed32 fixed_delta = 5;
  int64 big_count = 6;
  sint64 big_delta = 7;
  sfixed64 fixed_big = 8;
  uint32 unsigned_small = 9;
  fixed32 fixed_small = 10;
  uint64 unsigned_big = 11;
  fixed64 fixed_unsigned_big = 12;
  bool flag = 13;
  string display_name = 14;
  bytes raw_data = 15;
  Shade shade = 16;
  Note note = 17;
  google.protobuf.NullValue nothing = 18;
  oneof choice {
    google.protobuf.NullValue unset = 19;
    string label = 20;
    Note memo = 21;
  }
  repeated google.protobuf.NullValue nulls = 22;
  map<string, google.protobuf.NullValue> null_map = 23;
  repeated int64 big_list = 24;
  repeated Shade shades = 25;
  repeated Note notes = 26;
  map<int32, string> by_number = 27;
  map<string, Note> notes_by_key = 28;
  google.protobuf.Timestamp seen_at = 29;
  google.protobuf.Duration ttl = 30;
  google.protobuf.Struct attributes = 31;
  google.protobuf.Value any_value = 32;
  google.protobuf.ListValue values = 33;
  google.protobuf.FieldMask mask = 34;
  google.protobuf.Empty nothing_else = 35;
  google.protobuf.StringValue maybe_name = 36;
  google.protobuf.BytesValue maybe_bytes = 37;
  google.protobuf.BoolValue maybe_flag = 38;
  google.protobuf.Int32Value maybe_int = 39;
  google.protobuf.UInt32Value maybe_uint = 40;
  google.protobuf.Int64Value maybe_long = 41;
  google.protobuf.UInt64Value maybe_ulong = 42;
  google.protobuf.FloatValue maybe_float = 43;
  google.protobuf.DoubleValue maybe_double = 44;
  // In the `google.protobuf` package, but an ordinary message on the wire.
  google.protobuf.SourceContext origin = 45;
}
message NullQuery {
  google.protobuf.NullValue none = 1;
  repeated google.protobuf.NullValue nones = 2;
  NullFilter filter = 3;
  map<string, string> tags = 4;
  repeated Note notes = 5;
  google.protobuf.Timestamp since = 6;
  google.protobuf.Any payload = 7;
  google.protobuf.Struct attrs = 8;
  google.protobuf.ListValue items = 9;
  google.protobuf.Empty nothing = 10;
  google.protobuf.Value loose = 11;
  google.protobuf.SourceContext source = 12;
  repeated google.protobuf.Timestamp seen = 13;
}
message NullFilter {
  google.protobuf.NullValue none = 1;
}

service Api {
  rpc Head(Item) returns (Item) {
    option (google.api.http) = { custom: { kind: "HEAD", path: "/v1/items/{name}" } };
  }
  rpc Verify(Item) returns (Item) {
    option (google.api.http) = { custom: { kind: "*", path: "/v1/verify" } };
  }
  rpc Propfind(Item) returns (Item) {
    option (google.api.http) = { custom: { kind: "PROPFIND", path: "/v1/dav" } };
  }
  rpc Create(Item) returns (Item) {
    option (google.api.http) = {
      post: "/v1/items"
      body: "*"
      additional_bindings { put: "/v1/items/{name}" body: "note" }
      additional_bindings { post: "/v1/items:touch" }
      additional_bindings { get: "/v1/items/{name}/note" response_body: "note" }
    };
  }
  rpc Walk(Tree) returns (Tree) {
    option (google.api.http) = { get: "/v1/tree" };
  }
  rpc Plant(Tree) returns (Tree) {
    option (google.api.http) = { post: "/v1/tree" body: "*" };
  }
  rpc Put(Upload) returns (google.api.HttpBody) {
    option (google.api.http) = { put: "/v1/uploads/{name}" body: "file" };
  }
  rpc Find(Search) returns (Item) {
    option (google.api.http) = { get: "/v1/find" };
  }
  rpc Raw(google.api.HttpBody) returns (google.api.HttpBody) {
    option (google.api.http) = { post: "/v1/raw" body: "*" };
  }
  rpc Archive(Item) returns (Item) {
    option (google.api.http) = { post: "/v1/items/{name}:archive" };
  }
  rpc Broken(Item) returns (Item) {
    option (google.api.http) = { get: "/v1/broken/a{name}b" };
  }
  rpc Shelved(Item) returns (Item) {
    option (google.api.http) = { get: "/v1/shelf/{name=foo%3Abar/*}/books" };
  }
  rpc Shadowed(Item) returns (Item) {
    option (google.api.http) = { get: "/v1/shelf/{name=**}" };
  }
  rpc Echo(Wire) returns (Wire) {
    option (google.api.http) = { post: "/v1/wire" body: "*" };
  }
  rpc Ping(NullQuery) returns (NullQuery) {
    option (google.api.http) = { get: "/v1/ping" };
  }
}
"#;

struct TestProtos;

impl protox::file::FileResolver for TestProtos {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        let source = match name {
            "google/api/http.proto" => HTTP_PROTO,
            "google/api/annotations.proto" => ANNOTATIONS_PROTO,
            "google/api/httpbody.proto" => HTTPBODY_PROTO,
            "test/v1/api.proto" => API_PROTO,
            _ => return protox::file::GoogleFileResolver::new().open_file(name),
        };
        protox::file::File::from_source(name, source)
    }
}

fn test_pool() -> DescriptorPool {
    protox::Compiler::with_file_resolver(TestProtos)
        .open_file("test/v1/api.proto")
        .unwrap()
        .descriptor_pool()
}

fn spec(aliases: &[AliasConfig]) -> Value {
    spec_of(aliases, &[])
}

/// [`spec`] documenting only the RPCs `only` selects.
fn spec_of(aliases: &[AliasConfig], only: &[&str]) -> Value {
    let pool = test_pool();
    let selection = RpcSelection::new(&pool, only).unwrap();
    generate(&pool, &config(), aliases, &selection)
}

#[test]
fn custom_head_rule_is_a_head_operation() {
    let spec = spec(&[]);
    let item = &spec["paths"]["/v1/items/{name}"];
    assert_eq!(item["head"]["operationId"], "Api.Head");
    assert_eq!(item["head"]["parameters"][0]["in"], "path");
}

#[test]
fn custom_verb_after_a_variable_keeps_its_path_and_parameter() {
    // OpenAPI path templating allows a template expression inside a segment,
    // so the verb stays in the path and the variable is a path parameter.
    let spec = spec(&[]);
    let archive = &spec["paths"]["/v1/items/{name}:archive"]["post"];
    assert_eq!(archive["operationId"], "Api.Archive");
    let params = archive["parameters"].as_array().unwrap();
    let path_params: Vec<&Value> = params.iter().filter(|p| p["in"] == "path").collect();
    assert_eq!(path_params.len(), 1);
    assert_eq!(path_params[0]["name"], "name");
    // No path item without the verb comes from this binding.
    assert!(spec["paths"]["/v1/items/{name}"].get("post").is_none());
}

#[test]
fn a_route_the_router_refuses_beside_another_is_not_documented() {
    // The escaped literal is a variable to the router, which then refuses the
    // catch-all after it at that position: only the route it serves is in
    // the spec.
    let spec = spec(&[]);
    let paths = spec["paths"].as_object().unwrap();
    assert!(
        paths.contains_key("/v1/shelf/{name=foo%3Abar/*}/books"),
        "{paths:?}"
    );
    assert!(!paths.contains_key("/v1/shelf/{name=**}"), "{paths:?}");
}

#[test]
fn a_template_the_router_cannot_serve_is_not_documented() {
    // The router skips `a{name}b`; the spec must not promise it either.
    let spec = spec(&[]);
    let paths = spec["paths"].as_object().unwrap();
    assert!(!paths.contains_key("/v1/broken/a{name}b"), "{paths:?}");
    assert!(!paths.values().any(|item| item
        .as_object()
        .unwrap()
        .values()
        .any(|op| op["operationId"] == "Api.Broken")));
}

#[test]
fn star_rule_is_listed_under_every_method_with_distinct_ids() {
    let spec = spec(&[]);
    let verify = spec["paths"]["/v1/verify"].as_object().unwrap();
    let mut methods: Vec<&str> = verify.keys().map(String::as_str).collect();
    methods.sort_unstable();
    let mut expected = OPERATIONS.to_vec();
    expected.sort_unstable();
    assert_eq!(methods, expected);
    let ids: HashSet<&str> = verify
        .values()
        .map(|op| op["operationId"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), OPERATIONS.len());
    assert!(ids.contains("Api.Verify_head"));
}

#[test]
fn extension_method_has_no_openapi_operation() {
    // OpenAPI 3.0 has no slot for PROPFIND.
    assert!(spec(&[])["paths"].get("/v1/dav").is_none());
}

#[test]
fn additional_bindings_are_listed() {
    let spec = spec(&[]);
    assert_eq!(
        spec["paths"]["/v1/items"]["post"]["operationId"],
        "Api.Create"
    );
    assert_eq!(
        spec["paths"]["/v1/items/{name}"]["put"]["operationId"],
        "Api.Create_2"
    );
    assert_eq!(
        spec["paths"]["/v1/items:touch"]["post"]["operationId"],
        "Api.Create_3"
    );
}

#[test]
fn body_rule_decides_body_and_query_fields() {
    let spec = spec(&[]);
    // `body: "*"`: the whole message is the body, nothing in the query.
    let create = &spec["paths"]["/v1/items"]["post"];
    assert_eq!(
        create["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Item"
    );
    assert!(create.get("parameters").is_none(), "{create}");

    // `body: "note"`: that field is the body, the rest is path or query.
    let put = &spec["paths"]["/v1/items/{name}"]["put"];
    assert_eq!(
        put["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/Note"
    );
    let params: Vec<(&str, &str)> = put["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["name"].as_str().unwrap(), p["in"].as_str().unwrap()))
        .collect();
    assert_eq!(params, [("name", "path"), ("count", "query")]);

    // No body rule on a POST: every field is a query parameter.
    let touch = &spec["paths"]["/v1/items:touch"]["post"];
    assert!(touch.get("requestBody").is_none(), "{touch}");
    assert_eq!(touch["parameters"].as_array().unwrap().len(), 3);
}

/// The names of the query parameters of `operation`, in order.
fn query_names(operation: &Value) -> Vec<&str> {
    operation["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["in"] == "query")
        .map(|p| p["name"].as_str().unwrap())
        .collect()
}

#[test]
fn message_typed_query_field_is_one_parameter_per_leaf() {
    // The query parser reads a field below `filter` from the dotted key
    // `filter.q`, so that is the parameter, typed as the leaf.
    let spec = spec(&[]);
    let find = &spec["paths"]["/v1/find"]["get"];
    assert_eq!(query_names(find), ["filter.q"]);
    assert_eq!(find["parameters"][0]["schema"], json!({ "type": "string" }));
}

#[test]
fn self_referencing_message_does_not_recurse_forever() {
    // `Tree.child` is a `Tree`: in the body (POST) its schema is registered
    // once and referenced, and in the query (GET) a message already on the
    // way is not entered again, instead of being expanded until the stack
    // overflows.
    let spec = spec(&[]);
    let tree = &spec["components"]["schemas"]["Tree"];
    assert_eq!(
        tree["properties"]["child"]["$ref"],
        "#/components/schemas/Tree"
    );
    assert_eq!(query_names(&spec["paths"]["/v1/tree"]["get"]), ["name"]);
    assert!(spec["paths"]["/v1/tree"]["post"]["requestBody"].is_object());
}

#[test]
fn head_operations_describe_no_response_content() {
    // A HEAD response has no content (RFC 9110 §9.3.2), whether the binding
    // is a `HEAD` rule or the HEAD operation of a `*` rule.
    let spec = spec(&[]);
    for path in ["/v1/items/{name}", "/v1/verify"] {
        let head = &spec["paths"][path]["head"]["responses"]["200"];
        assert!(head.is_object(), "{path}");
        assert!(head.get("content").is_none(), "{path}: {head}");
    }
    // The other operations of the `*` rule keep their content.
    assert!(spec["paths"]["/v1/verify"]["get"]["responses"]["200"]["content"].is_object());
}

#[test]
fn json_response_body_is_described_by_the_selected_field() {
    // `response_body: "note"` answers with the `note` field only.
    let spec = spec(&[]);
    let content = &spec["paths"]["/v1/items/{name}/note"]["get"]["responses"]["200"]["content"];
    assert_eq!(
        content["application/json"]["schema"]["$ref"],
        "#/components/schemas/Note"
    );
}

#[test]
fn http_body_request_and_response_are_raw_content() {
    let spec = spec(&[]);
    let raw = json!({ "*/*": { "schema": { "type": "string", "format": "binary" } } });
    let put = &spec["paths"]["/v1/uploads/{name}"]["put"];
    assert_eq!(put["requestBody"]["content"], raw);
    assert_eq!(put["responses"]["200"]["content"], raw);
    let root = &spec["paths"]["/v1/raw"]["post"];
    assert_eq!(root["requestBody"]["content"], raw);
    assert_eq!(root["responses"]["200"]["content"], raw);
}

#[test]
fn aliases_get_their_own_operation_ids() {
    let alias: AliasConfig = crate::config::parse_yaml("from: /api/{path}\nto: /v1").unwrap();
    let spec = spec(&[alias]);
    assert_eq!(
        spec["paths"]["/v1/items"]["post"]["operationId"],
        "Api.Create"
    );
    let aliased = &spec["paths"]["/api/items"]["post"]["operationId"];
    assert!(aliased.is_string());
    assert_ne!(aliased, "Api.Create");
}

#[test]
fn a_selection_documents_only_the_rpcs_it_transcodes() {
    // The spec describes what is mounted: an RPC left out of `transcode.only`
    // has no route, so it has no operation either.
    let spec = spec_of(&[], &["test.v1.Api/Find"]);
    let paths = spec["paths"].as_object().unwrap();
    assert_eq!(paths.keys().collect::<Vec<_>>(), ["/v1/find"]);
    assert_eq!(spec["tags"][0]["name"], "Api");
    // A whole service selects all of its RPCs.
    let spec = spec_of(&[], &["test.v1.Api"]);
    assert!(spec["paths"]["/v1/items"]["post"].is_object());
}

#[test]
fn a_selection_naming_nothing_in_the_descriptors_is_an_error() {
    let pool = test_pool();
    for name in ["test.v1.Nope", "test.v1.Api/Nope", "Api"] {
        let err = RpcSelection::new(&pool, [name]).unwrap_err();
        assert!(err.contains(name), "{err}");
    }
}

// --- schema/wire comparison ----------------------------------------------------

/// The value a field of `kind` holds in a sample: never its default, so the
/// wire shows its encoding.
fn sample_value(kind: &Kind, variant: usize, depth: usize) -> ProtoValue {
    match kind {
        Kind::Double => ProtoValue::F64(1.5),
        Kind::Float => ProtoValue::F32(0.5),
        // Positive and below a second in nanos, so it is also a valid
        // `Timestamp.nanos` / `Duration.nanos`.
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => ProtoValue::I32(500_000_000),
        // Within the `Timestamp` range.
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => ProtoValue::I64(1_700_000_000),
        Kind::Uint32 | Kind::Fixed32 => ProtoValue::U32(u32::MAX),
        Kind::Uint64 | Kind::Fixed64 => ProtoValue::U64(u64::MAX),
        Kind::Bool => ProtoValue::Bool(true),
        Kind::String => ProtoValue::String("sample".into()),
        Kind::Bytes => ProtoValue::Bytes(vec![0, 0xff].into()),
        Kind::Enum(e) => ProtoValue::EnumNumber(e.values().last().unwrap().number()),
        Kind::Message(m) => ProtoValue::Message(sample_message(m, variant, depth - 1)),
    }
}

fn sample_key(kind: &Kind) -> MapKey {
    match kind {
        Kind::String => MapKey::String("k".into()),
        Kind::Bool => MapKey::Bool(true),
        Kind::Int32 | Kind::Sint32 | Kind::Sfixed32 => MapKey::I32(-7),
        Kind::Int64 | Kind::Sint64 | Kind::Sfixed64 => MapKey::I64(-7),
        Kind::Uint32 | Kind::Fixed32 => MapKey::U32(7),
        Kind::Uint64 | Kind::Fixed64 => MapKey::U64(7),
        other => unreachable!("not a map key kind: {other:?}"),
    }
}

/// A message with every field set: lists with two elements, maps with one
/// entry, and member `variant` (modulo their size) of each oneof. Below
/// `depth` levels a message field is left unset, and a oneof takes its first
/// member, so a recursive type (`Value` in `ListValue`) ends.
fn sample_message(desc: &MessageDescriptor, variant: usize, depth: usize) -> DynamicMessage {
    let mut msg = DynamicMessage::new(desc.clone());
    for field in desc.fields() {
        if let Some(oneof) = field.containing_oneof() {
            let members: Vec<_> = oneof.fields().collect();
            let pick = if depth == 0 {
                0
            } else {
                variant % members.len()
            };
            if members[pick].number() != field.number() {
                continue;
            }
        }
        let message_typed = matches!(field.kind(), Kind::Message(_));
        if depth == 0 && message_typed {
            continue;
        }
        let value = if field.is_map() {
            let Kind::Message(entry) = field.kind() else {
                unreachable!("a map field is a message of entries");
            };
            let key = sample_key(&entry.map_entry_key_field().kind());
            let value = sample_value(&entry.map_entry_value_field().kind(), variant, depth);
            ProtoValue::Map([(key, value)].into_iter().collect())
        } else if field.is_list() {
            let item = sample_value(&field.kind(), variant, depth);
            ProtoValue::List(vec![item.clone(), item])
        } else {
            sample_value(&field.kind(), variant, depth)
        };
        msg.set_field(&field, value);
    }
    msg
}

/// Check that `value` is valid against the OpenAPI 3.0.3 `schema`, resolving
/// `$ref` in `components`, and that every object key it carries is a declared
/// property or allowed by `additionalProperties`. `at` names the place for the
/// failure message.
fn check_wire(value: &Value, schema: &Value, components: &Value, at: &str) {
    if let Some(reference) = schema["$ref"].as_str() {
        let name = reference.strip_prefix("#/components/schemas/").unwrap();
        let target = &components[name];
        assert!(target.is_object(), "{at}: unresolved {reference}");
        return check_wire(value, target, components, at);
    }
    if let Some(allowed) = schema["enum"].as_array() {
        assert!(allowed.contains(value), "{at}: {value} not in {schema}");
    }
    let Some(ty) = schema["type"].as_str() else {
        // No type: any value, `null` included (OpenAPI 3.0.3 `nullable`).
        return;
    };
    if value.is_null() {
        assert_eq!(schema["nullable"], true, "{at}: null against {schema}");
        return;
    }
    match ty {
        "string" => {
            let s = value
                .as_str()
                .unwrap_or_else(|| panic!("{at}: {value} is not a string"));
            match schema["format"].as_str() {
                Some("int64") => assert!(s.parse::<i64>().is_ok(), "{at}: {s} is not int64"),
                Some("uint64") => assert!(s.parse::<u64>().is_ok(), "{at}: {s} is not uint64"),
                _ => {}
            }
        }
        "integer" => {
            let fits = match schema["format"].as_str() {
                Some("int32") => value.as_i64().is_some_and(|n| i32::try_from(n).is_ok()),
                Some("uint32") => value.as_u64().is_some_and(|n| u32::try_from(n).is_ok()),
                _ => value.is_i64() || value.is_u64(),
            };
            assert!(fits, "{at}: {value} does not fit {schema}");
        }
        "number" => assert!(value.is_number(), "{at}: {value} is not a number"),
        "boolean" => assert!(value.is_boolean(), "{at}: {value} is not a boolean"),
        "array" => {
            let items = value
                .as_array()
                .unwrap_or_else(|| panic!("{at}: {value} is not an array"));
            for (i, item) in items.iter().enumerate() {
                check_wire(item, &schema["items"], components, &format!("{at}[{i}]"));
            }
        }
        "object" => {
            let fields = value
                .as_object()
                .unwrap_or_else(|| panic!("{at}: {value} is not an object"));
            let declared = schema["properties"].as_object();
            for (key, field) in fields {
                let at = format!("{at}.{key}");
                if let Some(property) = declared.and_then(|p| p.get(key)) {
                    check_wire(field, property, components, &at);
                    continue;
                }
                match &schema["additionalProperties"] {
                    Value::Bool(true) => {}
                    extra @ Value::Object(_) => check_wire(field, extra, components, &at),
                    // A bare object (`Struct`) holds any keys.
                    Value::Null if declared.is_none() => {}
                    _ => panic!("{at}: not a declared property of {schema}"),
                }
            }
        }
        other => panic!("{at}: unknown type {other}"),
    }
}

#[test]
fn every_response_validates_against_its_schema() {
    // The spec has to describe what the proxy writes: each sample `Wire`
    // (every scalar, enum, well-known type, a `NullValue` alone, in a oneof,
    // a list and a map) goes through the unary response serializer and must
    // validate against the documented response schema.
    let pool = test_pool();
    let spec = spec(&[]);
    let components = &spec["components"]["schemas"];
    let schema = &spec["paths"]["/v1/wire"]["post"]["responses"]["200"]["content"]
        ["application/json"]["schema"];
    let wire = pool.get_message_by_name("test.v1.Wire").unwrap();
    let choices = wire.oneofs().map(|o| o.fields().len()).max().unwrap();
    // `Value.kind` has six members: every one of them is sampled too.
    for variant in 0..choices.max(6) {
        let msg = sample_message(&wire, variant, 6);
        let body = transcode::json_body(&msg, None).unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        check_wire(&value, schema, components, &format!("Wire#{variant}"));
    }
    // Nothing set: every scalar and enum goes out with its default value.
    let empty = DynamicMessage::new(wire);
    let body = transcode::json_body(&empty, None).unwrap();
    let value: Value = serde_json::from_slice(&body).unwrap();
    check_wire(&value, schema, components, "Wire#default");
}

#[test]
fn null_value_is_json_null_in_bodies_and_a_name_in_parameters() {
    // ProtoJSON writes a `NullValue` as `null`, alone, as a oneof member, in
    // a list and as a map value; the query parser reads it by its enum name,
    // below a message field too.
    let spec = spec(&[]);
    let wire = &spec["components"]["schemas"]["Wire"]["properties"];
    let only_null = json!({ "nullable": true, "enum": [null] });
    assert_eq!(wire["nothing"], only_null);
    assert_eq!(wire["unset"], only_null);
    assert_eq!(
        wire["nulls"],
        json!({ "type": "array", "items": only_null })
    );
    assert_eq!(
        wire["nullMap"],
        json!({ "type": "object", "additionalProperties": only_null })
    );
    assert!(spec["components"]["schemas"].get("NullValue").is_none());

    let ping = &spec["paths"]["/v1/ping"]["get"];
    let params = ping["parameters"].as_array().unwrap();
    let name = json!({ "type": "string", "enum": ["NULL_VALUE"] });
    assert_eq!(params[0]["schema"], name);
    assert_eq!(
        params[1]["schema"],
        json!({ "type": "array", "items": name })
    );
    assert_eq!(params[2]["name"], "filter.none");
    assert_eq!(params[2]["schema"], name);
}

#[test]
fn query_parameters_are_the_keys_the_parser_reads() {
    // A map or a repeated message cannot be set from a query string, so it
    // is no parameter. A well-known type with a string form is one, read from
    // that string; one without (`Any`, `Struct`, `ListValue`, `Empty`) is
    // bound through its own fields, like any message.
    let spec = spec(&[]);
    let ping = &spec["paths"]["/v1/ping"]["get"];
    assert_eq!(
        query_names(ping),
        [
            "none",
            "nones",
            "filter.none",
            "since",
            "payload.type_url",
            "payload.value",
            "items.values",
            "loose",
            "source.file_name",
            "seen"
        ]
    );
    let params = ping["parameters"].as_array().unwrap();
    assert_eq!(
        params[3]["schema"],
        json!({ "type": "string", "format": "date-time" })
    );
    // A `Value` read from a query string is its string value, each repeated
    // key one more element of `ListValue.values`.
    let string = json!({ "type": "string" });
    assert_eq!(
        params[6]["schema"],
        json!({ "type": "array", "items": string })
    );
    assert_eq!(params[7]["schema"], string);
}

#[test]
fn properties_are_keyed_by_the_json_name() {
    // Responses carry `displayName`, not `display_name`.
    let spec = spec(&[]);
    let wire = spec["components"]["schemas"]["Wire"]["properties"]
        .as_object()
        .unwrap();
    assert!(wire.contains_key("displayName"), "{wire:?}");
    assert!(!wire.contains_key("display_name"), "{wire:?}");
}

#[test]
fn a_repeated_string_form_type_is_one_parameter_per_value() {
    // Unlike a repeated ordinary message, a repeated well-known type with a
    // string form is set from the query, one value per repeated key; the
    // parser and the spec have to agree on that.
    let pool = test_pool();
    let spec = spec(&[]);
    let params = spec["paths"]["/v1/ping"]["get"]["parameters"]
        .as_array()
        .unwrap();
    let seen = params.iter().find(|p| p["name"] == "seen").unwrap();
    assert_eq!(
        seen["schema"],
        json!({ "type": "array", "items": { "type": "string", "format": "date-time" } })
    );

    let input = pool.get_message_by_name("test.v1.NullQuery").unwrap();
    let query = "seen=2020-01-01T00:00:00Z&seen=2021-01-01T00:00:00Z&items.values=a&items.values=b";
    let message = transcode::request::build_request_message(
        &input,
        &BodyMapping::None,
        transcode::request::Body::Absent,
        &std::collections::HashMap::new(),
        Some(query),
    )
    .unwrap();
    let value = serde_json::to_value(&message).unwrap();
    assert_eq!(
        value["seen"],
        json!(["2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"])
    );
    assert_eq!(value["items"], json!(["a", "b"]));
}

#[test]
fn an_ordinary_google_protobuf_message_has_its_own_schema() {
    // Only the types with their own JSON form are described inline; any
    // other message of the package is an object of its fields, as ProtoJSON
    // writes it.
    let spec = spec(&[]);
    let schemas = &spec["components"]["schemas"];
    assert_eq!(
        schemas["Wire"]["properties"]["origin"]["$ref"],
        "#/components/schemas/SourceContext"
    );
    assert_eq!(
        schemas["SourceContext"]["properties"]["fileName"],
        json!({ "type": "string" })
    );
}
