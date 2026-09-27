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
    let spec = generate(&pool, &config(), &[]);

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
    };
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

fn spec(aliases: &[AliasConfig]) -> Value {
    let pool = protox::Compiler::with_file_resolver(TestProtos)
        .open_file("test/v1/api.proto")
        .unwrap()
        .descriptor_pool();
    generate(&pool, &config(), aliases)
}

#[test]
fn custom_head_rule_is_a_head_operation() {
    let spec = spec(&[]);
    let item = &spec["paths"]["/v1/items/{name}"];
    assert_eq!(item["head"]["operationId"], "Api.Head");
    assert_eq!(item["head"]["parameters"][0]["in"], "path");
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

#[test]
fn message_typed_query_parameter_schema_is_registered() {
    // `filter` is bound only through the query; its `$ref` must resolve to a
    // schema in `components`.
    let spec = spec(&[]);
    let param = &spec["paths"]["/v1/find"]["get"]["parameters"][0];
    assert_eq!(param["in"], "query");
    assert_eq!(param["schema"]["$ref"], "#/components/schemas/Filter");
    assert!(
        spec["components"]["schemas"].get("Filter").is_some(),
        "{}",
        spec["components"]["schemas"]
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
    let alias: AliasConfig = serde_yaml::from_str("from: /api/{path}\nto: /v1").unwrap();
    let spec = spec(&[alias]);
    assert_eq!(
        spec["paths"]["/v1/items"]["post"]["operationId"],
        "Api.Create"
    );
    let aliased = &spec["paths"]["/api/items"]["post"]["operationId"];
    assert!(aliased.is_string());
    assert_ne!(aliased, "Api.Create");
}
