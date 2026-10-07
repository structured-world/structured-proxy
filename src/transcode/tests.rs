use super::*;
use axum::routing::get;

/// Serves a minimal `google/api` from memory plus one test file.
struct OneApi(&'static str);

impl protox::file::FileResolver for OneApi {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        let source = match name {
            "google/api/annotations.proto" => {
                r#"syntax = "proto3";
package google.api;
import "google/protobuf/descriptor.proto";
message HttpRule {
  oneof pattern { string get = 2; string post = 4; }
  string body = 7;
  string response_body = 12;
}
extend google.protobuf.MethodOptions { HttpRule http = 72295728; }
"#
            }
            "api.proto" => self.0,
            _ => return protox::file::GoogleFileResolver::new().open_file(name),
        };
        protox::file::File::from_source(name, source)
    }
}

/// A descriptor pool compiled from one annotated `.proto` source.
fn api_pool(source: &'static str) -> DescriptorPool {
    protox::Compiler::with_file_resolver(OneApi(source))
        .open_file("api.proto")
        .unwrap()
        .descriptor_pool()
}

#[test]
fn response_body_names_proto_fields_not_json_keys() {
    // `response_body` is a proto field path (`user_info`), while the
    // serialized message uses JSON names (`userInfo`); multi-word fields must
    // still resolve, at every level.
    let pool = api_pool(
        r#"syntax = "proto3";
package t;
message Inner { string display_name = 1; }
message Resp { Inner user_info = 1; }
"#,
    );
    let inner_desc = pool.get_message_by_name("t.Inner").unwrap();
    let mut inner = DynamicMessage::new(inner_desc);
    inner.set_field_by_name("display_name", prost_reflect::Value::String("Ann".into()));
    let mut resp = DynamicMessage::new(pool.get_message_by_name("t.Resp").unwrap());
    resp.set_field_by_name("user_info", prost_reflect::Value::Message(inner));

    let json = |path| {
        serde_json::from_slice::<serde_json::Value>(&json_body(&resp, Some(path)).unwrap()).unwrap()
    };
    assert_eq!(json("user_info"), serde_json::json!({"displayName": "Ann"}));
    assert_eq!(json("user_info.display_name"), serde_json::json!("Ann"));
    // A path that names no field is JSON null, as before.
    assert_eq!(json("user_info.missing"), serde_json::Value::Null);
    assert_eq!(json("userInfo"), serde_json::Value::Null);
}

#[test]
fn alias_paths_are_converted_like_the_route_they_alias() {
    // An alias keeps the route's field template, so it must go through the
    // same template conversion: `{path=**}` is axum's `{*path}`, never a
    // literal capture named `path=**` that leaves the field unbound.
    let pool = api_pool(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string path = 1; }
service S {
  rpc Get(Req) returns (Req) { option (google.api.http) = { get: "/v1/files/{path=**}" }; }
  rpc Watch(Req) returns (stream Req) { option (google.api.http) = { get: "/v1/logs/{path=*}" }; }
}
"#,
    );
    let alias: AliasConfig = serde_yaml::from_str("from: /api/{path}\nto: /v1").unwrap();
    let paths = route_paths(&pool, &[alias], &RpcSelection::default());
    for expected in [
        "/v1/files/{*path}",
        "/api/files/{*path}",
        "/v1/logs/{path}",
        "/api/logs/{path}",
    ] {
        assert!(
            paths.contains(&("GET".to_owned(), expected.to_owned())),
            "{expected} missing from {paths:?}"
        );
    }
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

#[test]
fn custom_verb_after_a_variable_or_wildcard_is_split_off() {
    // `Template = "/" Segments [ Verb ]`: axum cannot match text after a
    // capture, so the verb leaves the mounted path and is kept to be matched
    // by the transcoded router.
    let cases = [
        // (template, axum path, shape, captures, verb)
        (
            "/v2/ops/{operation}:cancel",
            "/v2/ops/{operation}",
            "/v2/ops/{}",
            &["operation"][..],
            Some(":cancel"),
        ),
        (
            "/v1/{name=publishers/*/books/*}:archive",
            "/v1/{*name}",
            "/v1/{*}",
            &["name"][..],
            Some(":archive"),
        ),
        (
            "/v1/{name=*}:x",
            "/v1/{name}",
            "/v1/{}",
            &["name"][..],
            Some(":x"),
        ),
        (
            "/v1/files/{path=**}:x",
            "/v1/files/{*path}",
            "/v1/files/{*}",
            &["path"][..],
            Some(":x"),
        ),
        (
            "/v1/*:x",
            "/v1/{wildcard2}",
            "/v1/{}",
            &["wildcard2"][..],
            Some(":x"),
        ),
        (
            "/v1/**:x",
            "/v1/{*wildcard2}",
            "/v1/{*}",
            &["wildcard2"][..],
            Some(":x"),
        ),
        // A verb whose LITERAL holds a colon is the whole rest of the segment.
        ("/v1/{a}:b:c", "/v1/{a}", "/v1/{}", &["a"][..], Some(":b:c")),
    ];
    for (template, axum, shape, captures, verb) in cases {
        let mount = path::MountedPath::new(template);
        assert_eq!(mount.axum, axum, "{template}");
        assert_eq!(mount.shape, shape, "{template}");
        assert_eq!(mount.captures, captures, "{template}");
        assert_eq!(mount.verb.as_deref(), verb, "{template}");
        // Policies and the log see the template's own path, verb included.
        assert_eq!(
            mount.display(),
            axum.to_owned() + verb.unwrap(),
            "{template}"
        );
        assert!(path::mountable(&mount.axum).is_ok(), "{template}");
    }
    assert_eq!(proto_path_to_axum("/v2/ops/{op}:cancel"), "/v2/ops/{op}");
}

#[test]
fn verb_after_a_literal_or_anything_else_stays_in_the_path() {
    // After a literal axum matches the verb as part of it.
    let mount = path::MountedPath::new("/v1/nodes:batch");
    assert_eq!(mount.axum, "/v1/nodes:batch");
    assert_eq!(mount.verb, None);
    assert!(mount.captures.is_empty());
    // A colon before the last segment is no verb.
    let mount = path::MountedPath::new("/v1/{a}:x/items");
    assert_eq!(mount.verb, None);
    assert_eq!(mount.axum, "/v1/{a}:x/items");
    // An empty verb, and text after a variable that is not a verb, stay in the
    // path, which the router cannot match.
    for template in ["/v1/{a}:", "/v1/{a}x:y", "/v1/{a"] {
        let mount = path::MountedPath::new(template);
        assert_eq!(mount.verb, None, "{template}");
        assert!(path::mountable(&mount.axum).is_err(), "{template}");
    }
}

#[test]
fn mountable_refuses_what_axum_would_panic_on() {
    for (path, reason) in [
        ("/v1/a{x}b", "text around a capture"),
        ("/v1/{x}{y}", "two captures in one segment"),
        ("/v1/{}", "a capture without a name"),
        ("v1/items", "no leading slash"),
        ("/v1/:items", "a segment starting with ':'"),
        ("/v1/*items", "a segment starting with '*'"),
    ] {
        assert!(path::mountable(path).is_err(), "{path}: {reason}");
        // The same path does panic axum.
        let registered = std::panic::catch_unwind(|| {
            let _router: Router<()> = Router::new().route(path, get(|| async { "ok" }));
        });
        assert!(registered.is_err(), "{path}: axum took it");
    }
    for path in ["/v1/{x}", "/v1/{*rest}", "/v1/nodes:batch", "/"] {
        assert!(path::mountable(path).is_ok(), "{path}");
    }
}

#[test]
fn route_paths_list_one_route_for_bindings_that_differ_only_by_verb() {
    // A verb after a variable is matched past the router, so the bindings of
    // one method that differ only by it share a route; a repeated method,
    // shape and verb is a real duplicate and stays visible to the caller.
    let pool = api_pool(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string name = 1; string id = 2; }
service S {
  rpc Get(Req) returns (Req) { option (google.api.http) = { get: "/v1/ops/{name}" }; }
  rpc Cancel(Req) returns (Req) { option (google.api.http) = { post: "/v1/ops/{name}:cancel" }; }
  rpc Pause(Req) returns (Req) { option (google.api.http) = { post: "/v1/ops/{id}:pause" }; }
  rpc Batch(Req) returns (Req) { option (google.api.http) = { post: "/v1/ops:batch" }; }
  rpc Again(Req) returns (Req) { option (google.api.http) = { post: "/v1/ops/{id}:cancel" }; }
}
"#,
    );
    let paths = route_paths(&pool, &[], &RpcSelection::default());
    // A path with verbs answers every method (405 for those its verb is not
    // bound to), so it is listed as `*`.
    let expected = [
        ("*", "/v1/ops/{name}"),
        ("POST", "/v1/ops/{id}"),
        ("POST", "/v1/ops:batch"),
    ];
    let expected: Vec<(String, String)> = expected
        .iter()
        .map(|(m, p)| ((*m).to_owned(), (*p).to_owned()))
        .collect();
    assert_eq!(paths, expected);
}

#[test]
fn bindings_of_one_shape_share_one_table_whatever_their_names() {
    // The router tells `/v1/ops/{name}` and `/v1/ops/{id}` apart by shape
    // only; registering both panicked axum. One table takes them.
    let pool = api_pool(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string name = 1; string id = 2; }
service S {
  rpc Get(Req) returns (Req) { option (google.api.http) = { get: "/v1/ops/{name}" }; }
  rpc Post(Req) returns (Req) { option (google.api.http) = { post: "/v1/ops/{id}" }; }
  rpc Broken(Req) returns (Req) { option (google.api.http) = { get: "/v1/broken/a{name}b" }; }
}
"#,
    );
    let tables = path_tables(&pool, &[], &TranscodeOptions::default());
    let paths: Vec<&str> = tables.iter().map(|t| t.path.as_str()).collect();
    // The template the router cannot match is left out.
    assert_eq!(paths, ["/v1/ops/{name}"]);
    let built = table::Routes::new(tables);
    assert_eq!(answer(&built, Method::POST, "/v1/ops/x"), "/t.S/Post");
    // The router itself builds from them.
    let _router: Router<crate::ProxyState<tonic::transport::Channel>> = routes(&pool, &[]);
}

#[test]
fn swapped_capture_names_bind_each_binding_its_own_values() {
    // The table's path names its captures `a`, `b`; the POST binding names
    // them `b`, `a`. Renaming one by one would let one value overwrite the
    // other.
    let pool = api_pool(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string a = 1; string b = 2; }
service S {
  rpc Get(Req) returns (Req) { option (google.api.http) = { get: "/x/{a}/{b}" }; }
  rpc Post(Req) returns (Req) { option (google.api.http) = { post: "/x/{b}/{a}:go" }; }
}
"#,
    );
    let tables = path_tables(&pool, &[], &TranscodeOptions::default());
    assert_eq!(tables.len(), 1);
    let routes = table::Routes::new(tables);
    let table = &routes.tables[0];
    let matched = |b: &str| -> PathParams {
        [("a", "first"), ("b", b)]
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    };
    let post = bound(&routes, Method::POST, "/x/first/second:go");
    let mut params = matched("second:go");
    table.bind_params(post, &mut params);
    assert_eq!(params.len(), 2);
    assert_eq!(params["b"], "first");
    assert_eq!(params["a"], "second");
    // The binding with the path's own names and no verb is left as matched.
    let get = bound(&routes, Method::GET, "/x/first/second");
    let mut params = matched("second");
    table.bind_params(get, &mut params);
    assert_eq!(params, matched("second"));
}

/// The index of the binding answering `method path`, in the routes' only table.
fn bound(routes: &table::Routes, method: Method, path: &str) -> usize {
    match routes.choose(0, &method, path) {
        table::Choice::Route { table: 0, index } => index,
        _ => panic!("{method} {path} must be answered by the only table"),
    }
}

/// What answers `method path`: the gRPC path of the binding, or the status,
/// with the table the router itself would match it to.
fn answer(routes: &table::Routes, method: Method, path: &str) -> String {
    let mut router = matchit::Router::new();
    for (index, table) in routes.tables.iter().enumerate() {
        router.insert(table.path.as_str(), index).unwrap();
    }
    let Ok(matched) = router.at(path) else {
        return "no route".to_owned();
    };
    match routes.choose(*matched.value, &method, path) {
        table::Choice::Route { table, index } => routes.tables[table]
            .entry(index)
            .grpc_path
            .path()
            .to_owned(),
        table::Choice::MethodNotAllowed(allow) => format!("405 {}", allow.to_str().unwrap()),
        table::Choice::NotFound => "404".to_owned(),
    }
}

/// The routes of an annotated `.proto` source.
fn routes_of(source: &'static str) -> table::Routes {
    table::Routes::new(path_tables(
        &api_pool(source),
        &[],
        &TranscodeOptions::default(),
    ))
}

#[test]
fn the_verb_is_the_last_segment_from_its_first_colon() {
    // Neither a variable's value nor a verb holds an unencoded colon
    // (google/api/http.proto), so `x:b:c` is the variable `x` and the verb
    // `:b:c`: bound for GET only, a POST is 405, not the `:c` binding.
    let routes = routes_of(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string name = 1; }
service S {
  rpc Short(Req) returns (Req) { option (google.api.http) = { post: "/v1/{name}:c" }; }
  rpc Long(Req) returns (Req) { option (google.api.http) = { get: "/v1/{name}:b:c" }; }
}
"#,
    );
    assert_eq!(answer(&routes, Method::POST, "/v1/x:b:c"), "405 GET, HEAD");
    assert_eq!(answer(&routes, Method::GET, "/v1/x:b:c"), "/t.S/Long");
    assert_eq!(answer(&routes, Method::POST, "/v1/x:c"), "/t.S/Short");
    // No binding without a verb: an unbound verb has nothing to fall back on.
    assert_eq!(answer(&routes, Method::POST, "/v1/x:d"), "404");
}

#[test]
fn a_verb_matches_whatever_the_case_of_its_escapes() {
    // `%3A` and `%3a` are the same octet (RFC 3986 §6.2.2.1).
    let routes = routes_of(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string name = 1; }
service S {
  rpc Get(Req) returns (Req) { option (google.api.http) = { get: "/v1/{name}" }; }
  rpc RunNow(Req) returns (Req) { option (google.api.http) = { post: "/v1/{name}:run%3anow" }; }
}
"#,
    );
    assert_eq!(
        answer(&routes, Method::POST, "/v1/job:run%3Anow"),
        "/t.S/RunNow"
    );
    assert_eq!(
        answer(&routes, Method::POST, "/v1/job:run%3anow"),
        "/t.S/RunNow"
    );
}

#[test]
fn a_literal_route_keeps_its_url_over_a_verb_after_a_variable() {
    // The router picks the exact literal for `/v1/jobs/special:cancel`; that
    // route answers it, as a static route wins over a variable everywhere.
    let routes = routes_of(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string name = 1; }
service S {
  rpc Special(Req) returns (Req) { option (google.api.http) = { get: "/v1/jobs/special:cancel" }; }
  rpc Cancel(Req) returns (Req) { option (google.api.http) = { post: "/v1/jobs/{name}:cancel" }; }
}
"#,
    );
    assert_eq!(
        answer(&routes, Method::GET, "/v1/jobs/special:cancel"),
        "/t.S/Special"
    );
    assert_eq!(
        answer(&routes, Method::POST, "/v1/jobs/other:cancel"),
        "/t.S/Cancel"
    );
}

#[test]
fn a_path_with_only_verb_bindings_does_not_hide_a_plain_route() {
    // `/v1/jobs/{id}` binds `:cancel` only; `GET /v1/jobs/x` has no verb, so
    // the catch-all GET, which the router ranks lower, answers it.
    let routes = routes_of(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string id = 1; string path = 2; }
service S {
  rpc Cancel(Req) returns (Req) { option (google.api.http) = { post: "/v1/jobs/{id}:cancel" }; }
  rpc Files(Req) returns (Req) { option (google.api.http) = { get: "/v1/{path=**}" }; }
}
"#,
    );
    assert_eq!(answer(&routes, Method::GET, "/v1/jobs/x"), "/t.S/Files");
    assert_eq!(
        answer(&routes, Method::POST, "/v1/jobs/x:cancel"),
        "/t.S/Cancel"
    );
}

#[test]
fn a_multi_segment_field_template_constrains_its_value() {
    // `{name=shelves/*/books/*}` is mounted as a catch-all, yet only a value of
    // that structure binds; other templates on the same path keep theirs.
    let routes = routes_of(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string name = 1; }
service S {
  rpc Book(Req) returns (Req) { option (google.api.http) = { get: "/v1/{name=shelves/*/books/*}" }; }
  rpc Shelf(Req) returns (Req) { option (google.api.http) = { get: "/v1/{name=shelves/*}" }; }
  rpc Deep(Req) returns (Req) { option (google.api.http) = { get: "/v1/{name=deep/**}" }; }
}
"#,
    );
    assert_eq!(
        answer(&routes, Method::GET, "/v1/shelves/s1/books/b1"),
        "/t.S/Book"
    );
    assert_eq!(answer(&routes, Method::GET, "/v1/shelves/s1"), "/t.S/Shelf");
    assert_eq!(answer(&routes, Method::GET, "/v1/deep/a/b/c"), "/t.S/Deep");
    assert_eq!(answer(&routes, Method::GET, "/v1/deep"), "/t.S/Deep");
    for path in [
        "/v1/other/x",
        "/v1/shelves/s1/books",
        "/v1/shelves/s1/x/b1",
        "/v1/shelves",
    ] {
        assert_eq!(answer(&routes, Method::GET, path), "404", "{path}");
    }
}

#[test]
fn a_template_that_does_not_fit_leaves_the_url_to_a_lower_ranked_path() {
    // The router ranks `/v1/books/{name=special/*}` first for
    // `/v1/books/ordinary/x`; its template refuses the value, so the
    // catch-all answers, with or without a verb.
    let routes = routes_of(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string name = 1; string path = 2; }
service S {
  rpc Special(Req) returns (Req) { option (google.api.http) = { get: "/v1/books/{name=special/*}" }; }
  rpc Files(Req) returns (Req) { option (google.api.http) = { get: "/v1/{path=**}" }; }
  rpc SpecialGo(Req) returns (Req) { option (google.api.http) = { post: "/v2/books/{name=special/*}:go" }; }
  rpc FilesGo(Req) returns (Req) { option (google.api.http) = { post: "/v2/{path=**}:go" }; }
}
"#,
    );
    assert_eq!(
        answer(&routes, Method::GET, "/v1/books/special/x"),
        "/t.S/Special"
    );
    assert_eq!(
        answer(&routes, Method::GET, "/v1/books/ordinary/x"),
        "/t.S/Files"
    );
    assert_eq!(
        answer(&routes, Method::POST, "/v2/books/special/x:go"),
        "/t.S/SpecialGo"
    );
    assert_eq!(
        answer(&routes, Method::POST, "/v2/books/ordinary/x:go"),
        "/t.S/FilesGo"
    );
}

#[test]
fn a_bare_wildcard_binds_no_field() {
    // `*` matches a segment but names no field (google/api/http.proto); the
    // name the router gives it must not reach a field that happens to share
    // it.
    let routes = routes_of(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string wildcard2 = 1; string wildcard3 = 2; }
service S {
  rpc Run(Req) returns (Req) { option (google.api.http) = { post: "/v1/*:run" }; }
  rpc Get(Req) returns (Req) { option (google.api.http) = { get: "/v2/*/x/**" }; }
}
"#,
    );
    let run = bound_in(&routes, Method::POST, "/v1/a:run");
    let mut params: PathParams = [("wildcard2".to_owned(), "a:run".to_owned())].into();
    routes.tables[run.0].bind_params(run.1, &mut params);
    assert!(params.is_empty(), "{params:?}");
    let get = bound_in(&routes, Method::GET, "/v2/a/x/b/c");
    let mut params: PathParams = [
        ("wildcard2".to_owned(), "a".to_owned()),
        ("wildcard4".to_owned(), "b/c".to_owned()),
    ]
    .into();
    routes.tables[get.0].bind_params(get.1, &mut params);
    assert!(params.is_empty(), "{params:?}");
}

/// The table and binding answering `method path`, as the router would match it.
fn bound_in(routes: &table::Routes, method: Method, path: &str) -> (usize, usize) {
    let mut router = matchit::Router::new();
    for (index, table) in routes.tables.iter().enumerate() {
        router.insert(table.path.as_str(), index).unwrap();
    }
    let matched = *router.at(path).unwrap().value;
    match routes.choose(matched, &method, path) {
        table::Choice::Route { table, index } => (table, index),
        _ => panic!("{method} {path} must be answered"),
    }
}

#[test]
fn head_falls_back_to_get_and_a_bound_verb_owns_its_url() {
    let routes = routes_of(
        r#"syntax = "proto3";
package t;
import "google/api/annotations.proto";
message Req { string name = 1; }
service S {
  rpc Get(Req) returns (Req) { option (google.api.http) = { get: "/v1/{name}" }; }
  rpc Short(Req) returns (Req) { option (google.api.http) = { post: "/v1/{name}:c" }; }
  rpc Long(Req) returns (Req) { option (google.api.http) = { post: "/v1/{name}:b:c" }; }
}
"#,
    );
    let rpc = |method: Method, path: &str| answer(&routes, method, path);
    assert_eq!(rpc(Method::HEAD, "/v1/x"), "/t.S/Get");
    assert_eq!(rpc(Method::POST, "/v1/x:b:c"), "/t.S/Long");
    assert_eq!(rpc(Method::POST, "/v1/x:c"), "/t.S/Short");
    assert_eq!(rpc(Method::POST, "/v1/x"), "405 GET, HEAD");
    // `:c` is bound: the binding without a verb does not take `x:c`.
    assert_eq!(rpc(Method::PUT, "/v1/x:c"), "405 POST");
    assert_eq!(rpc(Method::GET, "/v1/x:c"), "405 POST");
    // `:z` is bound nowhere: it stays in the variable.
    assert_eq!(rpc(Method::GET, "/v1/x:z"), "/t.S/Get");
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

/// `Item { name: "alice", count: 42 }` — default fixture for the
/// serialization helpers.
fn item_message() -> DynamicMessage {
    item_message_named("alice", 42)
}

/// Build an `Item { name, count }` message from a freshly-decoded
/// descriptor pool, used to exercise the streaming serialization helpers.
fn item_message_named(name: &str, count: i64) -> DynamicMessage {
    use prost_reflect::prost::Message;
    use prost_reflect::prost_types::{
        field_descriptor_proto::{Label, Type},
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    let item = DescriptorProto {
        name: Some("Item".to_string()),
        field: vec![
            FieldDescriptorProto {
                name: Some("name".to_string()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            },
            FieldDescriptorProto {
                name: Some("count".to_string()),
                number: Some(2),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::Int64 as i32),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("item.proto".to_string()),
        package: Some("test.v1".to_string()),
        message_type: vec![item],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let mut bytes = Vec::new();
    FileDescriptorSet { file: vec![file] }
        .encode(&mut bytes)
        .unwrap();
    let pool = DescriptorPool::decode(bytes.as_slice()).unwrap();
    let desc = pool.get_message_by_name("test.v1.Item").unwrap();

    let mut msg = DynamicMessage::new(desc);
    msg.set_field_by_name("name", prost_reflect::Value::String(name.to_string()));
    msg.set_field_by_name("count", prost_reflect::Value::I64(count));
    msg
}

/// Collect a streaming response body into a single UTF-8 string.
async fn collect_body(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Terminal-frame renderer for a route with error details switched off.
fn no_details(status: &tonic::Status) -> serde_json::Value {
    error::error_body(status, None)
}

#[tokio::test]
async fn ndjson_error_frame_is_terminal() {
    // A gRPC error mid-stream must be the LAST frame: messages the upstream
    // would yield after the error are dropped, so the error line is an
    // unambiguous end-of-stream signal rather than a mid-stream marker.
    let items = vec![
        Ok(item_message_named("alice", 1)),
        Err(tonic::Status::internal("boom")),
        Ok(item_message_named("bob", 2)),
    ];
    let body = collect_body(ndjson_response(
        futures::stream::iter(items),
        no_details,
        false,
    ))
    .await;
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "stream must stop after the error frame");
    assert!(lines[0].contains("alice"));
    assert!(lines[1].contains("INTERNAL") && lines[1].contains("boom"));
    assert!(!body.contains("bob"), "post-error message must be dropped");
}

#[tokio::test]
async fn sse_error_uses_distinct_event_name() {
    // The terminal error is sent as `event: stream-error`, not the reserved
    // `error` type that collides with the browser EventSource onerror.
    let items = vec![
        Ok(item_message_named("alice", 1)),
        Err(tonic::Status::permission_denied("nope")),
        Ok(item_message_named("bob", 2)),
    ];
    let body = collect_body(sse_response(futures::stream::iter(items), no_details, 15)).await;
    assert!(body.contains("stream-error"));
    assert!(body.contains("PERMISSION_DENIED"));
    assert!(!body.contains("bob"), "post-error message must be dropped");
}

#[tokio::test]
async fn ndjson_terminal_frame_carries_status_details() {
    // Once the stream has started the HTTP status (200) is already on the
    // wire, so the only place a mid-stream error's details can travel is the
    // terminal frame: it must be the same body the unary path renders.
    use tonic_types::{ErrorDetail, ErrorInfo, StatusExt};
    let status = tonic::Status::with_error_details_vec(
        tonic::Code::ResourceExhausted,
        "quota",
        [ErrorDetail::from(ErrorInfo::new(
            "QUOTA",
            "acme.example.com",
            std::collections::HashMap::new(),
        ))],
    );
    let renderer = Arc::new(error::StatusDetails::new(&DescriptorPool::new()));
    let mut expected = error::error_body(&status, Some(&renderer));
    let render = move |s: &tonic::Status| error::error_body(s, Some(&renderer));

    let items = vec![Ok(item_message_named("alice", 1)), Err(status)];
    let body = collect_body(ndjson_response(futures::stream::iter(items), render, false)).await;
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    let frame: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    // The line is the unary error body plus the NDJSON frame marker.
    expected["@type"] = STATUS_TYPE_URL.into();
    assert_eq!(frame, expected);
    assert_eq!(
        frame["details"][0]["@type"],
        "type.googleapis.com/google.rpc.ErrorInfo"
    );
}

/// A `Wrapper { google.protobuf.Any payload = 1; }` whose payload names a type
/// no pool knows, so it cannot be serialized to JSON.
fn unserializable_message() -> DynamicMessage {
    use prost_reflect::prost_types::{
        field_descriptor_proto::{Label, Type},
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto,
    };

    let wrapper = DescriptorProto {
        name: Some("Wrapper".to_string()),
        field: vec![FieldDescriptorProto {
            name: Some("payload".to_string()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(".google.protobuf.Any".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("wrapper.proto".to_string()),
        package: Some("test.v1".to_string()),
        dependency: vec!["google/protobuf/any.proto".to_string()],
        message_type: vec![wrapper],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let mut pool = DescriptorPool::global();
    pool.add_file_descriptor_proto(file).unwrap();
    let desc = pool.get_message_by_name("test.v1.Wrapper").unwrap();
    let any_desc = pool.get_message_by_name("google.protobuf.Any").unwrap();

    let mut any = DynamicMessage::new(any_desc);
    any.set_field_by_name(
        "type_url",
        prost_reflect::Value::String("type.googleapis.com/acme.v1.Unknown".into()),
    );
    let mut msg = DynamicMessage::new(desc);
    msg.set_field_by_name("payload", prost_reflect::Value::Message(any));
    // Sanity: the fixture really is unserializable.
    assert!(message_to_json_string(&msg, &response_serialize_options()).is_err());
    msg
}

#[tokio::test]
async fn serialization_failure_ends_the_stream_with_the_shared_error_body() {
    // A message the proxy cannot turn into JSON ends the stream like an
    // upstream error: one terminal INTERNAL frame in the route's error body
    // (here with details on, so `details` is present and empty), then nothing.
    let renderer = Arc::new(error::StatusDetails::new(&DescriptorPool::new()));
    let render = move |s: &tonic::Status| error::error_body(s, Some(&renderer));
    let items = vec![
        Ok(item_message_named("alice", 1)),
        Ok(unserializable_message()),
        Ok(item_message_named("bob", 2)),
    ];
    let body = collect_body(ndjson_response(futures::stream::iter(items), render, false)).await;
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "{body}");
    let frame: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(frame["@type"], STATUS_TYPE_URL);
    assert_eq!(frame["error"], "INTERNAL");
    assert_eq!(frame["code"], 13);
    assert_eq!(frame["details"], serde_json::json!([]));
    assert!(
        frame["message"]
            .as_str()
            .unwrap()
            .starts_with("serialization error: "),
        "{frame}"
    );
}

#[tokio::test]
async fn terminal_frame_ends_the_body_while_the_upstream_stays_open() {
    // After the terminal frame the body ends at once, without polling the
    // upstream again: an upstream that stays open (neither a message nor a
    // close) must not keep the response open, whichever failure ended it.
    let serialization_failure = futures::stream::iter(vec![Ok(unserializable_message())]);
    let upstream_error = futures::stream::iter(vec![Err(tonic::Status::internal("boom"))]);
    for (name, items) in [
        ("serialization failure", serialization_failure),
        ("upstream error", upstream_error),
    ] {
        let open_upstream = items.chain(futures::stream::pending());
        let body = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            collect_body(ndjson_response(open_upstream, no_details, false)),
        )
        .await
        .unwrap_or_else(|_| panic!("{name}: body stayed open after the terminal frame"));
        assert_eq!(body.lines().count(), 1, "{name}: {body}");
    }
}

#[tokio::test]
async fn sse_error_payload_is_the_unary_body_without_the_ndjson_marker() {
    // SSE frames the error by its event type, so the payload is exactly the
    // body a unary error gets: no `@type` marker.
    let status = tonic::Status::permission_denied("nope");
    let expected = error::error_body(&status, None);
    let items = vec![Err(status)];
    let body = collect_body(sse_response(futures::stream::iter(items), no_details, 15)).await;
    let payload = body
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    let frame: serde_json::Value = serde_json::from_str(payload).unwrap();
    assert_eq!(frame, expected);
}

#[tokio::test]
async fn ndjson_envelope_wraps_data_and_error_lines() {
    // With the envelope every line says what it is by its only key, so a data
    // message can never be read as the terminal error, whatever it contains;
    // the error line then needs no marker, and nothing follows it.
    let status = tonic::Status::internal("boom");
    let expected_error = error::error_body(&status, None);
    let items = vec![
        Ok(item_message_named("alice", 1)),
        Err(status),
        Ok(item_message_named("bob", 2)),
    ];
    let body = collect_body(ndjson_response(
        futures::stream::iter(items),
        no_details,
        true,
    ))
    .await;
    let lines: Vec<serde_json::Value> = body
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        lines,
        vec![
            serde_json::json!({"result": {"name": "alice", "count": "1"}}),
            serde_json::json!({"error": expected_error}),
        ]
    );
}

#[test]
fn wants_sse_detects_event_stream_accept() {
    let mut headers = HeaderMap::new();
    headers.insert("accept", "text/event-stream".parse().unwrap());
    assert!(wants_sse(&headers));
}

#[test]
fn wants_sse_matches_within_list_and_ignores_params() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "accept",
        "application/json, text/event-stream;q=0.9".parse().unwrap(),
    );
    assert!(wants_sse(&headers));
}

#[test]
fn wants_sse_false_for_json_and_missing() {
    let mut headers = HeaderMap::new();
    headers.insert("accept", "application/json".parse().unwrap());
    assert!(!wants_sse(&headers));
    assert!(!wants_sse(&HeaderMap::new()));
}

#[test]
fn wants_sse_rejects_explicit_q_zero() {
    // RFC 7231 §5.3.1: `q=0` means the media type is explicitly NOT
    // acceptable, so it must not select the SSE path.
    let mut headers = HeaderMap::new();
    headers.insert("accept", "text/event-stream;q=0".parse().unwrap());
    assert!(!wants_sse(&headers));
}

#[test]
fn wants_sse_honors_second_accept_header_line() {
    // A client may send multiple `Accept` header lines; the negotiation
    // must consider all of them, not just the first.
    let mut headers = HeaderMap::new();
    headers.append("accept", "application/json".parse().unwrap());
    headers.append("accept", "text/event-stream".parse().unwrap());
    assert!(wants_sse(&headers));
}

#[test]
fn message_to_json_string_stringifies_64bit() {
    let opts = response_serialize_options();
    let json = message_to_json_string(&item_message(), &opts).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["name"], "alice");
    // 64-bit integers are stringified to survive JS number precision limits.
    assert_eq!(value["count"], "42");
}

#[test]
fn ndjson_response_omits_manual_transfer_encoding() {
    // hyper picks the framing per protocol version; a hand-set
    // transfer-encoding would be illegal on HTTP/2.
    let resp = ndjson_response(
        futures::stream::empty::<Result<DynamicMessage, tonic::Status>>(),
        no_details,
        false,
    );
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/x-ndjson"
    );
    assert!(resp.headers().get("transfer-encoding").is_none());
}

#[test]
fn stream_error_frame_carries_grpc_code_name() {
    let status = tonic::Status::permission_denied("nope");
    let value = no_details(&status);
    assert_eq!(value["error"], "PERMISSION_DENIED");
    assert_eq!(value["message"], "nope");
    assert_eq!(value["code"], tonic::Code::PermissionDenied as i32);
}
