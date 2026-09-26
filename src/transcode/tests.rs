use super::*;

/// Build a standalone `HttpRule`-shaped descriptor (self-referential
/// `additional_bindings`) so the binding parser can be tested without the
/// google.api extension wiring.
fn http_rule_descriptor() -> prost_reflect::MessageDescriptor {
    use prost_reflect::prost::Message;
    use prost_reflect::prost_types::{
        field_descriptor_proto::{Label, Type},
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    let str_field = |name: &str, num: i32| FieldDescriptorProto {
        name: Some(name.to_string()),
        number: Some(num),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::String as i32),
        ..Default::default()
    };
    let rule = DescriptorProto {
        name: Some("HttpRule".to_string()),
        field: vec![
            str_field("get", 2),
            str_field("put", 3),
            str_field("post", 4),
            str_field("delete", 5),
            str_field("patch", 6),
            str_field("body", 7),
            str_field("response_body", 12),
            FieldDescriptorProto {
                name: Some("additional_bindings".to_string()),
                number: Some(11),
                label: Some(Label::Repeated as i32),
                r#type: Some(Type::Message as i32),
                type_name: Some(".gapi.HttpRule".to_string()),
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("http.proto".to_string()),
        package: Some("gapi".to_string()),
        message_type: vec![rule],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };
    let pool = DescriptorPool::decode(fds.encode_to_vec().as_slice()).unwrap();
    pool.get_message_by_name("gapi.HttpRule").unwrap()
}

#[test]
fn collect_bindings_reads_body_response_and_additional() {
    let desc = http_rule_descriptor();

    // additional_bindings entry: POST /v1/items with whole-body mapping.
    let mut extra = DynamicMessage::new(desc.clone());
    extra.set_field_by_name("post", prost_reflect::Value::String("/v1/items".into()));
    extra.set_field_by_name("body", prost_reflect::Value::String("*".into()));

    // primary rule: GET /v1/items/{id}, returns only the `result` subfield.
    let mut rule = DynamicMessage::new(desc);
    rule.set_field_by_name("get", prost_reflect::Value::String("/v1/items/{id}".into()));
    rule.set_field_by_name(
        "response_body",
        prost_reflect::Value::String("result".into()),
    );
    rule.set_field_by_name(
        "additional_bindings",
        prost_reflect::Value::List(vec![prost_reflect::Value::Message(extra)]),
    );

    let bindings = collect_bindings(&rule);
    assert_eq!(bindings.len(), 2);

    // Primary: GET, no body, response_body = result.
    assert!(matches!(bindings[0].http_method, HttpMethod::Get));
    assert_eq!(bindings[0].http_path, "/v1/items/{id}");
    assert_eq!(bindings[0].body, request::BodyMapping::None);
    assert_eq!(bindings[0].response_body.as_deref(), Some("result"));

    // Additional: POST, whole-body mapping, no response_body.
    assert!(matches!(bindings[1].http_method, HttpMethod::Post));
    assert_eq!(bindings[1].http_path, "/v1/items");
    assert_eq!(bindings[1].body, request::BodyMapping::Root);
    assert_eq!(bindings[1].response_body, None);
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
