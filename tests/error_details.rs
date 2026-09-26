//! REST error bodies carry the upstream's `google.rpc.Status` details.
//!
//! Runs the proxy (through its public `ProxyServer`) in front of a real tonic
//! gRPC server that fails with `tonic_types` details, so every case below goes
//! over the actual `grpc-status-details-bin` trailer: unary errors, a stream
//! refused before any response header, and a stream that fails after its first
//! message, in both NDJSON and SSE.

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use futures::stream::BoxStream;
use http::StatusCode;
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use serde_json::{json, Value};
use structured_proxy::config::ProxyConfig;
use structured_proxy::transcode::codec::DynamicCodec;
use structured_proxy::ProxyServer;
use tonic_types::{BadRequest, DebugInfo, ErrorDetail, ErrorInfo, FieldViolation, StatusExt};
use tower::ServiceExt;

// --- descriptors ------------------------------------------------------------

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
  }
  string body = 7;
  string response_body = 12;
  repeated HttpRule additional_bindings = 11;
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

const THINGS_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";

message Item {
  string name = 1;
  int64 count = 2;
}

// A detail type only this product defines.
message QuotaTicket {
  string ticket = 1;
}

service Things {
  rpc Get(Item) returns (Item) {
    option (google.api.http) = { get: "/v1/things/{name}" };
  }
  rpc GetQuiet(Item) returns (Item) {
    option (google.api.http) = { get: "/v1/quiet/{name}" };
  }
  rpc Watch(Item) returns (stream Item) {
    option (google.api.http) = { get: "/v1/things/{name}/watch" };
  }
  rpc WatchDenied(Item) returns (stream Item) {
    option (google.api.http) = { get: "/v1/things/{name}/denied" };
  }
}
"#;

/// Serves the three test sources from memory, and descriptor.proto from
/// protox's bundled Google files.
struct TestProtos;

impl protox::file::FileResolver for TestProtos {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        let source = match name {
            "google/api/http.proto" => HTTP_PROTO,
            "google/api/annotations.proto" => ANNOTATIONS_PROTO,
            "test/v1/things.proto" => THINGS_PROTO,
            _ => return protox::file::GoogleFileResolver::new().open_file(name),
        };
        protox::file::File::from_source(name, source)
    }
}

fn pool() -> DescriptorPool {
    protox::Compiler::with_file_resolver(TestProtos)
        .open_file("test/v1/things.proto")
        .expect("test protos compile")
        .descriptor_pool()
}

fn item_desc(pool: &DescriptorPool) -> MessageDescriptor {
    pool.get_message_by_name("test.v1.Item").unwrap()
}

// --- upstream ---------------------------------------------------------------

/// `INVALID_ARGUMENT` with ErrorInfo + BadRequest, and a DebugInfo that must
/// not reach the HTTP client.
fn rich_status() -> tonic::Status {
    tonic::Status::with_error_details_vec(
        tonic::Code::InvalidArgument,
        "invalid email",
        [
            ErrorDetail::from(ErrorInfo::new(
                "EMAIL_TAKEN",
                "identity.example.com",
                [("email".to_string(), "a@b.c".to_string())]
                    .into_iter()
                    .collect::<std::collections::HashMap<_, _>>(),
            )),
            ErrorDetail::from(BadRequest::new(vec![FieldViolation::new(
                "email",
                "already registered",
            )])),
            ErrorDetail::from(DebugInfo::new(
                vec!["at identity::register (register.rs:42)".to_string()],
                "unique violation on users_email_key",
            )),
        ],
    )
}

/// The `details` a client must see for [`rich_status`].
fn rich_details() -> Value {
    json!([
        {
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": "EMAIL_TAKEN",
            "domain": "identity.example.com",
            "metadata": {"email": "a@b.c"}
        },
        {
            "@type": "type.googleapis.com/google.rpc.BadRequest",
            "fieldViolations": [{"field": "email", "description": "already registered"}]
        }
    ])
}

/// A product-defined detail, an unknown one and a well-known type, packed by
/// hand since tonic-types only builds the google.rpc ones.
fn mixed_status(pool: &DescriptorPool) -> tonic::Status {
    let mut ticket = DynamicMessage::new(pool.get_message_by_name("test.v1.QuotaTicket").unwrap());
    ticket.set_field_by_name("ticket", prost_reflect::Value::String("T-1".into()));
    let duration = prost_reflect::prost_types::Duration {
        seconds: 1,
        nanos: 500_000_000,
    };
    let details = [
        (
            "type.googleapis.com/test.v1.QuotaTicket",
            ticket.encode_to_vec(),
        ),
        (
            "type.googleapis.com/acme.v1.Missing",
            vec![0x08, 0x96, 0x01],
        ),
        (
            "type.googleapis.com/google.protobuf.Duration",
            duration.encode_to_vec(),
        ),
    ];
    let mut rpc = tonic_types::pb::Status {
        code: tonic::Code::FailedPrecondition as i32,
        message: "not yet".into(),
        ..Default::default()
    };
    for (type_url, value) in details {
        rpc.details.push(Default::default());
        let any = rpc.details.last_mut().expect("just pushed");
        any.type_url = type_url.to_string();
        any.value = value;
    }
    tonic::Status::with_details(
        tonic::Code::FailedPrecondition,
        "not yet",
        bytes::Bytes::from(rpc.encode_to_vec()),
    )
}

/// Unary RPCs fail according to the requested `name`.
#[derive(Clone)]
struct Failing {
    pool: DescriptorPool,
}

impl tonic::server::UnaryService<DynamicMessage> for Failing {
    type Response = DynamicMessage;
    type Future = Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let name = match request.get_ref().get_field_by_name("name").as_deref() {
            Some(prost_reflect::Value::String(name)) => name.clone(),
            _ => String::new(),
        };
        ready(Err(match name.as_str() {
            "rich" => rich_status(),
            "mixed" => mixed_status(&self.pool),
            _ => tonic::Status::not_found("no such thing"),
        }))
    }
}

/// `Watch`: one message, then a rich error after the response has started.
#[derive(Clone)]
struct FailsMidStream {
    item: MessageDescriptor,
}

impl tonic::server::ServerStreamingService<DynamicMessage> for FailsMidStream {
    type Response = DynamicMessage;
    type ResponseStream = BoxStream<'static, Result<DynamicMessage, tonic::Status>>;
    type Future = Ready<Result<tonic::Response<Self::ResponseStream>, tonic::Status>>;

    fn call(&mut self, _request: tonic::Request<DynamicMessage>) -> Self::Future {
        let mut first = DynamicMessage::new(self.item.clone());
        first.set_field_by_name("name", prost_reflect::Value::String("first".into()));
        first.set_field_by_name("count", prost_reflect::Value::I64(1));
        let items: Vec<Result<DynamicMessage, tonic::Status>> = vec![Ok(first), Err(rich_status())];
        ready(Ok(tonic::Response::new(Box::pin(futures::stream::iter(
            items,
        )))))
    }
}

/// `WatchDenied`: refuses before sending any message or response header.
#[derive(Clone)]
struct RefusesStream;

impl tonic::server::ServerStreamingService<DynamicMessage> for RefusesStream {
    type Response = DynamicMessage;
    type ResponseStream = BoxStream<'static, Result<DynamicMessage, tonic::Status>>;
    type Future = Ready<Result<tonic::Response<Self::ResponseStream>, tonic::Status>>;

    fn call(&mut self, _request: tonic::Request<DynamicMessage>) -> Self::Future {
        ready(Err(tonic::Status::with_error_details_vec(
            tonic::Code::PermissionDenied,
            "not your thing",
            [ErrorDetail::from(ErrorInfo::new(
                "NOT_OWNER",
                "things.example.com",
                std::collections::HashMap::new(),
            ))],
        )))
    }
}

/// The `test.v1.Things` gRPC service, dispatching by method path.
#[derive(Clone)]
struct Things {
    pool: DescriptorPool,
}

impl tonic::server::NamedService for Things {
    const NAME: &'static str = "test.v1.Things";
}

impl tower::Service<http::Request<tonic::body::Body>> for Things {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let pool = self.pool.clone();
        Box::pin(async move {
            let item = item_desc(&pool);
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(item.clone()));
            let resp = match req.uri().path() {
                "/test.v1.Things/Get" | "/test.v1.Things/GetQuiet" => {
                    grpc.unary(Failing { pool }, req).await
                }
                "/test.v1.Things/Watch" => {
                    grpc.server_streaming(FailsMidStream { item }, req).await
                }
                "/test.v1.Things/WatchDenied" => grpc.server_streaming(RefusesStream, req).await,
                other => panic!("unexpected gRPC path {other}"),
            };
            Ok(resp)
        })
    }
}

/// Start the upstream on a random local port and return its URL.
async fn start_upstream(pool: DescriptorPool) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = futures::stream::unfold(listener, |listener| async move {
        let conn = listener.accept().await.map(|(stream, _)| stream);
        Some((conn, listener))
    });
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(Things { pool })
            .serve_with_incoming(incoming),
    );
    format!("http://{addr}")
}

// --- proxy harness ----------------------------------------------------------

/// A proxy router in front of a fresh upstream, with `error_details_yaml`
/// appended to the config (empty for the defaults).
async fn proxy(error_details_yaml: &str) -> axum::Router {
    let pool = pool();
    let upstream = start_upstream(pool.clone()).await;
    let config = ProxyConfig::from_yaml_str(&format!(
        "upstream:\n  default: \"{upstream}\"\n{error_details_yaml}"
    ))
    .unwrap();
    ProxyServer::from_config(config)
        .with_descriptors(pool)
        .router()
        .unwrap()
}

async fn get(app: &axum::Router, path: &str, accept: Option<&str>) -> (StatusCode, String) {
    let mut req = http::Request::get(path);
    if let Some(accept) = accept {
        req = req.header("accept", accept);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

async fn get_json(app: &axum::Router, path: &str) -> (StatusCode, Value) {
    let (status, body) = get(app, path, None).await;
    (status, serde_json::from_str(&body).unwrap())
}

// --- unary ------------------------------------------------------------------

#[tokio::test]
async fn unary_error_carries_error_info_and_bad_request() {
    // The acceptance case: typed details arrive as ProtoJSON `Any`s next to
    // the existing fields, with the HTTP status of the gRPC → HTTP mapping,
    // and DebugInfo stays behind.
    let app = proxy("").await;
    let (status, body) = get_json(&app, "/v1/things/rich").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body,
        json!({
            "error": "INVALID_ARGUMENT",
            "message": "invalid email",
            "code": 3,
            "details": rich_details()
        })
    );
    let text = body.to_string();
    assert!(!text.contains("register.rs") && !text.contains("users_email_key"));
}

#[tokio::test]
async fn unary_error_without_trailer_has_empty_details() {
    let app = proxy("").await;
    let (status, body) = get_json(&app, "/v1/things/missing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        body,
        json!({"error": "NOT_FOUND", "message": "no such thing", "code": 5, "details": []})
    );
}

#[tokio::test]
async fn product_unknown_and_well_known_details_are_told_apart() {
    // Three different renderings side by side: a product message expands to
    // its fields, a well-known type with a special JSON form sits under
    // `value` as that JSON, and an unresolvable type uses the opaque-detail
    // extension (original type URL, base64 of the original bytes).
    let app = proxy("").await;
    let (status, body) = get_json(&app, "/v1/things/mixed").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["details"],
        json!([
            {"@type": "type.googleapis.com/test.v1.QuotaTicket", "ticket": "T-1"},
            {"@type": "type.googleapis.com/acme.v1.Missing", "value": "CJYB"},
            {"@type": "type.googleapis.com/google.protobuf.Duration", "value": "1.500s"}
        ])
    );
}

// --- per-route switch -------------------------------------------------------

#[tokio::test]
async fn route_rule_switches_details_off_for_one_route() {
    // Only the matched route loses `details` (the key is absent, not empty);
    // its HTTP status and the other routes are unaffected.
    let app =
        proxy("error_details:\n  routes:\n    - pattern: \"/v1/quiet/*\"\n      enabled: false\n")
            .await;
    let (status, quiet) = get_json(&app, "/v1/quiet/rich").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        quiet,
        json!({"error": "INVALID_ARGUMENT", "message": "invalid email", "code": 3})
    );
    let (_, loud) = get_json(&app, "/v1/things/rich").await;
    assert_eq!(loud["details"], rich_details());
}

#[tokio::test]
async fn global_switch_off_with_a_sub_route_back_on() {
    // Global off, `/v1/things/**` back on: the sub-route (including its
    // streaming routes) keeps details, everything else drops them.
    let app = proxy(
        "error_details:\n  enabled: false\n  routes:\n    - pattern: \"/v1/things/**\"\n      enabled: true\n",
    )
    .await;
    let (_, quiet) = get_json(&app, "/v1/quiet/rich").await;
    assert!(quiet.get("details").is_none(), "{quiet}");
    let (_, things) = get_json(&app, "/v1/things/rich").await;
    assert_eq!(things["details"], rich_details());
    let (_, denied) = get_json(&app, "/v1/things/x/denied").await;
    assert_eq!(denied["details"][0]["reason"], "NOT_OWNER");
}

#[tokio::test]
async fn global_switch_off_removes_details_from_stream_frames_too() {
    // The switch covers the in-stream terminal frame as well: a route with
    // details off ends its stream with the bare error body.
    let app = proxy("error_details:\n  enabled: false\n").await;
    let (status, body) = get(&app, "/v1/things/x/watch", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let last: Value = serde_json::from_str(body.lines().last().unwrap()).unwrap();
    assert_eq!(
        last,
        json!({"error": "INVALID_ARGUMENT", "message": "invalid email", "code": 3})
    );
}

// --- streaming --------------------------------------------------------------

#[tokio::test]
async fn stream_refused_before_headers_maps_like_a_unary_error() {
    // No message was sent yet, so the proxy still owns the HTTP status: it is
    // mapped (PERMISSION_DENIED → 403) and the body is the unary error body.
    let app = proxy("").await;
    let (status, body) = get_json(&app, "/v1/things/x/denied").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        body,
        json!({
            "error": "PERMISSION_DENIED",
            "message": "not your thing",
            "code": 7,
            "details": [{
                "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                "reason": "NOT_OWNER",
                "domain": "things.example.com"
            }]
        })
    );
}

#[tokio::test]
async fn ndjson_stream_failing_after_first_message_ends_with_detailed_error_line() {
    // The 200 and the first message are already on the wire when the upstream
    // fails, so the status cannot change: the error arrives as exactly one
    // final NDJSON line holding the same body a unary error would have.
    let app = proxy("").await;
    let (status, body) = get(&app, "/v1/things/x/watch", None).await;
    assert_eq!(status, StatusCode::OK);
    let lines: Vec<Value> = body
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        lines,
        vec![
            json!({"name": "first", "count": "1"}),
            json!({
                "error": "INVALID_ARGUMENT",
                "message": "invalid email",
                "code": 3,
                "details": rich_details()
            }),
        ]
    );
}

#[tokio::test]
async fn sse_stream_failing_after_first_message_ends_with_detailed_stream_error_event() {
    // Same failure over SSE: one data event, then exactly one `stream-error`
    // event with the full error body, and nothing after it.
    let app = proxy("").await;
    let (status, body) = get(&app, "/v1/things/x/watch", Some("text/event-stream")).await;
    assert_eq!(status, StatusCode::OK);
    let events: Vec<(Option<&str>, Value)> = body
        .split("\n\n")
        .filter(|block| !block.trim().is_empty())
        .map(|block| {
            let mut event = None;
            let mut data = None;
            for line in block.lines() {
                if let Some(name) = line.strip_prefix("event: ") {
                    event = Some(name);
                } else if let Some(payload) = line.strip_prefix("data: ") {
                    data = Some(serde_json::from_str(payload).unwrap());
                }
            }
            (event, data.expect("every event carries data"))
        })
        .collect();
    assert_eq!(
        events,
        vec![
            (None, json!({"name": "first", "count": "1"})),
            (
                Some("stream-error"),
                json!({
                    "error": "INVALID_ARGUMENT",
                    "message": "invalid email",
                    "code": 3,
                    "details": rich_details()
                })
            ),
        ]
    );
}
