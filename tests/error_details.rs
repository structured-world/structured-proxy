//! REST error bodies carry the upstream's `google.rpc.Status` details.
//!
//! Runs the proxy (through its public `ProxyServer`) in front of a real tonic
//! gRPC server that fails with `tonic_types` details, so every case below goes
//! over the actual `grpc-status-details-bin` trailer: unary errors, a stream
//! refused before any response header, and a stream that fails after its first
//! message, in both NDJSON and SSE.

mod common;

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
use structured_proxy::transcode::codec::DynamicCodec;
use structured_proxy::transcode::error::ErrorDetailsPolicy;
use tonic_types::{BadRequest, DebugInfo, ErrorDetail, ErrorInfo, FieldViolation, StatusExt};

// --- descriptors ------------------------------------------------------------

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

fn pool() -> DescriptorPool {
    common::compile("test/v1/things.proto", THINGS_PROTO)
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

/// `NOT_FOUND` whose `ErrorInfo` detail is truncated: a known type with bytes
/// that do not decode, i.e. a broken upstream response.
fn corrupt_status() -> tonic::Status {
    let mut rpc = tonic_types::pb::Status {
        code: tonic::Code::NotFound as i32,
        message: "gone".into(),
        ..Default::default()
    };
    rpc.details.push(Default::default());
    let any = rpc.details.last_mut().expect("just pushed");
    any.type_url = "type.googleapis.com/google.rpc.ErrorInfo".to_string();
    any.value = vec![0x0a, 0x05, b'a'];
    tonic::Status::with_details(
        tonic::Code::NotFound,
        "gone",
        bytes::Bytes::from(rpc.encode_to_vec()),
    )
}

/// The body a client gets instead of a broken upstream error status.
fn malformed_upstream_status_body() -> Value {
    json!({
        "error": "INTERNAL",
        "message": "upstream returned a malformed error status",
        "code": 13,
        "details": []
    })
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
            "corrupt" => corrupt_status(),
            _ => tonic::Status::not_found("no such thing"),
        }))
    }
}

/// `Watch`: one message, then an error after the response has started: the
/// corrupt one for `name == "corrupt"`, the rich one otherwise.
#[derive(Clone)]
struct FailsMidStream {
    item: MessageDescriptor,
}

impl tonic::server::ServerStreamingService<DynamicMessage> for FailsMidStream {
    type Response = DynamicMessage;
    type ResponseStream = BoxStream<'static, Result<DynamicMessage, tonic::Status>>;
    type Future = Ready<Result<tonic::Response<Self::ResponseStream>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let failure = match request.get_ref().get_field_by_name("name").as_deref() {
            Some(prost_reflect::Value::String(name)) if name == "corrupt" => corrupt_status(),
            _ => rich_status(),
        };
        let mut first = DynamicMessage::new(self.item.clone());
        first.set_field_by_name("name", prost_reflect::Value::String("first".into()));
        first.set_field_by_name("count", prost_reflect::Value::I64(1));
        let items: Vec<Result<DynamicMessage, tonic::Status>> = vec![Ok(first), Err(failure)];
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

// --- proxy harness ----------------------------------------------------------

/// A proxy router in front of a fresh upstream, returning error details as
/// `error_details` decides.
async fn proxy(error_details: ErrorDetailsPolicy) -> axum::Router {
    let pool = pool();
    let upstream = common::serve(Things { pool: pool.clone() }).await;
    common::proxy(&upstream, pool, error_details)
}

async fn get(app: &axum::Router, path: &str, accept: Option<&str>) -> (StatusCode, String) {
    let mut req = http::Request::get(path);
    if let Some(accept) = accept {
        req = req.header("accept", accept);
    }
    common::send(app, req.body(Body::empty()).unwrap()).await
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
    let app = proxy(ErrorDetailsPolicy::default()).await;
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
    let app = proxy(ErrorDetailsPolicy::default()).await;
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
    // its fields and a well-known type with a special JSON form sits under
    // `value` as that JSON, both in `details`; the type no descriptor
    // describes goes to `opaqueDetails` (its position, original type URL and
    // base64 of the original bytes), never into `details`.
    let app = proxy(ErrorDetailsPolicy::default()).await;
    let (status, body) = get_json(&app, "/v1/things/mixed").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["details"],
        json!([
            {"@type": "type.googleapis.com/test.v1.QuotaTicket", "ticket": "T-1"},
            {"@type": "type.googleapis.com/google.protobuf.Duration", "value": "1.500s"}
        ])
    );
    assert_eq!(
        body["opaqueDetails"],
        json!([{"index": 1, "typeUrl": "type.googleapis.com/acme.v1.Missing", "bytes": "CJYB"}])
    );
}

// --- per-route switch -------------------------------------------------------

#[tokio::test]
async fn route_rule_switches_details_off_for_one_route() {
    // Only the matched route loses `details` (the key is absent, not empty);
    // its HTTP status and the other routes are unaffected.
    let app = proxy(
        ErrorDetailsPolicy::default()
            .route("/v1/quiet/*", false)
            .unwrap(),
    )
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
        ErrorDetailsPolicy::disabled()
            .route("/v1/things/**", true)
            .unwrap(),
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
    let app = proxy(ErrorDetailsPolicy::disabled()).await;
    let (status, body) = get(&app, "/v1/things/x/watch", None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let last: Value = serde_json::from_str(body.lines().last().unwrap()).unwrap();
    assert_eq!(
        last,
        json!({
            "@type": "type.googleapis.com/google.rpc.Status",
            "error": "INVALID_ARGUMENT",
            "message": "invalid email",
            "code": 3
        })
    );
}

// --- broken upstream status ---------------------------------------------------

#[tokio::test]
async fn unary_error_with_a_corrupt_known_detail_becomes_a_safe_internal() {
    // The type resolves but its bytes do not decode: a broken upstream
    // response. Before headers the proxy still owns the status, so the client
    // gets a generic 500 INTERNAL, not the upstream's NOT_FOUND with the detail
    // dropped, passed on as base64, or otherwise reinterpreted.
    let app = proxy(ErrorDetailsPolicy::default()).await;
    let (status, body) = get(&app, "/v1/things/corrupt", None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        malformed_upstream_status_body()
    );
    assert!(!body.contains("CgVh") && !body.contains("gone"), "{body}");
}

#[tokio::test]
async fn stream_error_with_a_corrupt_known_detail_ends_with_a_safe_internal_frame() {
    // After the first message the 200 is sent, so the same failure becomes the
    // terminal frame instead, in both formats.
    let app = proxy(ErrorDetailsPolicy::default()).await;
    let (status, body) = get(&app, "/v1/things/corrupt/watch", None).await;
    assert_eq!(status, StatusCode::OK);
    let mut expected = malformed_upstream_status_body();
    expected["@type"] = "type.googleapis.com/google.rpc.Status".into();
    let lines: Vec<Value> = body
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        lines,
        vec![json!({"name": "first", "count": "1"}), expected]
    );

    let (status, body) = get(&app, "/v1/things/corrupt/watch", Some("text/event-stream")).await;
    assert_eq!(status, StatusCode::OK);
    let error_payload = body
        .split("\n\n")
        .find(|event| event.contains("event: stream-error"))
        .and_then(|event| event.lines().find_map(|line| line.strip_prefix("data: ")))
        .expect("a stream-error event");
    assert_eq!(
        serde_json::from_str::<Value>(error_payload).unwrap(),
        malformed_upstream_status_body()
    );
}

// --- errors the proxy raises itself ------------------------------------------

#[tokio::test]
async fn unmappable_request_gets_the_shared_error_body() {
    // A request the proxy rejects before calling the upstream answers in the
    // same body as an upstream error on that route, so a client parses one
    // shape: here INVALID_ARGUMENT with empty details.
    let app = proxy(ErrorDetailsPolicy::default()).await;
    let (status, body) = get_json(&app, "/v1/things/rich?count=many").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "INVALID_ARGUMENT");
    assert_eq!(body["code"], 3);
    assert_eq!(body["details"], json!([]));
    assert!(body["message"].is_string());
}

#[tokio::test]
async fn unreachable_upstream_gets_the_shared_error_body() {
    // Nothing listens on the upstream port: 503 UNAVAILABLE in the shared
    // body. With details switched off for the route, the key is absent here
    // too.
    let app = common::proxy(
        "http://127.0.0.1:1",
        pool(),
        ErrorDetailsPolicy::default()
            .route("/v1/quiet/*", false)
            .unwrap(),
    );
    let (status, body) = get_json(&app, "/v1/things/rich").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "UNAVAILABLE");
    assert_eq!(body["code"], 14);
    assert_eq!(body["details"], json!([]));

    let (status, quiet) = get_json(&app, "/v1/quiet/rich").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(quiet["code"], 14);
    assert!(quiet.get("details").is_none(), "{quiet}");
}

// --- streaming --------------------------------------------------------------

#[tokio::test]
async fn stream_refused_before_headers_maps_like_a_unary_error() {
    // No message was sent yet, so the proxy still owns the HTTP status: it is
    // mapped (PERMISSION_DENIED → 403) and the body is the unary error body.
    let app = proxy(ErrorDetailsPolicy::default()).await;
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
    // final NDJSON line holding the same body a unary error would have, marked
    // by `@type: google.rpc.Status` so it is not mistaken for a data line.
    let app = proxy(ErrorDetailsPolicy::default()).await;
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
                "@type": "type.googleapis.com/google.rpc.Status",
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
    let app = proxy(ErrorDetailsPolicy::default()).await;
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
