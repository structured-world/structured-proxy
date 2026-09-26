//! Server-streaming routes map the HTTP request onto the gRPC request exactly
//! like unary routes: path parameters, query parameters and the `body` rule.
//!
//! The upstream echoes the request it received as the only stream message, so
//! each test sees what actually reached the service.

mod common;

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use futures::stream::BoxStream;
use http::StatusCode;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use serde_json::{json, Value};
use structured_proxy::transcode::codec::DynamicCodec;

const THINGS_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";

message Item {
  string name = 1;
  int64 count = 2;
}

service Things {
  rpc Watch(Item) returns (stream Item) {
    option (google.api.http) = {
      get: "/v1/things/{name}/watch"
      additional_bindings { post: "/v1/things:watch" body: "*" }
    };
  }
}
"#;

/// Streams back the request it was called with.
#[derive(Clone)]
struct EchoStream;

impl tonic::server::ServerStreamingService<DynamicMessage> for EchoStream {
    type Response = DynamicMessage;
    type ResponseStream = BoxStream<'static, Result<DynamicMessage, tonic::Status>>;
    type Future = Ready<Result<tonic::Response<Self::ResponseStream>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let echoed: Vec<Result<DynamicMessage, tonic::Status>> = vec![Ok(request.into_inner())];
        ready(Ok(tonic::Response::new(Box::pin(futures::stream::iter(
            echoed,
        )))))
    }
}

#[derive(Clone)]
struct Things {
    item: MessageDescriptor,
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
        let item = self.item.clone();
        Box::pin(async move {
            assert_eq!(req.uri().path(), "/test.v1.Things/Watch");
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(item));
            Ok(grpc.server_streaming(EchoStream, req).await)
        })
    }
}

async fn proxy() -> axum::Router {
    let pool: DescriptorPool = common::compile("test/v1/things.proto", THINGS_PROTO);
    let item = pool.get_message_by_name("test.v1.Item").unwrap();
    let upstream = common::serve(Things { item }).await;
    common::proxy(&upstream, pool, "")
}

/// The NDJSON lines of a streaming response, parsed.
fn ndjson(body: &str) -> Vec<Value> {
    body.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn get_stream_binds_path_and_query_parameters() {
    // `{name}` comes from the path and `count` from the query string; before
    // the fix the upstream received an empty request.
    let app = proxy().await;
    let (status, body) = common::send(
        &app,
        http::Request::get("/v1/things/alpha/watch?count=7")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ndjson(&body), vec![json!({"name": "alpha", "count": "7"})]);
}

#[tokio::test]
async fn sse_stream_binds_the_request_too() {
    // The request mapping does not depend on the negotiated stream format.
    let app = proxy().await;
    let (status, body) = common::send(
        &app,
        http::Request::get("/v1/things/alpha/watch?count=7")
            .header("accept", "text/event-stream")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let data: Vec<Value> = body
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .map(|payload| serde_json::from_str(payload).unwrap())
        .collect();
    assert_eq!(data, vec![json!({"name": "alpha", "count": "7"})]);
}

#[tokio::test]
async fn post_stream_maps_the_whole_body() {
    let app = proxy().await;
    let (status, body) = common::send(
        &app,
        http::Request::post("/v1/things:watch")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name": "beta", "count": "3"}"#))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(ndjson(&body), vec![json!({"name": "beta", "count": "3"})]);
}

#[tokio::test]
async fn post_stream_with_malformed_body_is_rejected_before_the_upstream() {
    // A body that is not JSON is the client's error, answered with 400 like on
    // a unary route, instead of opening a stream with an empty request.
    let app = proxy().await;
    let (status, body) = common::send(
        &app,
        http::Request::post("/v1/things:watch")
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "INVALID_ARGUMENT");
    assert_eq!(error["code"], 3);
    assert_eq!(error["details"], json!([]));
}

#[tokio::test]
async fn get_stream_with_ill_typed_query_is_rejected_before_the_upstream() {
    // `count` is an int64: a non-numeric value cannot build the request.
    let app = proxy().await;
    let (status, body) = common::send(
        &app,
        http::Request::get("/v1/things/alpha/watch?count=many")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let error: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["error"], "INVALID_ARGUMENT");
    assert_eq!(error["code"], 3);
    assert_eq!(error["details"], json!([]));
}
