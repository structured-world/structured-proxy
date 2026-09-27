//! A unary request is built from the path, the query and a JSON or form body,
//! and reaches the upstream as that message.
//!
//! The upstream answers with the request it received, so each test sees what
//! actually reached the service. Every case runs against a remote and an
//! in-process upstream.

#[macro_use]
mod common;

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use http::StatusCode;
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor};
use serde_json::{json, Value};
use structured_proxy::transcode::codec::DynamicCodec;

const ITEMS_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
import "google/protobuf/duration.proto";
import "google/protobuf/timestamp.proto";
import "google/protobuf/wrappers.proto";

message Item {
  string name = 1;
  string display_name = 2;
  int32 max_items = 3;
  google.protobuf.Timestamp at = 4;
  google.protobuf.Duration ttl = 5;
  google.protobuf.StringValue note = 6;
}

service Items {
  rpc Echo(Item) returns (Item) {
    option (google.api.http) = {
      get: "/v1/items/{name}"
      additional_bindings { post: "/v1/items" body: "*" }
      additional_bindings { post: "/v1/items/{name}/note" body: "note" }
    };
  }
}
"#;

/// Answers with the request it was called with.
#[derive(Clone)]
struct Echo;

impl tonic::server::UnaryService<DynamicMessage> for Echo {
    type Response = DynamicMessage;
    type Future = Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        ready(Ok(tonic::Response::new(request.into_inner())))
    }
}

#[derive(Clone)]
struct Items {
    item: MessageDescriptor,
}

impl tonic::server::NamedService for Items {
    const NAME: &'static str = "test.v1.Items";
}

impl tower::Service<http::Request<tonic::body::Body>> for Items {
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
            assert_eq!(req.uri().path(), "/test.v1.Items/Echo");
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(item));
            Ok(grpc.unary(Echo, req).await)
        })
    }
}

async fn proxy(upstream: common::Upstream) -> common::App {
    let pool: DescriptorPool = common::compile("test/v1/items.proto", ITEMS_PROTO);
    let item = pool.get_message_by_name("test.v1.Item").unwrap();
    common::proxy(upstream, Items { item }, pool, Default::default()).await
}

async fn get(app: &common::App, uri: &str) -> (StatusCode, Value) {
    let (status, body) =
        common::send(app, http::Request::get(uri).body(Body::empty()).unwrap()).await;
    (status, serde_json::from_str(&body).unwrap())
}

async fn post_form(app: &common::App, uri: &str, form: &'static str) -> (StatusCode, Value) {
    let request = http::Request::post(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    let (status, body) = common::send(app, request).await;
    (status, serde_json::from_str(&body).unwrap())
}

upstream_tests! {
async fn query_and_form_keys_bind_by_proto_or_json_name() {
    // ProtoJSON reads a field under either name; a query or form key does too,
    // rather than being dropped as unknown.
    let app = proxy(UPSTREAM).await;
    let (status, body) = get(&app, "/v1/items/a?displayName=Ann&max_items=3").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"name": "a", "displayName": "Ann", "maxItems": 3})
    );
    let (status, body) = post_form(&app, "/v1/items", "name=b&displayName=Bo&maxItems=4").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"name": "b", "displayName": "Bo", "maxItems": 4})
    );
}

async fn well_known_type_fields_bind_one_by_one() {
    // A Timestamp, Duration or wrapper can be sent whole or field by field;
    // none of the client's values is lost.
    let app = proxy(UPSTREAM).await;
    let (status, body) = get(
        &app,
        "/v1/items/a?at.seconds=5&at.nanos=7&ttl=1.5s&note.value=hi",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["at"], "1970-01-01T00:00:05.000000007Z");
    assert_eq!(body["ttl"], "1.500s");
    assert_eq!(body["note"], "hi");
    // A form body bound to a wrapper field fills it through its `value`.
    let (status, body) = post_form(&app, "/v1/items/c/note", "value=hello").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "c");
    assert_eq!(body["note"], "hello");
}

async fn an_invalid_well_known_value_is_rejected_before_the_upstream() {
    // Field by field a client could write what no JSON form holds: nanos past
    // 999999999, or seconds and nanos of opposite sign.
    let app = proxy(UPSTREAM).await;
    for uri in [
        "/v1/items/a?at.nanos=2000000000",
        "/v1/items/a?ttl.seconds=5&ttl.nanos=-1",
    ] {
        let (status, body) = get(&app, uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}: {body}");
        assert_eq!(body["error"], "INVALID_ARGUMENT", "{uri}");
        assert_eq!(body["code"], 3, "{uri}");
    }
}
}
