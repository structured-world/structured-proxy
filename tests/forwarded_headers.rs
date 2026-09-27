//! Forwarded request headers reach a real tonic upstream as the client sent
//! them: every value, in order, over the actual HTTP/2 stream.

mod common;

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use http::StatusCode;
use prost_reflect::{DescriptorPool, DynamicMessage, Value as PbValue};
use structured_proxy::transcode::codec::DynamicCodec;
use structured_proxy::transcode::error::ErrorDetailsPolicy;

const HEADERS_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";

message Req {}
message Reply {
  string name = 1;
}

service Headers {
  rpc Seen(Req) returns (Reply) {
    option (google.api.http) = { get: "/v1/seen" };
  }
}
"#;

fn pool() -> DescriptorPool {
    common::compile("test/v1/headers.proto", HEADERS_PROTO)
}

/// Answers with the `dpop` values it received, joined by `|`.
#[derive(Clone)]
struct Seen {
    pool: DescriptorPool,
}

impl tonic::server::NamedService for Seen {
    const NAME: &'static str = "test.v1.Headers";
}

impl tonic::server::UnaryService<DynamicMessage> for Seen {
    type Response = DynamicMessage;
    type Future = Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let seen: Vec<&str> = request
            .metadata()
            .get_all("dpop")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        let mut reply =
            DynamicMessage::new(self.pool.get_message_by_name("test.v1.Reply").unwrap());
        reply.set_field_by_name("name", PbValue::String(seen.join("|")));
        ready(Ok(tonic::Response::new(reply)))
    }
}

impl tower::Service<http::Request<tonic::body::Body>> for Seen {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let method = service
                .pool
                .get_service_by_name("test.v1.Headers")
                .unwrap()
                .methods()
                .find(|m| m.name() == "Seen")
                .unwrap();
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(method.input()));
            Ok(grpc.unary(service, req).await)
        })
    }
}

async fn proxy() -> axum::Router {
    let upstream = common::serve(Seen { pool: pool() }).await;
    common::proxy(&upstream, pool(), ErrorDetailsPolicy::default())
}

#[tokio::test]
async fn every_value_of_a_repeated_header_reaches_the_upstream_in_order() {
    // RFC 9449 §4.3 has the server reject a request with two DPoP headers;
    // behind the proxy it can only do that if both arrive.
    let app = proxy().await;
    let request = http::Request::get("/v1/seen")
        .header("dpop", "proof-a")
        .header("dpop", "proof-b")
        .body(Body::empty())
        .unwrap();
    let (status, body) = common::send(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["name"],
        "proof-a|proof-b"
    );
}

#[tokio::test]
async fn a_single_value_is_unchanged() {
    let app = proxy().await;
    let request = http::Request::get("/v1/seen")
        .header("dpop", "proof-a")
        .body(Body::empty())
        .unwrap();
    let (status, body) = common::send(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["name"],
        "proof-a"
    );
}
