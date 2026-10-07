//! Custom verbs (`Template = "/" Segments [ Verb ]`, google/api/http.proto):
//! a binding answers only the requests whose last segment ends in its verb,
//! after a variable, a multi-segment field template or a literal alike.
//!
//! The upstream answers with the request it received and the RPC it was
//! called as, so each test sees which binding a request reached and with which
//! path variables. Every case runs against a remote and an in-process
//! upstream.

#[macro_use]
mod common;

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use http::{Method, StatusCode};
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, Value as PbValue};
use serde_json::{json, Value};
use structured_proxy::transcode::codec::DynamicCodec;
use tower::ServiceExt;

const OPS_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";

message Msg {
  string name = 1;
  string operation = 2;
  string rpc = 3;
}

service Ops {
  rpc Get(Msg) returns (Msg) {
    option (google.api.http) = { get: "/v2/ops/{operation}" };
  }
  rpc Cancel(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v2/ops/{operation}:cancel" };
  }
  rpc Archive(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v2/ops/{operation}:archive" };
  }
  rpc Pause(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v2/ops/{name}:pause" };
  }
  rpc Drop(Msg) returns (Msg) {
    option (google.api.http) = { delete: "/v2/ops/{name}" };
  }
  rpc Restore(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v1/{name=publishers/*/books/*}:restore" };
  }
  rpc Batch(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v1/nodes:batch" };
  }
  rpc Broken(Msg) returns (Msg) {
    option (google.api.http) = { get: "/v1/broken/a{name}b" };
  }
}
"#;

/// Answers with the request, `rpc` set to the method it was called as.
#[derive(Clone)]
struct Echo {
    rpc: String,
}

impl tonic::server::UnaryService<DynamicMessage> for Echo {
    type Response = DynamicMessage;
    type Future = Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let mut msg = request.into_inner();
        msg.set_field_by_name("rpc", PbValue::String(self.rpc.clone()));
        ready(Ok(tonic::Response::new(msg)))
    }
}

#[derive(Clone)]
struct Ops {
    msg: MessageDescriptor,
}

impl tonic::server::NamedService for Ops {
    const NAME: &'static str = "test.v1.Ops";
}

impl tower::Service<http::Request<tonic::body::Body>> for Ops {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<tonic::body::Body>) -> Self::Future {
        let msg = self.msg.clone();
        Box::pin(async move {
            let rpc = req
                .uri()
                .path()
                .strip_prefix("/test.v1.Ops/")
                .expect("an Ops method")
                .to_owned();
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(msg));
            Ok(grpc.unary(Echo { rpc }, req).await)
        })
    }
}

async fn proxy(upstream: common::Upstream) -> common::App {
    let pool: DescriptorPool = common::compile("test/v1/ops.proto", OPS_PROTO);
    let msg = pool.get_message_by_name("test.v1.Msg").unwrap();
    common::proxy(upstream, Ops { msg }, pool, Default::default()).await
}

/// Send `method uri`; returns the status, the `Allow` header and the body as
/// JSON (`null` when empty).
async fn call(app: &common::App, method: Method, uri: &str) -> (StatusCode, String, Value) {
    let request = http::Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(request).await.unwrap();
    let status = resp.status();
    let allow = resp
        .headers()
        .get(http::header::ALLOW)
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, allow, body)
}

upstream_tests! {
async fn verb_after_a_variable_routes_with_the_variable_bound() {
    // `{operation}:cancel`: the variable takes the segment without the verb.
    let app = proxy(UPSTREAM).await;
    let (status, _, body) = call(&app, Method::POST, "/v2/ops/op-1:cancel").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"name": "", "operation": "op-1", "rpc": "Cancel"}));
}

async fn bindings_differing_only_by_verb_reach_their_own_methods() {
    let app = proxy(UPSTREAM).await;
    for (verb, rpc) in [("cancel", "Cancel"), ("archive", "Archive")] {
        let (status, _, body) =
            call(&app, Method::POST, &format!("/v2/ops/op-7:{verb}")).await;
        assert_eq!(status, StatusCode::OK, "{verb}: {body}");
        assert_eq!(body["rpc"], rpc, "{verb}");
        assert_eq!(body["operation"], "op-7", "{verb}");
    }
    // The same shape with another variable name binds that name.
    let (status, _, body) = call(&app, Method::POST, "/v2/ops/op-7:pause").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"name": "op-7", "operation": "", "rpc": "Pause"}));
}

async fn a_request_without_the_verb_does_not_reach_a_verb_binding() {
    // Only the GET and DELETE bindings answer `/v2/ops/{..}` without a verb.
    let app = proxy(UPSTREAM).await;
    let (status, allow, _) = call(&app, Method::POST, "/v2/ops/op-1").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(allow, "GET, DELETE, HEAD");
    let (status, _, body) = call(&app, Method::GET, "/v2/ops/op-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Get");
    assert_eq!(body["operation"], "op-1");
}

async fn bindings_of_one_path_bind_their_own_variable_names() {
    // `/v2/ops/{operation}` (GET) and `/v2/ops/{name}` (DELETE) are one path
    // to the router; each binding still fills its own field.
    let app = proxy(UPSTREAM).await;
    let (status, _, body) = call(&app, Method::DELETE, "/v2/ops/op-3").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"name": "op-3", "operation": "", "rpc": "Drop"}));
}

async fn head_is_answered_by_the_get_binding_without_a_body() {
    let app = proxy(UPSTREAM).await;
    let (status, _, body) = call(&app, Method::HEAD, "/v2/ops/op-1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Value::Null);
}

async fn another_verb_does_not_reach_a_verb_binding() {
    let app = proxy(UPSTREAM).await;
    let (status, allow, _) = call(&app, Method::POST, "/v2/ops/op-1:delete").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(allow, "GET, DELETE, HEAD");
    // A binding without a verb takes the whole segment, colon included.
    let (status, _, body) = call(&app, Method::GET, "/v2/ops/op-1:delete").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Get");
    assert_eq!(body["operation"], "op-1:delete");
}

async fn an_encoded_colon_is_data_not_a_verb() {
    // `%3A` is a colon in the value, not the verb delimiter (RFC 3986 §2.2).
    let app = proxy(UPSTREAM).await;
    let (status, _, _) = call(&app, Method::POST, "/v2/ops/op-1%3Acancel").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _, body) = call(&app, Method::GET, "/v2/ops/op-1%3Acancel").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["operation"], "op-1:cancel");
}

async fn a_verb_with_an_empty_variable_does_not_match() {
    // `Variable` matches a non-empty segment: `/:cancel` binds nothing.
    let app = proxy(UPSTREAM).await;
    let (status, _, _) = call(&app, Method::POST, "/v2/ops/:cancel").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

async fn a_method_no_binding_of_the_url_answers_lists_those_that_do() {
    // PUT is bound nowhere; GET and DELETE (without a verb) and POST
    // (`:cancel`) answer this URL, POST `:archive` and `:pause` do not.
    let app = proxy(UPSTREAM).await;
    let (status, allow, _) = call(&app, Method::PUT, "/v2/ops/op-1:cancel").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(allow, "GET, POST, DELETE, HEAD");
}

async fn verb_after_a_multi_segment_field_template_routes() {
    // AIP-136: `POST /v1/{name=publishers/*/books/*}:restore`.
    let app = proxy(UPSTREAM).await;
    let (status, _, body) =
        call(&app, Method::POST, "/v1/publishers/p1/books/b2:restore").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Restore");
    assert_eq!(body["name"], "publishers/p1/books/b2");
    for uri in ["/v1/publishers/p1/books/b2", "/v1/publishers/p1/books/b2:archive"] {
        let (status, _, body) = call(&app, Method::POST, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
    }
}

async fn verb_after_a_literal_routes_as_before() {
    let app = proxy(UPSTREAM).await;
    let (status, _, body) = call(&app, Method::POST, "/v1/nodes:batch").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Batch");
    for uri in ["/v1/nodes", "/v1/nodes:other"] {
        let (status, _, body) = call(&app, Method::POST, uri).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
    }
}

async fn a_template_the_router_cannot_serve_is_skipped_not_fatal() {
    // `a{name}b` puts text around a variable, which the router cannot
    // match; that binding is left out and every other one still serves.
    let app = proxy(UPSTREAM).await;
    let request = http::Request::get("/v1/broken/axb").body(Body::empty()).unwrap();
    let (status, _) = common::send(&app, request).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, body) = call(&app, Method::GET, "/v2/ops/op-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
}

#[tokio::test]
async fn a_verb_bound_twice_for_one_method_is_refused_at_startup() {
    // Two POST `:cancel` bindings on one path cannot both serve; the proxy
    // says so instead of serving one of them.
    const TWICE_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
message Msg { string name = 1; string id = 2; }
service Twice {
  rpc A(Msg) returns (Msg) { option (google.api.http) = { post: "/v1/x/{name}:cancel" }; }
  rpc B(Msg) returns (Msg) { option (google.api.http) = { post: "/v1/x/{id}:cancel" }; }
}
"#;
    let pool = common::compile("test/v1/twice.proto", TWICE_PROTO);
    let err = structured_proxy::ProxyServer::from_yaml_str(
        "upstream:\n  default: \"http://127.0.0.1:1\"\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .router()
    .expect_err("a repeated method, path and verb must be rejected");
    assert!(err.to_string().contains("more than one endpoint"), "{err}");
}
