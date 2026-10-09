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
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::Body;
use http::{Method, StatusCode};
use prost_reflect::{DescriptorPool, DynamicMessage, MessageDescriptor, Value as PbValue};
use serde_json::{json, Value};
use structured_proxy::hooks::{ExtraRoute, ExtraRouteHandler, RouteRequest, RouteResponse};
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
  rpc Make(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v3/x/{name}" };
  }
  rpc Sweep(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v3/{operation}/{name}:sweep" };
  }
  rpc Purge(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v4/{name=**}:purge" };
  }
  rpc RunNow(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v2/jobs/{name}:run%3Anow" };
  }
  rpc RunSlash(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v6/{name=**}:run%2Fnow" };
  }
  rpc Fixed(Msg) returns (Msg) {
    option (google.api.http) = { get: "/v7/{name=foo%2Fbar}" };
  }
  rpc FixedMid(Msg) returns (Msg) {
    option (google.api.http) = { get: "/v8/{name=foo%2Fbar}/x" };
  }
  rpc Literal(Msg) returns (Msg) {
    option (google.api.http) = { get: "/v9/{name=foo%2Fbar/*}/x" };
  }
  rpc Shelve(Msg) returns (Msg) {
    option (google.api.http) = { post: "/v5/{name=publishers/*}/books/{operation}" };
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

/// An embedder's extra route answering `pong`.
struct Ping;

#[async_trait::async_trait]
impl ExtraRouteHandler for Ping {
    async fn handle(&self, _req: RouteRequest) -> RouteResponse {
        RouteResponse::new(StatusCode::OK, bytes::Bytes::from_static(b"pong"))
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

async fn a_bound_verb_owns_its_url_for_every_method() {
    // `:cancel` is bound (POST), so `/v2/ops/op-1:cancel` names the verb, not
    // an operation called `op-1:cancel`: the bindings without a verb do not
    // answer it, whatever the method.
    let app = proxy(UPSTREAM).await;
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let (status, allow, _) = call(&app, method.clone(), "/v2/ops/op-1:cancel").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
        assert_eq!(allow, "POST", "{method}");
    }
}

async fn the_verb_starts_at_the_first_colon_of_the_last_segment() {
    // A variable holds no unencoded colon (google/api/http.proto: a client
    // percent-encodes it), so `op-1:b:cancel` is the verb `:b:cancel`, which
    // no binding has; as an unbound verb it stays in the variable.
    let app = proxy(UPSTREAM).await;
    let (status, allow, _) = call(&app, Method::POST, "/v2/ops/op-1:b:cancel").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(allow, "GET, DELETE, HEAD");
    let (status, _, body) = call(&app, Method::GET, "/v2/ops/op-1:b:cancel").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["operation"], "op-1:b:cancel");
}

async fn a_verb_of_another_path_shape_is_found() {
    // `/v3/x/{name}` and `/v3/{operation}/{name}:sweep`: the router prefers
    // the static `x` for `/v3/x/y:sweep`, yet the bound verb belongs to the
    // other path, which binds its own variables.
    let app = proxy(UPSTREAM).await;
    let (status, _, body) = call(&app, Method::POST, "/v3/x/y:sweep").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"name": "y", "operation": "x", "rpc": "Sweep"}));
    let (status, _, body) = call(&app, Method::POST, "/v3/a/b:sweep").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"name": "b", "operation": "a", "rpc": "Sweep"}));
    let (status, _, body) = call(&app, Method::POST, "/v3/x/y").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"name": "y", "operation": "", "rpc": "Make"}));
}

async fn a_double_wildcard_before_a_verb_may_match_no_segment() {
    // `**` matches zero or more segments (google/api/http.proto).
    let app = proxy(UPSTREAM).await;
    let (status, _, body) = call(&app, Method::POST, "/v4/:purge").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Purge");
    assert_eq!(body["name"], "");
    let (status, _, body) = call(&app, Method::POST, "/v4/a/b:purge").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "a/b");
}

async fn an_encoded_character_in_the_verb_is_taken_off_decoded() {
    // `:run%3Anow` keeps its reserved character encoded, as the template
    // grammar asks; the variable gets the value without the decoded verb.
    let app = proxy(UPSTREAM).await;
    let (status, _, body) = call(&app, Method::POST, "/v2/jobs/j1:run%3Anow").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "RunNow");
    assert_eq!(body["name"], "j1");
}

async fn a_variable_over_several_segments_keeps_an_encoded_slash() {
    // A variable that matches several segments is decoded except for `%2F`,
    // which stays as received; a one-segment variable decodes it
    // (google/api/http.proto).
    let app = proxy(UPSTREAM).await;
    let (status, _, body) = call(&app, Method::POST, "/v5/publishers/a%2Fb%20c/books/x%2Fy").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Shelve");
    assert_eq!(body["name"], "publishers/a%2Fb c");
    assert_eq!(body["operation"], "x/y");
    let (status, _, body) = call(&app, Method::POST, "/v4/a%2fb%20c/d:purge").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "a%2fb c/d");
    let (status, _, body) = call(&app, Method::POST, "/v1/publishers/p%2F1/books/b2:restore").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "publishers/p%2F1/books/b2");
    // The verb comes off such a value decoded the same way.
    let (status, _, body) = call(&app, Method::POST, "/v6/a/b:run%2Fnow").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "RunSlash");
    assert_eq!(body["name"], "a/b");
    // Whatever the case of its escape.
    let (status, _, body) = call(&app, Method::POST, "/v6/a/b:run%2fnow").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["name"], "a/b");
    // A literal of the template is taken from the request, `%2F` as received.
    let (status, _, body) = call(&app, Method::GET, "/v9/foo%2fbar/p1/x").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Literal");
    assert_eq!(body["name"], "foo%2fbar/p1");
}

async fn a_field_template_of_one_segment_is_decoded_in_full() {
    // A template of one segment is a one-segment variable: `%2F` is decoded
    // like any other escape (google/api/http.proto).
    let app = proxy(UPSTREAM).await;
    for (uri, rpc) in [("/v7/foo%2Fbar", "Fixed"), ("/v8/foo%2fbar/x", "FixedMid")] {
        let (status, _, body) = call(&app, Method::GET, uri).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body}");
        assert_eq!(body["rpc"], rpc, "{uri}");
        assert_eq!(body["name"], "foo/bar", "{uri}");
    }
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
    // The field template constrains the value: its literals and its number
    // of segments, not just any tail.
    for uri in [
        "/v1/anything/else:restore",
        "/v1/publishers/p1/shelves/b2:restore",
        "/v1/publishers/p1/books:restore",
        "/v1/publishers/p1/books/b2/c3:restore",
    ] {
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

async fn an_extra_route_shares_a_transcoded_path_on_another_method() {
    // The embedder's GET and the transcoded POST on one path both serve, as
    // they did when each method had its own route.
    let pool: DescriptorPool = common::compile("test/v1/ops.proto", OPS_PROTO);
    let msg = pool.get_message_by_name("test.v1.Msg").unwrap();
    let app = common::app(UPSTREAM, Ops { msg }, |yaml| {
        structured_proxy::ProxyServer::from_yaml_str(yaml)
            .unwrap()
            .with_descriptors(pool)
            .with_extra_routes([ExtraRoute::new(
                Method::GET,
                "/v1/nodes:batch",
                Arc::new(Ping),
            )])
    })
    .await;
    let request = http::Request::get("/v1/nodes:batch").body(Body::empty()).unwrap();
    let (status, body) = common::send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "pong");
    let (status, _, body) = call(&app, Method::POST, "/v1/nodes:batch").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Batch");
}

async fn a_request_goes_where_one_router_of_every_route_sends_it() {
    // The proxy matches a transcoded request itself, yet each one still goes
    // where one router holding every route sends it: the extra route's static
    // `/v3/x/ping` ranks before the variable of the transcoded `/v3/x/{name}`
    // for every method, and a HEAD on the path of an extra GET route next to
    // a transcoded POST is that route's.
    let pool: DescriptorPool = common::compile("test/v1/ops.proto", OPS_PROTO);
    let msg = pool.get_message_by_name("test.v1.Msg").unwrap();
    let app = common::app(UPSTREAM, Ops { msg }, |yaml| {
        structured_proxy::ProxyServer::from_yaml_str(yaml)
            .unwrap()
            .with_descriptors(pool)
            .with_extra_routes([
                ExtraRoute::new(Method::GET, "/v3/x/ping", Arc::new(Ping)),
                ExtraRoute::new(Method::GET, "/v1/nodes:batch", Arc::new(Ping)),
            ])
    })
    .await;
    let request = http::Request::get("/v3/x/ping").body(Body::empty()).unwrap();
    assert_eq!(
        common::send(&app, request).await,
        (StatusCode::OK, "pong".to_owned())
    );
    let (status, _, _) = call(&app, Method::POST, "/v3/x/ping").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _, body) = call(&app, Method::POST, "/v3/x/pong").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Make");
    let request = http::Request::head("/v1/nodes:batch")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        common::send(&app, request).await,
        (StatusCode::OK, String::new())
    );
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

#[tokio::test]
async fn an_extra_route_on_a_path_with_verbs_is_refused_at_startup() {
    // The transcoded route of `/v1/x/{name}` answers every method of a URL
    // ending in a bound verb; an extra GET there would take `GET
    // /v1/x/a:cancel` past it.
    const VERB_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
message Msg { string name = 1; }
service Verb {
  rpc Cancel(Msg) returns (Msg) { option (google.api.http) = { post: "/v1/x/{name}:cancel" }; }
}
"#;
    let pool = common::compile("test/v1/verb.proto", VERB_PROTO);
    let err = structured_proxy::ProxyServer::from_yaml_str(
        "upstream:\n  default: \"http://127.0.0.1:1\"\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .with_extra_routes([ExtraRoute::new(Method::GET, "/v1/x/{id}", Arc::new(Ping))])
    .router()
    .expect_err("an extra route on a path with verbs must be rejected");
    assert!(err.to_string().contains("more than one endpoint"), "{err}");
}

#[tokio::test]
async fn a_guard_may_scope_an_extension_method_bound_with_a_verb() {
    // The path is reserved for every method, yet `PROPFIND` is still a method
    // a route answers, so a scope may name it.
    const DAV_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
message Msg { string name = 1; }
service Dav {
  rpc Inspect(Msg) returns (Msg) {
    option (google.api.http) = { custom: { kind: "PROPFIND" path: "/v1/x/{name}:inspect" } };
  }
}
"#;
    let pool = common::compile("test/v1/dav.proto", DAV_PROTO);
    let router = structured_proxy::ProxyServer::from_yaml_str(
        "upstream:\n  default: \"http://127.0.0.1:1\"\nmaintenance:\n  enabled: true\n  scope:\n    traffic: [transcoded]\n    methods: [\"PROPFIND\"]\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .router();
    assert!(router.is_ok(), "PROPFIND is routed: {router:?}");
}

#[tokio::test]
async fn a_url_no_binding_answers_reaches_the_fallback() {
    // The router matches these paths, yet no template takes the URL: not its
    // field template, not its verb. It belongs to the embedder's fallback,
    // while a URL a binding answers for another method stays a 405.
    let pool: DescriptorPool = common::compile("test/v1/ops.proto", OPS_PROTO);
    let msg = pool.get_message_by_name("test.v1.Msg").unwrap();
    let fallback = axum::Router::new().fallback(|| async { (StatusCode::IM_A_TEAPOT, "yours") });
    let service = structured_proxy::ProxyServer::new()
        .with_descriptors(pool)
        .service(tonic::service::Routes::new(Ops { msg }))
        .unwrap()
        .with_fallback(fallback);
    let app = common::App::new(service);
    for uri in ["/v1/anything/else:restore", "/v2/jobs/j1:other"] {
        let request = http::Request::post(uri).body(Body::empty()).unwrap();
        let (status, body) = common::send(&app, request).await;
        assert_eq!(status, StatusCode::IM_A_TEAPOT, "{uri}");
        assert_eq!(body, "yours", "{uri}");
    }
    let (status, _, _) = call(&app, Method::GET, "/v2/jobs/j1:run%3Anow").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _, body) = call(&app, Method::POST, "/v1/publishers/p1/books/b2:restore").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rpc"], "Restore");
}

#[tokio::test]
async fn a_preflight_for_a_url_no_binding_answers_reaches_the_fallback() {
    // The proxy's CORS policy answers a preflight only for its own routes;
    // this URL is the fallback's, preflight included.
    let pool: DescriptorPool = common::compile("test/v1/ops.proto", OPS_PROTO);
    let msg = pool.get_message_by_name("test.v1.Msg").unwrap();
    let fallback = axum::Router::new().fallback(|| async { (StatusCode::IM_A_TEAPOT, "yours") });
    let service = structured_proxy::ProxyServer::from_yaml_str(
        "cors:\n  origins: [\"https://app.example\"]\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .service(tonic::service::Routes::new(Ops { msg }))
    .unwrap()
    .with_fallback(fallback);
    let app = common::App::new(service);
    let request = http::Request::builder()
        .method(Method::OPTIONS)
        .uri("/v1/anything/else:restore")
        .header(http::header::ORIGIN, "https://app.example")
        .header(http::header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        .body(Body::empty())
        .unwrap();
    let (status, body) = common::send(&app, request).await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(body, "yours");
}

#[tokio::test]
async fn a_url_no_binding_answers_reaches_a_route_of_the_proxy_below_it() {
    // `/v1/books/{name=special/*}` ranks above the extra route `/v1/{*path}`,
    // yet does not take `/v1/books/ordinary/x`: the extra route does.
    const SPECIAL_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
message Msg { string name = 1; }
service Special {
  rpc Get(Msg) returns (Msg) { option (google.api.http) = { get: "/v1/books/{name=special/*}" }; }
}
"#;
    let pool = common::compile("test/v1/special.proto", SPECIAL_PROTO);
    let router = structured_proxy::ProxyServer::from_yaml_str(
        "upstream:\n  default: \"http://127.0.0.1:1\"\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .with_extra_routes([ExtraRoute::new(Method::GET, "/v1/{*path}", Arc::new(Ping))])
    .router()
    .unwrap();
    let request = http::Request::get("/v1/books/ordinary/x")
        .body(Body::empty())
        .unwrap();
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"pong");
}

#[tokio::test]
async fn a_url_no_binding_answers_reaches_a_route_below_it_in_a_nested_router() {
    // Nested, the router reports the route it matched with the prefix in
    // front; the URL still goes past the transcoded route that does not take
    // it, to the extra route below.
    const SPECIAL_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
message Msg { string name = 1; }
service Special {
  rpc Get(Msg) returns (Msg) { option (google.api.http) = { get: "/v1/books/{name=special/*}" }; }
}
"#;
    let pool = common::compile("test/v1/special.proto", SPECIAL_PROTO);
    let router = structured_proxy::ProxyServer::from_yaml_str(
        "upstream:\n  default: \"http://127.0.0.1:1\"\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .with_extra_routes([ExtraRoute::new(Method::GET, "/v1/{*path}", Arc::new(Ping))])
    .router()
    .unwrap();
    let app = axum::Router::new().nest("/api", router);
    let request = http::Request::get("/api/v1/books/ordinary/x")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"pong");
}

#[tokio::test]
async fn the_fallback_routes_a_url_no_binding_answers_as_its_own() {
    // The transcoded route that matched the path but took no binding leaves
    // nothing behind: an axum fallback sees only its own route and captures.
    let pool: DescriptorPool = common::compile("test/v1/ops.proto", OPS_PROTO);
    let msg = pool.get_message_by_name("test.v1.Msg").unwrap();
    let fallback = axum::Router::new().route(
        "/v1/{*rest}",
        axum::routing::any(
            |axum::extract::Path(rest): axum::extract::Path<String>,
             path: axum::extract::MatchedPath| async move {
                format!("{} {rest}", path.as_str())
            },
        ),
    );
    let service = structured_proxy::ProxyServer::new()
        .with_descriptors(pool)
        .service(tonic::service::Routes::new(Ops { msg }))
        .unwrap()
        .with_fallback(fallback);
    let app = common::App::new(service);
    let request = http::Request::post("/v1/anything/else:restore")
        .body(Body::empty())
        .unwrap();
    let (status, body) = common::send(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, "/v1/{*rest} anything/else:restore");
}

#[tokio::test]
async fn a_guard_may_scope_an_extension_method_a_star_rule_answers() {
    // A `custom` `*` rule answers every method, `PROPFIND` included, so a
    // scope may name it even when no rule names it on its own.
    const ANY_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
message Msg { string name = 1; }
service Any {
  rpc Inspect(Msg) returns (Msg) {
    option (google.api.http) = { custom: { kind: "*" path: "/v1/x/{name}" } };
  }
}
"#;
    let pool = common::compile("test/v1/any.proto", ANY_PROTO);
    let router = structured_proxy::ProxyServer::from_yaml_str(
        "upstream:\n  default: \"http://127.0.0.1:1\"\nmaintenance:\n  enabled: true\n  scope:\n    traffic: [transcoded]\n    methods: [\"PROPFIND\"]\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .router();
    assert!(router.is_ok(), "the `*` rule answers PROPFIND: {router:?}");
}

#[tokio::test]
async fn a_star_rule_with_a_verb_starts_beside_another_verb() {
    // A `custom` `*` rule answers every method, but only for its own verb, so
    // it does not clash with a POST binding of another verb on its path.
    const STAR_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
message Msg { string name = 1; }
service Star {
  rpc Inspect(Msg) returns (Msg) {
    option (google.api.http) = { custom: { kind: "*" path: "/v1/x/{name}:inspect" } };
  }
  rpc Cancel(Msg) returns (Msg) { option (google.api.http) = { post: "/v1/x/{name}:cancel" }; }
}
"#;
    let pool = common::compile("test/v1/star.proto", STAR_PROTO);
    let router = structured_proxy::ProxyServer::from_yaml_str(
        "upstream:\n  default: \"http://127.0.0.1:1\"\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .router();
    assert!(
        router.is_ok(),
        "bindings of different verbs share their path: {router:?}"
    );
}
