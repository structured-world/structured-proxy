//! The upstream decides the HTTP answer: response metadata becomes response
//! headers, `x-http-code` sets the status of a successful unary call,
//! `google.api.HttpBody` carries a raw body both ways, and `custom` rules bind
//! any method.
//!
//! Runs the proxy (through its public `ProxyServer`) in front of a real tonic
//! gRPC server, so metadata, trailers and trailers-only errors go over the
//! actual HTTP/2 stream.

mod common;

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use bytes::Bytes;
use futures::stream::BoxStream;
use http::{HeaderMap, HeaderName, Method, StatusCode};
use http_body_util::BodyExt;
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, Value as PbValue};
use serde_json::{json, Value};
use structured_proxy::transcode::codec::DynamicCodec;
use structured_proxy::transcode::error::ErrorDetailsPolicy;
use structured_proxy::ProxyServer;
use tonic::metadata::{AsciiMetadataValue, BinaryMetadataValue};
use tower::ServiceExt;

// --- descriptors ------------------------------------------------------------

const CONTROLS_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
import "google/api/httpbody.proto";

message Req {
  string name = 1;
}
message Reply {
  string name = 1;
}
message TokenRequest {
  string grant_type = 1;
}
message Upload {
  string name = 1;
  google.api.HttpBody file = 2;
}

service Controls {
  rpc Get(Req) returns (Reply) {
    option (google.api.http) = { get: "/v1/things/{name}" };
  }
  rpc Trailers(Req) returns (Reply) {
    option (google.api.http) = { get: "/v1/trailers" };
  }
  rpc LateError(Req) returns (Reply) {
    option (google.api.http) = { get: "/v1/late-error" };
  }
  rpc Token(TokenRequest) returns (google.api.HttpBody) {
    option (google.api.http) = { post: "/v1/token" body: "*" };
  }
  rpc Authorize(Req) returns (google.api.HttpBody) {
    option (google.api.http) = { get: "/v1/authorize" };
  }
  rpc Jwks(Req) returns (google.api.HttpBody) {
    option (google.api.http) = { get: "/v1/jwks" };
  }
  rpc Echo(google.api.HttpBody) returns (google.api.HttpBody) {
    option (google.api.http) = { post: "/v1/echo" body: "*" };
  }
  rpc Put(Upload) returns (Reply) {
    option (google.api.http) = { put: "/v1/uploads/{name}" body: "file" };
  }
  rpc Probe(Req) returns (Reply) {
    option (google.api.http) = { custom: { kind: "HEAD" path: "/v1/probe/{name}" } };
  }
  rpc Verify(Req) returns (Reply) {
    option (google.api.http) = { custom: { kind: "*" path: "/v1/verify" } };
  }
  rpc Dav(Req) returns (Reply) {
    option (google.api.http) = {
      custom: { kind: "PROPFIND" path: "/v1/dav" }
      additional_bindings { get: "/v1/dav" }
    };
  }
  rpc Watch(Req) returns (stream Reply) {
    option (google.api.http) = { get: "/v1/things/{name}/watch" };
  }
  rpc Download(Req) returns (stream google.api.HttpBody) {
    option (google.api.http) = { get: "/v1/files/{name}" };
  }
}
"#;

fn pool() -> DescriptorPool {
    common::compile("test/v1/controls.proto", CONTROLS_PROTO)
}

// --- upstream ---------------------------------------------------------------

/// A message of `type_name` with string / bytes fields set.
fn message(pool: &DescriptorPool, type_name: &str, fields: &[(&str, PbValue)]) -> DynamicMessage {
    let mut msg = DynamicMessage::new(pool.get_message_by_name(type_name).unwrap());
    for (name, value) in fields {
        msg.set_field_by_name(name, value.clone());
    }
    msg
}

fn string(msg: &DynamicMessage, field: &str) -> String {
    match msg.get_field_by_name(field).as_deref() {
        Some(PbValue::String(s)) => s.clone(),
        _ => String::new(),
    }
}

fn bytes_field(msg: &DynamicMessage, field: &str) -> Bytes {
    match msg.get_field_by_name(field).as_deref() {
        Some(PbValue::Bytes(b)) => b.clone(),
        _ => Bytes::new(),
    }
}

fn reply(pool: &DescriptorPool, name: &str) -> DynamicMessage {
    message(
        pool,
        "test.v1.Reply",
        &[("name", PbValue::String(name.into()))],
    )
}

fn http_body(pool: &DescriptorPool, content_type: &str, data: &'static [u8]) -> DynamicMessage {
    message(
        pool,
        "google.api.HttpBody",
        &[
            ("content_type", PbValue::String(content_type.into())),
            ("data", PbValue::Bytes(Bytes::from_static(data))),
        ],
    )
}

fn ascii(value: &str) -> AsciiMetadataValue {
    AsciiMetadataValue::try_from(value).unwrap()
}

/// `UNAUTHENTICATED` whose trailers-only response carries a `WWW-Authenticate`
/// challenge (RFC 6750 §3).
fn invalid_token() -> tonic::Status {
    let mut status = tonic::Status::unauthenticated("token expired");
    status.metadata_mut().insert(
        "www-authenticate",
        ascii("Bearer error=\"invalid_token\", error_description=\"expired\""),
    );
    status
}

/// Unary handlers, by RPC name.
#[derive(Clone)]
struct Unary {
    pool: DescriptorPool,
    rpc: String,
}

impl tonic::server::UnaryService<DynamicMessage> for Unary {
    type Response = DynamicMessage;
    type Future = Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let pool = &self.pool;
        let req = request.into_inner();
        let result = match self.rpc.as_str() {
            "Get" => get(pool, &string(&req, "name")),
            "Token" => Ok(token(pool, &string(&req, "grant_type"))),
            "Authorize" => {
                let mut resp = tonic::Response::new(http_body(pool, "", b""));
                resp.metadata_mut().insert("x-http-code", ascii("302"));
                resp.metadata_mut().insert(
                    "location",
                    ascii("https://rp.example/cb?code=abc&state=xyz"),
                );
                Ok(resp)
            }
            "Jwks" => Ok(tonic::Response::new(http_body(
                pool,
                "application/jwk-set+json",
                br#"{"keys":[]}"#,
            ))),
            // The raw body and its content type come back as they arrived.
            "Echo" => Ok(tonic::Response::new(req)),
            "Put" => {
                let file = match req.get_field_by_name("file").as_deref() {
                    Some(PbValue::Message(file)) => file.clone(),
                    _ => panic!("upload without a file"),
                };
                let summary = format!(
                    "{}|{}|{}",
                    string(&req, "name"),
                    string(&file, "content_type"),
                    String::from_utf8(bytes_field(&file, "data").to_vec()).unwrap()
                );
                Ok(tonic::Response::new(reply(pool, &summary)))
            }
            "Probe" => {
                let mut resp = tonic::Response::new(reply(pool, "probed"));
                resp.metadata_mut()
                    .insert("x-probe", ascii(&string(&req, "name")));
                Ok(resp)
            }
            "Verify" => {
                let mut resp = tonic::Response::new(reply(pool, "verified"));
                resp.metadata_mut().insert("x-user-id", ascii("u-42"));
                Ok(resp)
            }
            "Dav" => Ok(tonic::Response::new(reply(pool, "dav"))),
            other => panic!("unexpected unary RPC {other}"),
        };
        ready(result)
    }
}

/// `Get`: behaviour chosen by `name`.
fn get(
    pool: &DescriptorPool,
    name: &str,
) -> Result<tonic::Response<DynamicMessage>, tonic::Status> {
    let mut resp = tonic::Response::new(reply(pool, name));
    let md = resp.metadata_mut();
    match name {
        "plain" => {}
        "meta" => {
            md.insert("cache-control", ascii("no-store"));
            md.append("set-cookie", ascii("a=1"));
            md.append("set-cookie", ascii("b=2"));
            md.insert("x-debug", ascii("internal"));
            md.insert("grpc-extra", ascii("1"));
            md.insert_bin("x-trace-bin", BinaryMetadataValue::from_bytes(b"\x00\x01"));
        }
        "created" => {
            md.insert("x-http-code", ascii("201"));
            md.insert("location", ascii("/v1/things/created"));
        }
        "no-content" => {
            md.insert("x-http-code", ascii("204"));
        }
        "bad-code" => {
            md.insert("x-http-code", ascii("abc"));
            md.insert("x-leak", ascii("must not reach the client"));
        }
        "unauth" => return Err(invalid_token()),
        "corrupt-unauth" => {
            // Details that are not a google.rpc.Status: a broken error, whose
            // metadata must not ride on the generic INTERNAL either.
            let mut status = tonic::Status::with_details(
                tonic::Code::Unauthenticated,
                "nope",
                Bytes::from_static(b"\xff\xff\xff"),
            );
            status
                .metadata_mut()
                .insert("www-authenticate", ascii("Bearer"));
            return Err(status);
        }
        other => panic!("unexpected Get name {other}"),
    }
    Ok(resp)
}

/// RFC 6749 token endpoint: success, or the §5.2 error body with 400; both
/// with `Cache-Control: no-store` (§5.1).
fn token(pool: &DescriptorPool, grant_type: &str) -> tonic::Response<DynamicMessage> {
    let (body, code): (&'static [u8], Option<&str>) = match grant_type {
        "authorization_code" => (br#"{"access_token":"at","token_type":"Bearer"}"#, None),
        _ => (
            br#"{"error":"invalid_grant","error_description":"code expired"}"#,
            Some("400"),
        ),
    };
    let mut resp = tonic::Response::new(http_body(pool, "application/json;charset=UTF-8", body));
    resp.metadata_mut()
        .insert("cache-control", ascii("no-store"));
    resp.metadata_mut().insert("pragma", ascii("no-cache"));
    if let Some(code) = code {
        resp.metadata_mut().insert("x-http-code", ascii(code));
    }
    resp
}

type ReplyStream = BoxStream<'static, Result<DynamicMessage, tonic::Status>>;

/// Server-streaming handlers, by RPC name.
#[derive(Clone)]
struct Streaming {
    pool: DescriptorPool,
    rpc: String,
}

impl tonic::server::ServerStreamingService<DynamicMessage> for Streaming {
    type Response = DynamicMessage;
    type ResponseStream = ReplyStream;
    type Future = Ready<Result<tonic::Response<ReplyStream>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let pool = &self.pool;
        let name = string(request.get_ref(), "name");
        let items: Vec<Result<DynamicMessage, tonic::Status>> =
            match (self.rpc.as_str(), name.as_str()) {
                ("Watch", "denied") => return ready(Err(invalid_token())),
                ("Watch", _) => vec![Ok(reply(pool, "one")), Ok(reply(pool, "two"))],
                ("Download", "broken") => vec![
                    Ok(http_body(pool, "text/csv", b"a,b\n")),
                    Err(tonic::Status::internal("disk failed")),
                ],
                ("Download", "empty") => Vec::new(),
                // Headers sent, then a failure before the first message.
                ("Download", "late-denied") => vec![Err(invalid_token())],
                ("Download", _) => vec![
                    Ok(http_body(pool, "text/csv", b"a,b\n")),
                    // Only the first message's content type counts.
                    Ok(http_body(pool, "text/plain", b"1,2\n")),
                    Ok(http_body(pool, "", b"")),
                    Ok(http_body(pool, "", b"3,4\n")),
                ],
                (rpc, _) => panic!("unexpected streaming RPC {rpc}"),
            };
        let mut resp = tonic::Response::new(Box::pin(futures::stream::iter(items)) as ReplyStream);
        resp.metadata_mut().insert("x-stream", ascii("1"));
        resp.metadata_mut()
            .insert("cache-control", ascii("max-age=60"));
        ready(Ok(resp))
    }
}

/// A successful `Trailers` answer written by hand, since tonic's server API
/// cannot set trailers on success: `x-both` in the headers and the trailers,
/// `x-trailer` only in the trailers, and gRPC's own trailer keys.
fn trailers_response(pool: &DescriptorPool) -> http::Response<tonic::body::Body> {
    let payload = reply(pool, "trailed").encode_to_vec();
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    trailers.insert("x-both", "trailer".parse().unwrap());
    trailers.insert("x-trailer", "t".parse().unwrap());
    let frames: Vec<Result<http_body::Frame<Bytes>, Infallible>> = vec![
        Ok(http_body::Frame::data(Bytes::from(frame))),
        Ok(http_body::Frame::trailers(trailers)),
    ];
    let body = http_body_util::StreamBody::new(futures::stream::iter(frames));
    http::Response::builder()
        .header("content-type", "application/grpc")
        .header("x-both", "initial")
        .body(tonic::body::Body::new(body))
        .unwrap()
}

/// A `LateError` answer written by hand: response headers with metadata
/// (`x-initial`), then no message and an `UNAUTHENTICATED` in the trailers,
/// which carry the challenge. tonic's server API would send a trailers-only
/// response instead.
fn late_error_response() -> http::Response<tonic::body::Body> {
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "16".parse().unwrap());
    trailers.insert("grpc-message", "expired".parse().unwrap());
    trailers.insert(
        "www-authenticate",
        "Bearer error=\"invalid_token\"".parse().unwrap(),
    );
    let frames: Vec<Result<http_body::Frame<Bytes>, Infallible>> =
        vec![Ok(http_body::Frame::trailers(trailers))];
    let body = http_body_util::StreamBody::new(futures::stream::iter(frames));
    http::Response::builder()
        .header("content-type", "application/grpc")
        .header("x-initial", "1")
        .body(tonic::body::Body::new(body))
        .unwrap()
}

/// The `test.v1.Controls` gRPC service, dispatching by method path.
#[derive(Clone)]
struct Controls {
    pool: DescriptorPool,
}

impl tonic::server::NamedService for Controls {
    const NAME: &'static str = "test.v1.Controls";
}

impl tower::Service<http::Request<tonic::body::Body>> for Controls {
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
            let rpc = req
                .uri()
                .path()
                .strip_prefix("/test.v1.Controls/")
                .unwrap()
                .to_owned();
            if rpc == "Trailers" || rpc == "LateError" {
                // Read the request to its end before answering.
                let _request = req.into_body().collect().await.unwrap();
                return Ok(if rpc == "Trailers" {
                    trailers_response(&pool)
                } else {
                    late_error_response()
                });
            }
            let method = pool
                .get_service_by_name("test.v1.Controls")
                .unwrap()
                .methods()
                .find(|m| m.name() == rpc)
                .unwrap();
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(method.input()));
            let resp = if method.is_server_streaming() {
                grpc.server_streaming(Streaming { pool, rpc }, req).await
            } else {
                grpc.unary(Unary { pool, rpc }, req).await
            };
            Ok(resp)
        })
    }
}

// --- proxy harness ----------------------------------------------------------

/// The proxy router in front of a fresh upstream, built by `configure`.
async fn proxy_with(configure: impl FnOnce(ProxyServer) -> ProxyServer) -> axum::Router {
    let pool = pool();
    let upstream = common::serve(Controls { pool: pool.clone() }).await;
    let server = ProxyServer::from_yaml_str(&format!("upstream:\n  default: \"{upstream}\"\n"))
        .unwrap()
        .with_descriptors(pool);
    configure(server).router().unwrap()
}

/// The proxy router in front of a fresh upstream, with default settings.
async fn proxy() -> axum::Router {
    let pool = pool();
    let upstream = common::serve(Controls { pool: pool.clone() }).await;
    common::proxy(&upstream, pool, ErrorDetailsPolicy::default())
}

/// Send `request`; returns the status, the headers and the raw body.
async fn send(app: &axum::Router, request: http::Request<Body>) -> (StatusCode, HeaderMap, Bytes) {
    let resp = app.clone().oneshot(request).await.unwrap();
    let (parts, body) = resp.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    (parts.status, parts.headers, body)
}

async fn call(app: &axum::Router, method: Method, path: &str) -> (StatusCode, HeaderMap, Bytes) {
    let request = http::Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    send(app, request).await
}

fn values<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a str> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect()
}

fn json_body(body: &Bytes) -> Value {
    serde_json::from_slice(body).unwrap()
}

// --- response metadata → headers ---------------------------------------------

#[tokio::test]
async fn unary_metadata_becomes_response_headers() {
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/things/meta").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body), json!({"name": "meta"}));
    assert_eq!(values(&headers, "cache-control"), ["no-store"]);
    assert_eq!(values(&headers, "set-cookie"), ["a=1", "b=2"]);
    assert_eq!(values(&headers, "x-debug"), ["internal"]);
    // gRPC's own keys and the binary encoding stay behind; the content type
    // is the transcoder's.
    assert!(headers.get("grpc-extra").is_none());
    assert!(headers.get("x-trace-bin").is_none());
    assert!(headers.get("grpc-status").is_none());
    assert!(headers.get("grpc-accept-encoding").is_none());
    assert_eq!(values(&headers, "content-type"), ["application/json"]);
}

#[tokio::test]
async fn plain_answer_adds_no_upstream_headers() {
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/things/plain").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body), json!({"name": "plain"}));
    assert!(headers.get("cache-control").is_none());
    assert!(headers.get("x-http-code").is_none());
}

#[tokio::test]
async fn trailers_of_a_successful_call_become_headers_after_initial_metadata() {
    // A key in both the initial metadata and the trailers keeps both values,
    // initial first; gRPC's trailer keys stay behind.
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/trailers").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body), json!({"name": "trailed"}));
    assert_eq!(values(&headers, "x-both"), ["initial", "trailer"]);
    assert_eq!(values(&headers, "x-trailer"), ["t"]);
    assert!(headers.get("grpc-status").is_none());
}

#[tokio::test]
async fn deny_list_from_the_builder_drops_its_keys() {
    let app = proxy_with(|server| {
        server.with_denied_response_headers([HeaderName::from_static("x-debug")])
    })
    .await;
    let (_, headers, _) = call(&app, Method::GET, "/v1/things/meta").await;
    assert!(headers.get("x-debug").is_none());
    assert_eq!(values(&headers, "cache-control"), ["no-store"]);
}

#[tokio::test]
async fn deny_list_from_yaml_drops_its_keys() {
    let pool = pool();
    let upstream = common::serve(Controls { pool: pool.clone() }).await;
    let app = ProxyServer::from_yaml_str(&format!(
        "upstream:\n  default: \"{upstream}\"\nresponse_headers:\n  deny: [\"X-Debug\", \"set-cookie\"]\n"
    ))
    .unwrap()
    .with_descriptors(pool)
    .router()
    .unwrap();
    let (_, headers, _) = call(&app, Method::GET, "/v1/things/meta").await;
    assert!(headers.get("x-debug").is_none());
    assert!(headers.get("set-cookie").is_none());
    assert_eq!(values(&headers, "cache-control"), ["no-store"]);
}

#[tokio::test]
async fn trailers_only_error_carries_its_metadata() {
    // RFC 6750 §3: the 401 carries the upstream's `WWW-Authenticate`.
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/things/unauth").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        values(&headers, "www-authenticate"),
        ["Bearer error=\"invalid_token\", error_description=\"expired\""]
    );
    assert_eq!(json_body(&body)["error"], "UNAUTHENTICATED");
    assert_eq!(values(&headers, "content-type"), ["application/json"]);
}

#[tokio::test]
async fn unary_error_after_headers_carries_initial_metadata_and_trailers() {
    // The upstream sent response headers, then failed in its trailers: the
    // error keeps both, initial metadata first, as tonic's own unary call
    // does.
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/late-error").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(values(&headers, "x-initial"), ["1"]);
    assert_eq!(
        values(&headers, "www-authenticate"),
        ["Bearer error=\"invalid_token\""]
    );
    assert_eq!(json_body(&body)["message"], "expired");
}

#[tokio::test]
async fn http_body_stream_failing_before_its_first_message_keeps_initial_metadata() {
    // Headers were sent before the failure, so they belong to the error
    // response, next to the failure's own metadata.
    let app = proxy().await;
    let (status, headers, _) = call(&app, Method::GET, "/v1/files/late-denied").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(values(&headers, "x-stream"), ["1"]);
    assert_eq!(values(&headers, "cache-control"), ["max-age=60"]);
    assert!(values(&headers, "www-authenticate")[0].starts_with("Bearer error="));
}

#[tokio::test]
async fn malformed_error_status_carries_no_upstream_metadata() {
    // The answer is the generic INTERNAL, so nothing of the broken error,
    // headers included, reaches the client.
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/things/corrupt-unauth").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(json_body(&body)["error"], "INTERNAL");
    assert!(headers.get("www-authenticate").is_none());
}

// --- x-http-code ------------------------------------------------------------

#[tokio::test]
async fn http_code_sets_the_status_of_a_successful_call() {
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/things/created").await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(values(&headers, "location"), ["/v1/things/created"]);
    assert!(headers.get("x-http-code").is_none());
    assert_eq!(json_body(&body), json!({"name": "created"}));
}

#[tokio::test]
async fn http_code_204_answers_without_content() {
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/things/no-content").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
    assert!(headers.get("content-type").is_none());
}

#[tokio::test]
async fn invalid_http_code_is_a_malformed_upstream_internal() {
    // Never a partial response: no other upstream header rides along.
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/things/bad-code").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        json_body(&body),
        json!({
            "error": "INTERNAL",
            "message": "upstream returned a malformed response",
            "code": 13,
            "details": []
        })
    );
    assert!(headers.get("x-leak").is_none());
    assert!(headers.get("x-http-code").is_none());
}

#[tokio::test]
async fn redirect_with_location_and_an_empty_body() {
    // RFC 6749 §4.1.2: the authorization endpoint answers 302 + Location.
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/authorize").await;
    assert_eq!(status, StatusCode::FOUND);
    assert_eq!(
        values(&headers, "location"),
        ["https://rp.example/cb?code=abc&state=xyz"]
    );
    assert!(body.is_empty());
    assert!(headers.get("content-type").is_none());
}

// --- google.api.HttpBody ----------------------------------------------------

async fn post_form(
    app: &axum::Router,
    path: &str,
    form: &'static str,
) -> (StatusCode, HeaderMap, Bytes) {
    let request = http::Request::post(path)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .unwrap();
    send(app, request).await
}

#[tokio::test]
async fn token_error_is_the_rfc_6749_body_with_400_and_no_store() {
    // RFC 6749 §5.2: 400, the upstream's own JSON body, `Cache-Control:
    // no-store` (§5.1). Not the transcoder's error body.
    let app = proxy().await;
    let (status, headers, body) = post_form(&app, "/v1/token", "grant_type=refresh_token").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(values(&headers, "cache-control"), ["no-store"]);
    assert_eq!(values(&headers, "pragma"), ["no-cache"]);
    assert_eq!(
        values(&headers, "content-type"),
        ["application/json;charset=UTF-8"]
    );
    assert_eq!(
        json_body(&body),
        json!({"error": "invalid_grant", "error_description": "code expired"})
    );
}

#[tokio::test]
async fn token_success_is_the_raw_json_with_no_store() {
    let app = proxy().await;
    let (status, headers, body) =
        post_form(&app, "/v1/token", "grant_type=authorization_code").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(values(&headers, "cache-control"), ["no-store"]);
    assert_eq!(&body[..], br#"{"access_token":"at","token_type":"Bearer"}"#);
}

#[tokio::test]
async fn http_body_response_keeps_the_content_type_and_bytes() {
    // RFC 7517 §8.5: a JWK Set is served as application/jwk-set+json.
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/jwks").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        values(&headers, "content-type"),
        ["application/jwk-set+json"]
    );
    assert_eq!(&body[..], br#"{"keys":[]}"#);
}

#[tokio::test]
async fn http_body_request_receives_the_raw_body_and_content_type() {
    // Bytes that are neither JSON nor UTF-8 arrive untouched, with the full
    // Content-Type value (parameters included).
    let app = proxy().await;
    let raw: &'static [u8] = b"\x89PNG\r\n\x1a\n\x00\xff";
    let request = http::Request::post("/v1/echo")
        .header("content-type", "image/png; name=x")
        .body(Body::from(raw))
        .unwrap();
    let (status, headers, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(values(&headers, "content-type"), ["image/png; name=x"]);
    assert_eq!(&body[..], raw);
}

#[tokio::test]
async fn query_on_a_whole_message_http_body_route_is_ignored() {
    // With `body: "*"` on an HttpBody input every field comes from the body
    // (google/api/http.proto: no HTTP parameters with `*`), so a query that
    // names an HttpBody field is ignored instead of failing the request.
    let app = proxy().await;
    let request = http::Request::post("/v1/echo?extensions=x&content_type=y&data=z")
        .header("content-type", "text/plain")
        .body(Body::from("raw"))
        .unwrap();
    let (status, headers, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(values(&headers, "content-type"), ["text/plain"]);
    assert_eq!(&body[..], b"raw");
}

#[tokio::test]
async fn http_body_request_without_a_body_is_empty() {
    let app = proxy().await;
    let request = http::Request::post("/v1/echo").body(Body::empty()).unwrap();
    let (status, headers, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());
    assert!(headers.get("content-type").is_none());
}

#[tokio::test]
async fn http_body_field_receives_the_raw_body_next_to_path_fields() {
    let app = proxy().await;
    let request = http::Request::put("/v1/uploads/report")
        .header("content-type", "text/csv")
        .body(Body::from("a,b"))
        .unwrap();
    let (status, body) = common::send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({"name": "report|text/csv|a,b"})
    );
}

#[tokio::test]
async fn query_key_naming_the_raw_body_field_does_not_break_the_upload() {
    // The body binds `file`, and the body wins over the query: a `file`
    // query parameter (or one under it) is ignored rather than bound into
    // the HttpBody field before the raw body replaces it.
    let app = proxy().await;
    let request = http::Request::put("/v1/uploads/report?file=x&file.content_type=y")
        .header("content-type", "text/csv")
        .body(Body::from("a,b"))
        .unwrap();
    let (status, _, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(json_body(&body), json!({"name": "report|text/csv|a,b"}));
}

#[tokio::test]
async fn http_body_request_with_a_non_ascii_content_type_is_rejected() {
    // HttpBody.content_type is a proto string; bytes that are not visible
    // ASCII are refused before the upstream is called.
    let app = proxy().await;
    let request = http::Request::post("/v1/echo")
        .header(
            "content-type",
            http::HeaderValue::from_bytes(b"text/plain; x=\xe9").unwrap(),
        )
        .body(Body::from("x"))
        .unwrap();
    let (status, _, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json_body(&body)["error"], "INVALID_ARGUMENT");
}

// --- server streaming -------------------------------------------------------

#[tokio::test]
async fn streaming_initial_metadata_becomes_headers() {
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/things/x/watch").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(values(&headers, "x-stream"), ["1"]);
    assert_eq!(values(&headers, "content-type"), ["application/x-ndjson"]);
    let lines: Vec<Value> = std::str::from_utf8(&body)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines, [json!({"name": "one"}), json!({"name": "two"})]);
}

#[tokio::test]
async fn sse_keeps_its_own_cache_control_over_the_upstream_one() {
    // What the proxy writes describes the body it writes: SSE must not be
    // cached, whatever the upstream asked for.
    let app = proxy().await;
    let request = http::Request::get("/v1/things/x/watch")
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(values(&headers, "content-type"), ["text/event-stream"]);
    assert_eq!(values(&headers, "cache-control"), ["no-cache"]);
    assert_eq!(values(&headers, "x-stream"), ["1"]);
}

#[tokio::test]
async fn refused_stream_carries_its_metadata() {
    let app = proxy().await;
    let (status, headers, _) = call(&app, Method::GET, "/v1/things/denied/watch").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(values(&headers, "www-authenticate")[0].starts_with("Bearer error=\"invalid_token\""));
}

#[tokio::test]
async fn streaming_http_body_is_chunked_raw_data() {
    // Content type from the first message; every message's data in order.
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/files/report").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(values(&headers, "content-type"), ["text/csv"]);
    assert_eq!(values(&headers, "x-stream"), ["1"]);
    assert_eq!(&body[..], b"a,b\n1,2\n3,4\n");
}

#[tokio::test]
async fn streaming_http_body_ignores_sse_negotiation() {
    let app = proxy().await;
    let request = http::Request::get("/v1/files/report")
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .unwrap();
    let (_, headers, body) = send(&app, request).await;
    assert_eq!(values(&headers, "content-type"), ["text/csv"]);
    assert_eq!(&body[..], b"a,b\n1,2\n3,4\n");
}

#[tokio::test]
async fn empty_streaming_http_body_is_an_empty_ok() {
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::GET, "/v1/files/empty").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());
    assert!(headers.get("content-type").is_none());
}

#[tokio::test]
async fn streaming_http_body_failing_mid_stream_aborts_the_body() {
    // A raw body has no in-band error frame: the transfer is cut short so the
    // client cannot take the partial file for a complete one.
    let app = proxy().await;
    let request = http::Request::get("/v1/files/broken")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(request).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .is_err());
}

// --- custom rules ------------------------------------------------------------

#[tokio::test]
async fn custom_head_rule_routes_head_to_the_rpc() {
    let app = proxy().await;
    let (status, headers, body) = call(&app, Method::HEAD, "/v1/probe/disk").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(values(&headers, "x-probe"), ["disk"]);
    assert!(body.is_empty());
    // Only HEAD is bound on that path.
    let (status, _, _) = call(&app, Method::GET, "/v1/probe/disk").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn star_rule_routes_every_method_to_the_rpc() {
    // A forward-auth sub-request arrives with the original request's method.
    let app = proxy().await;
    for method in [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::OPTIONS,
        Method::from_bytes(b"PROPFIND").unwrap(),
    ] {
        let (status, headers, body) = call(&app, method.clone(), "/v1/verify").await;
        assert_eq!(status, StatusCode::OK, "{method}");
        assert_eq!(values(&headers, "x-user-id"), ["u-42"], "{method}");
        assert_eq!(json_body(&body), json!({"name": "verified"}), "{method}");
    }
}

#[tokio::test]
async fn extension_method_rule_routes_next_to_a_standard_one() {
    let app = proxy().await;
    let propfind = Method::from_bytes(b"PROPFIND").unwrap();
    let (status, _, body) = call(&app, propfind, "/v1/dav").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body), json!({"name": "dav"}));
    let (status, _, body) = call(&app, Method::GET, "/v1/dav").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json_body(&body), json!({"name": "dav"}));
    // A method nobody binds is 405 with the full Allow list (RFC 9110
    // §15.5.6).
    let (status, headers, _) = call(&app, Method::from_bytes(b"MKCOL").unwrap(), "/v1/dav").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(values(&headers, "allow"), ["PROPFIND, GET, HEAD"]);
    let (status, _, _) = call(&app, Method::DELETE, "/v1/dav").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn unbound_method_is_405_before_its_body_is_read() {
    // The method decides first: a method nobody binds on the path is 405
    // even with a body over the extractor limit, which is never buffered.
    let app = proxy().await;
    let request = http::Request::builder()
        .method(Method::DELETE)
        .uri("/v1/dav")
        .body(Body::from(vec![b'x'; 3 * 1024 * 1024]))
        .unwrap();
    let (status, headers, _) = send(&app, request).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(values(&headers, "allow"), ["PROPFIND, GET, HEAD"]);
}

#[tokio::test]
async fn star_rule_collides_with_another_method_on_its_path() {
    // `*` claims every method, so another binding on the same path is a
    // conflict the router refuses up front instead of an axum panic.
    const CLASH_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";
message Req { string name = 1; }
service Clash {
  rpc Any(Req) returns (Req) {
    option (google.api.http) = { custom: { kind: "*" path: "/v1/x" } };
  }
  rpc Get(Req) returns (Req) {
    option (google.api.http) = { get: "/v1/x" };
  }
}
"#;
    let pool = common::compile("test/v1/clash.proto", CLASH_PROTO);
    let err = ProxyServer::from_yaml_str("upstream:\n  default: \"http://127.0.0.1:1\"\n")
        .unwrap()
        .with_descriptors(pool)
        .router()
        .expect_err("a `*` rule next to another method must be rejected");
    assert!(err.to_string().contains("more than one endpoint"), "{err}");
}
