//! The proxy as the whole edge of a service: deadlines and trace context on
//! the way to the upstream, native gRPC and REST on one listener, the fallback
//! for what no route answers, and the client's address reaching an upstream in
//! process. Cases that hold for any upstream run against a remote and an
//! in-process one.

#[macro_use]
mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use http::StatusCode;
use prost_reflect::{DescriptorPool, DynamicMessage, Value as PbValue};
use serde_json::Value;
use structured_proxy::transcode::codec::DynamicCodec;
use structured_proxy::ProxyServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EDGE_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";

message Req {
  string name = 1;
}
// What the upstream saw of the call.
message Seen {
  string name = 1;
  string traceparent = 2;
  string grpc_timeout = 3;
  string peer = 4;
}

service Edge {
  rpc Echo(Req) returns (Seen) {
    option (google.api.http) = { get: "/v1/echo/{name}" };
  }
  // Never answers.
  rpc Hang(Req) returns (Seen) {
    option (google.api.http) = { get: "/v1/hang" };
  }
}
"#;

fn pool() -> DescriptorPool {
    common::compile("test/v1/edge.proto", EDGE_PROTO)
}

// --- upstream ---------------------------------------------------------------

type UnaryFuture = Pin<
    Box<
        dyn std::future::Future<Output = Result<tonic::Response<DynamicMessage>, tonic::Status>>
            + Send,
    >,
>;

/// `Echo` answers with what it saw; `Hang` never answers.
#[derive(Clone)]
struct Handler {
    pool: DescriptorPool,
    rpc: String,
}

impl tonic::server::UnaryService<DynamicMessage> for Handler {
    type Response = DynamicMessage;
    type Future = UnaryFuture;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        if self.rpc == "Hang" {
            return Box::pin(std::future::pending());
        }
        let metadata = |key: &str| {
            request
                .metadata()
                .get(key)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        let mut seen = DynamicMessage::new(self.pool.get_message_by_name("test.v1.Seen").unwrap());
        if let Some(PbValue::String(name)) = request.get_ref().get_field_by_name("name").as_deref()
        {
            seen.set_field_by_name("name", PbValue::String(name.clone()));
        }
        seen.set_field_by_name("traceparent", PbValue::String(metadata("traceparent")));
        seen.set_field_by_name("grpc_timeout", PbValue::String(metadata("grpc-timeout")));
        let peer = request
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        seen.set_field_by_name("peer", PbValue::String(peer));
        Box::pin(std::future::ready(Ok(tonic::Response::new(seen))))
    }
}

/// The `test.v1.Edge` gRPC service, dispatching by method path.
#[derive(Clone)]
struct Edge {
    pool: DescriptorPool,
}

impl tonic::server::NamedService for Edge {
    const NAME: &'static str = "test.v1.Edge";
}

impl tower::Service<http::Request<tonic::body::Body>> for Edge {
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
                .strip_prefix("/test.v1.Edge/")
                .unwrap()
                .to_owned();
            let input = pool.get_message_by_name("test.v1.Req").unwrap();
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(input));
            Ok(grpc.unary(Handler { pool, rpc }, req).await)
        })
    }
}

// --- harness ----------------------------------------------------------------

/// The proxy in front of the `Edge` service.
async fn proxy(upstream: common::Upstream) -> common::App {
    let pool = pool();
    common::proxy(
        upstream,
        Edge { pool: pool.clone() },
        pool,
        Default::default(),
    )
    .await
}

/// Serve the proxy (built from `extra_yaml`, with `fallback` for what no route
/// answers) on a local port in front of the `Edge` service; returns the port's
/// address.
async fn listen(
    upstream: common::Upstream,
    extra_yaml: &str,
    fallback: Option<axum::Router>,
) -> SocketAddr {
    let pool = pool();
    let service = Edge { pool: pool.clone() };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    match upstream {
        common::Upstream::Remote => {
            let url = common::serve(service).await;
            let server = ProxyServer::from_yaml_str(&format!(
                "upstream:\n  default: \"{url}\"\n{extra_yaml}"
            ))
            .unwrap()
            .with_descriptors(pool);
            let mut proxy = server.service(server.upstream().unwrap()).unwrap();
            if let Some(fallback) = fallback {
                proxy = proxy.with_fallback(fallback);
            }
            tokio::spawn(structured_proxy::serve(listener, proxy));
        }
        common::Upstream::InProcess => {
            let server = ProxyServer::from_yaml_str(extra_yaml)
                .unwrap()
                .with_descriptors(pool);
            let mut proxy = server
                .service(tonic::service::Routes::new(service))
                .unwrap();
            if let Some(fallback) = fallback {
                proxy = proxy.with_fallback(fallback);
            }
            tokio::spawn(structured_proxy::serve(listener, proxy));
        }
    }
    addr
}

async fn get(app: &common::App, path: &str, headers: &[(&str, &str)]) -> (StatusCode, Value) {
    let mut request = http::Request::get(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let (status, body) = common::send(app, request.body(Body::empty()).unwrap()).await;
    (status, serde_json::from_str(&body).unwrap())
}

/// A plain HTTP/1.1 `GET` over a fresh connection; returns the status, the
/// body, and the client's own address.
async fn http1_get(addr: SocketAddr, path: &str) -> (u16, String, SocketAddr) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let local = stream.local_addr().unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    let status = response[9..12].parse().unwrap();
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .unwrap_or_default();
    (status, body, local)
}

/// A native gRPC `Echo` call over HTTP/2 to `addr`.
async fn grpc_echo(addr: SocketAddr, name: &str) -> Result<DynamicMessage, tonic::Status> {
    let pool = pool();
    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    let mut req = DynamicMessage::new(pool.get_message_by_name("test.v1.Req").unwrap());
    req.set_field_by_name("name", PbValue::String(name.into()));
    let codec = DynamicCodec::new(pool.get_message_by_name("test.v1.Seen").unwrap());
    grpc.unary(
        tonic::Request::new(req),
        http::uri::PathAndQuery::from_static("/test.v1.Edge/Echo"),
        codec,
    )
    .await
    .map(tonic::Response::into_inner)
}

fn field(msg: &DynamicMessage, name: &str) -> String {
    match msg.get_field_by_name(name).as_deref() {
        Some(PbValue::String(s)) => s.clone(),
        _ => String::new(),
    }
}

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

upstream_tests! {
// --- context propagation -----------------------------------------------------

async fn a_client_traceparent_reaches_the_upstream() {
    // W3C Trace Context §3.2: the upstream joins the client's trace.
    let app = proxy(UPSTREAM).await;
    let (status, seen) = get(&app, "/v1/echo/a", &[("traceparent", TRACEPARENT)]).await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    assert_eq!(seen["traceparent"], TRACEPARENT);
}

async fn a_missing_traceparent_is_synthesized_for_the_upstream() {
    let app = proxy(UPSTREAM).await;
    let (status, seen) = get(&app, "/v1/echo/a", &[]).await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    let traceparent = seen["traceparent"].as_str().unwrap();
    assert!(traceparent.starts_with("00-"), "{traceparent}");
    assert_eq!(traceparent.len(), 55, "{traceparent}");
    assert_ne!(traceparent, TRACEPARENT);
}

async fn a_client_deadline_reaches_the_upstream() {
    // The upstream learns how long the client waits, whatever carries it.
    let app = proxy(UPSTREAM).await;
    let (status, seen) = get(&app, "/v1/echo/a", &[("grpc-timeout", "3S")]).await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    assert!(!seen["grpcTimeout"].as_str().unwrap().is_empty(), "{seen}");
}

async fn the_default_deadline_does_not_reach_the_upstream() {
    // A default deadline sent upstream would end a long server stream on an
    // upstream that applies `grpc-timeout` to the whole call.
    let app = proxy(UPSTREAM).await;
    let (status, seen) = get(&app, "/v1/echo/a", &[]).await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    assert_eq!(seen["grpcTimeout"], "");
}

// --- one listener --------------------------------------------------------------

async fn rest_and_native_grpc_share_one_listener() {
    // HTTP/1.1 REST and HTTP/2 gRPC clients reach the same port: the REST call
    // is transcoded, the gRPC call reaches the upstream as it was sent.
    let addr = listen(UPSTREAM, "", None).await;
    let (status, body, _) = http1_get(addr, "/v1/echo/rest").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["name"], "rest");
    let seen = grpc_echo(addr, "native").await.unwrap();
    assert_eq!(field(&seen, "name"), "native");
}

async fn an_unmatched_request_is_404_without_a_fallback() {
    let addr = listen(UPSTREAM, "", None).await;
    let (status, _, _) = http1_get(addr, "/static/index.html").await;
    assert_eq!(status, 404);
}

async fn maintenance_gates_the_routes_but_not_the_fallback_or_native_grpc() {
    // What the proxy does not serve is passed through untouched: its
    // maintenance gate answers 503 on its own routes only.
    let fallback = axum::Router::new().route(
        "/static/index.html",
        axum::routing::get(|| async { "static" }),
    );
    let addr = listen(UPSTREAM, "maintenance:\n  enabled: true\n", Some(fallback)).await;
    let (status, _, _) = http1_get(addr, "/v1/echo/rest").await;
    assert_eq!(status, 503);
    let (status, body, _) = http1_get(addr, "/static/index.html").await;
    assert_eq!(status, 200);
    assert_eq!(body, "static");
    let seen = grpc_echo(addr, "native").await.unwrap();
    assert_eq!(field(&seen, "name"), "native");
}
}

// --- deadlines ---------------------------------------------------------------

#[tokio::test]
async fn remote_default_deadline_ends_a_call_the_upstream_never_answers() {
    // Nothing on the remote side limits the call (no client `grpc-timeout`),
    // so the proxy's own deadline is what ends it: 504 DEADLINE_EXCEEDED.
    let app = proxy(common::Upstream::Remote).await;
    let started = std::time::Instant::now();
    let (status, body) = get(&app, "/v1/hang", &[]).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["error"], "DEADLINE_EXCEEDED");
    assert!(started.elapsed() >= structured_proxy::transcode::UPSTREAM_DEADLINE);
}

#[tokio::test(start_paused = true)]
async fn in_process_default_deadline_ends_a_call_the_upstream_never_answers() {
    // An upstream in process has no transport to time the call out, so the
    // proxy does.
    let app = proxy(common::Upstream::InProcess).await;
    let started = tokio::time::Instant::now();
    let (status, body) = get(&app, "/v1/hang", &[]).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["error"], "DEADLINE_EXCEEDED");
    assert_eq!(
        started.elapsed(),
        structured_proxy::transcode::UPSTREAM_DEADLINE
    );
}

#[tokio::test(start_paused = true)]
async fn in_process_client_deadline_shorter_than_the_default_ends_the_call() {
    // A remote tonic server enforces `grpc-timeout` itself and races the
    // proxy to the answer; in process only the proxy's clock runs.
    let app = proxy(common::Upstream::InProcess).await;
    let started = tokio::time::Instant::now();
    let (status, body) = get(&app, "/v1/hang", &[("grpc-timeout", "250m")]).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(250));
}

#[tokio::test(start_paused = true)]
async fn in_process_client_deadline_longer_than_the_default_is_capped() {
    let app = proxy(common::Upstream::InProcess).await;
    let started = tokio::time::Instant::now();
    let (status, _) = get(&app, "/v1/hang", &[("grpc-timeout", "1M")]).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert_eq!(
        started.elapsed(),
        structured_proxy::transcode::UPSTREAM_DEADLINE
    );
}

// --- the client's address -------------------------------------------------------

#[tokio::test]
async fn an_in_process_upstream_sees_the_client_address_of_a_rest_call() {
    // `Request::remote_addr` gives the HTTP client, not a loopback hop: a
    // forward-auth decision can key on it.
    let addr = listen(common::Upstream::InProcess, "", None).await;
    let (status, body, client) = http1_get(addr, "/v1/echo/rest").await;
    assert_eq!(status, 200, "{body}");
    let seen: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(seen["peer"], client.to_string());
}

#[tokio::test]
async fn an_in_process_upstream_sees_the_client_address_of_a_native_call() {
    // As behind tonic's own server: the gRPC client's address, on loopback
    // here, with the port its connection came from.
    let addr = listen(common::Upstream::InProcess, "", None).await;
    let seen = grpc_echo(addr, "native").await.unwrap();
    let peer: SocketAddr = field(&seen, "peer").parse().unwrap();
    assert!(peer.ip().is_loopback(), "{peer}");
    assert_ne!(peer.port(), addr.port());
}
