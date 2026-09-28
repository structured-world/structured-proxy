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
    listen_configured(upstream, extra_yaml, fallback, |server| server).await
}

/// [`listen`], with `configure` applied to the server before it is built.
async fn listen_configured(
    upstream: common::Upstream,
    extra_yaml: &str,
    fallback: Option<axum::Router>,
    configure: impl FnOnce(ProxyServer) -> ProxyServer,
) -> SocketAddr {
    let pool = pool();
    let service = Edge { pool: pool.clone() };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    match upstream {
        common::Upstream::Remote => {
            let url = common::serve(service).await;
            let server = configure(
                ProxyServer::from_yaml_str(&format!(
                    "upstream:\n  default: \"{url}\"\n{extra_yaml}"
                ))
                .unwrap()
                .with_descriptors(pool),
            );
            let mut proxy = server.service(server.upstream().unwrap()).unwrap();
            if let Some(fallback) = fallback {
                proxy = proxy.with_fallback(fallback);
            }
            tokio::spawn(structured_proxy::serve(listener, proxy));
        }
        common::Upstream::InProcess => {
            let server = configure(
                ProxyServer::from_yaml_str(extra_yaml)
                    .unwrap()
                    .with_descriptors(pool),
            );
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

// --- scoped guards ---------------------------------------------------------------

async fn a_guard_scoped_to_grpc_answers_native_calls_with_a_status() {
    // A gRPC client reads only a status: the guard's 503 reaches it as
    // UNAVAILABLE with the guard's message, while the REST route it does not
    // cover stays open.
    let yaml = "maintenance:\n  enabled: true\n  message: \"back soon\"\n  scope:\n    traffic: [grpc]\n";
    let addr = listen(UPSTREAM, yaml, None).await;
    let status = grpc_echo(addr, "native").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert_eq!(status.message(), "back soon");
    let (status, body, _) = http1_get(addr, "/v1/echo/rest").await;
    assert_eq!(status, 200, "{body}");
}

async fn a_guard_scoped_to_the_fallback_covers_it_and_nothing_else() {
    let fallback = axum::Router::new().route(
        "/static/index.html",
        axum::routing::get(|| async { "static" }),
    );
    let yaml = "maintenance:\n  enabled: true\n  scope:\n    traffic: [fallback]\n";
    let addr = listen(UPSTREAM, yaml, Some(fallback)).await;
    let (status, body, _) = http1_get(addr, "/static/index.html").await;
    assert_eq!(status, 503, "{body}");
    let body: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(body["error"], "UNAVAILABLE");
    let (status, body, _) = http1_get(addr, "/v1/echo/rest").await;
    assert_eq!(status, 200, "{body}");
}

async fn a_guard_narrowed_by_path_leaves_the_other_paths_alone() {
    let yaml = "maintenance:\n  enabled: true\n  scope:\n    paths: [\"/v1/echo/closed\"]\n";
    let addr = listen(UPSTREAM, yaml, None).await;
    let (status, _, _) = http1_get(addr, "/v1/echo/closed").await;
    assert_eq!(status, 503);
    let (status, body, _) = http1_get(addr, "/v1/echo/open").await;
    assert_eq!(status, 200, "{body}");
}

async fn the_auth_decider_scoped_to_grpc_gates_native_calls_by_the_client_address() {
    // The decider sees the gRPC client's address, and its 403 reaches the
    // client as PERMISSION_DENIED.
    let decider = std::sync::Arc::new(PeerDecider::default());
    let scope = structured_proxy::config::ScopeConfig::traffic([
        structured_proxy::config::Traffic::Grpc,
    ]);
    let addr = listen_configured(UPSTREAM, "", None, {
        let decider = decider.clone();
        move |server| {
            server
                .with_auth_decider(decider)
                .with_auth_decider_scope(scope)
        }
    })
    .await;
    let status = grpc_echo(addr, "native").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    let peer = decider.peer.lock().unwrap().unwrap();
    assert!(peer.ip().is_loopback(), "{peer}");
    // Scoped to gRPC: the transcoded route is not behind it.
    let (status, body, _) = http1_get(addr, "/v1/echo/rest").await;
    assert_eq!(status, 200, "{body}");
}

// --- gRPC-Web translation ------------------------------------------------------------

async fn binary_grpc_web_is_translated_for_an_upstream_that_speaks_only_grpc() {
    // The upstream has no gRPC-Web layer; the proxy converts the call, over
    // HTTP/1.1 here, to gRPC and the answer back.
    let app = translating_proxy(UPSTREAM, "").await;
    let (content_type, body) =
        grpc_web_echo_via(app, "application/grpc-web+proto", request_frame("web")).await;
    assert_eq!(content_type, "application/grpc-web+proto");
    assert_eq!(seen_name(&body), "web");
}

async fn text_grpc_web_is_translated_for_an_upstream_that_speaks_only_grpc() {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let app = translating_proxy(UPSTREAM, "").await;
    let (content_type, body) = grpc_web_echo_via(
        app,
        "application/grpc-web-text+proto",
        engine.encode(request_frame("text")).into_bytes(),
    )
    .await;
    assert_eq!(content_type, "application/grpc-web-text+proto");
    let decoded: Vec<u8> = body
        .chunks(4)
        .flat_map(|group| engine.decode(group).unwrap())
        .collect();
    assert_eq!(seen_name(&decoded), "text");
}

async fn a_guard_rejects_a_translated_call_in_grpc_web() {
    let yaml = "maintenance:\n  enabled: true\n  scope:\n    traffic: [grpc]\n";
    let request = http::Request::post("/test.v1.Edge/Echo")
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(Body::from(request_frame("web")))
        .unwrap();
    let app = translating_proxy(UPSTREAM, yaml).await;
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/grpc-web+proto"
    );
    assert_eq!(response.headers()["grpc-status"], "14");
}
}

/// The proxy in front of the `Edge` service with no gRPC-Web layer of its
/// own, translating gRPC-Web, with `extra_yaml`.
async fn translating_proxy(upstream: common::Upstream, extra_yaml: &str) -> common::App {
    let pool = pool();
    common::app(upstream, Edge { pool: pool.clone() }, |yaml| {
        ProxyServer::from_yaml_str(&format!("{yaml}grpc_web:\n  translate: true\n{extra_yaml}"))
            .unwrap()
            .with_descriptors(pool)
    })
    .await
}

// --- the capability builder ------------------------------------------------------

/// Send a native gRPC `Echo` through `app`; returns the gRPC status code.
async fn grpc_echo_status(app: common::App) -> String {
    let request = http::Request::post("/test.v1.Edge/Echo")
        .version(http::Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Body::from(request_frame("native")))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    let (parts, body) = response.into_parts();
    if let Some(status) = parts.headers.get("grpc-status") {
        return status.to_str().unwrap().to_owned();
    }
    let collected = http_body_util::BodyExt::collect(body).await.unwrap();
    collected.trailers().unwrap()["grpc-status"]
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn a_new_proxy_passes_everything_through() {
    // Nothing on: no transcoding, no health or metrics endpoints; native gRPC
    // reaches the upstream and REST the fallback.
    let fallback = axum::Router::new().fallback(|| async { (StatusCode::IM_A_TEAPOT, "yours") });
    let service = ProxyServer::new()
        .service(tonic::service::Routes::new(Edge { pool: pool() }))
        .unwrap()
        .with_fallback(fallback);
    let app = common::App::new(service);
    for path in ["/v1/echo/a", "/health", "/metrics"] {
        let (status, body) =
            common::send(&app, http::Request::get(path).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::IM_A_TEAPOT, "{path}");
        assert_eq!(body, "yours");
    }
    assert_eq!(grpc_echo_status(app).await, "0");
}

#[tokio::test]
async fn only_the_selected_rpcs_are_transcoded() {
    // `Hang` never answers: were it transcoded, its route would hang.
    let service = ProxyServer::new()
        .with_descriptors(pool())
        .with_transcoded_rpcs(["test.v1.Edge/Echo"])
        .service(tonic::service::Routes::new(Edge { pool: pool() }))
        .unwrap();
    let app = common::App::new(service);
    let (status, seen) = get(&app, "/v1/echo/a", &[]).await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    let (status, _) = common::send(
        &app,
        http::Request::get("/v1/hang").body(Body::empty()).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[test]
fn a_selection_the_descriptors_do_not_hold_fails_the_build() {
    let server = ProxyServer::new()
        .with_descriptors(pool())
        .with_transcoded_rpcs(["test.v1.Edge/Missing"]);
    let Err(err) = server.service(tonic::service::Routes::default()) else {
        panic!("an unknown RPC must be refused");
    };
    assert!(err.to_string().contains("transcode.only"), "{err}");
}

#[tokio::test]
async fn a_builder_section_behaves_as_its_yaml() {
    let maintenance =
        structured_proxy::config::from_yaml("enabled: true\nmessage: down\n").unwrap();
    let service = ProxyServer::new()
        .with_descriptors(pool())
        .with_maintenance(maintenance)
        .service(tonic::service::Routes::new(Edge { pool: pool() }))
        .unwrap();
    let (status, body) = get(&common::App::new(service), "/v1/echo/a", &[]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["message"], "down");
}

#[tokio::test]
async fn a_new_proxy_reaches_a_remote_upstream_by_address() {
    let url = common::serve(Edge { pool: pool() }).await;
    let server = ProxyServer::new()
        .with_descriptors(pool())
        .with_upstream_address(url);
    let app = common::App::new(server.service(server.upstream().unwrap()).unwrap());
    let (status, seen) = get(&app, "/v1/echo/remote", &[]).await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    assert_eq!(seen["name"], "remote");
}

#[test]
fn translation_needs_the_proxys_grpc_web_cors() {
    // The upstream cannot answer the preflight of a call it cannot read.
    let err =
        ProxyServer::from_yaml_str("grpc_web:\n  translate: true\ncors:\n  grpc_web: false\n")
            .err()
            .expect("translation without the proxy's gRPC-Web CORS is refused");
    assert!(err.to_string().contains("grpc_web.translate"), "{err}");
}

/// Denies every request with `403`, recording the peer it saw.
#[derive(Default)]
struct PeerDecider {
    peer: std::sync::Mutex<Option<SocketAddr>>,
}

#[async_trait::async_trait]
impl structured_proxy::hooks::AuthDecider for PeerDecider {
    async fn decide(
        &self,
        req: &structured_proxy::hooks::RequestParts<'_>,
    ) -> structured_proxy::hooks::Decision {
        *self.peer.lock().unwrap() = Some(req.peer);
        structured_proxy::hooks::Decision::Deny {
            status: StatusCode::FORBIDDEN,
            body: bytes::Bytes::from_static(br#"{"error":"denied"}"#),
        }
    }
}

#[test]
fn a_scope_that_covers_no_traffic_fails_the_build() {
    let server =
        ProxyServer::from_yaml_str("maintenance:\n  enabled: true\n  scope:\n    traffic: []\n")
            .unwrap()
            .with_descriptors(pool());
    let Err(err) = server.service(tonic::service::Routes::default()) else {
        panic!("a scope with no traffic must be refused");
    };
    assert!(
        err.to_string().contains("maintenance.scope.traffic"),
        "{err}"
    );
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

/// An upstream under backpressure that never frees a slot: `poll_ready` stays
/// pending, as behind a saturated concurrency limit.
#[derive(Clone)]
struct NeverReady;

impl tower::Service<http::Request<tonic::body::Body>> for NeverReady {
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = std::future::Pending<Result<Self::Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }

    fn call(&mut self, _req: http::Request<tonic::body::Body>) -> Self::Future {
        unreachable!("never ready, never called")
    }
}

#[tokio::test(start_paused = true)]
async fn waiting_for_a_saturated_upstream_counts_against_the_deadline() {
    // Readiness is part of the call: an upstream that never takes the call
    // must not hold the request past its deadline.
    let server = ProxyServer::from_yaml_str("")
        .unwrap()
        .with_descriptors(pool());
    let app = common::App::new(server.service(NeverReady).unwrap());
    let started = tokio::time::Instant::now();
    let (status, body) = get(&app, "/v1/echo/a", &[("grpc-timeout", "250m")]).await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT, "{body}");
    assert_eq!(body["error"], "DEADLINE_EXCEEDED");
    assert_eq!(started.elapsed(), std::time::Duration::from_millis(250));
}

// --- gRPC-Web --------------------------------------------------------------------

/// The proxy in front of the `Edge` service in process, made to speak gRPC-Web
/// the way an embedder does it: tonic-web's layer around its services.
fn grpc_web_proxy() -> common::App {
    grpc_web_proxy_with("")
}

/// [`grpc_web_proxy`] configured by `yaml`.
fn grpc_web_proxy_with(yaml: &str) -> common::App {
    let pool = pool();
    let upstream = tower::ServiceBuilder::new()
        .layer(tonic_web::GrpcWebLayer::new())
        .service(tonic::service::Routes::new(Edge { pool: pool.clone() }));
    let server = ProxyServer::from_yaml_str(yaml)
        .unwrap()
        .with_descriptors(pool);
    common::App::new(server.service(upstream).unwrap())
}

const ORIGIN: &str = "https://app.example";

/// A browser's cross-origin gRPC-Web call from [`ORIGIN`] through `app`;
/// returns the response headers.
async fn browser_grpc_web_call(app: common::App) -> http::HeaderMap {
    let request = http::Request::post("/test.v1.Edge/Echo")
        .header("origin", ORIGIN)
        .header("content-type", "application/grpc-web+proto")
        .header("x-grpc-web", "1")
        .body(Body::from(request_frame("browser")))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.headers().clone()
}

/// The browser's preflight for that call; returns the response headers.
async fn browser_grpc_web_preflight(app: common::App) -> http::HeaderMap {
    let request = http::Request::builder()
        .method("OPTIONS")
        .uri("/test.v1.Edge/Echo")
        .header("origin", ORIGIN)
        .header("access-control-request-method", "POST")
        .header(
            "access-control-request-headers",
            "content-type,x-grpc-web,x-user-agent",
        )
        .body(Body::empty())
        .unwrap();
    tower::ServiceExt::oneshot(app, request)
        .await
        .unwrap()
        .headers()
        .clone()
}

fn exposed(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get_all("access-control-expose-headers")
        .iter()
        .flat_map(|v| v.to_str().unwrap().split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .collect()
}

const CORS_YAML: &str = "cors:\n  origins: [\"https://app.example\"]\n";

#[tokio::test]
async fn a_browser_grpc_web_call_gets_the_cors_policy_its_preflight_got() {
    // The proxy answers the preflight under its CORS policy, so the call must
    // carry the same policy: without it the browser discards the response.
    let preflight = browser_grpc_web_preflight(grpc_web_proxy_with(CORS_YAML)).await;
    assert_eq!(preflight["access-control-allow-origin"], ORIGIN);
    let call = browser_grpc_web_call(grpc_web_proxy_with(CORS_YAML)).await;
    assert_eq!(call["access-control-allow-origin"], ORIGIN);
    assert_eq!(call["access-control-allow-credentials"], "true");
    // A gRPC-Web client reads the status and its details from these.
    let exposed = exposed(&call);
    for name in ["grpc-status", "grpc-message", "grpc-status-details-bin"] {
        assert!(exposed.iter().any(|e| e == name), "{name}: {exposed:?}");
    }
}

#[tokio::test]
async fn a_grpc_web_call_from_an_unlisted_origin_gets_no_allowance() {
    let request = http::Request::post("/test.v1.Edge/Echo")
        .header("origin", "https://evil.example")
        .header("content-type", "application/grpc-web+proto")
        .body(Body::from(request_frame("x")))
        .unwrap();
    let response = tower::ServiceExt::oneshot(grpc_web_proxy_with(CORS_YAML), request)
        .await
        .unwrap();
    assert!(response
        .headers()
        .get("access-control-allow-origin")
        .is_none());
}

#[tokio::test]
async fn configured_expose_headers_and_max_age_reach_the_browser() {
    // Upstream metadata a browser must read is exposed by name, and the
    // preflight tells the browser how long to cache it.
    let yaml = "cors:\n  origins: [\"https://app.example\"]\n  expose_headers: [\"x-request-id\"]\n  max_age_secs: 600\n";
    let call = browser_grpc_web_call(grpc_web_proxy_with(yaml)).await;
    assert!(exposed(&call).iter().any(|e| e == "x-request-id"));
    let preflight = browser_grpc_web_preflight(grpc_web_proxy_with(yaml)).await;
    assert_eq!(preflight["access-control-max-age"], "600");
}

#[tokio::test]
async fn cors_can_be_left_to_an_upstream_that_does_it_itself() {
    // `grpc_web: false`: the upstream's own CORS layer answers, and the proxy
    // adds nothing that could clash with it.
    let yaml = "cors:\n  origins: [\"https://app.example\"]\n  grpc_web: false\n";
    let call = browser_grpc_web_call(grpc_web_proxy_with(yaml)).await;
    assert!(call.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn a_grpc_web_preflight_is_answered_by_the_proxy_despite_a_fallback() {
    // The fallback takes what no route matches, but a gRPC-Web preflight
    // belongs to the call it announces, which carries the proxy's policy.
    let pool = pool();
    let upstream = tower::ServiceBuilder::new()
        .layer(tonic_web::GrpcWebLayer::new())
        .service(tonic::service::Routes::new(Edge { pool: pool.clone() }));
    let fallback = axum::Router::new().fallback(|| async { (StatusCode::IM_A_TEAPOT, "fallback") });
    let service = ProxyServer::from_yaml_str(CORS_YAML)
        .unwrap()
        .with_descriptors(pool)
        .service(upstream)
        .unwrap()
        .with_fallback(fallback);
    let preflight = browser_grpc_web_preflight(common::App::new(service)).await;
    assert_eq!(preflight["access-control-allow-origin"], ORIGIN);
}

/// An upstream that speaks gRPC-Web and sets its own CORS policy, allowing
/// only [`UPSTREAM_ORIGIN`].
fn upstream_with_its_own_cors() -> common::App {
    let pool = pool();
    let upstream = tower::ServiceBuilder::new()
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(http::HeaderValue::from_static(UPSTREAM_ORIGIN))
                .allow_methods([http::Method::POST])
                .allow_headers(tower_http::cors::Any),
        )
        .layer(tonic_web::GrpcWebLayer::new())
        .service(tonic::service::Routes::new(Edge { pool: pool.clone() }));
    let service = ProxyServer::from_yaml_str(
        "cors:\n  origins: [\"https://app.example\"]\n  grpc_web: false\n",
    )
    .unwrap()
    .with_descriptors(pool)
    .service(upstream)
    .unwrap();
    common::App::new(service)
}

const UPSTREAM_ORIGIN: &str = "https://upstream-policy.example";

#[tokio::test]
async fn a_grpc_web_preflight_goes_to_an_upstream_that_owns_cors() {
    // `grpc_web: false`: the preflight must get the policy the call will get,
    // the upstream's, not the proxy's.
    let request = http::Request::builder()
        .method("OPTIONS")
        .uri("/test.v1.Edge/Echo")
        .header("origin", UPSTREAM_ORIGIN)
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type,x-grpc-web")
        .body(Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(upstream_with_its_own_cors(), request)
        .await
        .unwrap();
    assert_eq!(
        response.headers()["access-control-allow-origin"],
        UPSTREAM_ORIGIN
    );
}

#[tokio::test]
async fn a_rest_preflight_stays_with_the_proxy_when_the_upstream_owns_grpc_web_cors() {
    // Only gRPC-Web preflights follow their call upstream: a REST route's
    // preflight keeps the proxy's policy.
    let request = http::Request::builder()
        .method("OPTIONS")
        .uri("/v1/echo/rest")
        .header("origin", ORIGIN)
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(upstream_with_its_own_cors(), request)
        .await
        .unwrap();
    assert_eq!(response.headers()["access-control-allow-origin"], ORIGIN);
}

#[tokio::test]
async fn a_listed_origin_gets_its_cors_allowance_on_a_rest_route() {
    // A named origin list with credentials must not use `*` for methods or
    // headers (Fetch §3.2.5): such a policy used to stop the proxy at startup.
    let app = grpc_web_proxy_with(CORS_YAML);
    let request = http::Request::get("/v1/echo/rest")
        .header("origin", ORIGIN)
        .body(Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(app.clone(), request)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["access-control-allow-origin"], ORIGIN);
    // The preflight echoes what the browser asked for.
    let preflight = http::Request::builder()
        .method("OPTIONS")
        .uri("/v1/echo/rest")
        .header("origin", ORIGIN)
        .header("access-control-request-method", "GET")
        .header("access-control-request-headers", "authorization")
        .body(Body::empty())
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, preflight).await.unwrap();
    assert_eq!(response.headers()["access-control-allow-methods"], "GET");
    assert_eq!(
        response.headers()["access-control-allow-headers"],
        "authorization"
    );
}

#[test]
fn an_origin_that_is_not_a_header_value_is_a_config_error() {
    // Dropping it would quietly narrow the policy.
    let server = ProxyServer::from_yaml_str("cors:\n  origins: [\"https://a.example\\n\"]\n")
        .unwrap()
        .with_descriptors(pool());
    let Err(err) = server.service(tonic::service::Routes::default()) else {
        panic!("an invalid origin must be refused");
    };
    assert!(err.to_string().contains("cors.origins"), "{err}");
}

#[test]
fn an_expose_header_that_is_not_a_header_name_is_a_config_error() {
    let server = ProxyServer::from_yaml_str("cors:\n  expose_headers: [\"not a header\"]\n")
        .unwrap()
        .with_descriptors(pool());
    let Err(err) = server.service(tonic::service::Routes::default()) else {
        panic!("an invalid header name must be refused");
    };
    assert!(err.to_string().contains("not a header"), "{err}");
}

/// One gRPC message frame (flag 0, big-endian length) holding `Req{name}`.
fn request_frame(name: &str) -> Vec<u8> {
    let pool = pool();
    let mut req = DynamicMessage::new(pool.get_message_by_name("test.v1.Req").unwrap());
    req.set_field_by_name("name", PbValue::String(name.into()));
    let payload = prost::Message::encode_to_vec(&req);
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// The `name` of the `Seen` message in the first frame of a gRPC-Web body.
fn seen_name(body: &[u8]) -> String {
    assert_eq!(body[0], 0, "a message frame comes first");
    let len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
    let seen = DynamicMessage::decode(
        pool().get_message_by_name("test.v1.Seen").unwrap(),
        &body[5..5 + len],
    )
    .unwrap();
    field(&seen, "name")
}

/// Send a gRPC-Web `Echo` with `body` as `content_type`; returns the response
/// content type and body.
async fn grpc_web_echo(content_type: &str, body: Vec<u8>) -> (String, bytes::Bytes) {
    grpc_web_echo_via(grpc_web_proxy(), content_type, body).await
}

/// [`grpc_web_echo`] through `app`.
async fn grpc_web_echo_via(
    app: common::App,
    content_type: &str,
    body: Vec<u8>,
) -> (String, bytes::Bytes) {
    // A gRPC-Web client names the encoding it reads back in `Accept`.
    let request = http::Request::post("/test.v1.Edge/Echo")
        .header("content-type", content_type)
        .header("accept", content_type)
        .header("x-grpc-web", "1")
        .body(Body::from(body))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    // A trailers-only answer is a failed call, whatever its HTTP status.
    assert!(
        response
            .headers()
            .get("grpc-status")
            .is_none_or(|status| status == "0"),
        "{:?}",
        response.headers()
    );
    let content_type = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (content_type, body)
}

#[tokio::test]
async fn binary_grpc_web_reaches_an_upstream_that_speaks_it() {
    // gRPC-Web passes through unchanged; the upstream's own gRPC-Web layer
    // answers it.
    let (content_type, body) =
        grpc_web_echo("application/grpc-web+proto", request_frame("web")).await;
    assert_eq!(content_type, "application/grpc-web+proto");
    assert_eq!(seen_name(&body), "web");
}

#[tokio::test]
async fn text_grpc_web_reaches_an_upstream_that_speaks_it() {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::STANDARD;
    let (content_type, body) = grpc_web_echo(
        "application/grpc-web-text+proto",
        engine.encode(request_frame("text")).into_bytes(),
    )
    .await;
    assert_eq!(content_type, "application/grpc-web-text+proto");
    // Each frame is its own base64 run, padded at its end (gRPC
    // PROTOCOL-WEB), so the body decodes group by group.
    let decoded: Vec<u8> = body
        .chunks(4)
        .flat_map(|group| engine.decode(group).unwrap())
        .collect();
    assert_eq!(seen_name(&decoded), "text");
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
