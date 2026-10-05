//! The request line an upstream in process receives with a transcoded call:
//! the method and path as the client sent them and the RPC its binding
//! selected, whatever binding, alias or router prefix led there. A remote
//! upstream receives none, since request extensions do not cross the wire.

#[macro_use]
mod common;

use std::convert::Infallible;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::Body;
use http::StatusCode;
use prost_reflect::{DescriptorPool, DynamicMessage};
use structured_proxy::transcode::codec::DynamicCodec;
use structured_proxy::transcode::error::ErrorDetailsPolicy;
use structured_proxy::{ProxyServer, ReceivedRequest};
use tower::ServiceExt;

const ITEMS_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";

message Req {
  string name = 1;
}

service Items {
  rpc Get(Req) returns (Req) {
    option (google.api.http) = {
      get: "/v1/items/{name}"
      additional_bindings { get: "/v1/legacy/items/{name}" }
    };
  }
  rpc Find(Req) returns (Req) {
    option (google.api.http) = {
      custom { kind: "PROPFIND" path: "/v1/items/{name}" }
    };
  }
  rpc Watch(Req) returns (stream Req) {
    option (google.api.http) = { get: "/v1/items/{name}/watch" };
  }
}
"#;

fn pool() -> DescriptorPool {
    common::compile("test/v1/items.proto", ITEMS_PROTO)
}

// --- upstream -------------------------------------------------------------------

/// What the upstream received with each call, in call order.
type Seen = Arc<Mutex<Vec<Option<ReceivedRequest>>>>;

/// Answers every call with its own request message, noting the
/// `ReceivedRequest` it carried.
#[derive(Clone)]
struct Echo {
    seen: Seen,
}

impl Echo {
    fn note<T>(&self, request: &tonic::Request<T>) {
        let received = request.extensions().get::<ReceivedRequest>().cloned();
        self.seen.lock().unwrap().push(received);
    }
}

impl tonic::server::UnaryService<DynamicMessage> for Echo {
    type Response = DynamicMessage;
    type Future = std::future::Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        self.note(&request);
        std::future::ready(Ok(tonic::Response::new(request.into_inner())))
    }
}

type ReqStream = Pin<Box<dyn futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send>>;

impl tonic::server::ServerStreamingService<DynamicMessage> for Echo {
    type Response = DynamicMessage;
    type ResponseStream = ReqStream;
    type Future = std::future::Ready<Result<tonic::Response<ReqStream>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        self.note(&request);
        let stream: ReqStream = Box::pin(futures::stream::iter([Ok(request.into_inner())]));
        std::future::ready(Ok(tonic::Response::new(stream)))
    }
}

/// The `test.v1.Items` service.
#[derive(Clone)]
struct Items {
    pool: DescriptorPool,
    seen: Seen,
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
        let input = self.pool.get_message_by_name("test.v1.Req").unwrap();
        let echo = Echo {
            seen: self.seen.clone(),
        };
        Box::pin(async move {
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(input));
            Ok(match req.uri().path() {
                "/test.v1.Items/Watch" => grpc.server_streaming(echo, req).await,
                _ => grpc.unary(echo, req).await,
            })
        })
    }
}

// --- harness ---------------------------------------------------------------------

/// The `Items` service recording into a fresh `Seen`.
fn items() -> (Items, Seen) {
    let seen = Seen::default();
    let items = Items {
        pool: pool(),
        seen: seen.clone(),
    };
    (items, seen)
}

/// The proxy in front of `Items` running as `upstream` says, and what the
/// upstream receives.
async fn proxy(upstream: common::Upstream) -> (common::App, Seen) {
    let (items, seen) = items();
    let app = common::proxy(upstream, items, pool(), ErrorDetailsPolicy::default()).await;
    (app, seen)
}

/// [`proxy`], with `/public/{path}` aliasing `/v1`.
async fn aliased_proxy(upstream: common::Upstream) -> (common::App, Seen) {
    let (items, seen) = items();
    let app = common::app(upstream, items, |yaml| {
        let yaml = format!("{yaml}aliases:\n  - from: \"/public/{{path}}\"\n    to: \"/v1\"\n");
        ProxyServer::from_yaml_str(&yaml)
            .unwrap()
            .with_descriptors(pool())
    })
    .await;
    (app, seen)
}

fn request(method: &str, uri: &str) -> http::Request<Body> {
    http::Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

/// Send `request` through `app` and expect it to succeed.
async fn send(app: &common::App, request: http::Request<Body>) {
    let (status, body) = common::send(app, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

/// The one call the upstream received: the request line `method` `target`
/// transcoded to `rpc` when it runs in process, nothing when it is remote.
fn assert_received(upstream: common::Upstream, seen: &Seen, method: &str, target: &str, rpc: &str) {
    let mut seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "one call reaches the upstream");
    let received = seen.pop().unwrap();
    if upstream == common::Upstream::Remote {
        assert_eq!(received, None, "request extensions do not cross the wire");
        return;
    }
    let received = received.expect("an upstream in process receives the request line");
    assert_eq!(received.method().as_str(), method);
    assert_eq!(received.path_and_query().as_str(), target);
    assert_eq!(received.rpc(), rpc);
}

// --- cases -------------------------------------------------------------------------

upstream_tests! {
    /// A unary call records the method, the path with its percent-encoding
    /// untouched, the whole query, and the RPC.
    async fn a_unary_call_records_its_request_line() {
        let (app, seen) = proxy(UPSTREAM).await;
        send(&app, request("GET", "/v1/items/a%20b?x=1&x=2")).await;
        assert_received(UPSTREAM, &seen, "GET", "/v1/items/a%20b?x=1&x=2", "/test.v1.Items/Get");
    }

    /// A server-streaming call records its request line too.
    async fn a_streaming_call_records_its_request_line() {
        let (app, seen) = proxy(UPSTREAM).await;
        send(&app, request("GET", "/v1/items/a/watch?from=3")).await;
        assert_received(UPSTREAM, &seen, "GET", "/v1/items/a/watch?from=3", "/test.v1.Items/Watch");
    }

    /// Two bindings of one RPC and an alias of it reach the same RPC; the
    /// recorded path is the one the client used, which the RPC path cannot
    /// tell.
    async fn bindings_and_aliases_of_one_rpc_are_told_apart() {
        for target in ["/v1/items/a", "/v1/legacy/items/a", "/public/items/a"] {
            let (app, seen) = aliased_proxy(UPSTREAM).await;
            send(&app, request("GET", target)).await;
            assert_received(UPSTREAM, &seen, "GET", target, "/test.v1.Items/Get");
        }
    }

    /// A `custom` binding records its own method, on a path a GET binding of
    /// another RPC shares.
    async fn a_custom_binding_records_its_method() {
        let (app, seen) = proxy(UPSTREAM).await;
        send(&app, request("PROPFIND", "/v1/items/a")).await;
        assert_received(UPSTREAM, &seen, "PROPFIND", "/v1/items/a", "/test.v1.Items/Find");
    }

    /// A GET route answering HEAD records HEAD, the method the client sent.
    async fn head_on_a_get_route_records_head() {
        let (app, seen) = proxy(UPSTREAM).await;
        send(&app, request("HEAD", "/v1/items/a")).await;
        assert_received(UPSTREAM, &seen, "HEAD", "/v1/items/a", "/test.v1.Items/Get");
    }

    /// Headers that claim another method or target change nothing recorded.
    async fn client_headers_do_not_change_the_record() {
        let (app, seen) = proxy(UPSTREAM).await;
        let mut spoofed = request("GET", "/v1/items/a?x=1");
        for (name, value) in [
            ("x-original-uri", "/v1/admin/items/a"),
            ("x-forwarded-uri", "/v1/admin/items/a"),
            ("x-forwarded-prefix", "/admin"),
            ("x-original-method", "DELETE"),
            ("x-http-method-override", "DELETE"),
        ] {
            spoofed.headers_mut().insert(name, value.parse().unwrap());
        }
        send(&app, spoofed).await;
        assert_received(UPSTREAM, &seen, "GET", "/v1/items/a?x=1", "/test.v1.Items/Get");
    }

    /// An absolute-form target, the form of every HTTP/2 request, records its
    /// path and query alone, as the same request over HTTP/1.1 does.
    async fn an_absolute_target_records_its_path_and_query() {
        let (app, seen) = proxy(UPSTREAM).await;
        send(&app, request("GET", "https://api.example/v1/items/a?x=1")).await;
        assert_received(UPSTREAM, &seen, "GET", "/v1/items/a?x=1", "/test.v1.Items/Get");
    }

    /// Nested in a router of the embedder's under a prefix, the proxy records
    /// the path with the prefix the outer router strips before routing.
    async fn a_router_prefix_stays_in_the_record() {
        let (app, seen) = proxy(UPSTREAM).await;
        let outer = axum::Router::new().nest_service("/api", app);
        let response = outer
            .oneshot(request("GET", "/api/v1/items/a?x=1"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_received(UPSTREAM, &seen, "GET", "/api/v1/items/a?x=1", "/test.v1.Items/Get");
    }
}
