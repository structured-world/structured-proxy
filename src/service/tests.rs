use super::*;

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::routing::get;
use tower::ServiceExt;

/// What a [`Recorder`] upstream saw of the last request it was called with.
#[derive(Debug, Default)]
struct Seen {
    path: Option<String>,
    body: Option<Bytes>,
    remote: Option<SocketAddr>,
    local: Option<SocketAddr>,
}

/// An upstream that records its request and answers `200` with an
/// `x-upstream` header, or fails to become ready.
#[derive(Clone, Default)]
struct Recorder {
    seen: Arc<Mutex<Seen>>,
    unready: bool,
}

impl Service<http::Request<tonic::body::Body>> for Recorder {
    type Response = http::Response<tonic::body::Body>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        if self.unready {
            return Poll::Ready(Err(Box::new(tonic::Status::unavailable("upstream down"))));
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
        let seen = self.seen.clone();
        Box::pin(async move {
            let (parts, body) = request.into_parts();
            let body = http_body_util::BodyExt::collect(body)
                .await
                .map_err(Into::<BoxError>::into)?
                .to_bytes();
            let connection = parts.extensions.get::<TcpConnectInfo>();
            *seen.lock().unwrap() = Seen {
                path: Some(parts.uri.path().to_owned()),
                body: Some(body),
                remote: connection.and_then(|c| c.remote_addr),
                local: connection.and_then(|c| c.local_addr),
            };
            Ok(http::Response::builder()
                .header("x-upstream", "1")
                .body(tonic::body::Body::empty())
                .unwrap())
        })
    }
}

/// A proxy with one HTTP route, `GET /route`, in front of `upstream`.
fn service(upstream: Recorder) -> ProxyService<Recorder> {
    let routes = axum::Router::new().route("/route", get(|| async { "route" }));
    ProxyService::new(upstream, routes)
}

fn grpc_request(path: &str) -> http::Request<Body> {
    http::Request::post(path)
        .header("content-type", "application/grpc")
        .body(Body::from("frame"))
        .unwrap()
}

async fn body_text(response: http::Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn a_grpc_request_reaches_the_upstream_unchanged() {
    let upstream = Recorder::default();
    let response = service(upstream.clone())
        .oneshot(grpc_request("/pkg.Svc/Method"))
        .await
        .unwrap();
    assert_eq!(response.headers()["x-upstream"], "1");
    let seen = upstream.seen.lock().unwrap();
    assert_eq!(seen.path.as_deref(), Some("/pkg.Svc/Method"));
    assert_eq!(seen.body.as_deref(), Some(&b"frame"[..]));
}

#[tokio::test]
async fn a_grpc_request_on_a_route_path_still_goes_to_the_upstream() {
    // The content type decides first, so a REST route (even a catch-all) can
    // never take a native gRPC call.
    let upstream = Recorder::default();
    let response = service(upstream.clone())
        .oneshot(grpc_request("/route"))
        .await
        .unwrap();
    assert_eq!(response.headers()["x-upstream"], "1");
    assert_eq!(
        upstream.seen.lock().unwrap().path.as_deref(),
        Some("/route")
    );
}

#[tokio::test]
async fn an_http_request_reaches_the_routes_not_the_upstream() {
    let upstream = Recorder::default();
    let response = service(upstream.clone())
        .oneshot(http::Request::get("/route").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(body_text(response).await, "route");
    assert!(upstream.seen.lock().unwrap().path.is_none());
}

#[tokio::test]
async fn an_unmatched_request_is_404_without_a_fallback() {
    let upstream = Recorder::default();
    let response = service(upstream.clone())
        .oneshot(
            http::Request::get("/elsewhere")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::NOT_FOUND);
    assert!(upstream.seen.lock().unwrap().path.is_none());
}

#[tokio::test]
async fn an_unmatched_request_goes_to_the_fallback() {
    let fallback = axum::Router::new().route("/elsewhere", get(|| async { "fallback" }));
    let response = service(Recorder::default())
        .with_fallback(fallback)
        .oneshot(
            http::Request::get("/elsewhere")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(body_text(response).await, "fallback");
}

#[tokio::test]
async fn a_route_path_with_another_method_stays_with_the_proxy() {
    // The path is the proxy's: a method it does not bind is its 405, not a
    // request for the fallback.
    let fallback = axum::Router::new().route("/route", axum::routing::post(|| async { "x" }));
    let response = service(Recorder::default())
        .with_fallback(fallback)
        .oneshot(http::Request::post("/route").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn an_upstream_that_cannot_take_the_call_answers_a_grpc_status() {
    // The gRPC client gets UNAVAILABLE in a trailers-only response, not a
    // dropped connection.
    let upstream = Recorder {
        unready: true,
        ..Recorder::default()
    };
    let response = service(upstream)
        .oneshot(grpc_request("/pkg.Svc/Method"))
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.headers()["grpc-status"], "14");
    assert_eq!(response.headers()["content-type"], "application/grpc");
}

fn connection() -> Connection {
    Connection {
        local: Some("10.0.0.1:8080".parse().unwrap()),
        remote: "192.0.2.7:40000".parse().unwrap(),
    }
}

#[tokio::test]
async fn a_served_grpc_request_carries_its_connection_to_the_upstream() {
    // A tonic handler behind the proxy reads the client's address with
    // `Request::remote_addr`, as it would behind tonic's own server.
    let upstream = Recorder::default();
    let proxy = service(upstream.clone()).on_connection(connection());
    proxy
        .oneshot(grpc_request("/pkg.Svc/Method"))
        .await
        .unwrap();
    let seen = upstream.seen.lock().unwrap();
    assert_eq!(seen.remote, Some("192.0.2.7:40000".parse().unwrap()));
    assert_eq!(seen.local, Some("10.0.0.1:8080".parse().unwrap()));
}

#[tokio::test]
async fn a_served_http_request_carries_its_peer_for_the_middleware() {
    let routes = axum::Router::new().route(
        "/peer",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
    );
    let proxy = ProxyService::new(Recorder::default(), routes).on_connection(connection());
    let response = proxy
        .oneshot(http::Request::get("/peer").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(body_text(response).await, "192.0.2.7:40000");
}

#[tokio::test]
async fn a_peer_set_by_an_outer_server_is_kept() {
    // An embedder's own server may have set the peer already (behind its own
    // proxy protocol handling, say); the proxy does not overwrite it.
    let routes = axum::Router::new().route(
        "/peer",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() }),
    );
    let proxy = ProxyService::new(Recorder::default(), routes).on_connection(connection());
    let mut request = http::Request::get("/peer").body(Body::empty()).unwrap();
    let outer: SocketAddr = "198.51.100.1:1".parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(outer));
    let response = proxy.oneshot(request).await.unwrap();
    assert_eq!(body_text(response).await, "198.51.100.1:1");
}
