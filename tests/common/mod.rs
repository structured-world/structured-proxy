//! Harness for proxy tests against a real tonic upstream: compiles a test
//! `.proto` with `google.api.http` routes in memory, serves a gRPC service on a
//! random local port, and drives the proxy router built by `ProxyServer`.

use axum::body::Body;
use http::StatusCode;
use prost_reflect::DescriptorPool;
use structured_proxy::config::ProxyConfig;
use structured_proxy::transcode::error::ErrorDetailsPolicy;
use structured_proxy::ProxyServer;
use tower::ServiceExt;

/// Minimal `google/api/http.proto`: the fields the transcoder reads.
const HTTP_PROTO: &str = r#"
syntax = "proto3";
package google.api;
message HttpRule {
  string selector = 1;
  oneof pattern {
    string get = 2;
    string put = 3;
    string post = 4;
    string delete = 5;
    string patch = 6;
  }
  string body = 7;
  string response_body = 12;
  repeated HttpRule additional_bindings = 11;
}
"#;

const ANNOTATIONS_PROTO: &str = r#"
syntax = "proto3";
package google.api;
import "google/api/http.proto";
import "google/protobuf/descriptor.proto";
extend google.protobuf.MethodOptions {
  HttpRule http = 72295728;
}
"#;

/// Serves the google.api sources and one test file from memory, and
/// descriptor.proto from protox's bundled Google files.
struct TestProtos {
    name: &'static str,
    source: &'static str,
}

impl protox::file::FileResolver for TestProtos {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        let source = match name {
            "google/api/http.proto" => HTTP_PROTO,
            "google/api/annotations.proto" => ANNOTATIONS_PROTO,
            _ if name == self.name => self.source,
            _ => return protox::file::GoogleFileResolver::new().open_file(name),
        };
        protox::file::File::from_source(name, source)
    }
}

/// Compile the test file `name` (which may import
/// `google/api/annotations.proto`) into a descriptor pool.
pub fn compile(name: &'static str, source: &'static str) -> DescriptorPool {
    protox::Compiler::with_file_resolver(TestProtos { name, source })
        .open_file(name)
        .expect("test protos compile")
        .descriptor_pool()
}

/// Serve `service` on a random local port; returns its `http://` URL.
pub async fn serve<S>(service: S) -> String
where
    S: tower::Service<
            http::Request<tonic::body::Body>,
            Response = http::Response<tonic::body::Body>,
            Error = std::convert::Infallible,
        > + tonic::server::NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = futures::stream::unfold(listener, |listener| async move {
        let conn = listener.accept().await.map(|(stream, _)| stream);
        Some((conn, listener))
    });
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming),
    );
    format!("http://{addr}")
}

/// The proxy router for `pool` in front of `upstream`, returning error details
/// as `error_details` decides.
pub fn proxy(
    upstream: &str,
    pool: DescriptorPool,
    error_details: ErrorDetailsPolicy,
) -> axum::Router {
    let config =
        ProxyConfig::from_yaml_str(&format!("upstream:\n  default: \"{upstream}\"\n")).unwrap();
    ProxyServer::from_config(config)
        .with_descriptors(pool)
        .with_error_details(error_details)
        .router()
        .unwrap()
}

/// Send `request` through `app`; returns the status and the body as text.
pub async fn send(app: &axum::Router, request: http::Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}
