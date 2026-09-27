//! Harness for proxy tests against a real tonic upstream: compiles a test
//! `.proto` with `google.api.http` routes in memory, runs the gRPC service
//! either on a random local port (a remote upstream) or in process, and drives
//! the proxy service built by `ProxyServer`.

use std::convert::Infallible;

use axum::body::Body;
use http::StatusCode;
use prost_reflect::DescriptorPool;
use structured_proxy::transcode::error::ErrorDetailsPolicy;
use structured_proxy::ProxyServer;
use tower::util::BoxCloneSyncService;
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
    CustomHttpPattern custom = 8;
  }
  string body = 7;
  string response_body = 12;
  repeated HttpRule additional_bindings = 11;
}
message CustomHttpPattern {
  string kind = 1;
  string path = 2;
}
"#;

/// `google/api/httpbody.proto`.
const HTTPBODY_PROTO: &str = r#"
syntax = "proto3";
package google.api;
import "google/protobuf/any.proto";
message HttpBody {
  string content_type = 1;
  bytes data = 2;
  repeated google.protobuf.Any extensions = 3;
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

/// Serves the google.api sources and one test file from memory, and the
/// `google/protobuf` files from protox's bundled Google files.
struct TestProtos {
    name: &'static str,
    source: &'static str,
}

impl protox::file::FileResolver for TestProtos {
    fn open_file(&self, name: &str) -> Result<protox::file::File, protox::Error> {
        let source = match name {
            "google/api/http.proto" => HTTP_PROTO,
            "google/api/annotations.proto" => ANNOTATIONS_PROTO,
            "google/api/httpbody.proto" => HTTPBODY_PROTO,
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

/// The bounds of a tonic service a test runs as its upstream.
pub trait TestService:
    tower::Service<
        http::Request<tonic::body::Body>,
        Response = http::Response<tonic::body::Body>,
        Error = Infallible,
        Future: Send + 'static,
    > + tonic::server::NamedService
    + Clone
    + Send
    + Sync
    + 'static
{
}

impl<S> TestService for S where
    S: tower::Service<
            http::Request<tonic::body::Body>,
            Response = http::Response<tonic::body::Body>,
            Error = Infallible,
            Future: Send + 'static,
        > + tonic::server::NamedService
        + Clone
        + Send
        + Sync
        + 'static
{
}

/// Serve `service` on a random local port; returns its `http://` URL.
pub async fn serve<S: TestService>(service: S) -> String {
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

/// Where the upstream of a proxy under test runs.
#[derive(Clone, Copy, Debug)]
pub enum Upstream {
    /// A tonic server on a local port, reached over HTTP/2.
    Remote,
    /// The same service called in process, with no socket in between.
    InProcess,
}

/// A proxy under test, whatever its upstream.
pub type App = BoxCloneSyncService<http::Request<Body>, http::Response<Body>, Infallible>;

/// The proxy `configure` builds, in front of `service` running as `upstream`
/// says. `configure` gets the YAML naming the upstream address: an
/// `upstream:` block for a remote upstream, nothing for one in process.
pub async fn app<S: TestService>(
    upstream: Upstream,
    service: S,
    configure: impl FnOnce(&str) -> ProxyServer,
) -> App {
    match upstream {
        Upstream::Remote => {
            let url = serve(service).await;
            let server = configure(&format!("upstream:\n  default: \"{url}\"\n"));
            App::new(server.service(server.upstream().unwrap()).unwrap())
        }
        Upstream::InProcess => {
            let server = configure("");
            App::new(
                server
                    .service(tonic::service::Routes::new(service))
                    .unwrap(),
            )
        }
    }
}

/// The proxy for `pool` in front of `service`, returning error details as
/// `error_details` decides.
pub async fn proxy<S: TestService>(
    upstream: Upstream,
    service: S,
    pool: DescriptorPool,
    error_details: ErrorDetailsPolicy,
) -> App {
    app(upstream, service, |yaml| {
        ProxyServer::from_yaml_str(yaml)
            .unwrap()
            .with_descriptors(pool)
            .with_error_details(error_details)
    })
    .await
}

/// Send `request` through `app`; returns the status and the body as text.
pub async fn send(app: &App, request: http::Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(request).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// Declare each test twice, in a `remote` and an `in_process` module, so every
/// case runs against both kinds of upstream. A body names the one it runs
/// against as `UPSTREAM`.
macro_rules! upstream_tests {
    ($($(#[$meta:meta])* async fn $name:ident() $body:block)*) => {
        mod remote {
            use super::*;
            const UPSTREAM: common::Upstream = common::Upstream::Remote;
            $($(#[$meta])* #[tokio::test] async fn $name() $body)*
        }
        mod in_process {
            use super::*;
            const UPSTREAM: common::Upstream = common::Upstream::InProcess;
            $($(#[$meta])* #[tokio::test] async fn $name() $body)*
        }
    };
}
