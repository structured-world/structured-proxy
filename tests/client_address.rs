//! The client address over real sockets: what a recording upstream receives
//! through every transport (transcoded unary and streaming calls, native gRPC,
//! gRPC-Web passed through and translated), for an upstream remote and in
//! process, and what the rate limits key by, from one resolution.

#[macro_use]
mod common;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use prost_reflect::{DescriptorPool, DynamicMessage, Value as PbValue};
use structured_proxy::client_address::Resolution;
use structured_proxy::transcode::codec::DynamicCodec;
use structured_proxy::{ClientAddress, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ADDR_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";

message Req {
  string name = 1;
}
// What the upstream received of the client's address.
message Seen {
  string xff = 1;
  string real_ip = 2;
  string forwarded = 3;
  string client = 4;
  string dpop = 5;
  string cf_ip = 6;
  string audit = 7;
}

service Addr {
  rpc Echo(Req) returns (Seen) {
    option (google.api.http) = { get: "/v1/addr" };
  }
  rpc Watch(Req) returns (stream Seen) {
    option (google.api.http) = { get: "/v1/addr/stream" };
  }
}
"#;

fn pool() -> DescriptorPool {
    common::compile("test/v1/addr.proto", ADDR_PROTO)
}

// --- upstream -------------------------------------------------------------------

/// What `request` carries of the client's address.
fn seen<T>(pool: &DescriptorPool, request: &tonic::Request<T>) -> DynamicMessage {
    let joined = |key: &str| {
        request
            .metadata()
            .get_all(key)
            .iter()
            .map(|v| String::from_utf8_lossy(v.as_encoded_bytes()).into_owned())
            .collect::<Vec<_>>()
            .join("|")
    };
    // In process only: a remote upstream never sees request extensions.
    let client = match request.extensions().get::<ClientAddress>() {
        None => String::new(),
        Some(client) => match client.resolution() {
            Resolution::Peer(ip) | Resolution::Forwarded(ip) => ip.to_string(),
            Resolution::Invalid(_) => "invalid".into(),
            Resolution::Unavailable => "unavailable".into(),
            _ => "unknown resolution".into(),
        },
    };
    let mut seen = DynamicMessage::new(pool.get_message_by_name("test.v1.Seen").unwrap());
    seen.set_field_by_name("xff", PbValue::String(joined("x-forwarded-for")));
    seen.set_field_by_name("real_ip", PbValue::String(joined("x-real-ip")));
    seen.set_field_by_name("forwarded", PbValue::String(joined("forwarded")));
    seen.set_field_by_name("client", PbValue::String(client));
    seen.set_field_by_name("cf_ip", PbValue::String(joined("cf-connecting-ip")));
    seen.set_field_by_name("audit", PbValue::String(joined("x-original-forwarded-for")));
    seen.set_field_by_name("dpop", PbValue::String(joined("dpop")));
    seen
}

#[derive(Clone)]
struct Echo {
    pool: DescriptorPool,
}

impl tonic::server::UnaryService<DynamicMessage> for Echo {
    type Response = DynamicMessage;
    type Future = std::future::Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        std::future::ready(Ok(tonic::Response::new(seen(&self.pool, &request))))
    }
}

type SeenStream =
    Pin<Box<dyn futures::Stream<Item = Result<DynamicMessage, tonic::Status>> + Send>>;

impl tonic::server::ServerStreamingService<DynamicMessage> for Echo {
    type Response = DynamicMessage;
    type ResponseStream = SeenStream;
    type Future = std::future::Ready<Result<tonic::Response<SeenStream>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let message = seen(&self.pool, &request);
        let stream: SeenStream = Box::pin(futures::stream::iter([Ok(message)]));
        std::future::ready(Ok(tonic::Response::new(stream)))
    }
}

/// The `test.v1.Addr` service, recording what reaches it.
#[derive(Clone)]
struct Recorder {
    pool: DescriptorPool,
}

impl tonic::server::NamedService for Recorder {
    const NAME: &'static str = "test.v1.Addr";
}

impl tower::Service<http::Request<tonic::body::Body>> for Recorder {
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
            let input = pool.get_message_by_name("test.v1.Req").unwrap();
            let mut grpc = tonic::server::Grpc::new(DynamicCodec::new(input));
            let echo = Echo { pool };
            Ok(match req.uri().path() {
                "/test.v1.Addr/Watch" => grpc.server_streaming(echo, req).await,
                _ => grpc.unary(echo, req).await,
            })
        })
    }
}

// --- harness ---------------------------------------------------------------------

/// Serve the recorder, able to answer gRPC-Web itself, on a local port.
async fn serve_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let incoming = futures::stream::unfold(listener, |listener| async move {
        let conn = listener.accept().await.map(|(stream, _)| stream);
        Some((conn, listener))
    });
    tokio::spawn(
        tonic::transport::Server::builder()
            .accept_http1(true)
            .layer(tonic_web::GrpcWebLayer::new())
            .add_service(Recorder { pool: pool() })
            .serve_with_incoming(incoming),
    );
    format!("http://{addr}")
}

/// The recorder in process, answering gRPC-Web itself as an embedder's
/// services do.
fn in_process_upstream() -> impl structured_proxy::upstream::Upstream {
    tower::ServiceBuilder::new()
        .layer(tonic_web::GrpcWebLayer::new())
        .service(tonic::service::Routes::new(Recorder { pool: pool() }))
}

/// The proxy configured by `yaml` in front of the recorder in process.
fn in_process_proxy(
    yaml: &str,
    configure: impl FnOnce(ProxyServer) -> ProxyServer,
) -> structured_proxy::ProxyService<impl structured_proxy::upstream::Upstream> {
    configure(
        ProxyServer::from_yaml_str(yaml)
            .unwrap()
            .with_descriptors(pool()),
    )
    .service(in_process_upstream())
    .unwrap()
}

/// Serve `service` on a local port; returns its address.
async fn spawn_serve<U: structured_proxy::upstream::Upstream>(
    service: structured_proxy::ProxyService<U>,
) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(structured_proxy::serve(listener, service));
    addr
}

/// The proxy configured by `yaml` in front of the recorder, as `upstream`
/// says, served on a local port; returns its address.
async fn listen(upstream: common::Upstream, yaml: &str) -> SocketAddr {
    match upstream {
        common::Upstream::Remote => {
            let url = serve_upstream().await;
            let server =
                ProxyServer::from_yaml_str(&format!("upstream:\n  default: \"{url}\"\n{yaml}"))
                    .unwrap()
                    .with_descriptors(pool());
            spawn_serve(server.service(server.upstream().unwrap()).unwrap()).await
        }
        common::Upstream::InProcess => spawn_serve(in_process_proxy(yaml, |s| s)).await,
    }
}

/// How a call reaches the upstream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    /// A transcoded unary REST call over HTTP/1.1.
    Unary,
    /// A transcoded server-streaming REST call (NDJSON) over HTTP/1.1.
    Stream,
    /// Native gRPC over HTTP/2.
    Grpc,
    /// Binary gRPC-Web over HTTP/1.1, passed through or translated.
    GrpcWeb,
}

const TRANSPORTS: [Transport; 4] = [
    Transport::Unary,
    Transport::Stream,
    Transport::Grpc,
    Transport::GrpcWeb,
];

/// What the upstream received, or how the proxy refused the call.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Seen {
        xff: String,
        real_ip: String,
        forwarded: String,
        client: String,
        dpop: String,
        cf_ip: String,
        audit: String,
    },
    /// The HTTP status of a REST call, or the gRPC code of a gRPC one.
    Refused(String),
}

impl Outcome {
    fn from_message(seen: &DynamicMessage) -> Self {
        let field = |name: &str| match seen.get_field_by_name(name).as_deref() {
            Some(PbValue::String(s)) => s.clone(),
            _ => String::new(),
        };
        Self::Seen {
            xff: field("xff"),
            real_ip: field("real_ip"),
            forwarded: field("forwarded"),
            client: field("client"),
            dpop: field("dpop"),
            cf_ip: field("cf_ip"),
            audit: field("audit"),
        }
    }

    fn from_json(json: &serde_json::Value) -> Self {
        let field = |name: &str| json[name].as_str().unwrap_or_default().to_owned();
        Self::Seen {
            xff: field("xff"),
            real_ip: field("realIp"),
            forwarded: field("forwarded"),
            client: field("client"),
            dpop: field("dpop"),
            cf_ip: field("cfIp"),
            audit: field("audit"),
        }
    }

    /// The resolved address, as the upstream saw it under the default
    /// forwarding: `X-Real-IP` carries it, it is the first element of the
    /// verified `X-Forwarded-For`, and in process the `ClientAddress` agrees.
    fn address(&self, upstream: common::Upstream) -> &str {
        let Self::Seen {
            xff,
            real_ip,
            forwarded,
            client,
            ..
        } = self
        else {
            panic!("the call was refused: {self:?}");
        };
        assert_eq!(
            xff.split(", ").next().unwrap_or_default(),
            real_ip,
            "{self:?}"
        );
        assert_eq!(forwarded, "", "{self:?}");
        match upstream {
            common::Upstream::Remote => assert_eq!(client, "", "{self:?}"),
            common::Upstream::InProcess => {
                let expected = if real_ip.is_empty() {
                    "invalid"
                } else {
                    real_ip.as_str()
                };
                if client != "unavailable" {
                    assert_eq!(client, expected, "{self:?}");
                }
            }
        }
        real_ip
    }

    /// `X-Forwarded-For` as the upstream saw it.
    fn xff(&self) -> &str {
        match self {
            Self::Seen { xff, .. } => xff,
            Self::Refused(_) => panic!("the call was refused: {self:?}"),
        }
    }

    fn client(&self) -> &str {
        match self {
            Self::Seen { client, .. } => client,
            Self::Refused(_) => panic!("the call was refused: {self:?}"),
        }
    }
}

/// How `transport` reports a refusal with `code`.
fn refusal(transport: Transport, code: tonic::Code) -> Outcome {
    Outcome::Refused(match transport {
        Transport::Unary | Transport::Stream => match code {
            tonic::Code::InvalidArgument => "400".into(),
            tonic::Code::Internal => "500".into(),
            tonic::Code::ResourceExhausted => "429".into(),
            other => panic!("no HTTP status in these tests for {other:?}"),
        },
        Transport::Grpc | Transport::GrpcWeb => (code as i32).to_string(),
    })
}

/// Call the upstream through the proxy at `addr` over `transport`, with
/// `headers` (repeated names as repeated fields, in order).
async fn call(addr: SocketAddr, transport: Transport, headers: &[(&str, &str)]) -> Outcome {
    match transport {
        Transport::Unary | Transport::Stream => {
            let path = if transport == Transport::Unary {
                "/v1/addr"
            } else {
                "/v1/addr/stream"
            };
            let (status, _, body) = http1(addr, "GET", path, headers, &[]).await;
            if status != 200 {
                return Outcome::Refused(status.to_string());
            }
            let body = String::from_utf8(body).unwrap();
            // An NDJSON stream's first line is its first message.
            let line = body.lines().next().unwrap();
            Outcome::from_json(&serde_json::from_str(line).unwrap())
        }
        Transport::Grpc => {
            let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
                .unwrap()
                .connect()
                .await
                .unwrap();
            let mut grpc = tonic::client::Grpc::new(channel);
            grpc.ready().await.unwrap();
            let mut request = tonic::Request::new(req_message());
            for (name, value) in headers {
                let key = tonic::metadata::AsciiMetadataKey::from_bytes(name.as_bytes()).unwrap();
                request.metadata_mut().append(key, value.parse().unwrap());
            }
            let codec = DynamicCodec::new(pool().get_message_by_name("test.v1.Seen").unwrap());
            match grpc
                .unary(
                    request,
                    http::uri::PathAndQuery::from_static("/test.v1.Addr/Echo"),
                    codec,
                )
                .await
            {
                Ok(response) => Outcome::from_message(response.get_ref()),
                Err(status) => Outcome::Refused((status.code() as i32).to_string()),
            }
        }
        Transport::GrpcWeb => {
            let mut all = vec![
                ("content-type", "application/grpc-web+proto"),
                ("x-grpc-web", "1"),
            ];
            all.extend_from_slice(headers);
            let (_, response_headers, body) =
                http1(addr, "POST", "/test.v1.Addr/Echo", &all, &request_frame()).await;
            if let Some((_, code)) = response_headers.iter().find(|(n, _)| n == "grpc-status") {
                if code != "0" {
                    return Outcome::Refused(code.clone());
                }
            }
            if body[0] & 0x80 != 0 {
                // A trailers frame first: the call failed.
                let trailers = String::from_utf8_lossy(&body[5..]).into_owned();
                let code = trailers
                    .lines()
                    .find_map(|line| line.strip_prefix("grpc-status:"))
                    .unwrap()
                    .trim()
                    .to_owned();
                return Outcome::Refused(code);
            }
            let len = u32::from_be_bytes(body[1..5].try_into().unwrap()) as usize;
            let seen = DynamicMessage::decode(
                pool().get_message_by_name("test.v1.Seen").unwrap(),
                &body[5..5 + len],
            )
            .unwrap();
            Outcome::from_message(&seen)
        }
    }
}

fn req_message() -> DynamicMessage {
    DynamicMessage::new(pool().get_message_by_name("test.v1.Req").unwrap())
}

/// One gRPC message frame holding an empty `Req`.
fn request_frame() -> Vec<u8> {
    let payload = prost::Message::encode_to_vec(&req_message());
    let mut frame = vec![0];
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

/// An HTTP/1.1 request over a fresh connection; returns the status, the
/// response headers (names lowercase) and the decoded body.
async fn http1(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    // Head and body in one write: a guard that refuses before reading the
    // body closes the connection, and a body still unread in the socket then
    // turns the close into a reset that loses the refusal.
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    stream.write_all(&bytes).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response head");
    let head = String::from_utf8(response[..split].to_vec()).unwrap();
    let mut lines = head.lines();
    let status = lines.next().unwrap()[9..12].parse().unwrap();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let raw = &response[split + 4..];
    let chunked = headers
        .iter()
        .any(|(n, v)| n == "transfer-encoding" && v.eq_ignore_ascii_case("chunked"));
    let body = if chunked { dechunk(raw) } else { raw.to_vec() };
    (status, headers, body)
}

/// The data of a chunked body (RFC 9112 §7.1).
fn dechunk(mut raw: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    loop {
        let end = raw.windows(2).position(|w| w == b"\r\n").unwrap();
        let size_line = std::str::from_utf8(&raw[..end]).unwrap();
        let size = usize::from_str_radix(size_line.split(';').next().unwrap().trim(), 16).unwrap();
        raw = &raw[end + 2..];
        if size == 0 {
            return body;
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

const TRUST_LOOPBACK: &str = "client_address:\n  trusted_proxies: [\"127.0.0.1\"]\n";
const TRUST_LOOPBACK_AND_LB: &str =
    "client_address:\n  trusted_proxies: [\"127.0.0.1\", \"10.0.0.0/8\"]\n";
const TRUST_LOOPBACK_REQUIRED: &str =
    "client_address:\n  trusted_proxies: [\"127.0.0.1\", \"10.0.0.0/8\"]\n  required: true\n";
/// A rate limit no test reaches, so the limiter runs on every call.
const ROOMY_SHIELD: &str = "shield:\n  enabled: true\n  scope: { traffic: [all] }\n  profiles:\n    roomy: { rate: \"10000/min\", burst: 10000 }\n  rules:\n    - pattern: \"/**\"\n      key: { type: ip }\n      profile: roomy\n";

/// What `transport` delivers through a proxy at `addr` for `xff` lines.
async fn address_via(
    addr: SocketAddr,
    upstream: common::Upstream,
    transport: Transport,
    xff: &[&str],
) -> String {
    let headers: Vec<(&str, &str)> = xff.iter().map(|v| ("x-forwarded-for", *v)).collect();
    call(addr, transport, &headers)
        .await
        .address(upstream)
        .to_owned()
}

upstream_tests! {
async fn an_edge_proxy_replaces_whatever_the_client_forwards() {
    // No trusted proxy: the peer is the client, and every address the client
    // asserted is gone, whichever header it used and however a guard is set.
    for yaml in ["", ROOMY_SHIELD] {
        let addr = listen(UPSTREAM, yaml).await;
        let forged = [
            ("x-forwarded-for", "198.51.100.1"),
            ("x-forwarded-for", "198.51.100.4, 198.51.100.5"),
            ("x-real-ip", "198.51.100.2"),
            ("forwarded", "for=198.51.100.3"),
        ];
        for transport in TRANSPORTS {
            let outcome = call(addr, transport, &forged).await;
            assert_eq!(outcome.address(UPSTREAM), "127.0.0.1", "{transport:?} {yaml:?}");
        }
    }
}

async fn a_trusted_proxy_forwards_the_client() {
    for shield in ["", ROOMY_SHIELD] {
        let addr = listen(UPSTREAM, &format!("{TRUST_LOOPBACK}{shield}")).await;
        for transport in TRANSPORTS {
            assert_eq!(
                address_via(addr, UPSTREAM, transport, &["203.0.113.7"]).await,
                "203.0.113.7",
                "{transport:?}"
            );
            // A trusted peer that forwards nothing is the client itself.
            assert_eq!(
                address_via(addr, UPSTREAM, transport, &[]).await,
                "127.0.0.1",
                "{transport:?}"
            );
        }
    }
}

async fn the_chain_is_walked_right_to_left_through_trusted_proxies() {
    let addr = listen(UPSTREAM, TRUST_LOOPBACK_AND_LB).await;
    for (xff, client) in [
        // Two trusted proxies.
        (&["203.0.113.7, 10.0.0.2"][..], "203.0.113.7"),
        // A forged prefix is never read.
        (&["198.51.100.1, 203.0.113.7"][..], "203.0.113.7"),
        // An untrusted intermediate stops the walk.
        (&["203.0.113.7, 198.51.100.9, 10.0.0.2"][..], "198.51.100.9"),
        // Repeated fields are one list, in order.
        (&["198.51.100.1, 203.0.113.7", "10.0.0.2"][..], "203.0.113.7"),
        // IPv6, bracketed with a port.
        (&["[2001:db8::7]:443, 10.0.0.2"][..], "2001:db8::7"),
        // IPv4 with a port.
        (&["203.0.113.7:51234"][..], "203.0.113.7"),
        // Malformed data left of the client is not read.
        (&["garbage, 203.0.113.7"][..], "203.0.113.7"),
        // Every hop trusted: the leftmost.
        (&["10.0.0.5, 10.0.0.2"][..], "10.0.0.5"),
    ] {
        for transport in TRANSPORTS {
            assert_eq!(
                address_via(addr, UPSTREAM, transport, xff).await,
                client,
                "{transport:?} {xff:?}"
            );
        }
    }
}

async fn a_broken_trusted_report_resolves_no_address() {
    // The report of a trusted proxy that cannot be read leaves the upstream
    // with no address at all, never the proxy's own.
    let addr = listen(UPSTREAM, TRUST_LOOPBACK_AND_LB).await;
    let too_many = vec!["10.0.0.2"; 40].join(", ");
    let broken = format!("203.0.113.7, {too_many}");
    for xff in ["garbage", "203.0.113.7, unknown", broken.as_str()] {
        for transport in TRANSPORTS {
            let outcome = call(addr, transport, &[("x-forwarded-for", xff)]).await;
            assert_eq!(outcome.address(UPSTREAM), "", "{transport:?} {xff:.30}");
            if UPSTREAM == common::Upstream::InProcess {
                assert_eq!(outcome.client(), "invalid");
            }
        }
    }
}

async fn a_required_address_that_does_not_resolve_is_refused() {
    let addr = listen(UPSTREAM, TRUST_LOOPBACK_REQUIRED).await;
    for transport in TRANSPORTS {
        assert_eq!(
            call(addr, transport, &[("x-forwarded-for", "garbage")]).await,
            refusal(transport, tonic::Code::InvalidArgument),
            "{transport:?}"
        );
        // The data needed to name the client cannot be bypassed through
        // another header either.
        assert_eq!(
            call(
                addr,
                transport,
                &[("x-forwarded-for", "garbage"), ("x-real-ip", "203.0.113.7")]
            )
            .await,
            refusal(transport, tonic::Code::InvalidArgument),
            "{transport:?}"
        );
        // A resolved one passes.
        assert_eq!(
            address_via(addr, UPSTREAM, transport, &["203.0.113.7"]).await,
            "203.0.113.7"
        );
    }
}

async fn a_listed_forwarding_header_does_not_restore_the_raw_one() {
    let yaml = "forwarded_headers: [\"x-forwarded-for\", \"x-real-ip\", \"forwarded\", \"dpop\"]\n";
    let addr = listen(UPSTREAM, yaml).await;
    let headers = [
        ("x-forwarded-for", "198.51.100.1"),
        ("x-real-ip", "198.51.100.2"),
        ("forwarded", "for=198.51.100.3"),
        ("dpop", "proof-a"),
        ("dpop", "proof-b"),
    ];
    for transport in TRANSPORTS {
        let outcome = call(addr, transport, &headers).await;
        assert_eq!(outcome.address(UPSTREAM), "127.0.0.1", "{transport:?}");
        // Unrelated repeated headers keep every value (RFC 9449 §4.3).
        let Outcome::Seen { dpop, .. } = &outcome else {
            unreachable!()
        };
        assert_eq!(dpop, "proof-a|proof-b", "{transport:?}");
    }
}

async fn the_rate_limits_key_by_the_address_the_upstream_receives() {
    // One budget per resolved client: the limiter and the upstream agree on
    // who the client is, through every transport.
    let shield = "shield:\n  enabled: true\n  scope: { traffic: [all] }\n  profiles:\n    one: { rate: \"1/min\", burst: 1 }\n  rules:\n    - pattern: \"/**\"\n      key: { type: ip }\n      profile: one\n";
    for transport in TRANSPORTS {
        let addr = listen(UPSTREAM, &format!("{TRUST_LOOPBACK}{shield}")).await;
        assert_eq!(
            address_via(addr, UPSTREAM, transport, &["203.0.113.7"]).await,
            "203.0.113.7"
        );
        // The same client, whatever it prepends.
        assert_eq!(
            call(addr, transport, &[("x-forwarded-for", "198.51.100.1, 203.0.113.7")]).await,
            refusal(transport, tonic::Code::ResourceExhausted),
            "{transport:?}"
        );
        // Another client has its own budget.
        assert_eq!(
            address_via(addr, UPSTREAM, transport, &["203.0.113.8"]).await,
            "203.0.113.8"
        );
    }
}
}

/// The forwarding policy, over every transport and both kinds of upstream.
mod forwarding {
    use super::*;

    upstream_tests! {
    async fn each_forwarding_mode_reaches_the_upstream_through_every_transport() {
        // The client wrote a forged first element; the balancer at 10.0.0.2
        // appended the client, and this proxy's peer is the loopback client of
        // the test, trusted as the last balancer.
        let sent = [
            ("x-forwarded-for", "198.51.100.1, 203.0.113.7"),
            ("x-forwarded-for", "10.0.0.2"),
            ("x-real-ip", "198.51.100.2"),
            ("forwarded", "for=198.51.100.3"),
            ("cf-connecting-ip", "198.51.100.4"),
            ("x-original-forwarded-for", "198.51.100.5"),
        ];
        let arrived = "198.51.100.1, 203.0.113.7|10.0.0.2";
        for (mode, xff, real_ip, forwarded) in [
            ("verified", "203.0.113.7, 10.0.0.2, 127.0.0.1", "", ""),
            ("resolved", "203.0.113.7", "", ""),
            ("append", "198.51.100.1, 203.0.113.7, 10.0.0.2, 127.0.0.1", "", ""),
            ("preserve", arrived, "198.51.100.2", "for=198.51.100.3"),
            ("remove", "", "", ""),
        ] {
            let yaml = format!(
                "{TRUST_LOOPBACK_AND_LB}  forward:\n    x_forwarded_for: {mode}\n    client_header: cf-connecting-ip\n    audit_header: x-original-forwarded-for\n"
            );
            let addr = listen(UPSTREAM, &yaml).await;
            for transport in TRANSPORTS {
                let outcome = call(addr, transport, &sent).await;
                let Outcome::Seen { xff: seen_xff, real_ip: seen_real_ip, forwarded: seen_forwarded, cf_ip, audit, .. } = &outcome else {
                    panic!("{mode} {transport:?}: {outcome:?}");
                };
                assert_eq!(seen_xff, xff, "{mode} {transport:?}");
                assert_eq!(seen_real_ip, real_ip, "{mode} {transport:?}");
                assert_eq!(seen_forwarded, forwarded, "{mode} {transport:?}");
                // Whatever the mode: the resolved address under the configured
                // name, and the list as it arrived under the audit name.
                assert_eq!(cf_ip, "203.0.113.7", "{mode} {transport:?}");
                assert_eq!(audit, arrived, "{mode} {transport:?}");
            }
        }
    }

    async fn the_audit_header_is_off_by_default() {
        let addr = listen(UPSTREAM, TRUST_LOOPBACK).await;
        for transport in TRANSPORTS {
            let outcome = call(
                addr,
                transport,
                &[
                    ("x-forwarded-for", "203.0.113.7"),
                    ("x-original-forwarded-for", "198.51.100.5"),
                ],
            )
            .await;
            let Outcome::Seen { audit, .. } = &outcome else {
                panic!("{transport:?}: {outcome:?}");
            };
            // Off, the proxy writes nothing under the name: it is the
            // client's own header, which native gRPC and gRPC-Web pass on as
            // they pass any other, and a transcoded call forwards only when
            // `forwarded_headers` lists it.
            let expected = match transport {
                Transport::Grpc | Transport::GrpcWeb => "198.51.100.5",
                Transport::Unary | Transport::Stream => "",
            };
            assert_eq!(audit, expected, "{transport:?}");
            assert_eq!(outcome.xff(), "203.0.113.7, 127.0.0.1");
        }
    }
    }
}

#[tokio::test]
async fn a_claim_mapped_onto_a_forwarding_header_fails_the_build() {
    // The configured client header is the proxy's alone, as the fixed
    // client-address headers are.
    struct Accepting;

    #[async_trait::async_trait]
    impl structured_proxy::hooks::TokenVerifier for Accepting {
        async fn verify(&self, _token: &str) -> Option<serde_json::Value> {
            Some(serde_json::json!({ "sub": "alice" }))
        }
    }

    let yaml = "client_address:\n  forward:\n    client_header: cf-connecting-ip\nauth:\n  mode: jwt\n  jwt:\n    claims_headers:\n      sub: cf-connecting-ip\n";
    let server = ProxyServer::from_yaml_str(yaml)
        .unwrap()
        .with_descriptors(pool())
        .with_token_verifier(std::sync::Arc::new(Accepting));
    let Err(err) = server.service(in_process_upstream()) else {
        panic!("a claim mapped onto the client header must be refused");
    };
    assert!(err.to_string().contains("cf-connecting-ip"), "{err}");
}

#[tokio::test]
async fn translated_grpc_web_carries_the_resolved_address() {
    for upstream in [common::Upstream::Remote, common::Upstream::InProcess] {
        let yaml = format!("{TRUST_LOOPBACK}grpc_web:\n  translate: true\n");
        let addr = listen(upstream, &yaml).await;
        assert_eq!(
            address_via(
                addr,
                upstream,
                Transport::GrpcWeb,
                &["198.51.100.1, 203.0.113.7"]
            )
            .await,
            "203.0.113.7",
            "{upstream:?}"
        );
    }
}

#[tokio::test]
async fn x_real_ip_is_read_only_when_selected() {
    let yaml = "client_address:\n  trusted_proxies: [\"127.0.0.1\"]\n  header: x_real_ip\n";
    let addr = listen(common::Upstream::InProcess, yaml).await;
    for transport in TRANSPORTS {
        let outcome = call(
            addr,
            transport,
            &[
                ("x-real-ip", "203.0.113.7"),
                ("x-forwarded-for", "198.51.100.1"),
            ],
        )
        .await;
        assert_eq!(
            outcome.address(common::Upstream::InProcess),
            "203.0.113.7",
            "{transport:?}"
        );
    }
}

#[tokio::test]
async fn without_connection_information_no_address_resolves() {
    // A server that records no peer: forwarding headers cannot be traced to
    // anyone, so nothing resolves, and nothing reaches the upstream.
    let app = common::proxy(
        common::Upstream::InProcess,
        Recorder { pool: pool() },
        pool(),
        Default::default(),
    )
    .await;
    let request = http::Request::get("/v1/addr")
        .header("x-forwarded-for", "203.0.113.7")
        .body(Body::empty())
        .unwrap();
    let (status, body) = common::send(&app, request).await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    let outcome = Outcome::from_json(&serde_json::from_str(&body).unwrap());
    assert_eq!(
        outcome,
        Outcome::Seen {
            xff: String::new(),
            real_ip: String::new(),
            forwarded: String::new(),
            client: "unavailable".into(),
            dpop: String::new(),
            cf_ip: String::new(),
            audit: String::new(),
        }
    );

    // Required: refused as the server's own failure, in each protocol.
    let app = common::app(
        common::Upstream::InProcess,
        Recorder { pool: pool() },
        |yaml| {
            ProxyServer::from_yaml_str(&format!("{yaml}{TRUST_LOOPBACK_REQUIRED}"))
                .unwrap()
                .with_descriptors(pool())
        },
    )
    .await;
    let request = http::Request::get("/v1/addr").body(Body::empty()).unwrap();
    let (status, body) = common::send(&app, request).await;
    assert_eq!(status, http::StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    let request = http::Request::post("/test.v1.Addr/Echo")
        .version(http::Version::HTTP_2)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Body::from(request_frame()))
        .unwrap();
    let response = tower::ServiceExt::oneshot(app, request).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "13");
}

#[tokio::test]
async fn the_router_resolves_the_address_too() {
    // `ProxyServer::router` behind the embedder's own axum server; it
    // answers HTTP only, so the upstream needs no gRPC-Web.
    let url = common::serve(Recorder { pool: pool() }).await;
    for (yaml, xff, expected) in [
        ("", "198.51.100.1", "127.0.0.1"),
        (TRUST_LOOPBACK, "198.51.100.1, 203.0.113.7", "203.0.113.7"),
    ] {
        let router =
            ProxyServer::from_yaml_str(&format!("upstream:\n  default: \"{url}\"\n{yaml}"))
                .unwrap()
                .with_descriptors(pool())
                .router()
                .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
        });
        for transport in [Transport::Unary, Transport::Stream] {
            assert_eq!(
                address_via(addr, common::Upstream::Remote, transport, &[xff]).await,
                expected,
                "{transport:?} {yaml:?}"
            );
        }
    }
}

#[tokio::test]
async fn the_fallback_and_the_decider_read_the_same_address() {
    use std::sync::{Arc, Mutex};

    /// Allows every request, recording the address it saw.
    #[derive(Default)]
    struct Recording(Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl structured_proxy::hooks::AuthDecider for Recording {
        async fn decide(
            &self,
            req: &structured_proxy::hooks::RequestParts<'_>,
        ) -> structured_proxy::hooks::Decision {
            let ip = req.client.ip().map(|ip| ip.to_string()).unwrap_or_default();
            self.0.lock().unwrap().push(ip);
            structured_proxy::hooks::Decision::Allow {
                inject_headers: http::HeaderMap::new(),
            }
        }
    }

    let decider = Arc::new(Recording::default());
    let service = in_process_proxy(TRUST_LOOPBACK, {
        let decider = decider.clone();
        move |server| {
            server.with_auth_decider(decider).with_auth_decider_scope(
                structured_proxy::config::ScopeConfig::traffic([
                    structured_proxy::config::Traffic::All,
                ]),
            )
        }
    });
    let fallback = axum::Router::new().fallback(
        |axum::Extension(client): axum::Extension<ClientAddress>, headers: http::HeaderMap| async move {
            let xff: Vec<_> = headers
                .get_all("x-forwarded-for")
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect();
            format!("{}|{}", client.ip().unwrap(), xff.join(","))
        },
    );
    let addr = spawn_serve(service.with_fallback(fallback)).await;

    let forwarded = [("x-forwarded-for", "198.51.100.1, 203.0.113.7")];
    let (status, _, body) = http1(addr, "GET", "/static/page", &forwarded, &[]).await;
    assert_eq!(status, 200);
    // The verified chain: the client, then the trusted peer it came through.
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "203.0.113.7|203.0.113.7, 127.0.0.1"
    );
    for transport in TRANSPORTS {
        let outcome = call(addr, transport, &forwarded).await;
        assert_eq!(outcome.address(common::Upstream::InProcess), "203.0.113.7");
    }
    let seen = decider.0.lock().unwrap().clone();
    assert_eq!(seen.len(), 1 + TRANSPORTS.len());
    assert!(seen.iter().all(|ip| ip == "203.0.113.7"), "{seen:?}");
}

#[tokio::test]
async fn shield_in_an_embedders_router_keys_by_the_forwarded_client() {
    // Shield mounted on its own, behind a trusted load balancer: the public
    // resolution layer in front of it names the client, so one client cannot
    // spend the budget of every other client behind the same balancer.
    use structured_proxy::client_address::ClientAddressLayer;
    use structured_proxy::config::{self, ClientAddressConfig, ShieldConfig};

    let shield: ShieldConfig = config::from_yaml(
        "enabled: true\nprofiles:\n  one: { rate: \"1/min\", burst: 1 }\nrules:\n  - pattern: \"/**\"\n    key: { type: ip }\n    profile: one\n",
    )
    .unwrap();
    let shield = structured_proxy::shield::Shield::build(&shield)
        .unwrap()
        .unwrap();
    let mut trust = ClientAddressConfig::default();
    trust.trusted_proxies = vec!["127.0.0.1".into()];
    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(
                |axum::Extension(client): axum::Extension<ClientAddress>| async move {
                    client.ip().unwrap().to_string()
                },
            ),
        )
        .layer(axum::middleware::from_fn_with_state(
            shield,
            structured_proxy::shield::pre_auth_middleware,
        ))
        .layer(ClientAddressLayer::new(&trust).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    });

    let get = |xff: &'static str| async move {
        let (status, _, body) = http1(addr, "GET", "/", &[("x-forwarded-for", xff)], &[]).await;
        (status, String::from_utf8(body).unwrap())
    };
    assert_eq!(get("203.0.113.7").await, (200, "203.0.113.7".to_owned()));
    // The same client is out of budget...
    assert_eq!(get("198.51.100.1, 203.0.113.7").await.0, 429);
    // ...another client behind the same balancer is not.
    assert_eq!(get("203.0.113.8").await, (200, "203.0.113.8".to_owned()));
}

#[test]
fn an_invalid_trust_list_fails_the_layer() {
    let mut trust = structured_proxy::config::ClientAddressConfig::default();
    trust.trusted_proxies = vec!["10.0.0.0/33".into()];
    let Err(err) = structured_proxy::client_address::ClientAddressLayer::new(&trust) else {
        panic!("an invalid trusted_proxies entry must be refused");
    };
    assert!(err.to_string().contains("10.0.0.0/33"), "{err}");
}

#[tokio::test]
async fn a_guard_cannot_set_the_client_address_headers() {
    // The proxy writes these from the resolved address alone: a decider that
    // injects them changes nothing the upstream or the fallback sees, so they
    // never disagree with the address the rate limits keyed by.
    struct Forging;

    #[async_trait::async_trait]
    impl structured_proxy::hooks::AuthDecider for Forging {
        async fn decide(
            &self,
            _req: &structured_proxy::hooks::RequestParts<'_>,
        ) -> structured_proxy::hooks::Decision {
            let mut inject_headers = http::HeaderMap::new();
            inject_headers.insert("x-forwarded-for", "198.51.100.66".parse().unwrap());
            inject_headers.insert("x-real-ip", "198.51.100.67".parse().unwrap());
            inject_headers.insert("forwarded", "for=198.51.100.68".parse().unwrap());
            inject_headers.insert("x-user-id", "alice".parse().unwrap());
            structured_proxy::hooks::Decision::Allow { inject_headers }
        }
    }

    let service = in_process_proxy(TRUST_LOOPBACK, |server| {
        server
            .with_auth_decider(std::sync::Arc::new(Forging))
            .with_auth_decider_scope(structured_proxy::config::ScopeConfig::traffic([
                structured_proxy::config::Traffic::All,
            ]))
    });
    let fallback = axum::Router::new().fallback(|headers: http::HeaderMap| async move {
        let all = |name: &str| {
            headers
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "{}|{}|{}|{}",
            all("x-forwarded-for"),
            all("x-real-ip"),
            all("forwarded"),
            all("x-user-id")
        )
    });
    let addr = spawn_serve(service.with_fallback(fallback)).await;

    let forwarded = [("x-forwarded-for", "203.0.113.7")];
    let (status, _, body) = http1(addr, "GET", "/static/page", &forwarded, &[]).await;
    assert_eq!(status, 200);
    // The decider's other headers still go through.
    assert_eq!(
        String::from_utf8(body).unwrap(),
        "203.0.113.7, 127.0.0.1|203.0.113.7||alice"
    );
    for transport in TRANSPORTS {
        let outcome = call(addr, transport, &forwarded).await;
        assert_eq!(
            outcome.address(common::Upstream::InProcess),
            "203.0.113.7",
            "{transport:?}"
        );
    }
}
