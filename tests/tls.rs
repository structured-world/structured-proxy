//! The proxy behind TLS, an embedder's own (a rustls acceptor and hyper's
//! HTTP/1.1 + HTTP/2 connection, with the proxy as the service) or its
//! built-in listener (`listen.tls`, mTLS with a client CA). REST and native
//! gRPC share the TLS port, and a tonic upstream in process reads the client's
//! address and TLS certificate as behind tonic's own server.

#[path = "common/protos.rs"]
mod protos;

use std::convert::Infallible;
use std::future::{ready, Ready};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::Engine as _;
use hyper_util::rt::{TokioExecutor, TokioIo};
use prost_reflect::{DescriptorPool, DynamicMessage, Value as PbValue};
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
use serde_json::Value;
use structured_proxy::service::TlsConnectInfo;
use structured_proxy::transcode::codec::DynamicCodec;
use structured_proxy::{ConnectionInfo, ProxyServer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::transport::server::Connected;

const CA: &str = include_str!("../src/tls/testdata/ca.pem");
const CERT: &str = include_str!("../src/tls/testdata/ecdsa.pem");
const KEY: &str = include_str!("../src/tls/testdata/ecdsa.key.pem");

const WHO_PROTO: &str = r#"
syntax = "proto3";
package test.v1;
import "google/api/annotations.proto";

message Req {}
// The connection the upstream saw the call on.
message Seen {
  string peer = 1;
  bytes cert = 2;
}

service Who {
  rpc Me(Req) returns (Seen) {
    option (google.api.http) = { get: "/v1/me" };
  }
}
"#;

fn pool() -> DescriptorPool {
    protos::compile("test/v1/who.proto", WHO_PROTO)
}

// --- upstream ---------------------------------------------------------------

/// Answers with the caller's address and the first certificate it presented.
#[derive(Clone)]
struct Me {
    pool: DescriptorPool,
}

impl tonic::server::UnaryService<DynamicMessage> for Me {
    type Response = DynamicMessage;
    type Future = Ready<Result<tonic::Response<DynamicMessage>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<DynamicMessage>) -> Self::Future {
        let peer = request
            .remote_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        // What `Request::peer_certs` reads, with tonic's TLS feature on.
        let cert = request
            .extensions()
            .get::<TlsConnectInfo>()
            .and_then(|tls| tls.peer_certs())
            .and_then(|chain| chain.first().map(|c| c.as_ref().to_vec()))
            .unwrap_or_default();
        let mut seen = DynamicMessage::new(self.pool.get_message_by_name("test.v1.Seen").unwrap());
        seen.set_field_by_name("peer", PbValue::String(peer));
        seen.set_field_by_name("cert", PbValue::Bytes(cert.into()));
        ready(Ok(tonic::Response::new(seen)))
    }
}

#[derive(Clone)]
struct Who {
    pool: DescriptorPool,
}

impl tonic::server::NamedService for Who {
    const NAME: &'static str = "test.v1.Who";
}

impl tower::Service<http::Request<tonic::body::Body>> for Who {
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
            Ok(grpc.unary(Me { pool }, req).await)
        })
    }
}

// --- the embedder's TLS server ------------------------------------------------

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls_rustcrypto::provider())
}

fn chain() -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_slice_iter(CERT.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap()
}

fn key() -> PrivateKeyDer<'static> {
    PrivateKeyDer::from_pem_slice(KEY.as_bytes()).unwrap()
}

/// Asks for a client certificate and takes any that proves its key: these
/// tests check that the certificate reaches the upstream, not how an embedder
/// decides to trust it.
#[derive(Debug)]
struct AnyClientCert(Arc<rustls::crypto::CryptoProvider>);

impl ClientCertVerifier for AnyClientCert {
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Serve the proxy in front of `Who`, in process, on a local TLS port, the
/// way an embedder with its own TLS does: accept, handshake, tell the proxy
/// the connection, serve HTTP/1.1 or HTTP/2 as the client speaks.
async fn listen() -> SocketAddr {
    let pool = pool();
    let proxy = ProxyServer::from_yaml_str("")
        .unwrap()
        .with_descriptors(pool.clone())
        .service(tonic::service::Routes::new(Who { pool }))
        .unwrap();
    let mut config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(Arc::new(AnyClientCert(provider())))
        .with_single_cert(chain(), key())
        .unwrap();
    // gRPC clients negotiate HTTP/2, browsers and curl may take HTTP/1.1.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let service = proxy.for_connection(ConnectionInfo::tls(tls.connect_info()));
                let served = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(tls),
                        hyper_util::service::TowerToHyperService::new(service),
                    )
                    .await;
                // A client dropping its connection ends it with an error; the
                // cases check what the client received.
                if let Err(error) = served {
                    eprintln!("connection ended: {error}");
                }
            });
        }
    });
    addr
}

/// The directory of the test PKI.
const TESTDATA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tls/testdata");

/// Serve the proxy in front of `Who` with the proxy's own TLS listener,
/// configured by the `listen:` of `listen_yaml` (its `tls:` and its limits).
async fn listen_builtin(listen_yaml: &str) -> SocketAddr {
    // Builds without a crypto backend feature take the process's provider.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider())
            .expect("each test runs in its own process");
    }
    let pool = pool();
    let server = ProxyServer::from_yaml_str(&format!("listen:\n{listen_yaml}"))
        .unwrap()
        .with_descriptors(pool.clone());
    let proxy = server
        .service(tonic::service::Routes::new(Who { pool }))
        .unwrap();
    let options = server.serve_options().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(structured_proxy::serve_with(listener, proxy, options));
    addr
}

/// `listen.tls` for the test server certificate, verifying client
/// certificates against the client CA with `client_auth` when given.
fn tls_yaml(client_auth: Option<&str>) -> String {
    let mut yaml = format!(
        "  tls:\n    cert_file: {TESTDATA}/ecdsa.pem\n    key_file: {TESTDATA}/ecdsa.key.pem\n"
    );
    if let Some(client_auth) = client_auth {
        yaml.push_str(&format!(
            "    client_ca_file: {TESTDATA}/client-ca.pem\n    client_auth: {client_auth}\n"
        ));
    }
    yaml
}

// --- clients --------------------------------------------------------------------

/// The certificate a test client presents.
#[derive(Clone, Copy)]
enum Identity {
    /// None.
    Anonymous,
    /// The server's own leaf, which a verifier that checks usage refuses.
    ServerLeaf,
    /// A client leaf of the client CA.
    Client,
}

impl Identity {
    fn cert(self) -> Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let client = || {
            let chain = CertificateDer::pem_file_iter(format!("{TESTDATA}/client.pem"))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let key = PrivateKeyDer::from_pem_file(format!("{TESTDATA}/client.key.pem")).unwrap();
            (chain, key)
        };
        match self {
            Self::Anonymous => None,
            Self::ServerLeaf => Some((chain(), key())),
            Self::Client => Some(client()),
        }
    }
}

/// A TLS connection to `addr` trusting the test CA, offering `alpn`, and
/// presenting `identity`'s certificate.
async fn connect(
    addr: SocketAddr,
    alpn: &[u8],
    identity: Identity,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(CA.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let mut config = match identity.cert() {
        Some((chain, key)) => builder.with_client_auth_cert(chain, key).unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap()
}

/// `GET /v1/me` over HTTP/1.1 and TLS; returns the status, the JSON body and
/// the client's own address.
async fn rest_me(addr: SocketAddr, identity: Identity) -> (u16, Value, SocketAddr) {
    let mut tls = connect(addr, b"http/1.1", identity).await;
    let client = tls.get_ref().0.local_addr().unwrap();
    tls.write_all(b"GET /v1/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    match tls.read_to_end(&mut response).await {
        Ok(_) => {}
        // A server that closes without close_notify still delivered the
        // response.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("reading the response: {e}"),
    }
    let response = String::from_utf8(response).unwrap();
    let status = response[9..12].parse().unwrap();
    let body = response.split_once("\r\n\r\n").unwrap().1;
    (status, serde_json::from_str(body).unwrap(), client)
}

/// A native `Me` call over HTTP/2 and TLS; returns what the upstream saw and
/// the client's own address.
async fn grpc_me(addr: SocketAddr, identity: Identity) -> (DynamicMessage, SocketAddr) {
    let (sender, mut client_addr) = tokio::sync::mpsc::channel(1);
    let connector = tower::service_fn(move |_: http::Uri| {
        let sender = sender.clone();
        async move {
            let tls = connect(addr, b"h2", identity).await;
            sender
                .send(tls.get_ref().0.local_addr().unwrap())
                .await
                .unwrap();
            Ok::<_, std::io::Error>(TokioIo::new(tls))
        }
    });
    let channel = tonic::transport::Endpoint::from_static("http://localhost")
        .connect_with_connector(connector)
        .await
        .unwrap();
    let mut grpc = tonic::client::Grpc::new(channel);
    grpc.ready().await.unwrap();
    let pool = pool();
    let req = DynamicMessage::new(pool.get_message_by_name("test.v1.Req").unwrap());
    let codec = DynamicCodec::new(pool.get_message_by_name("test.v1.Seen").unwrap());
    let seen = grpc
        .unary(
            tonic::Request::new(req),
            http::uri::PathAndQuery::from_static("/test.v1.Who/Me"),
            codec,
        )
        .await
        .unwrap()
        .into_inner();
    (seen, client_addr.recv().await.unwrap())
}

fn leaf_der() -> Vec<u8> {
    chain()[0].as_ref().to_vec()
}

// --- cases --------------------------------------------------------------------

#[tokio::test]
async fn rest_over_tls_reaches_the_upstream_with_the_client_address() {
    let addr = listen().await;
    let (status, seen, client) = rest_me(addr, Identity::Anonymous).await;
    assert_eq!(status, 200, "{seen}");
    assert_eq!(seen["peer"], client.to_string());
    // No certificate presented, none reported.
    assert_eq!(seen["cert"], "");
}

#[tokio::test]
async fn native_grpc_shares_the_tls_port() {
    let addr = listen().await;
    let (seen, client) = grpc_me(addr, Identity::Anonymous).await;
    let peer = match seen.get_field_by_name("peer").as_deref() {
        Some(PbValue::String(peer)) => peer.clone(),
        _ => String::new(),
    };
    assert_eq!(peer, client.to_string());
}

#[tokio::test]
async fn a_client_certificate_reaches_a_transcoded_call() {
    // mTLS: the upstream authorizes on the certificate as behind tonic's own
    // TLS server, although the call came in as REST.
    let addr = listen().await;
    let (status, seen, _) = rest_me(addr, Identity::ServerLeaf).await;
    assert_eq!(status, 200, "{seen}");
    let cert = base64::engine::general_purpose::STANDARD
        .decode(seen["cert"].as_str().unwrap())
        .unwrap();
    assert_eq!(cert, leaf_der());
}

#[tokio::test]
async fn a_client_certificate_reaches_a_native_call() {
    let addr = listen().await;
    let (seen, _) = grpc_me(addr, Identity::ServerLeaf).await;
    let cert = match seen.get_field_by_name("cert").as_deref() {
        Some(PbValue::Bytes(cert)) => cert.to_vec(),
        _ => Vec::new(),
    };
    assert_eq!(cert, leaf_der());
}

// --- the proxy's own TLS listener -----------------------------------------------

fn seen_cert(seen: &DynamicMessage) -> Vec<u8> {
    match seen.get_field_by_name("cert").as_deref() {
        Some(PbValue::Bytes(cert)) => cert.to_vec(),
        _ => Vec::new(),
    }
}

fn client_leaf_der() -> Vec<u8> {
    Identity::Client.cert().unwrap().0[0].as_ref().to_vec()
}

#[tokio::test]
async fn the_builtin_tls_listener_serves_rest_and_native_grpc() {
    let addr = listen_builtin(&tls_yaml(None)).await;
    let (status, seen, client) = rest_me(addr, Identity::Anonymous).await;
    assert_eq!(status, 200, "{seen}");
    assert_eq!(seen["peer"], client.to_string());
    let (seen, client) = grpc_me(addr, Identity::Anonymous).await;
    let peer = match seen.get_field_by_name("peer").as_deref() {
        Some(PbValue::String(peer)) => peer.clone(),
        _ => String::new(),
    };
    assert_eq!(peer, client.to_string());
}

#[tokio::test]
async fn builtin_mtls_passes_a_verified_client_certificate_to_the_upstream() {
    let addr = listen_builtin(&tls_yaml(Some("required"))).await;
    let (status, seen, _) = rest_me(addr, Identity::Client).await;
    assert_eq!(status, 200, "{seen}");
    let cert = base64::engine::general_purpose::STANDARD
        .decode(seen["cert"].as_str().unwrap())
        .unwrap();
    assert_eq!(cert, client_leaf_der());
    let (seen, _) = grpc_me(addr, Identity::Client).await;
    assert_eq!(seen_cert(&seen), client_leaf_der());
}

/// Whether a request on a TLS connection presenting `identity` gets any
/// answer: a refused client certificate ends the connection instead (in TLS
/// 1.3 after the client's side of the handshake completed).
async fn answered(addr: SocketAddr, identity: Identity) -> bool {
    let mut tls = connect(addr, b"http/1.1", identity).await;
    let written = tls
        .write_all(b"GET /v1/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await;
    let mut response = Vec::new();
    let read = tls.read_to_end(&mut response).await;
    written.is_ok() && read.is_ok() && response.starts_with(b"HTTP/1.1 200")
}

#[tokio::test]
async fn builtin_mtls_required_refuses_a_client_without_a_valid_certificate() {
    let addr = listen_builtin(&tls_yaml(Some("required"))).await;
    assert!(!answered(addr, Identity::Anonymous).await);
    // Signed by a CA the listener does not trust for clients.
    assert!(!answered(addr, Identity::ServerLeaf).await);
    assert!(answered(addr, Identity::Client).await);
}

#[tokio::test]
async fn a_client_ca_alone_requires_a_client_certificate() {
    let yaml = format!(
        "{}    client_ca_file: {TESTDATA}/client-ca.pem\n",
        tls_yaml(None)
    );
    let addr = listen_builtin(&yaml).await;
    assert!(!answered(addr, Identity::Anonymous).await);
    assert!(answered(addr, Identity::Client).await);
}

#[tokio::test]
async fn builtin_mtls_optional_serves_a_client_without_a_certificate() {
    let addr = listen_builtin(&tls_yaml(Some("optional"))).await;
    let (status, seen, _) = rest_me(addr, Identity::Anonymous).await;
    assert_eq!(status, 200, "{seen}");
    assert_eq!(seen["cert"], "");
}
