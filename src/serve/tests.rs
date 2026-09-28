use super::*;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Serve the proxy's health routes with `options` on a local port.
async fn listen(options: ServeOptions) -> SocketAddr {
    let service = crate::ProxyServer::from_yaml_str("service:\n  name: demo\n")
        .unwrap()
        .service(tonic::service::Routes::default())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_with(listener, service, options));
    addr
}

/// Send a keep-alive `GET /health/live` on `stream`.
async fn request(stream: &mut TcpStream) {
    stream
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
}

/// Read until the end of a response head; returns its status line.
async fn status_line(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut byte).await.unwrap();
        assert_eq!(read, 1, "the connection closed before a response");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    head.lines().next().unwrap().to_owned()
}

#[tokio::test]
async fn a_connection_past_the_limit_is_served_once_another_closes() {
    let addr = listen(ServeOptions::new().max_connections(1)).await;

    let mut first = TcpStream::connect(addr).await.unwrap();
    request(&mut first).await;
    assert_eq!(status_line(&mut first).await, "HTTP/1.1 200 OK");

    // The kernel completes the second connection, but the proxy does not
    // accept it while the first stays open.
    let mut second = TcpStream::connect(addr).await.unwrap();
    request(&mut second).await;
    let waiting = tokio::time::timeout(Duration::from_millis(300), status_line(&mut second)).await;
    assert!(waiting.is_err(), "served past the connection limit");

    drop(first);
    let served = tokio::time::timeout(Duration::from_secs(5), status_line(&mut second))
        .await
        .expect("the freed slot serves the waiting connection");
    assert_eq!(served, "HTTP/1.1 200 OK");
}

#[tokio::test]
async fn an_idle_http2_connection_gives_up_its_slot() {
    // A gRPC channel keeps its HTTP/2 connection open between calls; with
    // one slot, that alone would lock every other client out.
    let options = ServeOptions::new()
        .max_connections(1)
        .idle_timeout(Some(Duration::from_millis(300)));
    let addr = listen(options).await;
    let channel = tonic::transport::Channel::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = tonic_health::pb::health_client::HealthClient::new(channel);
    // No upstream service: the call completes with UNIMPLEMENTED, and the
    // connection stays open with no stream on it.
    let status = client
        .check(tonic_health::pb::HealthCheckRequest::default())
        .await
        .unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);

    let mut other = TcpStream::connect(addr).await.unwrap();
    request(&mut other).await;
    let served = tokio::time::timeout(Duration::from_secs(5), status_line(&mut other))
        .await
        .expect("the idle connection's slot is freed");
    assert_eq!(served, "HTTP/1.1 200 OK");
    drop(client);
}

#[tokio::test]
async fn a_client_that_trickles_its_headers_is_disconnected() {
    // Headers that never complete would otherwise hold the connection (and
    // its slot) forever.
    let options = ServeOptions::new()
        .idle_timeout(None)
        .header_read_timeout(Duration::from_millis(300));
    let addr = listen(options).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /health/live HTTP/1.1\r\nHost: local")
        .await
        .unwrap();
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
        .await
        .expect("the server closes a connection whose headers never end");
    // End of stream, or a reset: either way the server let go.
    assert!(
        closed.as_ref().map_or_else(
            |e| e.kind() == std::io::ErrorKind::ConnectionReset,
            |_| true
        ),
        "{closed:?}"
    );
}

#[tokio::test]
async fn without_a_limit_connections_are_served_together() {
    let addr = listen(ServeOptions::new()).await;
    let mut first = TcpStream::connect(addr).await.unwrap();
    let mut second = TcpStream::connect(addr).await.unwrap();
    request(&mut first).await;
    request(&mut second).await;
    assert_eq!(status_line(&mut second).await, "HTTP/1.1 200 OK");
    assert_eq!(status_line(&mut first).await, "HTTP/1.1 200 OK");
}

#[test]
#[should_panic(expected = "max_connections must be at least 1")]
fn a_limit_of_zero_is_refused() {
    let _ = ServeOptions::new().max_connections(0);
}

#[test]
fn connection_timeouts_come_from_the_config() {
    let server = crate::ProxyServer::from_yaml_str(
        "listen:\n  idle_timeout_secs: 0\n  header_read_timeout_secs: 5\n",
    )
    .unwrap();
    let options = server.serve_options().unwrap();
    // 0 keeps idle connections open.
    assert_eq!(options.idle_timeout, None);
    assert_eq!(options.header_read_timeout, Duration::from_secs(5));
    let defaults = crate::ProxyServer::new().serve_options().unwrap();
    assert_eq!(defaults.idle_timeout, Some(Duration::from_secs(60)));
    assert_eq!(defaults.header_read_timeout, Duration::from_secs(30));
}

#[test]
fn a_zero_header_read_timeout_is_an_error() {
    let server =
        crate::ProxyServer::from_yaml_str("listen:\n  header_read_timeout_secs: 0\n").unwrap();
    let err = server.serve_options().unwrap_err();
    assert!(
        err.to_string().contains("header_read_timeout_secs"),
        "{err}"
    );
}

#[test]
fn a_zero_limit_in_the_config_is_an_error() {
    let server = crate::ProxyServer::from_yaml_str("listen:\n  max_connections: 0\n").unwrap();
    let err = server.serve_options().unwrap_err();
    assert!(err.to_string().contains("listen.max_connections"), "{err}");
}

/// A process crypto provider, for builds without a crypto backend feature.
fn install_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        rustls::crypto::CryptoProvider::install_default(rustls_rustcrypto::provider())
            .expect("each test runs in its own process");
    }
}

#[test]
fn tls_is_set_up_from_the_config_files() {
    install_provider();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tls/testdata");
    let yaml = format!(
        "listen:\n  tls:\n    cert_file: {dir}/ecdsa.pem\n    key_file: {dir}/ecdsa.key.pem\n    client_ca_file: {dir}/client-ca.pem\n"
    );
    let options = crate::ProxyServer::from_yaml_str(&yaml)
        .unwrap()
        .serve_options()
        .unwrap();
    let tls = options.tls.expect("listen.tls configures TLS");
    // gRPC clients negotiate HTTP/2 on the same port as HTTP/1.1 ones.
    assert_eq!(tls.alpn_protocols, [b"h2".to_vec(), b"http/1.1".to_vec()]);
}

#[test]
fn client_auth_without_a_client_ca_is_an_error() {
    // `client_auth: required` alone would otherwise give a listener that
    // verifies no client, although the config asks for mTLS.
    install_provider();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/tls/testdata");
    for client_auth in ["required", "optional"] {
        let yaml = format!(
            "listen:\n  tls:\n    cert_file: {dir}/ecdsa.pem\n    key_file: {dir}/ecdsa.key.pem\n    client_auth: {client_auth}\n"
        );
        let err = crate::ProxyServer::from_yaml_str(&yaml)
            .unwrap()
            .serve_options()
            .unwrap_err();
        assert!(err.to_string().contains("client_ca_file"), "{err}");
    }
}

#[test]
fn a_missing_tls_file_names_itself() {
    install_provider();
    let yaml = "listen:\n  tls:\n    cert_file: /nonexistent/tls.crt\n    key_file: /nonexistent/tls.key\n";
    let err = crate::ProxyServer::from_yaml_str(yaml)
        .unwrap()
        .serve_options()
        .unwrap_err();
    assert!(err.to_string().contains("/nonexistent/tls.crt"), "{err}");
}
