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
fn a_missing_tls_file_names_itself() {
    install_provider();
    let yaml = "listen:\n  tls:\n    cert_file: /nonexistent/tls.crt\n    key_file: /nonexistent/tls.key\n";
    let err = crate::ProxyServer::from_yaml_str(yaml)
        .unwrap()
        .serve_options()
        .unwrap_err();
    assert!(err.to_string().contains("/nonexistent/tls.crt"), "{err}");
}
