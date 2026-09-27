//! The outbound TLS client against a local HTTPS server over the pure-Rust
//! provider: the handshake completes over TLS 1.3 and TLS 1.2 with ECDSA and
//! RSA server keys, and a certificate for another name or from an unknown CA
//! is refused. Fixtures come from `testdata/generate.sh`.

use super::*;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ProtocolVersion, SupportedProtocolVersion};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CA: &str = include_str!("testdata/ca.pem");
const OTHER_CA: &str = include_str!("testdata/other-ca.pem");
const ECDSA_CERT: &str = include_str!("testdata/ecdsa.pem");
const ECDSA_KEY: &str = include_str!("testdata/ecdsa.key.pem");
const RSA_CERT: &str = include_str!("testdata/rsa.pem");
const RSA_KEY: &str = include_str!("testdata/rsa.key.pem");

/// The JWKS document the test server returns.
const JWKS: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;

fn roots(pem: &str) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    roots
}

/// Serve one HTTPS request with [`JWKS`] from `cert`/`key` over `versions`.
/// The task yields the negotiated version, or `None` when the handshake failed.
async fn serve(
    cert: &str,
    key: &str,
    versions: &[&'static SupportedProtocolVersion],
) -> (SocketAddr, tokio::task::JoinHandle<Option<ProtocolVersion>>) {
    let chain = CertificateDer::pem_slice_iter(cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap();
    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.ok()?;
        let version = tls.get_ref().1.protocol_version();
        let mut request = Vec::new();
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = tls.read(&mut buf).await.ok()?;
            if n == 0 {
                return None;
            }
            request.extend_from_slice(&buf[..n]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{JWKS}",
            JWKS.len()
        );
        tls.write_all(response.as_bytes()).await.ok()?;
        tls.shutdown().await.ok()?;
        version
    });
    (addr, task)
}

/// A client trusting `trusted`, with `host` resolving to the test server.
fn client(trusted: &str, host: &str, addr: SocketAddr) -> reqwest::Client {
    reqwest::Client::builder()
        .tls_backend_preconfigured(client_config_with_roots(roots(trusted)))
        .resolve(host, addr)
        .build()
        .unwrap()
}

async fn fetch(trusted: &str, host: &str, addr: SocketAddr) -> reqwest::Result<String> {
    client(trusted, host, addr)
        .get(format!("https://{host}:{}/jwks", addr.port()))
        .send()
        .await?
        .text()
        .await
}

#[tokio::test]
async fn jwks_fetch_over_tls13_with_an_ecdsa_certificate() {
    let (addr, server) = serve(ECDSA_CERT, ECDSA_KEY, &[&rustls::version::TLS13]).await;
    let body = fetch(CA, "localhost", addr).await.unwrap();
    assert_eq!(body, JWKS);
    assert_eq!(server.await.unwrap(), Some(ProtocolVersion::TLSv1_3));
}

#[tokio::test]
async fn jwks_fetch_over_tls12_with_an_ecdsa_certificate() {
    let (addr, server) = serve(ECDSA_CERT, ECDSA_KEY, &[&rustls::version::TLS12]).await;
    let body = fetch(CA, "localhost", addr).await.unwrap();
    assert_eq!(body, JWKS);
    assert_eq!(server.await.unwrap(), Some(ProtocolVersion::TLSv1_2));
}

#[tokio::test]
async fn jwks_fetch_over_tls13_with_an_rsa_certificate() {
    // The server's handshake signature is RSA-PSS, verified by the provider.
    let (addr, server) = serve(RSA_CERT, RSA_KEY, &[&rustls::version::TLS13]).await;
    let body = fetch(CA, "localhost", addr).await.unwrap();
    assert_eq!(body, JWKS);
    assert_eq!(server.await.unwrap(), Some(ProtocolVersion::TLSv1_3));
}

#[tokio::test]
async fn jwks_fetch_over_tls12_with_an_rsa_certificate() {
    let (addr, server) = serve(RSA_CERT, RSA_KEY, &[&rustls::version::TLS12]).await;
    let body = fetch(CA, "localhost", addr).await.unwrap();
    assert_eq!(body, JWKS);
    assert_eq!(server.await.unwrap(), Some(ProtocolVersion::TLSv1_2));
}

/// The rustls error behind a failed request, as text.
fn tls_error(error: &reqwest::Error) -> String {
    let mut source: Option<&dyn std::error::Error> = Some(error);
    let mut chain = String::new();
    while let Some(err) = source {
        chain.push_str(&format!("{err:?} | "));
        source = err.source();
    }
    chain
}

#[tokio::test]
async fn certificate_for_another_name_is_refused() {
    // The certificate names `localhost`; the client asked for another host.
    let (addr, server) = serve(ECDSA_CERT, ECDSA_KEY, &[&rustls::version::TLS13]).await;
    let error = fetch(CA, "jwks.example.test", addr).await.unwrap_err();
    assert!(
        tls_error(&error).contains("NotValidForName"),
        "{}",
        tls_error(&error)
    );
    assert_eq!(server.await.unwrap(), None);
}

#[tokio::test]
async fn certificate_from_an_unknown_ca_is_refused() {
    let (addr, server) = serve(ECDSA_CERT, ECDSA_KEY, &[&rustls::version::TLS13]).await;
    let error = fetch(OTHER_CA, "localhost", addr).await.unwrap_err();
    assert!(
        tls_error(&error).contains("UnknownIssuer"),
        "{}",
        tls_error(&error)
    );
    assert_eq!(server.await.unwrap(), None);
}

#[test]
fn production_config_trusts_the_bundled_mozilla_roots() {
    // Same provider, and the bundled root store is not empty.
    let config = client_config();
    assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
    assert!(config
        .crypto_provider()
        .cipher_suites
        .iter()
        .any(|suite| suite.version() == &rustls::version::TLS13));
}
