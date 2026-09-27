//! The outbound TLS client against a local HTTPS server over the provider the
//! build brings: the handshake completes over TLS 1.3 and TLS 1.2 with ECDSA and
//! RSA server keys, and a certificate for another name or from an unknown CA
//! is refused. Then which provider the client takes, and the errors when it
//! has none. Fixtures come from `testdata/generate.sh`.

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
///
/// It runs on the provider the build brings (aws-lc with `aws_lc_rs`), so the
/// handshakes below cover the one production uses; a build without a backend
/// falls back to RustCrypto, as an embedder would install one.
fn client(trusted: &str, host: &str, addr: SocketAddr) -> reqwest::Client {
    let provider = Arc::new(builtin_provider().unwrap_or_else(rustls_rustcrypto::provider));
    reqwest::Client::builder()
        .tls_backend_preconfigured(client_config_with(provider, roots(trusted)).unwrap())
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

#[cfg(any(feature = "rust_crypto", feature = "aws_lc_rs"))]
#[test]
fn production_config_trusts_the_bundled_mozilla_roots() {
    // The backend's provider, and the bundled root store is not empty.
    let config = client_config().unwrap();
    assert!(!webpki_roots::TLS_SERVER_ROOTS.is_empty());
    assert!(config
        .crypto_provider()
        .cipher_suites
        .iter()
        .any(|suite| suite.version() == &rustls::version::TLS13));
}

/// Which provider `p` is: its key provider's type, named by `Debug`.
#[cfg(any(feature = "rust_crypto", feature = "aws_lc_rs"))]
fn kind(p: &rustls::crypto::CryptoProvider) -> String {
    format!("{:?}", p.key_provider)
}

#[cfg(feature = "aws_lc_rs")]
#[test]
fn the_aws_lc_backend_brings_the_aws_lc_provider() {
    // Also with `rust_crypto` on: aws-lc wins the tie, as for JWTs.
    let builtin = builtin_provider().unwrap();
    assert_eq!(
        kind(&builtin),
        kind(&rustls::crypto::aws_lc_rs::default_provider())
    );
    assert_ne!(kind(&builtin), kind(&rustls_rustcrypto::provider()));
}

#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc_rs")))]
#[test]
fn the_rust_crypto_backend_brings_the_rustcrypto_provider() {
    let builtin = builtin_provider().unwrap();
    assert_eq!(kind(&builtin), kind(&rustls_rustcrypto::provider()));
}

#[cfg(not(any(feature = "rust_crypto", feature = "aws_lc_rs")))]
#[test]
fn without_a_crypto_backend_no_provider_is_linked() {
    // The build a transcoding-only consumer takes: no TLS crypto of its own.
    assert!(builtin_provider().is_none());
}

#[test]
fn the_installed_provider_wins_over_the_builtin_one() {
    let installed = Arc::new(rustls_rustcrypto::provider());
    let chosen = select_provider(Some(&installed), || {
        panic!("the builtin provider is not built when one is installed")
    })
    .unwrap();
    assert!(Arc::ptr_eq(&chosen, &installed));
}

#[test]
fn without_an_installed_provider_the_builtin_one_is_used() {
    let chosen = select_provider(None, || Some(rustls_rustcrypto::provider())).unwrap();
    assert!(!chosen.cipher_suites.is_empty());
}

#[test]
fn without_any_provider_the_error_names_both_remedies() {
    let err = select_provider(None, || None).unwrap_err();
    for remedy in [
        "rust_crypto",
        "aws_lc_rs",
        "CryptoProvider::install_default",
    ] {
        assert!(err.contains(remedy), "{remedy}: {err}");
    }
}

#[test]
fn a_provider_without_tls12_or_tls13_suites_is_refused() {
    // An installed provider is the embedder's; one that cannot negotiate a
    // safe version is an error, not a panic.
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: Vec::new(),
        ..rustls_rustcrypto::provider()
    };
    let err = client_config_with(Arc::new(provider), roots(CA)).unwrap_err();
    assert!(err.contains("TLS 1.2 or 1.3"), "{err}");
}
