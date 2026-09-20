//! The rustls client configuration for the proxy's own outbound HTTPS calls
//! (JWKS fetches, the rate-limit service).

use std::sync::Arc;

/// Build the rustls client config for an outbound HTTPS client.
///
/// Uses the pure-Rust `ring` provider (installed per-config, not process-global)
/// and bundles Mozilla's root store via `webpki-roots`, so the binary needs no
/// system CA bundle and works in musl / scratch / distroless images.
pub(crate) fn client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}
