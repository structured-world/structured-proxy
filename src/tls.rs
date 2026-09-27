//! The rustls client configuration for the proxy's own outbound HTTPS calls
//! (JWKS fetches, the rate-limit service).

use std::sync::Arc;

/// Build the rustls client config for an outbound HTTPS client.
///
/// Trusts Mozilla's root store bundled via `webpki-roots`, so the binary needs
/// no system CA bundle and works in musl / scratch / distroless images.
pub(crate) fn client_config() -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    client_config_with_roots(roots)
}

/// [`client_config`] trusting `roots`.
///
/// The crypto provider is the pure-Rust RustCrypto one, installed per config
/// rather than process-wide, so nothing here links C and no global default
/// has to be set first.
pub(crate) fn client_config_with_roots(roots: rustls::RootCertStore) -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()
        .expect("the RustCrypto provider supports the default TLS protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[cfg(test)]
mod tests;
