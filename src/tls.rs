//! The rustls client configuration for the proxy's own outbound HTTPS calls
//! (JWKS fetches, the rate-limit service).

use std::sync::Arc;

use rustls::crypto::CryptoProvider;

/// Build the rustls client config for an outbound HTTPS client.
///
/// Trusts Mozilla's root store bundled via `webpki-roots`, so the binary needs
/// no system CA bundle and works in musl / scratch / distroless images.
///
/// # Errors
///
/// No crypto provider is available (see [`provider`]), or the one installed
/// for the process supports neither TLS 1.2 nor TLS 1.3.
pub(crate) fn client_config() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = select_provider(CryptoProvider::get_default(), builtin_provider)?;
    client_config_with(provider, roots)
}

/// A client config over `provider` trusting `roots`.
///
/// The provider is set per config rather than process-wide, so building one
/// has no global side effect and no install ordering to respect.
pub(crate) fn client_config_with(
    provider: Arc<CryptoProvider>,
    roots: rustls::RootCertStore,
) -> Result<rustls::ClientConfig, String> {
    Ok(rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("the rustls crypto provider cannot do TLS 1.2 or 1.3: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// The crypto provider for outbound TLS: the one the process `installed`, else
/// the `builtin` one this crate's crypto backend brings.
///
/// An installed provider is the application's explicit choice and wins, the
/// order rustls itself follows. Without a backend feature the crate links no
/// provider, so a build that only transcodes pulls no TLS crypto at all.
/// Every outbound client needs one, `http://` endpoints included: reqwest
/// builds its TLS connector with the client.
///
/// # Errors
///
/// Neither is available: the message names both ways to provide one.
fn select_provider(
    installed: Option<&Arc<CryptoProvider>>,
    builtin: impl FnOnce() -> Option<CryptoProvider>,
) -> Result<Arc<CryptoProvider>, String> {
    if let Some(installed) = installed {
        return Ok(Arc::clone(installed));
    }
    builtin().map(Arc::new).ok_or_else(|| {
        "the outbound HTTP client needs a rustls crypto provider: enable the \
         `rust_crypto` or `aws_lc_rs` feature, or install one with \
         `rustls::crypto::CryptoProvider::install_default` before building the proxy"
            .to_string()
    })
}

/// aws-lc wins whenever it is compiled in, as it does for JWT verification:
/// constant-time, and free of the advisories the RustCrypto provider carries.
#[cfg(feature = "aws_lc_rs")]
fn builtin_provider() -> Option<CryptoProvider> {
    Some(rustls::crypto::aws_lc_rs::default_provider())
}

/// The pure-Rust RustCrypto provider, the only backend this build compiled.
#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc_rs")))]
fn builtin_provider() -> Option<CryptoProvider> {
    Some(rustls_rustcrypto::provider())
}

/// No crypto backend is compiled in.
#[cfg(not(any(feature = "rust_crypto", feature = "aws_lc_rs")))]
fn builtin_provider() -> Option<CryptoProvider> {
    None
}

#[cfg(test)]
mod tests;
