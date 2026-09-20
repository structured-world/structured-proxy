//! Process-wide `jsonwebtoken` crypto provider selection.
//!
//! `jsonwebtoken` infers its provider from its own two backend features, and
//! with both on it cannot: it falls back to a provider that panics on first
//! use. Cargo features being additive, that combination arrives on its own.
//! Either this crate's `rust_crypto` and `aws_lc_rs` are both enabled (two
//! dependents asking for different backends, or `--all-features`, which is what
//! docs.rs and `cargo-semver-checks` use), or one of ours is enabled while
//! another crate in the graph turns on the other `jsonwebtoken` feature
//! directly. The second case looks single-backend from here, so the provider is
//! installed explicitly whichever backend this crate compiled with.

#[cfg(test)]
mod tests;

/// The provider this crate installs.
///
/// `aws_lc_rs` wins whenever it is compiled in: it is constant-time and
/// advisory-free, while `rust_crypto` pulls in `rsa` (RUSTSEC-2023-0071).
#[cfg(feature = "aws_lc_rs")]
pub(crate) fn preferred_provider() -> &'static jsonwebtoken::crypto::CryptoProvider {
    &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
}

/// The provider this crate installs: RustCrypto, the only backend this build
/// compiled with.
#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc_rs")))]
pub(crate) fn preferred_provider() -> &'static jsonwebtoken::crypto::CryptoProvider {
    &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
}

/// Select the `jsonwebtoken` crypto provider for this process.
///
/// Call it once at startup, before anything in the process signs or verifies a
/// JWT. It is idempotent, and installs the backend this crate was built with,
/// so `jsonwebtoken` never has to infer one.
///
/// A plain [`ProxyServer`](crate::ProxyServer) deployment needs no call: the
/// server does this while it is being built. It is public for the case the
/// server cannot cover, which is also how the ambiguity arises in the first
/// place: another crate in the graph uses `jsonwebtoken` too and may reach it
/// first. Call this at the top of `main` and every consumer is covered,
/// whichever runs first.
///
/// With both backends linked the choice is `aws_lc_rs`: constant-time, and free
/// of the `rsa` advisory `rust_crypto` carries. A process that wants a different
/// one installs it through
/// [`CryptoProvider::install_default`](jsonwebtoken::crypto::CryptoProvider::install_default)
/// before calling this, and the earlier choice stands.
pub fn install_default_crypto_provider() {
    if preferred_provider().install_default().is_err() {
        // Something installed a provider before us: an embedder that made its
        // own choice, or an earlier call here. Either way it stands: the
        // process gets one provider, and the first explicit choice is the one
        // the caller meant.
        tracing::debug!("jsonwebtoken crypto provider already installed; keeping it");
    }
}
