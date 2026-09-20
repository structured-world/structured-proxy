//! Process-wide `jsonwebtoken` crypto provider selection.
//!
//! Cargo features are additive, so `rust_crypto` and `aws_lc_rs` can both end up
//! compiled in: two dependents of this crate asking for different backends
//! unify into that build, and so does `--all-features` (which is what docs.rs
//! and `cargo-semver-checks` use). `jsonwebtoken` cannot infer its provider from
//! its own features then, and falls back to one that panics on first use, so the
//! choice has to be made here.

#[cfg(test)]
mod tests;

/// The provider this crate picks when both backends are linked.
///
/// `aws_lc_rs` wins the tie because it is constant-time and advisory-free,
/// while `rust_crypto` pulls in `rsa` (RUSTSEC-2023-0071).
#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
pub(crate) fn preferred_provider() -> &'static jsonwebtoken::crypto::CryptoProvider {
    &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
}

/// Select the `jsonwebtoken` crypto provider for this process.
///
/// Call it once at startup, before anything in the process signs or verifies a
/// JWT. It is idempotent, and a no-op unless both backend features are on: with
/// a single backend `jsonwebtoken` infers the provider from its own features.
///
/// A plain [`ProxyServer`](crate::ProxyServer) deployment needs no call: the
/// server does this while it is being built. It is public for the case the
/// server cannot cover, which is the same one that makes both backends end up
/// linked: another crate in the graph uses `jsonwebtoken` too and may reach it
/// first. Call this at the top of `main` and every consumer is covered,
/// whichever runs first.
///
/// With both backends linked the choice is `aws_lc_rs`: constant-time, and free
/// of the `rsa` advisory `rust_crypto` carries. A process that wants the other
/// one installs it through
/// [`CryptoProvider::install_default`](jsonwebtoken::crypto::CryptoProvider::install_default)
/// before calling this, and the earlier choice stands.
#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
pub fn install_default_crypto_provider() {
    if preferred_provider().install_default().is_err() {
        // Something installed a provider before us: an embedder that made its
        // own choice, or an earlier call here. Either way it stands: the
        // process gets one provider, and the first explicit choice is the one
        // the caller meant.
        tracing::debug!("jsonwebtoken crypto provider already installed; keeping it");
    }
}

/// No-op: with a single backend `jsonwebtoken` picks the provider from its own
/// features. Kept callable so embedders need no feature-dependent code.
#[cfg(not(all(feature = "rust_crypto", feature = "aws_lc_rs")))]
pub fn install_default_crypto_provider() {}
