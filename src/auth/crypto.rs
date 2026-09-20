//! Process-wide `jsonwebtoken` crypto provider selection.
//!
//! Cargo features are additive, so `rust_crypto` and `aws_lc_rs` can both end up
//! compiled in: two dependents of this crate asking for different backends
//! unify into that build, and so does `--all-features` (which is what docs.rs
//! and `cargo-semver-checks` use). `jsonwebtoken` cannot infer its provider from
//! its own features then, and falls back to one that panics on first use, so the
//! choice has to be made here.

/// Select the crypto provider for this process when both backends are linked.
///
/// Call before any `jsonwebtoken` operation. Idempotent, and a no-op unless both
/// backend features are on: with a single backend `jsonwebtoken` infers it.
///
/// `aws_lc_rs` wins the tie because it is constant-time and advisory-free, while
/// `rust_crypto` pulls in `rsa` (RUSTSEC-2023-0071). A build that wants the
/// other one regardless installs its own provider first, or drops the
/// `aws_lc_rs` feature.
#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
pub(crate) fn install_default_provider() {
    if jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
        .install_default()
        .is_err()
    {
        // Something installed a provider before us: an embedder that made its
        // own choice, or an earlier call here. Either way it stands — the
        // process gets one provider, and the first explicit choice is the one
        // the caller meant.
        tracing::debug!("jsonwebtoken crypto provider already installed; keeping it");
    }
}

/// No-op: with a single backend `jsonwebtoken` picks the provider from its own
/// features.
#[cfg(not(all(feature = "rust_crypto", feature = "aws_lc_rs")))]
pub(crate) fn install_default_provider() {}
