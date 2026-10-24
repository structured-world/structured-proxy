//! Process-wide `jsonwebtoken` crypto provider selection.
//!
//! The RustCrypto backend uses jsonwebtoken's extension interface with current
//! primitives. The optional aws-lc backend retains its existing precedence.
//! Explicit installation avoids feature inference when dependencies enable
//! different jsonwebtoken backends in one process.

#[cfg(test)]
mod tests;

#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc_rs")))]
mod rust_crypto;

/// The provider this crate installs.
///
/// `aws_lc_rs` retains precedence when both optional backends are compiled in.
#[cfg(feature = "aws_lc_rs")]
pub(crate) fn preferred_provider() -> &'static jsonwebtoken::crypto::CryptoProvider {
    &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
}

/// The provider this crate installs: RustCrypto, the only backend this build
/// compiled with.
#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc_rs")))]
pub(crate) fn preferred_provider() -> &'static jsonwebtoken::crypto::CryptoProvider {
    &rust_crypto::DEFAULT_PROVIDER
}

/// Select the `jsonwebtoken` crypto provider for this process.
///
/// Call it once at startup, before anything in the process signs or verifies a
/// JWT. It is idempotent, and installs the backend this crate was built with,
/// so `jsonwebtoken` never has to infer one.
///
/// A plain [`ProxyServer`](crate::ProxyServer) deployment with `auth.mode:
/// "jwt"` needs no call: building the built-in verifier does this. A proxy
/// without it installs nothing and leaves the provider to its host. It is
/// public for the case the server cannot cover, which is also how the ambiguity arises in the first
/// place: another crate in the graph uses `jsonwebtoken` too and may reach it
/// first. Call this at the top of `main` and every consumer is covered,
/// whichever runs first.
///
/// With both backends linked the choice is `aws_lc_rs`. A process that wants
/// a different one installs it through
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
