/// The selection itself, read before anything installs a provider. Verifying a
/// token proves only that *some* provider is installed (both backends do
/// EdDSA), so the choice is asserted here at its own seam.
///
/// With both backends linked it must be `aws_lc_rs`, the constant-time and
/// advisory-free one.
#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
#[test]
fn tie_break_selects_aws_lc_rs() {
    let selected = super::preferred_provider();
    assert!(
        std::ptr::eq(selected, &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER),
        "the tie-break must select the aws_lc_rs provider"
    );
    assert!(
        !std::ptr::eq(
            selected,
            &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
        ),
        "the tie-break must not fall back to RustCrypto"
    );
}

/// A single-backend build installs that backend rather than leaving
/// `jsonwebtoken` to infer it: another crate in the graph may have turned on the
/// other `jsonwebtoken` feature directly, which is invisible from here and makes
/// inference ambiguous.
#[cfg(all(feature = "aws_lc_rs", not(feature = "rust_crypto")))]
#[test]
fn aws_lc_rs_only_build_installs_aws_lc_rs() {
    assert!(std::ptr::eq(
        super::preferred_provider(),
        &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
    ));
}

/// The same for the default build: RustCrypto is named explicitly, not inferred.
#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc_rs")))]
#[test]
fn rust_crypto_only_build_installs_rust_crypto() {
    assert!(std::ptr::eq(
        super::preferred_provider(),
        &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
    ));
}

/// Installing twice is not an error the caller has to think about: the first
/// choice stands and the second call is a no-op.
#[test]
fn installing_twice_is_harmless() {
    super::install_default_crypto_provider();
    super::install_default_crypto_provider();
}
