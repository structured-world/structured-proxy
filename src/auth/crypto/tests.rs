/// The tie-break itself, read before anything installs a provider: with both
/// backends linked the choice must be `aws_lc_rs`, the constant-time and
/// advisory-free one. Verifying a token proves only that *some* provider is
/// installed (both backends do EdDSA), so the selection is asserted here at its
/// own seam.
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
