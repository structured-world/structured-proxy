/// The selection itself, read before anything installs a provider. Verifying a
/// token proves only that *some* provider is installed (both backends do
/// EdDSA), so the choice is asserted here at its own seam.
///
/// With both backends linked it must be `aws_lc_rs`, the constant-time and
/// advisory-free one.
#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
#[test]
fn tie_break_selects_aws_lc_rs() {
    assert!(
        std::ptr::eq(
            super::preferred_provider(),
            &jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
        ),
        "the tie-break must select the aws_lc_rs provider"
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
        sid_crypto::jwt::rustcrypto::provider()
    ));
}

/// Installing twice is not an error the caller has to think about: the first
/// choice stands and the second call is a no-op.
#[test]
fn installing_twice_is_harmless() {
    super::install_default_crypto_provider();
    super::install_default_crypto_provider();
}

/// A proxy without `auth:` uses no JWT and leaves the process-wide jsonwebtoken
/// provider to the host: an application with its own token checks must keep
/// its own choice. The probe install succeeds only if nothing installed one
/// first (each test runs in its own process).
#[test]
fn a_proxy_without_auth_installs_no_jwt_provider() {
    let service = crate::ProxyServer::from_yaml_str("service:\n  name: demo\n")
        .unwrap()
        .service(tonic::service::Routes::default())
        .unwrap();
    drop(service);
    assert!(
        super::preferred_provider().install_default().is_ok(),
        "building a proxy without auth must not install a jsonwebtoken provider"
    );
}

/// The built-in verifier, once built, has the provider it verifies with.
#[test]
fn building_the_builtin_verifier_installs_the_provider() {
    let jwt = crate::config::JwtConfig {
        jwks_uri: Some("https://issuer.example/jwks".into()),
        jwks_max_age_secs: 300,
        issuer: None,
        audience: None,
        public_key_pem_file: None,
        claims_headers: Default::default(),
        roles_claim: "roles".into(),
        cache: Default::default(),
    };
    super::super::verifier::ConfigVerifier::build(&jwt).unwrap();
    assert!(super::preferred_provider().install_default().is_err());
}

/// RSA public verification does not authorize any local RSA signer factory.
#[cfg(all(feature = "rust_crypto", not(feature = "aws_lc_rs")))]
#[test]
fn rust_crypto_refuses_rsa_signer_factories() {
    use jsonwebtoken::{Algorithm, EncodingKey};
    let key = EncodingKey::from_rsa_der(&[]);
    for algorithm in [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ] {
        assert!((super::preferred_provider().signer_factory)(&algorithm, &key).is_err());
    }
}
