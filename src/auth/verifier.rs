//! The built-in [`TokenVerifier`]: keys from config, verification via
//! `jsonwebtoken`.
//!
//! Compiled only with the `builtin_jwt` feature (implied by `rust_crypto` /
//! `aws_lc_rs`). Without it the crate links no JWT crypto, and `auth.mode:
//! "jwt"` requires a verifier injected by the embedder instead.

use std::sync::Arc;

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde_json::Value;

use super::jwks::JwksCache;
use crate::config::JwtConfig;

/// Where verifying keys come from.
enum KeySource {
    /// A single Ed25519 public key (EdDSA).
    Pem(Arc<DecodingKey>),
    /// Keys discovered from a JWKS endpoint, selected by `kid`.
    Jwks(JwksCache),
}

/// Config-driven verifier: a static PEM key or a JWKS endpoint, plus the
/// expected issuer and audience applied to every token.
pub(crate) struct ConfigVerifier {
    keys: KeySource,
    issuer: Option<String>,
    audience: Option<String>,
}

impl ConfigVerifier {
    /// Build from the `auth.jwt` block.
    ///
    /// # Errors
    /// Returns an error string when no key source is configured, the PEM file
    /// cannot be read, or it is not a valid Ed25519 public key.
    pub(crate) fn build(jwt: &JwtConfig) -> Result<Self, String> {
        // Normally settled in `ProxyServer::from_config` already; repeated here
        // because a verifier can also be built without going through the
        // server, and the call costs one atomic once the provider is in place.
        super::crypto::install_default_crypto_provider();

        let keys = if let Some(uri) = &jwt.jwks_uri {
            KeySource::Jwks(JwksCache::new(uri.clone()))
        } else if let Some(pem_path) = &jwt.public_key_pem_file {
            let pem = std::fs::read(pem_path)
                .map_err(|e| format!("failed to read auth.jwt.public_key_pem_file: {e}"))?;
            let key = DecodingKey::from_ed_pem(&pem)
                .map_err(|e| format!("invalid Ed25519 public key PEM: {e}"))?;
            KeySource::Pem(Arc::new(key))
        } else {
            return Err("auth.jwt requires either jwks_uri or public_key_pem_file".to_string());
        };

        Ok(Self {
            keys,
            issuer: jwt.issuer.clone(),
            audience: jwt.audience.clone(),
        })
    }

    /// Verify a token and return its claims, or `None` if invalid.
    ///
    /// Inherent rather than an impl of [`TokenVerifier`](crate::hooks::TokenVerifier):
    /// this is the default path, and calling it directly keeps the boxed future
    /// an `#[async_trait]` object would cost off every verification.
    pub(crate) async fn verify(&self, token: &str) -> Option<Value> {
        let header = decode_header(token).ok()?;
        let (key, algorithm) = match &self.keys {
            KeySource::Pem(k) => (k.clone(), Algorithm::EdDSA),
            KeySource::Jwks(cache) => {
                let kid = header.kid.as_deref()?;
                let vk = cache.key_for(kid).await?;
                (vk.key, vk.algorithm)
            }
        };
        // Reject algorithm confusion: the token must use the key's algorithm.
        if header.alg != algorithm {
            return None;
        }

        let mut validation = Validation::new(algorithm);
        if let Some(iss) = &self.issuer {
            validation.set_issuer(&[iss]);
        }
        match &self.audience {
            Some(aud) => validation.set_audience(&[aud]),
            None => validation.validate_aud = false,
        }

        decode::<Value>(token, &key, &validation)
            .ok()
            .map(|data| data.claims)
    }
}
