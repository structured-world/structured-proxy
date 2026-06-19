//! JWKS fetching and key cache.
//!
//! Keys are fetched from the configured JWKS URI and cached by `kid`. An unknown
//! `kid` triggers a refresh (throttled), which is how key rotation is picked up.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey};
use tokio::sync::RwLock;

/// A decoding key plus the signature algorithm it is valid for.
#[derive(Clone)]
pub struct VerifyingKey {
    pub key: Arc<DecodingKey>,
    pub algorithm: Algorithm,
}

/// Fetches and caches JWKS keys by `kid`.
pub struct JwksCache {
    uri: String,
    client: reqwest::Client,
    keys: RwLock<HashMap<String, VerifyingKey>>,
    last_refresh: RwLock<Option<Instant>>,
}

/// Minimum spacing between refreshes triggered by an unknown `kid`, so a flood
/// of bogus `kid`s cannot hammer the JWKS endpoint.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

impl JwksCache {
    /// Create a cache for `uri` (keys are loaded lazily on first lookup).
    pub fn new(uri: String) -> Self {
        Self {
            uri,
            client: reqwest::Client::new(),
            keys: RwLock::new(HashMap::new()),
            last_refresh: RwLock::new(None),
        }
    }

    /// Resolve the verifying key for `kid`, refreshing from the JWKS endpoint
    /// once (throttled) if it is not already cached.
    pub async fn key_for(&self, kid: &str) -> Option<VerifyingKey> {
        if let Some(k) = self.keys.read().await.get(kid).cloned() {
            return Some(k);
        }
        if self.refresh().await.is_err() {
            return None;
        }
        self.keys.read().await.get(kid).cloned()
    }

    /// Fetch the JWKS and replace the cache. Throttled by [`MIN_REFRESH_INTERVAL`]
    /// unless the cache is still empty (first load).
    async fn refresh(&self) -> Result<(), String> {
        {
            let last = self.last_refresh.read().await;
            if let Some(t) = *last {
                let empty = self.keys.read().await.is_empty();
                if !empty && t.elapsed() < MIN_REFRESH_INTERVAL {
                    return Err("refresh throttled".to_string());
                }
            }
        }
        *self.last_refresh.write().await = Some(Instant::now());

        let set: JwkSet = self
            .client
            .get(&self.uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("JWKS decode failed: {e}"))?;

        let new_keys = parse_jwks(&set);
        *self.keys.write().await = new_keys;
        Ok(())
    }
}

/// Build the `kid → VerifyingKey` map from a JWK set, skipping keys without a
/// `kid`, symmetric keys, or those that fail to convert.
fn parse_jwks(set: &JwkSet) -> HashMap<String, VerifyingKey> {
    let mut map = HashMap::new();
    for jwk in &set.keys {
        let Some(kid) = jwk.common.key_id.clone() else {
            continue;
        };
        let Some(algorithm) = algorithm_for(&jwk.algorithm) else {
            continue;
        };
        if let Ok(key) = DecodingKey::from_jwk(jwk) {
            map.insert(
                kid,
                VerifyingKey {
                    key: Arc::new(key),
                    algorithm,
                },
            );
        }
    }
    map
}

/// Pick the signature algorithm implied by a key's type. Symmetric keys
/// (`OctetKey`) are rejected: HMAC secrets do not belong in a public JWKS.
fn algorithm_for(params: &AlgorithmParameters) -> Option<Algorithm> {
    match params {
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(_) => Some(Algorithm::ES256),
        AlgorithmParameters::OctetKeyPair(_) => Some(Algorithm::EdDSA),
        AlgorithmParameters::OctetKey(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_jwks_keeps_asymmetric_keys_and_maps_algorithms() {
        // A minimal RSA JWK with a kid (values are a real test key from the
        // jsonwebtoken test vectors).
        let set: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "rsa-1",
                "use": "sig",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368Qen-JS7-zw04o6sJ9qjp6lFm5_T4nzcCqRfMOgRA_g_S0d7e9k7B0v0vqHr0e1V_o-z0ow5dWpql8-zKj4hQp8sg_Pn8O0R5ZQS4t8hUE-3-r3ftt1YzQ",
                "e": "AQAB"
            }]
        })).unwrap();
        let keys = parse_jwks(&set);
        assert!(keys.contains_key("rsa-1"));
        assert_eq!(keys["rsa-1"].algorithm, Algorithm::RS256);
    }

    #[test]
    fn parse_jwks_skips_symmetric_and_keyless() {
        let set: JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [
                { "kty": "oct", "kid": "hmac", "k": "c2VjcmV0" },
                { "kty": "RSA", "n": "0vx7ag", "e": "AQAB" }
            ]
        }))
        .unwrap();
        // Symmetric key rejected; RSA without a kid skipped.
        assert!(parse_jwks(&set).is_empty());
    }
}
