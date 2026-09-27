//! JWKS fetching and key cache.
//!
//! Keys are fetched from the configured JWKS URI and cached by `kid`. An unknown
//! `kid` triggers a refresh (throttled), which is how key rotation is picked up.
//! The cached set also ages out: a lookup after [`JwksCache::with_max_age`]
//! refetches it, so a key the provider has removed stops verifying tokens even
//! when no request ever names an unknown `kid`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey};
use tokio::sync::{Mutex, RwLock};

/// A decoding key plus the signature algorithm it is valid for.
#[derive(Clone)]
pub struct VerifyingKey {
    pub key: Arc<DecodingKey>,
    pub algorithm: Algorithm,
}

/// The keys of the last successful fetch.
#[derive(Default)]
struct KeySet {
    keys: HashMap<String, VerifyingKey>,
    /// When they were fetched; `None` before the first fetch.
    fetched: Option<Instant>,
}

/// Fetches and caches JWKS keys by `kid`.
pub struct JwksCache {
    uri: String,
    client: reqwest::Client,
    set: RwLock<KeySet>,
    last_refresh: Mutex<Option<Instant>>,
    max_age: Duration,
    min_refresh_interval: Duration,
}

/// Minimum spacing between refreshes, so a flood of bogus `kid`s cannot hammer
/// the JWKS endpoint.
pub(crate) const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// Default age after which the cached keys are refetched: the `cache_duration`
/// Envoy's `remote_jwks` uses.
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(300);

/// Bound the worst-case latency of a slow/stalled JWKS endpoint.
const JWKS_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

impl JwksCache {
    /// Create a cache for `uri` (keys are loaded lazily on first lookup), whose
    /// keys are refetched after [`DEFAULT_MAX_AGE`].
    pub fn new(uri: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(JWKS_HTTP_TIMEOUT)
            // Hand reqwest a fully preconfigured rustls backend rather than
            // relying on a process-global default provider: no install ordering
            // constraint, no global side effect, safe for library/test callers.
            .tls_backend_preconfigured(crate::tls::client_config())
            .build()
            .unwrap_or_default();
        Self {
            uri,
            client,
            set: RwLock::new(KeySet::default()),
            last_refresh: Mutex::new(None),
            max_age: DEFAULT_MAX_AGE,
            min_refresh_interval: MIN_REFRESH_INTERVAL,
        }
    }

    /// Refetch the keys once they are older than `max_age`. Refreshes stay
    /// at least a minute apart, so a shorter age behaves as one minute.
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    #[cfg(test)]
    fn with_min_refresh_interval(mut self, interval: Duration) -> Self {
        self.min_refresh_interval = interval;
        self
    }

    /// Resolve the verifying key for `kid`, refreshing from the JWKS endpoint
    /// once (throttled) if it is not cached or the cached keys are too old.
    pub async fn key_for(&self, kid: &str) -> Option<VerifyingKey> {
        {
            let set = self.set.read().await;
            if set.fetched.is_some_and(|t| t.elapsed() < self.max_age) {
                if let Some(key) = set.keys.get(kid) {
                    return Some(key.clone());
                }
            }
        }
        if let Err(reason) = self.refresh().await {
            tracing::debug!(%reason, "JWKS not refetched; using the keys already known");
        }
        // Answer from the current set whatever the refresh did: another
        // request may have replaced it meanwhile, and a key it dropped must
        // not survive in an earlier copy. An unreachable endpoint leaves the
        // set as it was, so the keys already known keep working: failing every
        // token while the provider is down would turn its outage into ours.
        self.set.read().await.keys.get(kid).cloned()
    }

    /// Fetch the JWKS and replace the cache. Throttled by the minimum refresh
    /// interval unless no fetch has succeeded yet (first load); a provider
    /// that answered with no keys has been loaded.
    async fn refresh(&self) -> Result<(), String> {
        // Claim the refresh slot atomically: hold the lock across the throttle
        // check and the timestamp update so concurrent callers cannot all pass.
        {
            let mut last = self.last_refresh.lock().await;
            if let Some(t) = *last {
                let loaded = self.set.read().await.fetched.is_some();
                if loaded && t.elapsed() < self.min_refresh_interval {
                    return Err("refresh throttled".to_string());
                }
            }
            *last = Some(Instant::now());
        }

        let response = self
            .client
            .get(&self.uri)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| format!("JWKS fetch failed: {e}"))?;
        let set: JwkSet = response
            .json()
            .await
            .map_err(|e| format!("JWKS decode failed: {e}"))?;

        *self.set.write().await = KeySet {
            keys: parse_jwks(&set),
            fetched: Some(Instant::now()),
        };
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
        let Some(algorithm) = algorithm_for(jwk) else {
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

/// Pick the signature algorithm for a key.
///
/// The JWK's explicit `alg` is authoritative (so ES384 / RS512 / PS256 keys are
/// not mis-pinned). Without it, fall back to the key type and EC curve.
/// Symmetric keys (`OctetKey`) and unsupported variants are rejected.
fn algorithm_for(jwk: &Jwk) -> Option<Algorithm> {
    if let Some(alg) = jwk.common.key_algorithm.and_then(key_algorithm_to_alg) {
        return Some(alg);
    }
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => Some(Algorithm::RS256),
        AlgorithmParameters::EllipticCurve(ec) => match ec.curve {
            EllipticCurve::P256 => Some(Algorithm::ES256),
            EllipticCurve::P384 => Some(Algorithm::ES384),
            // P-521 (ES512) is not supported by the verifier.
            _ => None,
        },
        AlgorithmParameters::OctetKeyPair(_) => Some(Algorithm::EdDSA),
        AlgorithmParameters::OctetKey(_) => None,
        // The enum is non-exhaustive: key types added upstream are not
        // verifiable here until they are mapped explicitly.
        _ => None,
    }
}

/// Map a JWK signature `alg` to a verifier algorithm, rejecting symmetric and
/// encryption algorithms (only asymmetric signatures are usable from a JWKS).
fn key_algorithm_to_alg(ka: KeyAlgorithm) -> Option<Algorithm> {
    Some(match ka {
        KeyAlgorithm::ES256 => Algorithm::ES256,
        KeyAlgorithm::ES384 => Algorithm::ES384,
        KeyAlgorithm::RS256 => Algorithm::RS256,
        KeyAlgorithm::RS384 => Algorithm::RS384,
        KeyAlgorithm::RS512 => Algorithm::RS512,
        KeyAlgorithm::PS256 => Algorithm::PS256,
        KeyAlgorithm::PS384 => Algorithm::PS384,
        KeyAlgorithm::PS512 => Algorithm::PS512,
        KeyAlgorithm::EdDSA => Algorithm::EdDSA,
        _ => return None,
    })
}

#[cfg(test)]
mod tests;
