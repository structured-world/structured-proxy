use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::http::StatusCode;

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
fn algorithm_prefers_explicit_jwk_alg() {
    // An EC key that explicitly declares ES384 must not be pinned to ES256.
    let jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-384", "alg": "ES384", "kid": "k",
        "x": "AAAA", "y": "AAAA"
    }))
    .unwrap();
    assert_eq!(algorithm_for(&jwk), Some(Algorithm::ES384));
}

#[test]
fn algorithm_falls_back_to_curve_not_es256() {
    // No alg field → infer from the curve, not a blanket ES256.
    let jwk: Jwk = serde_json::from_value(serde_json::json!({
        "kty": "EC", "crv": "P-384", "kid": "k", "x": "AAAA", "y": "AAAA"
    }))
    .unwrap();
    assert_eq!(algorithm_for(&jwk), Some(Algorithm::ES384));
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

/// What the test JWKS endpoint answers, and how often it was asked.
struct Endpoint {
    answer: std::sync::Mutex<(StatusCode, serde_json::Value)>,
    fetches: AtomicUsize,
}

impl Endpoint {
    fn answer(&self, status: StatusCode, body: serde_json::Value) {
        *self.answer.lock().unwrap() = (status, body);
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::Relaxed)
    }
}

/// An Ed25519 key set holding `kid` (the public key of RFC 8037 A.2).
fn key_set(kid: &str) -> serde_json::Value {
    serde_json::json!({ "keys": [{
        "kty": "OKP", "crv": "Ed25519", "kid": kid,
        "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }]})
}

/// A local JWKS endpoint serving `key_set("k1")` until told otherwise.
async fn endpoint() -> (Arc<Endpoint>, String) {
    let endpoint = Arc::new(Endpoint {
        answer: std::sync::Mutex::new((StatusCode::OK, key_set("k1"))),
        fetches: AtomicUsize::new(0),
    });
    let served = endpoint.clone();
    let app = axum::Router::new().route(
        "/jwks",
        axum::routing::get(move || {
            let served = served.clone();
            async move {
                served.fetches.fetch_add(1, Ordering::Relaxed);
                let (status, body) = served.answer.lock().unwrap().clone();
                (status, axum::Json(body))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let uri = format!("http://{}/jwks", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, uri)
}

#[tokio::test]
async fn fresh_keys_are_served_from_the_cache() {
    let (endpoint, uri) = endpoint().await;
    let cache = JwksCache::new(uri);
    assert!(cache.key_for("k1").await.is_some());
    assert!(cache.key_for("k1").await.is_some());
    assert_eq!(endpoint.fetches(), 1);
}

#[tokio::test]
async fn a_key_removed_by_the_provider_stops_verifying_once_the_set_ages_out() {
    // The provider drops k1 and no request ever names an unknown kid: the
    // aged set is refetched on the next lookup, and k1 is gone.
    let (endpoint, uri) = endpoint().await;
    let cache = JwksCache::new(uri)
        .with_max_age(Duration::ZERO)
        .with_min_refresh_interval(Duration::ZERO);
    assert!(cache.key_for("k1").await.is_some());
    endpoint.answer(StatusCode::OK, key_set("k2"));
    assert!(cache.key_for("k1").await.is_none());
    assert!(cache.key_for("k2").await.is_some());
}

#[tokio::test]
async fn an_unreachable_provider_keeps_the_known_keys() {
    let (endpoint, uri) = endpoint().await;
    let cache = JwksCache::new(uri)
        .with_max_age(Duration::ZERO)
        .with_min_refresh_interval(Duration::ZERO);
    assert!(cache.key_for("k1").await.is_some());
    endpoint.answer(
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::json!({"error": "down"}),
    );
    assert!(cache.key_for("k1").await.is_some());
    assert_eq!(endpoint.fetches(), 2);
}

#[tokio::test]
async fn aged_keys_refresh_no_more_often_than_the_minimum_interval() {
    // Aged out, but a refresh has just run: the known key is used without
    // another fetch.
    let (endpoint, uri) = endpoint().await;
    let cache = JwksCache::new(uri).with_max_age(Duration::ZERO);
    assert!(cache.key_for("k1").await.is_some());
    assert!(cache.key_for("k1").await.is_some());
    assert_eq!(endpoint.fetches(), 1);
}
