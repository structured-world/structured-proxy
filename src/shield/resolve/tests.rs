use super::*;

fn profiles() -> HashMap<String, CompiledProfile> {
    let mut m = HashMap::new();
    m.insert(
        "premium".to_string(),
        profile_from_numbers(1000, 100).unwrap(), // limit 1000
    );
    m
}

fn jwt_limits() -> JwtLimits {
    JwtLimits::from_config(&JwtLimitConfig {
        tier_claim: "ratelimit_tier".to_string(),
        rpm_claim: "ratelimit_rpm".to_string(),
        burst_claim: "ratelimit_burst".to_string(),
    })
}

/// The service's HTTP client needs a rustls provider. A build without a
/// crypto backend links none, so the test process installs the pure-Rust one,
/// as an embedder of such a build would.
fn with_tls_provider() {
    #[cfg(not(any(feature = "rust_crypto", feature = "aws_lc_rs")))]
    {
        use rustls::crypto::CryptoProvider;
        // A concurrent test may have installed it first; either way one is set.
        let installed = rustls_rustcrypto::provider().install_default().is_ok();
        assert!(installed || CryptoProvider::get_default().is_some());
    }
}

#[test]
fn jwt_tier_name_maps_to_profile() {
    let claims = serde_json::json!({ "ratelimit_tier": "premium" });
    let p = jwt_limits().resolve(&claims, &profiles()).unwrap();
    assert_eq!(p.limit, 1000);
}

#[test]
fn jwt_direct_numbers_build_a_profile() {
    let claims = serde_json::json!({ "ratelimit_rpm": 300, "ratelimit_burst": 30 });
    let p = jwt_limits().resolve(&claims, &profiles()).unwrap();
    assert_eq!(p.limit, 300);
}

#[test]
fn jwt_tier_takes_precedence_over_numbers() {
    let claims = serde_json::json!({ "ratelimit_tier": "premium", "ratelimit_rpm": 5 });
    let p = jwt_limits().resolve(&claims, &profiles()).unwrap();
    assert_eq!(p.limit, 1000);
}

#[test]
fn jwt_unknown_tier_falls_through_to_numbers_then_none() {
    // Unknown tier + no numbers → no resolution.
    let claims = serde_json::json!({ "ratelimit_tier": "gold" });
    assert!(jwt_limits().resolve(&claims, &profiles()).is_none());
    // Unknown tier + numbers → numbers win.
    let claims = serde_json::json!({ "ratelimit_tier": "gold", "ratelimit_rpm": 42 });
    assert_eq!(
        jwt_limits().resolve(&claims, &profiles()).unwrap().limit,
        42
    );
}

#[tokio::test]
async fn actively_used_stale_entry_survives_eviction() {
    use crate::config::LimitServiceConfig;
    with_tls_provider();
    let svc = LimitService::build(
        &LimitServiceConfig {
            endpoint: "http://127.0.0.1:0/".to_string(),
            ttl_secs: 1,
            timeout_ms: 50,
        },
        profiles(),
    )
    .unwrap();
    // Simulate a service outage: the last successful fetch was long ago, so
    // `at` is stale and well past evict_after, but the key is still in active
    // use right now.
    let old = Instant::now()
        .checked_sub(Duration::from_secs(600))
        .expect("clock supports the offset");
    svc.cache.insert(
        "k".to_string(),
        Cached {
            profile: Some(profile_from_numbers(10, 10).unwrap()),
            at: old,
            last_access: old,
        },
    );
    let _ = svc.resolve("k");
    svc.sweep();
    assert!(
        svc.cache.contains_key("k"),
        "an actively-used stale entry must not be evicted during an outage"
    );
}

fn service(endpoint: &str) -> Arc<LimitService> {
    with_tls_provider();
    LimitService::build(
        &LimitServiceConfig {
            endpoint: endpoint.to_string(),
            ttl_secs: 60,
            timeout_ms: 50,
        },
        profiles(),
    )
    .unwrap()
}

#[test]
fn service_unknown_tier_falls_through_to_numbers() {
    let svc = service("http://127.0.0.1:9/");
    // Unknown tier but explicit numbers present → numbers win (like JWT).
    let p = svc
        .map_response(LimitResponse {
            tier: Some("gold".to_string()),
            rate_per_min: Some(50),
            burst: None,
        })
        .unwrap();
    assert_eq!(p.limit, 50);
}

#[test]
fn build_rejects_non_http_endpoint() {
    // Syntactically valid URLs that reqwest GET can't use must be rejected.
    for ep in ["redis://127.0.0.1/", "file:///etc/passwd", "ftp://h/x"] {
        let r = LimitService::build(
            &LimitServiceConfig {
                endpoint: ep.to_string(),
                ttl_secs: 60,
                timeout_ms: 50,
            },
            profiles(),
        );
        assert!(r.is_err(), "expected {ep} to be rejected");
    }
}

#[test]
fn build_rejects_malformed_endpoint() {
    let bad = LimitService::build(
        &LimitServiceConfig {
            endpoint: "not a url".to_string(),
            ttl_secs: 60,
            timeout_ms: 50,
        },
        profiles(),
    );
    assert!(bad.is_err());
}

#[test]
fn jwt_zero_rate_is_not_a_usable_limit() {
    // A dynamic rate of 0 must not clamp to 1; it yields no limit so the
    // caller falls through to the next resolver.
    let claims = serde_json::json!({ "ratelimit_rpm": 0 });
    assert!(jwt_limits().resolve(&claims, &profiles()).is_none());
}

#[test]
fn numeric_string_claims_are_accepted() {
    let claims = serde_json::json!({ "ratelimit_rpm": "250" });
    assert_eq!(
        jwt_limits().resolve(&claims, &profiles()).unwrap().limit,
        250
    );
}
