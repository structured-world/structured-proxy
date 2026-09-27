use super::*;
use serde_json::json;

const NOW: u64 = 1_800_000_000;

fn config(max_entries: usize, max_ttl_secs: u64) -> JwtCacheConfig {
    JwtCacheConfig {
        enabled: true,
        max_entries,
        max_ttl_secs,
    }
}

fn cache(max_entries: usize, max_ttl_secs: u64) -> ClaimsCache {
    ClaimsCache::build(&config(max_entries, max_ttl_secs))
        .unwrap()
        .unwrap()
}

fn claims(value: Value) -> Arc<Value> {
    Arc::new(value)
}

fn key(n: u32) -> TokenKey {
    token_key(&format!("token-{n}"))
}

#[test]
fn hit_returns_the_same_claims_until_exp() {
    let cache = cache(10, 3600);
    let stored = claims(json!({"sub": "u", "exp": NOW + 30}));
    cache.insert(key(1), &stored, NOW);
    let hit = cache.get(&key(1), NOW + 29).unwrap();
    // Shared, not copied.
    assert!(Arc::ptr_eq(&hit, &stored));
    // At `exp` the entry is no longer used, and it is dropped.
    assert!(cache.get(&key(1), NOW + 30).is_none());
    assert_eq!(cache.len(), 0);
}

#[test]
fn max_ttl_bounds_a_long_lived_token() {
    let cache = cache(10, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 86_400})), NOW);
    assert!(cache.get(&key(1), NOW + 59).is_some());
    assert!(cache.get(&key(1), NOW + 60).is_none());
}

#[test]
fn unknown_token_misses() {
    let cache = cache(10, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 30})), NOW);
    assert!(cache.get(&key(2), NOW).is_none());
}

#[test]
fn tokens_that_must_not_be_cached_are_not() {
    let cache = cache(10, 60);
    // No exp.
    cache.insert(key(1), &claims(json!({"sub": "u"})), NOW);
    // Not yet valid.
    cache.insert(
        key(2),
        &claims(json!({"exp": NOW + 30, "nbf": NOW + 1})),
        NOW,
    );
    // Already expired (accepted only through the verifier's leeway).
    cache.insert(key(3), &claims(json!({"exp": NOW})), NOW);
    cache.insert(key(4), &claims(json!({"exp": NOW - 10})), NOW);
    // exp that is not a NumericDate.
    cache.insert(key(5), &claims(json!({"exp": "tomorrow"})), NOW);
    cache.insert(key(6), &claims(json!({"exp": -5})), NOW);
    assert_eq!(cache.len(), 0);
    for n in 1..=6 {
        assert!(cache.get(&key(n), NOW).is_none(), "token {n}");
    }
}

#[test]
fn nbf_in_the_past_and_fractional_exp_are_accepted() {
    let cache = cache(10, 60);
    cache.insert(
        key(1),
        &claims(json!({"exp": NOW + 30, "nbf": NOW - 5})),
        NOW,
    );
    // A fractional NumericDate counts in whole seconds, rounded down.
    cache.insert(
        key(2),
        &claims(json!({"exp": (NOW + 10) as f64 + 0.9})),
        NOW,
    );
    assert!(cache.get(&key(1), NOW).is_some());
    assert!(cache.get(&key(2), NOW + 9).is_some());
    assert!(cache.get(&key(2), NOW + 10).is_none());
}

#[test]
fn full_cache_of_live_entries_stores_nothing_more() {
    let cache = cache(3, 60);
    for n in 0..3 {
        cache.insert(key(n), &claims(json!({"exp": NOW + 30})), NOW);
    }
    cache.insert(key(9), &claims(json!({"exp": NOW + 30})), NOW);
    assert_eq!(cache.len(), 3);
    assert!(cache.get(&key(9), NOW).is_none());
    // The entries already there stay usable.
    assert!(cache.get(&key(0), NOW).is_some());
}

#[test]
fn full_cache_sweeps_expired_entries_to_make_room() {
    let cache = cache(3, 60);
    for n in 0..3 {
        cache.insert(key(n), &claims(json!({"exp": NOW + 5})), NOW);
    }
    cache.insert(key(9), &claims(json!({"exp": NOW + 60})), NOW + 10);
    assert!(cache.get(&key(9), NOW + 10).is_some());
    assert_eq!(cache.len(), 1);
}

#[test]
fn storing_the_same_token_twice_takes_one_slot() {
    let cache = cache(2, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 30})), NOW);
    cache.insert(key(1), &claims(json!({"exp": NOW + 30})), NOW);
    // The second slot is still free.
    cache.insert(key(2), &claims(json!({"exp": NOW + 30})), NOW);
    assert!(cache.get(&key(2), NOW).is_some());
    assert_eq!(cache.len(), 2);
}

#[test]
fn expired_lookups_give_their_slot_back() {
    let cache = cache(1, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 5})), NOW);
    assert!(cache.get(&key(1), NOW + 5).is_none());
    cache.insert(key(2), &claims(json!({"exp": NOW + 60})), NOW + 5);
    assert!(cache.get(&key(2), NOW + 5).is_some());
}

#[test]
fn concurrent_inserts_never_exceed_the_limit() {
    let cache = Arc::new(cache(50, 60));
    let threads: Vec<_> = (0..8u32)
        .map(|t| {
            let cache = cache.clone();
            std::thread::spawn(move || {
                for n in 0..200 {
                    cache.insert(key(t * 1000 + n), &claims(json!({"exp": NOW + 30})), NOW);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    assert_eq!(cache.len(), 50);
}

#[test]
fn switched_off_or_empty_config() {
    let disabled = JwtCacheConfig {
        enabled: false,
        ..config(10, 60)
    };
    assert!(ClaimsCache::build(&disabled).unwrap().is_none());
    for bad in [config(0, 60), config(10, 0)] {
        let Err(err) = ClaimsCache::build(&bad) else {
            panic!("a zero-sized cache must be rejected");
        };
        assert!(err.contains("enabled: false"), "{err}");
    }
}

#[test]
fn token_key_is_the_sha256_of_the_token() {
    assert_eq!(token_key("a"), token_key("a"));
    assert_ne!(token_key("a"), token_key("b"));
    assert_eq!(
        token_key("abc")[..4],
        [0xba, 0x78, 0x16, 0xbf],
        "SHA-256(\"abc\") starts ba7816bf"
    );
}
