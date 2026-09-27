use super::*;
use serde_json::json;

const NOW: u64 = 1_800_000_000;
const STARTED: u64 = 1_000;

fn config(max_entries: usize, max_ttl_secs: u64) -> JwtCacheConfig {
    JwtCacheConfig {
        enabled: true,
        max_entries,
        max_ttl_secs,
        max_token_bytes: 4096,
    }
}

fn cache(max_entries: usize, max_ttl_secs: u64) -> ClaimsCache {
    ClaimsCache::build(&config(max_entries, max_ttl_secs))
        .unwrap()
        .unwrap()
}

/// `secs` after `NOW`, with both clocks running together.
fn at(secs: u64) -> Now {
    Now {
        unix: NOW + secs,
        mono: STARTED + secs,
    }
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
    cache.insert(key(1), &stored, at(0));
    let hit = cache.get(&key(1), at(29)).unwrap();
    // Shared, not copied.
    assert!(Arc::ptr_eq(&hit, &stored));
    // At `exp` the entry is no longer used, and it is dropped.
    assert!(cache.get(&key(1), at(30)).is_none());
    assert_eq!(cache.len(), 0);
}

#[test]
fn max_ttl_bounds_a_long_lived_token() {
    let cache = cache(10, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 86_400})), at(0));
    assert!(cache.get(&key(1), at(59)).is_some());
    assert!(cache.get(&key(1), at(60)).is_none());
}

#[test]
fn wall_clock_set_back_does_not_extend_max_ttl() {
    // 60 real seconds after the insert, with the wall clock set back 30
    // seconds: the entry is as old as the configured maximum, whatever the
    // wall clock says.
    let cache = cache(10, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 86_400})), at(0));
    let set_back = Now {
        unix: NOW + 30,
        mono: STARTED + 60,
    };
    assert!(cache.get(&key(1), set_back).is_none());
}

#[test]
fn exp_follows_the_wall_clock() {
    // `exp` is a wall-clock time: a wall clock that reaches it ends the entry
    // even when little time has passed on the monotonic clock.
    let cache = cache(10, 3600);
    cache.insert(key(1), &claims(json!({"exp": NOW + 30})), at(0));
    let jumped = Now {
        unix: NOW + 30,
        mono: STARTED + 1,
    };
    assert!(cache.get(&key(1), jumped).is_none());
}

#[test]
fn unknown_token_misses() {
    let cache = cache(10, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 30})), at(0));
    assert!(cache.get(&key(2), at(0)).is_none());
}

#[test]
fn tokens_that_must_not_be_cached_are_not() {
    let cache = cache(10, 60);
    // No exp.
    cache.insert(key(1), &claims(json!({"sub": "u"})), at(0));
    // Not yet valid.
    cache.insert(
        key(2),
        &claims(json!({"exp": NOW + 30, "nbf": NOW + 1})),
        at(0),
    );
    // Already expired (accepted only through the verifier's leeway).
    cache.insert(key(3), &claims(json!({"exp": NOW})), at(0));
    cache.insert(key(4), &claims(json!({"exp": NOW - 10})), at(0));
    // exp that is not a NumericDate.
    cache.insert(key(5), &claims(json!({"exp": "tomorrow"})), at(0));
    cache.insert(key(6), &claims(json!({"exp": -5})), at(0));
    assert_eq!(cache.len(), 0);
    for n in 1..=6 {
        assert!(cache.get(&key(n), at(0)).is_none(), "token {n}");
    }
}

#[test]
fn nbf_in_the_past_and_fractional_exp_are_accepted() {
    let cache = cache(10, 60);
    cache.insert(
        key(1),
        &claims(json!({"exp": NOW + 30, "nbf": NOW - 5})),
        at(0),
    );
    // A fractional NumericDate counts in whole seconds, rounded down.
    cache.insert(
        key(2),
        &claims(json!({"exp": (NOW + 10) as f64 + 0.9})),
        at(0),
    );
    assert!(cache.get(&key(1), at(0)).is_some());
    assert!(cache.get(&key(2), at(9)).is_some());
    assert!(cache.get(&key(2), at(10)).is_none());
}

#[test]
fn only_tokens_within_the_size_limit_are_admitted() {
    let cache = ClaimsCache::build(&JwtCacheConfig {
        max_token_bytes: 8,
        ..config(10, 60)
    })
    .unwrap()
    .unwrap();
    assert!(cache.admits("12345678"));
    assert!(!cache.admits("123456789"));
}

#[test]
fn full_cache_of_live_entries_stores_nothing_more() {
    let cache = cache(3, 60);
    for n in 0..3 {
        cache.insert(key(n), &claims(json!({"exp": NOW + 30})), at(0));
    }
    cache.insert(key(9), &claims(json!({"exp": NOW + 30})), at(0));
    assert_eq!(cache.len(), 3);
    assert!(cache.get(&key(9), at(0)).is_none());
    // The entries already there stay usable.
    assert!(cache.get(&key(0), at(0)).is_some());
}

#[test]
fn full_cache_sweeps_expired_entries_to_make_room() {
    let cache = cache(3, 60);
    for n in 0..3 {
        cache.insert(key(n), &claims(json!({"exp": NOW + 5})), at(0));
    }
    cache.insert(key(9), &claims(json!({"exp": NOW + 60})), at(10));
    assert!(cache.get(&key(9), at(10)).is_some());
    assert_eq!(cache.len(), 1);
}

#[test]
fn late_callers_do_not_repeat_a_sweep() {
    // A full cache, one entry of which ends at NOW + 100.
    let cache = cache(3, 3600);
    for n in 0..2 {
        cache.insert(key(n), &claims(json!({"exp": NOW + 3600})), at(0));
    }
    cache.insert(key(2), &claims(json!({"exp": NOW + 100})), at(0));

    // Sweeps at second 10 and frees nothing.
    cache.insert(key(9), &claims(json!({"exp": NOW + 3600})), at(10));
    // A caller that read the clock before that sweep, then one in the same
    // second as it: neither sweeps again, even though the second one's wall
    // clock is past the short entry's `exp`.
    cache.insert(key(10), &claims(json!({"exp": NOW + 3600})), at(9));
    let same_second = Now {
        unix: NOW + 200,
        mono: STARTED + 10,
    };
    cache.insert(key(11), &claims(json!({"exp": NOW + 3600})), same_second);
    assert!(cache.get(&key(11), same_second).is_none());
    assert_eq!(cache.len(), 3);

    // The next second sweeps, and the freed slot takes the new token.
    let next_second = Now {
        unix: NOW + 200,
        mono: STARTED + 11,
    };
    cache.insert(key(12), &claims(json!({"exp": NOW + 3600})), next_second);
    assert!(cache.get(&key(12), next_second).is_some());
    assert_eq!(cache.len(), 3);
}

#[test]
fn storing_the_same_token_twice_takes_one_slot() {
    let cache = cache(2, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 30})), at(0));
    cache.insert(key(1), &claims(json!({"exp": NOW + 30})), at(0));
    // The second slot is still free.
    cache.insert(key(2), &claims(json!({"exp": NOW + 30})), at(0));
    assert!(cache.get(&key(2), at(0)).is_some());
    assert_eq!(cache.len(), 2);
}

#[test]
fn expired_lookups_give_their_slot_back() {
    let cache = cache(1, 60);
    cache.insert(key(1), &claims(json!({"exp": NOW + 5})), at(0));
    assert!(cache.get(&key(1), at(5)).is_none());
    cache.insert(key(2), &claims(json!({"exp": NOW + 60})), at(5));
    assert!(cache.get(&key(2), at(5)).is_some());
}

#[test]
fn concurrent_inserts_never_exceed_the_limit() {
    let cache = Arc::new(cache(50, 60));
    let threads: Vec<_> = (0..8u32)
        .map(|t| {
            let cache = cache.clone();
            std::thread::spawn(move || {
                for n in 0..200 {
                    cache.insert(key(t * 1000 + n), &claims(json!({"exp": NOW + 30})), at(0));
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
    let no_bytes = JwtCacheConfig {
        max_token_bytes: 0,
        ..config(10, 60)
    };
    for bad in [config(0, 60), config(10, 0), no_bytes] {
        let Err(err) = ClaimsCache::build(&bad) else {
            panic!("a zero-sized cache must be rejected");
        };
        assert!(err.contains("enabled: false"), "{err}");
    }
}

#[test]
fn now_reads_both_clocks() {
    let cache = cache(10, 60);
    let now = cache.now();
    assert!(now.unix > NOW - 1_000_000_000, "{now:?}");
    assert!(now.mono < 60, "{now:?}");
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
