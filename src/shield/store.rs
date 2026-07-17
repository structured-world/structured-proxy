//! In-process GCRA state store.
//!
//! Holds one value per key: the theoretical arrival time (TAT), as milliseconds
//! since the store's base instant. The check is synchronous and lock-free across
//! keys (a `DashMap` shard lock is held only for the single key being updated),
//! so it adds no measurable latency to the request path.
//!
//! This is always the authority for the local limit decision. Cross-instance
//! reconciliation, when enabled, sits beside it and is updated asynchronously;
//! it never turns this check into a blocking operation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry;

use super::gcra::{Gcra, Verdict};

/// Run eviction of drained entries at most once per this interval.
const SWEEP_INTERVAL_MS: u64 = 60_000;

/// In-process per-instance GCRA store.
// no-std: caller-provided Clock + spin/hashbrown map.
#[derive(Debug)]
pub struct GcraStore {
    /// key → TAT in nanoseconds since `base`.
    tats: dashmap::DashMap<String, u64>,
    base: Instant,
    last_sweep_ms: AtomicU64,
}

impl Default for GcraStore {
    fn default() -> Self {
        Self::new()
    }
}

impl GcraStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            tats: dashmap::DashMap::new(),
            base: Instant::now(),
            last_sweep_ms: AtomicU64::new(0),
        }
    }

    /// Evaluate one request for `key` against `gcra`, recording the new TAT when
    /// the request is admitted.
    pub fn check(&self, key: &str, gcra: &Gcra) -> Verdict {
        let now = self.now();
        self.maybe_sweep(now);

        match self.tats.entry(key.to_string()) {
            Entry::Occupied(mut o) => {
                let stored = Some(Duration::from_nanos(*o.get()));
                let verdict = gcra.check(stored, now);
                if verdict.allowed {
                    *o.get_mut() = dur_nanos(verdict.new_tat);
                }
                verdict
            }
            Entry::Vacant(v) => {
                let verdict = gcra.check(None, now);
                if verdict.allowed {
                    v.insert(dur_nanos(verdict.new_tat));
                }
                verdict
            }
        }
    }

    /// Milliseconds elapsed since the store's base instant.
    fn now(&self) -> Duration {
        self.base.elapsed()
    }

    /// Drop entries whose TAT is in the past: a key with `TAT <= now` has fully
    /// drained and is indistinguishable from a first-seen key, so re-inserting it
    /// on the next hit yields the same result. Without eviction, client-controlled
    /// key cardinality (IP / principal) would grow the map without bound.
    fn evict_drained(&self, now: Duration) {
        let now_nanos = dur_nanos(now);
        self.tats.retain(|_, tat| *tat > now_nanos);
    }

    /// Evict at most once per [`SWEEP_INTERVAL_MS`]; the first caller past the
    /// interval claims the sweep so it stays an infrequent O(n) pass.
    fn maybe_sweep(&self, now: Duration) {
        let now_ms = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < SWEEP_INTERVAL_MS {
            return;
        }
        if self
            .last_sweep_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.evict_drained(now);
        }
    }

    /// Number of live entries (test/introspection helper).
    #[cfg(test)]
    fn len(&self) -> usize {
        self.tats.len()
    }
}

/// A `Duration` as whole nanoseconds, saturating at `u64::MAX`. Nanosecond TATs
/// preserve precision for sub-millisecond emission intervals (very high rates);
/// `u64` nanoseconds span ~584 years, far beyond any process uptime.
fn dur_nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gcra(rate: u64, burst: u64) -> Gcra {
        Gcra::from_profile(super::super::gcra::Profile {
            rate,
            window: Duration::from_secs(60),
            burst,
        })
    }

    #[test]
    fn admits_burst_then_blocks() {
        let store = GcraStore::new();
        let g = gcra(60, 2); // 1/s, burst 2
        assert!(store.check("k", &g).allowed);
        assert!(store.check("k", &g).allowed);
        // Burst of 2 spent within the same millisecond window.
        assert!(!store.check("k", &g).allowed);
    }

    #[test]
    fn keys_are_independent() {
        let store = GcraStore::new();
        let g = gcra(60, 1); // burst 1
        assert!(store.check("a", &g).allowed);
        assert!(store.check("b", &g).allowed);
        assert!(!store.check("a", &g).allowed);
    }

    #[test]
    fn eviction_reclaims_drained_keys() {
        let store = GcraStore::new();
        let g = gcra(600, 1); // 10/s → 100ms emission, burst 1
        store.check("a", &g);
        store.check("b", &g);
        assert_eq!(store.len(), 2);
        // Force the base far into the past so both TATs are drained, then sweep.
        std::thread::sleep(Duration::from_millis(120));
        store.evict_drained(store.now());
        assert_eq!(store.len(), 0);
    }
}
