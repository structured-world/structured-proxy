//! Rate-limit counter storage.
//!
//! [`RateLimitStore`] abstracts where per-key counters live. [`MemoryStore`] is
//! the default and keeps counters in-process (per replica).
// The `RedisStore` reference is an intra-doc link only when the `redis` feature
// (and thus the type) is compiled in; otherwise a plain code span, so `cargo
// doc` stays warning-free in every feature combination.
#![cfg_attr(
    feature = "redis",
    doc = "[`RedisStore`] (behind the `redis` feature) shares counters across replicas, which is what a multi-instance deployment behind a load balancer needs for correct global limits."
)]
#![cfg_attr(
    not(feature = "redis"),
    doc = "`RedisStore` (behind the `redis` feature) shares counters across replicas, which is what a multi-instance deployment behind a load balancer needs for correct global limits."
)]

use std::time::Duration;

use super::rate::Rate;

/// Outcome of recording one request against a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Whether the request is within the limit.
    pub allowed: bool,
    /// The configured limit (for the `X-RateLimit-Limit` header).
    pub limit: u64,
    /// Requests remaining in the current window (0 once exceeded).
    pub remaining: u64,
    /// How long until the window resets, when the request is rejected.
    pub retry_after: Option<Duration>,
}

/// A backend that records request hits and decides whether each is allowed.
#[async_trait::async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Record one hit for `key` and return the limiting decision for `rate`.
    ///
    /// A store that cannot reach its backend should fail open (allow the
    /// request) rather than reject legitimate traffic.
    async fn hit(&self, key: &str, rate: &Rate) -> Decision;
}

/// In-process fixed-window counter store (per replica).
///
/// Counters are not shared between replicas, so global limits only hold for a
/// single instance.
#[cfg_attr(
    feature = "redis",
    doc = "Use [`RedisStore`] for multi-instance deployments."
)]
#[cfg_attr(
    not(feature = "redis"),
    doc = "Use `RedisStore` (feature `redis`) for multi-instance deployments."
)]
#[derive(Debug)]
pub struct MemoryStore {
    // no-std: caller-provided Clock + spin/hashbrown map.
    windows: dashmap::DashMap<String, Window>,
    base: std::time::Instant,
    last_sweep_ms: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    expires_at: std::time::Instant,
    count: u64,
}

/// Run eviction of expired entries at most once per this interval.
const SWEEP_INTERVAL_MS: u64 = 60_000;

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            windows: dashmap::DashMap::new(),
            base: std::time::Instant::now(),
            last_sweep_ms: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Drop every entry whose window has elapsed.
    ///
    /// Entries are reset lazily on access, but keys that are never hit again
    /// would otherwise linger forever; with client-controlled key cardinality
    /// (IP / identifier) that is an unbounded-growth / OOM risk.
    fn evict_expired(&self, now: std::time::Instant) {
        self.windows.retain(|_, w| w.expires_at > now);
    }

    /// Evict expired entries at most once per [`SWEEP_INTERVAL_MS`]; the first
    /// thread past the interval claims the sweep so it stays O(n) infrequently.
    fn maybe_sweep(&self, now: std::time::Instant) {
        use std::sync::atomic::Ordering;
        let now_ms = now.duration_since(self.base).as_millis() as u64;
        let last = self.last_sweep_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < SWEEP_INTERVAL_MS {
            return;
        }
        if self
            .last_sweep_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.evict_expired(now);
        }
    }
}

#[async_trait::async_trait]
impl RateLimitStore for MemoryStore {
    async fn hit(&self, key: &str, rate: &Rate) -> Decision {
        let now = std::time::Instant::now();
        self.maybe_sweep(now);

        let mut entry = self.windows.entry(key.to_string()).or_insert(Window {
            expires_at: now + rate.window,
            count: 0,
        });

        // Reset the counter once the current window has elapsed.
        if now >= entry.expires_at {
            entry.expires_at = now + rate.window;
            entry.count = 0;
        }
        entry.count += 1;

        let count = entry.count;
        let expires_at = entry.expires_at;
        drop(entry);

        let allowed = count <= rate.limit;
        Decision {
            allowed,
            limit: rate.limit,
            remaining: rate.limit.saturating_sub(count),
            retry_after: (!allowed).then(|| expires_at.saturating_duration_since(now)),
        }
    }
}

/// Redis-backed fixed-window counter store, shared across replicas.
///
/// The client is opened eagerly (URL validation) but the multiplexed
/// connection is established lazily on first use, so construction stays
/// synchronous and a Redis that is briefly unavailable at startup does not
/// block the proxy from booting.
#[cfg(feature = "redis")]
pub struct RedisStore {
    client: redis::Client,
    conn: tokio::sync::OnceCell<redis::aio::MultiplexedConnection>,
}

#[cfg(feature = "redis")]
impl RedisStore {
    /// Open a Redis client for `url` (e.g. `redis://127.0.0.1/`).
    ///
    /// # Errors
    /// Returns the underlying Redis error when the URL is invalid.
    pub fn open(url: &str) -> redis::RedisResult<Self> {
        Ok(Self {
            client: redis::Client::open(url)?,
            conn: tokio::sync::OnceCell::new(),
        })
    }

    /// Get the shared multiplexed connection, establishing it on first call.
    async fn connection(&self) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
        self.conn
            .get_or_try_init(|| self.client.get_multiplexed_async_connection())
            .await
            .cloned()
    }

    /// Allow the request when Redis is unreachable: an outage must not take the
    /// proxy down.
    fn fail_open(rate: &Rate, err: redis::RedisError) -> Decision {
        tracing::warn!("rate-limit store unavailable, allowing request: {err}");
        Decision {
            allowed: true,
            limit: rate.limit,
            remaining: rate.limit,
            retry_after: None,
        }
    }
}

#[cfg(feature = "redis")]
#[async_trait::async_trait]
impl RateLimitStore for RedisStore {
    async fn hit(&self, key: &str, rate: &Rate) -> Decision {
        let window_ms = rate.window.as_millis().max(1) as u64;
        let mut conn = match self.connection().await {
            Ok(c) => c,
            Err(e) => return Self::fail_open(rate, e),
        };

        // INCR and (re)set the TTL atomically in one round trip. Doing them in
        // separate commands risks an immortal key if INCR lands but EXPIRE does
        // not; the PTTL<0 guard also re-arms the TTL on any key that somehow
        // lost it, so a key can never accumulate increments forever.
        let script = redis::Script::new(
            r"local c = redis.call('INCR', KEYS[1])
              if redis.call('PTTL', KEYS[1]) < 0 then
                redis.call('PEXPIRE', KEYS[1], ARGV[1])
              end
              return {c, redis.call('PTTL', KEYS[1])}",
        );
        let (count, pttl): (i64, i64) =
            match script.key(key).arg(window_ms).invoke_async(&mut conn).await {
                Ok(v) => v,
                Err(e) => return Self::fail_open(rate, e),
            };

        let count = count.max(0) as u64;
        let allowed = count <= rate.limit;
        Decision {
            allowed,
            limit: rate.limit,
            remaining: rate.limit.saturating_sub(count),
            retry_after: (!allowed).then(|| Duration::from_millis(pttl.max(0) as u64)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_evicts_expired_entries() {
        let store = MemoryStore::new();
        let rate = Rate {
            limit: 5,
            window: Duration::from_millis(20),
        };
        store.hit("a", &rate).await;
        store.hit("b", &rate).await;
        assert_eq!(store.windows.len(), 2);

        tokio::time::sleep(Duration::from_millis(30)).await;
        // Both windows have elapsed; eviction reclaims them so the map can't
        // grow without bound from keys that are never hit again.
        store.evict_expired(std::time::Instant::now());
        assert_eq!(store.windows.len(), 0);
    }

    #[tokio::test]
    async fn memory_store_allows_then_blocks_within_window() {
        let store = MemoryStore::new();
        let rate = Rate {
            limit: 2,
            window: Duration::from_secs(60),
        };

        let d1 = store.hit("k", &rate).await;
        assert!(d1.allowed && d1.remaining == 1);
        let d2 = store.hit("k", &rate).await;
        assert!(d2.allowed && d2.remaining == 0);
        let d3 = store.hit("k", &rate).await;
        assert!(!d3.allowed);
        assert_eq!(d3.remaining, 0);
        assert!(d3.retry_after.is_some());
    }

    #[tokio::test]
    async fn memory_store_resets_after_window() {
        let store = MemoryStore::new();
        let rate = Rate {
            limit: 1,
            window: Duration::from_millis(50),
        };

        assert!(store.hit("k", &rate).await.allowed);
        assert!(!store.hit("k", &rate).await.allowed);
        tokio::time::sleep(Duration::from_millis(60)).await;
        // New window: the counter has reset.
        assert!(store.hit("k", &rate).await.allowed);
    }

    #[tokio::test]
    async fn memory_store_isolates_keys() {
        let store = MemoryStore::new();
        let rate = Rate {
            limit: 1,
            window: Duration::from_secs(60),
        };
        assert!(store.hit("a", &rate).await.allowed);
        // A different key has its own independent counter.
        assert!(store.hit("b", &rate).await.allowed);
        assert!(!store.hit("a", &rate).await.allowed);
    }
}
