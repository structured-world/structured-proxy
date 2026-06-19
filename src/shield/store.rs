//! Rate-limit counter storage.
//!
//! [`RateLimitStore`] abstracts where per-key counters live. [`MemoryStore`] is
//! the default and keeps counters in-process (per replica). [`RedisStore`]
//! (behind the `redis` feature) shares counters across replicas, which is what
//! a multi-instance deployment behind a load balancer needs for correct global
//! limits.

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
/// single instance. Use [`RedisStore`] for multi-instance deployments.
#[derive(Debug, Default)]
pub struct MemoryStore {
    // no-std: caller-provided Clock + spin/hashbrown map.
    windows: dashmap::DashMap<String, Window>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: std::time::Instant,
    count: u64,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl RateLimitStore for MemoryStore {
    async fn hit(&self, key: &str, rate: &Rate) -> Decision {
        let now = std::time::Instant::now();
        let mut entry = self.windows.entry(key.to_string()).or_insert(Window {
            start: now,
            count: 0,
        });

        // Reset the counter once the current window has elapsed.
        if now.duration_since(entry.start) >= rate.window {
            entry.start = now;
            entry.count = 0;
        }
        entry.count += 1;

        let count = entry.count;
        let elapsed = now.duration_since(entry.start);
        drop(entry);

        let allowed = count <= rate.limit;
        Decision {
            allowed,
            limit: rate.limit,
            remaining: rate.limit.saturating_sub(count),
            retry_after: (!allowed).then(|| rate.window.saturating_sub(elapsed)),
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
}

#[cfg(feature = "redis")]
#[async_trait::async_trait]
impl RateLimitStore for RedisStore {
    async fn hit(&self, key: &str, rate: &Rate) -> Decision {
        use redis::AsyncCommands;
        let window_secs = rate.window.as_secs().max(1);
        let mut conn = match self.connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("rate-limit store unavailable, allowing request: {e}");
                return Decision {
                    allowed: true,
                    limit: rate.limit,
                    remaining: rate.limit,
                    retry_after: None,
                };
            }
        };

        // INCR then set the TTL on the first hit of a window. The key expiring
        // is what rolls the window over.
        let count: u64 = match conn.incr(key, 1u64).await {
            Ok(c) => c,
            // Fail open: a Redis outage must not take down the proxy.
            Err(e) => {
                tracing::warn!("rate-limit store unavailable, allowing request: {e}");
                return Decision {
                    allowed: true,
                    limit: rate.limit,
                    remaining: rate.limit,
                    retry_after: None,
                };
            }
        };
        if count == 1 {
            let _: Result<(), _> = conn.expire(key, window_secs as i64).await;
        }

        let allowed = count <= rate.limit;
        let retry_after = if allowed {
            None
        } else {
            let ttl: i64 = conn.ttl(key).await.unwrap_or(window_secs as i64);
            Some(Duration::from_secs(ttl.max(0) as u64))
        };
        Decision {
            allowed,
            limit: rate.limit,
            remaining: rate.limit.saturating_sub(count),
            retry_after,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
