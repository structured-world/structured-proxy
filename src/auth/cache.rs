//! Cache of claims the built-in verifier accepted, so a client that sends the
//! same token on every request pays for one signature check.
//!
//! Keyed by the SHA-256 of the token, so no bearer token is held in memory.
//! An entry is reused until the earlier of the token's `exp` and a configured
//! maximum age, which bounds how long a token keeps passing after its signing
//! key has left the JWKS. Rejected tokens are never stored, so garbage cannot
//! fill it. The size is capped without background work: expired entries are
//! dropped when looked up, and swept when an insert finds the cache full.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::config::JwtCacheConfig;

/// SHA-256 of a token: the cache key.
pub(crate) type TokenKey = [u8; 32];

/// The cache key of `token`.
pub(crate) fn token_key(token: &str) -> TokenKey {
    Sha256::digest(token.as_bytes()).into()
}

/// Seconds since the Unix epoch, the unit of `exp` and `nbf`.
// no-std: caller-provided clock
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

struct Entry {
    claims: Arc<Value>,
    /// First second (Unix time) at which the entry is no longer used.
    expires_at: u64,
}

/// Verified claims by token, bounded in size and age.
pub(crate) struct ClaimsCache {
    entries: DashMap<TokenKey, Entry>,
    /// Slots taken: an insert reserves one before storing, so concurrent
    /// inserts can never take the map past `max_entries`.
    taken: AtomicUsize,
    max_entries: usize,
    max_ttl_secs: u64,
    /// When a full cache was last swept, so a burst of inserts into a cache
    /// full of live entries sweeps at most once per second.
    last_sweep: AtomicU64,
}

impl ClaimsCache {
    /// A cache as `config` describes, or `None` when it is switched off.
    pub(crate) fn build(config: &JwtCacheConfig) -> Result<Option<Self>, String> {
        if !config.enabled {
            return Ok(None);
        }
        if config.max_entries == 0 || config.max_ttl_secs == 0 {
            return Err(
                "auth.jwt.cache.max_entries and max_ttl_secs must be positive; \
                 set enabled: false to turn the cache off"
                    .to_string(),
            );
        }
        Ok(Some(Self {
            entries: DashMap::new(),
            taken: AtomicUsize::new(0),
            max_entries: config.max_entries,
            max_ttl_secs: config.max_ttl_secs,
            last_sweep: AtomicU64::new(0),
        }))
    }

    /// The claims cached for `key`, if the entry is still valid at `now`.
    pub(crate) fn get(&self, key: &TokenKey, now: u64) -> Option<Arc<Value>> {
        {
            let entry = self.entries.get(key)?;
            if entry.expires_at > now {
                return Some(entry.claims.clone());
            }
        }
        if self
            .entries
            .remove_if(key, |_, entry| entry.expires_at <= now)
            .is_some()
        {
            self.taken.fetch_sub(1, Ordering::Relaxed);
        }
        None
    }

    /// Store `claims`, just verified at `now`, for `key`. Nothing is stored
    /// for a token without `exp`, one not yet valid (`nbf` in the future), one
    /// that would expire at once, or when the cache is full of live entries.
    pub(crate) fn insert(&self, key: TokenKey, claims: &Arc<Value>, now: u64) {
        let Some(exp) = numeric_date(claims, "exp") else {
            return;
        };
        if numeric_date(claims, "nbf").is_some_and(|nbf| nbf > now) {
            return;
        }
        // Never beyond `exp`: past it the verifier's own leeway decides. The
        // sum saturates on purpose: a `max_ttl_secs` near u64::MAX means "no
        // age limit", and `exp` still bounds the result.
        let expires_at = exp.min(now.saturating_add(self.max_ttl_secs));
        if expires_at <= now {
            return;
        }
        if !self.reserve() {
            if self.last_sweep.swap(now, Ordering::Relaxed) == now {
                return;
            }
            self.sweep(now);
            if !self.reserve() {
                return;
            }
        }
        let entry = Entry {
            claims: claims.clone(),
            expires_at,
        };
        // The same token verified twice at once: the second store replaces
        // the first and gives its slot back.
        if self.entries.insert(key, entry).is_some() {
            self.taken.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Take one slot, unless all `max_entries` are taken.
    fn reserve(&self) -> bool {
        self.taken
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |taken| {
                (taken < self.max_entries).then_some(taken + 1)
            })
            .is_ok()
    }

    /// Drop every entry expired at `now`, giving their slots back.
    fn sweep(&self, now: u64) {
        let mut freed = 0usize;
        self.entries.retain(|_, entry| {
            let keep = entry.expires_at > now;
            freed += usize::from(!keep);
            keep
        });
        self.taken.fetch_sub(freed, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// A JWT NumericDate claim (RFC 7519 §2) as whole seconds, rounded down; `None`
/// when absent, negative or not a number.
fn numeric_date(claims: &Value, name: &str) -> Option<u64> {
    let value = claims.get(name)?;
    if let Some(secs) = value.as_u64() {
        return Some(secs);
    }
    let secs = value.as_f64()?;
    if !(secs.is_finite() && secs >= 0.0 && secs < u64::MAX as f64) {
        return None;
    }
    // In range, the cast truncates to the whole seconds.
    Some(secs as u64)
}

#[cfg(test)]
mod tests;
