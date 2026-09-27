//! Cache of claims the built-in verifier accepted, so a client that sends the
//! same token on every request pays for one signature check.
//!
//! Keyed by the SHA-256 of the token, so no bearer token is held in memory.
//! An entry is reused until the earlier of the token's `exp` and a configured
//! maximum age, which bounds how long a token keeps passing after its signing
//! key has left the JWKS. Rejected tokens are never stored, so garbage cannot
//! fill it, and tokens over a size limit are not stored either, so the memory
//! held is bounded too. The size is capped without background work: expired
//! entries are dropped when looked up, and swept when an insert finds the
//! cache full.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
// no-std: caller-provided monotonic clock
use std::time::Instant;

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

/// A moment on both clocks the cache reads, in whole seconds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Now {
    /// Unix time, the clock `exp` and `nbf` are written in.
    pub(crate) unix: u64,
    /// Seconds since the cache was built. Never goes back, so a wall clock
    /// set back cannot stretch the maximum age of an entry.
    pub(crate) mono: u64,
}

struct Entry {
    claims: Arc<Value>,
    /// The token's `exp` (Unix time): not used from this second on.
    exp: u64,
    /// `Now::mono` from which the entry is too old to use.
    deadline: u64,
}

impl Entry {
    fn live(&self, now: Now) -> bool {
        now.unix < self.exp && now.mono < self.deadline
    }
}

/// Verified claims by token, bounded in size and age.
pub(crate) struct ClaimsCache {
    entries: DashMap<TokenKey, Entry>,
    /// Slots taken: an insert reserves one before storing, so concurrent
    /// inserts can never take the map past `max_entries`.
    taken: AtomicUsize,
    max_entries: usize,
    max_ttl_secs: u64,
    max_token_bytes: usize,
    /// Origin of `Now::mono`.
    started: Instant,
    /// First `Now::mono` second at which a full cache may be swept again, so
    /// a burst of inserts into a cache full of live entries sweeps at most
    /// once per second. Only ever moves forward.
    next_sweep: AtomicU64,
}

impl ClaimsCache {
    /// A cache as `config` describes, or `None` when it is switched off.
    pub(crate) fn build(config: &JwtCacheConfig) -> Result<Option<Self>, String> {
        if !config.enabled {
            return Ok(None);
        }
        if config.max_entries == 0 || config.max_ttl_secs == 0 || config.max_token_bytes == 0 {
            return Err(
                "auth.jwt.cache.max_entries, max_ttl_secs and max_token_bytes must be \
                 positive; set enabled: false to turn the cache off"
                    .to_string(),
            );
        }
        Ok(Some(Self {
            entries: DashMap::new(),
            taken: AtomicUsize::new(0),
            max_entries: config.max_entries,
            max_ttl_secs: config.max_ttl_secs,
            max_token_bytes: config.max_token_bytes,
            started: Instant::now(),
            next_sweep: AtomicU64::new(0),
        }))
    }

    /// Whether `token` is small enough to be cached.
    pub(crate) fn admits(&self, token: &str) -> bool {
        token.len() <= self.max_token_bytes
    }

    /// The current moment on both clocks.
    pub(crate) fn now(&self) -> Now {
        Now {
            // no-std: caller-provided wall clock
            unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            mono: self.started.elapsed().as_secs(),
        }
    }

    /// The claims cached for `key`, if the entry is still valid at `now`.
    pub(crate) fn get(&self, key: &TokenKey, now: Now) -> Option<Arc<Value>> {
        {
            let entry = self.entries.get(key)?;
            if entry.live(now) {
                return Some(entry.claims.clone());
            }
        }
        if self
            .entries
            .remove_if(key, |_, entry| !entry.live(now))
            .is_some()
        {
            self.taken.fetch_sub(1, Ordering::Relaxed);
        }
        None
    }

    /// Store `claims`, just verified at `now`, for `key`. Nothing is stored
    /// for a token without `exp`, one not yet valid (`nbf` in the future), one
    /// that would expire at once, or when the cache is full of live entries.
    pub(crate) fn insert(&self, key: TokenKey, claims: &Arc<Value>, now: Now) {
        // Never beyond `exp`: past it the verifier's own leeway decides.
        let Some(exp) = numeric_date(claims, "exp") else {
            return;
        };
        if exp <= now.unix || numeric_date(claims, "nbf").is_some_and(|nbf| nbf > now.unix) {
            return;
        }
        // Saturates on purpose: `mono` counts from start-up, so only a
        // `max_ttl_secs` near u64::MAX reaches the bound, and that setting
        // means "no age limit", with `exp` still in force.
        let deadline = now.mono.saturating_add(self.max_ttl_secs);
        if !self.reserve() {
            if !self.claim_sweep(now.mono) {
                return;
            }
            self.sweep(now);
            if !self.reserve() {
                return;
            }
        }
        let entry = Entry {
            claims: claims.clone(),
            exp,
            deadline,
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

    /// Whether the caller at second `mono` is the one to sweep: the first to
    /// reach a second past the last sweep. A caller whose `mono` was read
    /// before that sweep never sweeps, so late callers cannot repeat it.
    fn claim_sweep(&self, mono: u64) -> bool {
        self.next_sweep
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                // `mono` counts seconds since start-up: `+ 1` cannot overflow.
                (mono >= next).then_some(mono + 1)
            })
            .is_ok()
    }

    /// Drop every entry no longer valid at `now`, giving their slots back.
    fn sweep(&self, now: Now) {
        let mut freed = 0usize;
        self.entries.retain(|_, entry| {
            let keep = entry.live(now);
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
