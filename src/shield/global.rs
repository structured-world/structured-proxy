//! Cross-instance reconciliation of the fleet-wide limit view via a shared store.
//!
//! The request path never touches the store. It reads a cached estimate of what
//! the *rest* of the fleet has consumed for a key (updated by the background
//! task) plus this instance's own count, and gates on that. A background task
//! pushes this instance's deltas (`INCRBY`) and pulls the aggregate (`MGET`) on
//! an interval, so a store outage degrades to per-instance limiting rather than
//! failing requests.
//!
//! Counts are held in a sliding window (see [`super::window`]) so the fleet gate
//! has no boundary burst. The worst-case overshoot is bounded by one sync
//! interval of the other instances' traffic: `(N-1) × rate × interval`.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::window;

/// Redis key namespace for a rate-limit key at a given epoch.
fn epoch_key(key: &str, epoch: u64) -> String {
    format!("sp:rl:{key}:{epoch}")
}

/// Wall-clock time since the Unix epoch (shared reference so every instance
/// agrees on window boundaries).
fn unix_now() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

/// Drop per-key state untouched for this long (bounds memory under churning
/// key cardinality).
const KEY_TTL: Duration = Duration::from_secs(600);

/// Per-key reconciliation state.
#[derive(Debug, Clone)]
struct KeyState {
    epoch: u64,
    /// Window length in seconds (from the resolved profile).
    window_secs: u64,
    /// Requests this instance admitted in the current epoch.
    local_count: u64,
    /// How much of `local_count` has already been pushed to the store.
    pushed: u64,
    /// The rest of the fleet's sliding consumption, from the last pull.
    remote_estimate: u64,
    last_seen: Instant,
}

impl KeyState {
    fn new(epoch: u64, window_secs: u64) -> Self {
        Self {
            epoch,
            window_secs,
            local_count: 0,
            pushed: 0,
            remote_estimate: 0,
            last_seen: Instant::now(),
        }
    }

    /// Advance to `epoch`, resetting the per-epoch counts. The remote estimate is
    /// kept (the background task refreshes it) so a fresh epoch does not briefly
    /// open the full budget fleet-wide.
    fn roll_to(&mut self, epoch: u64) {
        if self.epoch != epoch {
            self.epoch = epoch;
            self.local_count = 0;
            self.pushed = 0;
        }
    }
}

/// Cross-instance counter reconciliation over a shared Redis-protocol store.
pub struct GlobalCounters {
    client: redis::Client,
    conn: tokio::sync::OnceCell<redis::aio::MultiplexedConnection>,
    interval: Duration,
    states: dashmap::DashMap<String, KeyState>,
}

impl GlobalCounters {
    /// Open the shared store and return the reconciler.
    ///
    /// # Errors
    /// Returns the underlying error when the store URL is invalid.
    pub fn build(url: &str, interval: Duration) -> Result<Arc<Self>, String> {
        let client = redis::Client::open(url)
            .map_err(|e| format!("invalid shared-store URL for rate limiting: {e}"))?;
        Ok(Arc::new(Self {
            client,
            conn: tokio::sync::OnceCell::new(),
            interval: interval.max(Duration::from_millis(50)),
            states: dashmap::DashMap::new(),
        }))
    }

    /// Whether a request for `key` is within the fleet budget. Read-only: reads
    /// the cached remote estimate plus this instance's count. Does not touch the
    /// store and does not record the admit (call [`record`](Self::record) after
    /// the local check also passes).
    pub fn gate(&self, key: &str, budget: u64, window: Duration) -> bool {
        let now = unix_now();
        let ep = window::epoch(now, window);
        let window_secs = window.as_secs().max(1);
        let mut state = self
            .states
            .entry(key.to_string())
            .or_insert_with(|| KeyState::new(ep, window_secs));
        state.roll_to(ep);
        state.last_seen = Instant::now();
        state.remote_estimate + state.local_count < budget
    }

    /// Record one admitted request for `key`, to be pushed to the store on the
    /// next background tick.
    pub fn record(&self, key: &str, window: Duration) {
        let now = unix_now();
        let ep = window::epoch(now, window);
        let window_secs = window.as_secs().max(1);
        let mut state = self
            .states
            .entry(key.to_string())
            .or_insert_with(|| KeyState::new(ep, window_secs));
        state.roll_to(ep);
        state.local_count += 1;
        state.last_seen = Instant::now();
    }

    /// Spawn the background reconciliation loop. A no-op (with a warning) when
    /// called outside a Tokio runtime, so the local shaper still works.
    pub fn spawn(self: &Arc<Self>) {
        if tokio::runtime::Handle::try_current().is_err() {
            tracing::warn!("rate-limit reconciler not started: no Tokio runtime in this context");
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(this.interval);
            loop {
                ticker.tick().await;
                this.reconcile().await;
            }
        });
    }

    async fn connection(&self) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
        self.conn
            .get_or_try_init(|| self.client.get_multiplexed_async_connection())
            .await
            .cloned()
    }

    /// One reconciliation pass: push this instance's deltas, pull the aggregate,
    /// refresh each key's remote estimate, and evict stale keys.
    async fn reconcile(&self) {
        self.evict_stale();

        // Phase 1 (locked, brief): snapshot each active key's push delta and the
        // epoch keys to read. No store I/O while holding a lock.
        let now = unix_now();
        let mut plans: Vec<PushPlan> = Vec::new();
        for entry in self.states.iter() {
            let key = entry.key().clone();
            let s = entry.value();
            let window = Duration::from_secs(s.window_secs);
            let ep = window::epoch(now, window);
            let delta = s.local_count.saturating_sub(s.pushed);
            plans.push(PushPlan {
                key,
                epoch: ep,
                window,
                delta,
            });
        }
        if plans.is_empty() {
            return;
        }

        let mut conn = match self.connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("rate-limit shared store unavailable, staying local: {e}");
                return;
            }
        };

        // Phase 2 (no locks): push deltas, then read current+previous epochs.
        if let Err(e) = self.push_deltas(&mut conn, &plans).await {
            tracing::warn!("rate-limit delta push failed: {e}");
            return;
        }
        let reads = match self.read_epochs(&mut conn, &plans).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("rate-limit aggregate read failed: {e}");
                return;
            }
        };

        // Phase 3 (locked, brief): commit pushed deltas and the fresh estimate.
        for (plan, (cur, prev)) in plans.iter().zip(reads) {
            if let Some(mut s) = self.states.get_mut(&plan.key) {
                if s.epoch == plan.epoch {
                    s.pushed += plan.delta;
                }
                let elapsed = window::elapsed_in_window(now, plan.window);
                let est = window::sliding_estimate(cur, prev, elapsed, plan.window);
                // Exclude this instance's own current-epoch contribution: the
                // gate adds `local_count` separately.
                let others = (est.round() as i64 - s.pushed as i64).max(0);
                s.remote_estimate = others as u64;
            }
        }
    }

    /// `INCRBY` each key with a pending delta and re-arm its TTL, in one pipeline.
    async fn push_deltas(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        plans: &[PushPlan],
    ) -> redis::RedisResult<()> {
        let mut pipe = redis::pipe();
        let mut any = false;
        for p in plans.iter().filter(|p| p.delta > 0) {
            any = true;
            let k = epoch_key(&p.key, p.epoch);
            let ttl_ms = (p.window.as_millis() as u64).saturating_mul(2).max(1);
            pipe.cmd("INCRBY").arg(&k).arg(p.delta).ignore();
            pipe.cmd("PEXPIRE").arg(&k).arg(ttl_ms).ignore();
        }
        if !any {
            return Ok(());
        }
        pipe.query_async(conn).await
    }

    /// `MGET` the current and previous epoch counts for every plan, returning
    /// `(cur, prev)` per plan in order.
    async fn read_epochs(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        plans: &[PushPlan],
    ) -> redis::RedisResult<Vec<(u64, u64)>> {
        let mut keys: Vec<String> = Vec::with_capacity(plans.len() * 2);
        for p in plans {
            keys.push(epoch_key(&p.key, p.epoch));
            keys.push(epoch_key(&p.key, p.epoch.saturating_sub(1)));
        }
        let vals: Vec<Option<i64>> = redis::cmd("MGET").arg(&keys).query_async(conn).await?;
        Ok(plans
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let cur = vals.get(i * 2).copied().flatten().unwrap_or(0).max(0) as u64;
                let prev = vals.get(i * 2 + 1).copied().flatten().unwrap_or(0).max(0) as u64;
                (cur, prev)
            })
            .collect())
    }

    /// Drop per-key state not seen within [`KEY_TTL`].
    fn evict_stale(&self) {
        let now = Instant::now();
        self.states
            .retain(|_, s| now.duration_since(s.last_seen) < KEY_TTL);
    }
}

/// A per-key push plan captured under lock, used without holding locks.
struct PushPlan {
    key: String,
    epoch: u64,
    window: Duration,
    delta: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(60);

    // Opening a client does not connect, so gate/record can be exercised without
    // a running store.
    fn counters() -> Arc<GlobalCounters> {
        GlobalCounters::build("redis://127.0.0.1/", Duration::from_millis(500)).unwrap()
    }

    #[test]
    fn gate_admits_until_local_count_reaches_budget() {
        let g = counters();
        // Budget 3: three admits pass, the fourth is over budget.
        for _ in 0..3 {
            assert!(g.gate("k", 3, W));
            g.record("k", W);
        }
        assert!(!g.gate("k", 3, W));
    }

    #[test]
    fn gate_accounts_for_remote_estimate() {
        let g = counters();
        // Simulate the background task having observed 2 requests elsewhere.
        let now = unix_now();
        let ep = window::epoch(now, W);
        let mut state = KeyState::new(ep, W.as_secs());
        state.remote_estimate = 2;
        g.states.insert("k".to_string(), state);
        // Budget 3, remote 2 → one local admit fits, the next is over budget.
        assert!(g.gate("k", 3, W));
        g.record("k", W);
        assert!(!g.gate("k", 3, W));
    }

    #[test]
    fn independent_keys_have_independent_budgets() {
        let g = counters();
        assert!(g.gate("a", 1, W));
        g.record("a", W);
        assert!(!g.gate("a", 1, W));
        // A different key is unaffected.
        assert!(g.gate("b", 1, W));
    }

    /// End-to-end reconciliation against a live Redis-protocol store: one
    /// instance's admits become visible to another after a reconcile pass, so
    /// the two enforce one combined budget.
    ///
    /// Requires a reachable store; the URL comes from `SHIELD_REDIS_TEST_URL`
    /// (CI sets it to its Redis service). Without it the test reports that it was
    /// skipped for lack of infrastructure rather than silently passing.
    #[tokio::test]
    async fn reconciles_across_instances() {
        let Ok(url) = std::env::var("SHIELD_REDIS_TEST_URL") else {
            eprintln!("SKIP reconciles_across_instances: SHIELD_REDIS_TEST_URL not set");
            return;
        };
        // Unique key per run so repeated runs / parallel suites do not collide.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key = format!("it:{}:{nonce}", std::process::id());

        let a = GlobalCounters::build(&url, Duration::from_millis(200)).unwrap();
        let b = GlobalCounters::build(&url, Duration::from_millis(200)).unwrap();

        // Instance A admits two requests and pushes them to the store.
        a.record(&key, W);
        a.record(&key, W);
        a.reconcile().await;

        // B's first contact with the key: it has not reconciled this key yet, so
        // it admits once (the documented one-interval lag / bounded overshoot).
        assert!(b.gate(&key, 3, W), "B admits its first request for the key");
        b.record(&key, W);

        // After a reconcile pass B has pushed its own admit and pulled the
        // aggregate: the combined view is 3 (A's 2 + B's 1) = the budget, so B
        // rejects the next request. The two instances enforce one combined limit.
        b.reconcile().await;
        assert!(
            !b.gate(&key, 3, W),
            "B must reject once the combined budget is reached"
        );
    }
}
