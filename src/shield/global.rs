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
//! has no boundary burst. The worst-case fleet overshoot is bounded by one sync
//! interval of the other instances' traffic, about
//! `(N-1) * rate * (interval / window)` requests (interval and window in the
//! same unit).

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
    /// Admits from the previous epoch that were never pushed before the epoch
    /// rolled, still owed to `carryover_epoch`'s counter. Carried so a boundary
    /// crossing between the last push and a roll does not silently drop them.
    carryover: u64,
    /// The epoch `carryover` is owed to.
    carryover_epoch: u64,
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
            carryover: 0,
            carryover_epoch: 0,
            remote_estimate: 0,
            last_seen: Instant::now(),
        }
    }

    /// Advance to `epoch`, resetting the per-epoch counts. Any admits not yet
    /// pushed are stashed as `carryover` owed to the epoch being left, so the
    /// reconciler still publishes them to that epoch's counter. The remote
    /// estimate is kept (the background task refreshes it) so a fresh epoch does
    /// not briefly open the full budget fleet-wide.
    ///
    /// A single carryover slot assumes the reconcile interval is much shorter
    /// than the window (the default 500ms vs seconds+), so at most one unpushed
    /// epoch exists between reconciles.
    fn roll_to(&mut self, epoch: u64) {
        if self.epoch != epoch {
            let unpushed = self.local_count.saturating_sub(self.pushed);
            if unpushed > 0 {
                self.carryover += unpushed;
                self.carryover_epoch = self.epoch;
            }
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
    ///
    /// This is deliberately a read then a separate record, not an atomic
    /// reserve/rollback. The per-instance [`GcraStore`](super::store::GcraStore)
    /// is the hard local cap and is atomic per key; this fleet gate is only an
    /// approximate cross-instance cap. A race where concurrent requests all pass
    /// the gate before any records is bounded by the local burst plus the
    /// documented one-interval overshoot, which is the accepted trade-off for
    /// keeping the hot path lock-free and non-blocking.
    pub fn gate(&self, key: &str, budget: u64, window: Duration) -> bool {
        let state = self.state_for(key, window);
        state.remote_estimate + state.local_count < budget
    }

    /// Record one admitted request for `key`, to be pushed to the store on the
    /// next background tick.
    pub fn record(&self, key: &str, window: Duration) {
        let mut state = self.state_for(key, window);
        state.local_count += 1;
    }

    /// Look up (or create) the per-key state, rolled to the current epoch and
    /// stamped as seen. If the resolved `window` differs from the one the entry
    /// was created with, the entry is reset: a different window is a different
    /// accounting unit, so mixing counts across it would corrupt the estimate.
    fn state_for(
        &self,
        key: &str,
        window: Duration,
    ) -> dashmap::mapref::one::RefMut<'_, String, KeyState> {
        let now = unix_now();
        let window_secs = window.as_secs().max(1);
        let ep = window::epoch(now, window);
        let mut state = self
            .states
            .entry(key.to_string())
            .or_insert_with(|| KeyState::new(ep, window_secs));
        if state.window_secs != window_secs {
            *state = KeyState::new(ep, window_secs);
        }
        state.roll_to(ep);
        state.last_seen = Instant::now();
        state
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

    /// One reconciliation pass at the current wall clock.
    async fn reconcile(&self) {
        self.reconcile_at(unix_now()).await;
    }

    /// One reconciliation pass at instant `now` (parameterised for tests): push
    /// this instance's deltas, pull the aggregate, refresh each key's remote
    /// estimate, and evict stale keys.
    async fn reconcile_at(&self, now: Duration) {
        self.evict_stale();

        // Phase 1 (locked, brief): snapshot each key's pending delta. The delta
        // is pushed to the epoch it was accumulated in (`push_epoch`), while the
        // estimate reads the current epoch (`read_epoch`); the two differ when a
        // window boundary is crossed between a record and this tick.
        let mut plans: Vec<PushPlan> = Vec::new();
        for entry in self.states.iter() {
            let s = entry.value();
            let window = Duration::from_secs(s.window_secs);
            let read_epoch = window::epoch(now, window);
            plans.push(PushPlan {
                key: entry.key().clone(),
                push_epoch: s.epoch,
                read_epoch,
                window,
                delta: s.local_count.saturating_sub(s.pushed),
                is_carryover: false,
            });
            // Deltas from a prior epoch that rolled before they were pushed.
            if s.carryover > 0 {
                plans.push(PushPlan {
                    key: entry.key().clone(),
                    push_epoch: s.carryover_epoch,
                    read_epoch,
                    window,
                    delta: s.carryover,
                    is_carryover: true,
                });
            }
        }
        if plans.iter().all(|p| p.delta == 0) {
            return;
        }

        let mut conn = match self.connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("rate-limit shared store unavailable, staying local: {e}");
                return;
            }
        };

        // Push each pending delta as an atomic INCRBY (never a SET, so concurrent
        // instances' increments accumulate rather than clobber). On success,
        // commit `pushed` immediately so a later read failure cannot cause the
        // same delta to be pushed a second time on the next tick.
        if let Err(e) = self.push_deltas(&mut conn, &plans).await {
            tracing::warn!("rate-limit delta push failed: {e}");
            return; // `pushed` not advanced → same delta retried next tick, no double count
        }
        self.commit_pushed(&plans);

        let reads = match self.read_epochs(&mut conn, &plans).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("rate-limit aggregate read failed: {e}");
                return;
            }
        };
        self.apply_estimates(now, &plans, &reads);
    }

    /// Advance each key's `pushed` by the delta we just pushed, but only while
    /// the state still holds the epoch the delta belonged to (a concurrent roll
    /// resets the counts, so there is nothing to advance).
    fn commit_pushed(&self, plans: &[PushPlan]) {
        for p in plans.iter().filter(|p| p.delta > 0) {
            if let Some(mut s) = self.states.get_mut(&p.key) {
                if p.is_carryover {
                    // Clear the carried-over amount now that its epoch counter has it.
                    if s.carryover_epoch == p.push_epoch {
                        s.carryover = s.carryover.saturating_sub(p.delta);
                    }
                } else if s.epoch == p.push_epoch {
                    s.pushed += p.delta;
                }
            }
        }
    }

    /// Refresh each key's cached estimate of the rest of the fleet's consumption.
    fn apply_estimates(&self, now: Duration, plans: &[PushPlan], reads: &[(u64, u64)]) {
        for (p, (cur, prev)) in plans.iter().zip(reads) {
            // Carryover plans only publish a past epoch's delta; the estimate is
            // driven by the current-epoch plan for the same key.
            if p.is_carryover {
                continue;
            }
            if let Some(mut s) = self.states.get_mut(&p.key) {
                // A request may have reset the key to a new window, or rolled it
                // to a newer epoch, while the read was in flight. The estimate we
                // computed is for the plan's (window, epoch); applying it would
                // clobber the fresh state with a stale value, so skip it.
                if s.window_secs != p.window.as_secs() || s.epoch > p.read_epoch {
                    continue;
                }
                let elapsed = window::elapsed_in_window(now, p.window);
                let est = window::sliding_estimate(*cur, *prev, elapsed, p.window);
                // Subtract only our own contribution to the current epoch's count
                // (the gate adds `local_count` back separately). If the key's
                // pushes went to an earlier epoch, our current-epoch share is 0.
                let my_current = if s.epoch == p.read_epoch { s.pushed } else { 0 };
                let others = (est.round() as i64 - my_current as i64).max(0);
                s.remote_estimate = others as u64;
            }
        }
    }

    /// `INCRBY` each key with a pending delta and re-arm its TTL. Wrapped in a
    /// `MULTI`/`EXEC` transaction so the batch applies all-or-nothing: a
    /// mid-pipeline failure can't leave some `INCRBY`s applied while the caller
    /// skips `commit_pushed` and re-pushes the same deltas next tick.
    async fn push_deltas(
        &self,
        conn: &mut redis::aio::MultiplexedConnection,
        plans: &[PushPlan],
    ) -> redis::RedisResult<()> {
        let mut pipe = redis::pipe();
        pipe.atomic();
        let mut any = false;
        for p in plans.iter().filter(|p| p.delta > 0) {
            any = true;
            let k = epoch_key(&p.key, p.push_epoch);
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
            keys.push(epoch_key(&p.key, p.read_epoch));
            keys.push(epoch_key(&p.key, p.read_epoch.saturating_sub(1)));
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
    /// Epoch the pending delta was accumulated in (target of the `INCRBY`).
    push_epoch: u64,
    /// Current epoch, whose sliding window the estimate reads.
    read_epoch: u64,
    window: Duration,
    delta: u64,
    /// True for a plan publishing a prior epoch's carried-over delta (no estimate).
    is_carryover: bool,
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
    fn roll_preserves_unpushed_deltas_as_carryover() {
        // 5 admits in an epoch, 2 already pushed, then the epoch rolls before the
        // remaining 3 are pushed: they must survive as carryover owed to the old
        // epoch, not be silently dropped.
        let mut s = KeyState::new(10, 60);
        s.local_count = 5;
        s.pushed = 2;
        s.roll_to(11);
        assert_eq!(s.carryover, 3);
        assert_eq!(s.carryover_epoch, 10);
        assert_eq!(s.local_count, 0);
        assert_eq!(s.pushed, 0);
        assert_eq!(s.epoch, 11);
    }

    #[test]
    fn stale_estimate_not_applied_after_window_reset() {
        let g = counters();
        let key = "k";
        // The key currently lives on a 120s window with a fresh remote estimate.
        g.record(key, Duration::from_secs(120));
        g.states.get_mut(key).unwrap().remote_estimate = 5;

        // A reconcile plan captured earlier for the OLD 60s window resumes after
        // its read. Its estimate must not clobber the freshly-reset state.
        let now = unix_now();
        let plan = PushPlan {
            key: key.to_string(),
            push_epoch: window::epoch(now, W),
            read_epoch: window::epoch(now, W),
            window: W,
            delta: 0,
            is_carryover: false,
        };
        g.apply_estimates(now, &[plan], &[(100, 0)]);

        assert_eq!(
            g.states.get(key).unwrap().remote_estimate,
            5,
            "an old-window estimate must not overwrite the reset state"
        );
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

    /// A carried-over delta from a rolled epoch is published to that epoch's
    /// counter (not the current one) and then cleared.
    #[tokio::test]
    async fn carryover_is_pushed_to_its_epoch() {
        let Ok(url) = std::env::var("SHIELD_REDIS_TEST_URL") else {
            eprintln!("SKIP carryover_is_pushed_to_its_epoch: SHIELD_REDIS_TEST_URL not set");
            return;
        };
        let win = Duration::from_secs(3600);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key = format!("it3:{}:{nonce}", std::process::id());

        let g = GlobalCounters::build(&url, Duration::from_millis(200)).unwrap();
        let cur = window::epoch(unix_now(), win);
        let mut st = KeyState::new(cur, win.as_secs());
        st.carryover = 3;
        st.carryover_epoch = cur - 1;
        g.states.insert(key.clone(), st);

        g.reconcile().await;

        let client = redis::Client::open(url).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let prev: i64 = redis::cmd("GET")
            .arg(epoch_key(&key, cur - 1))
            .query_async(&mut conn)
            .await
            .unwrap_or(0);
        assert_eq!(prev, 3, "carryover must be published to its own epoch");
        assert_eq!(
            g.states.get(&key).unwrap().carryover,
            0,
            "carryover must be cleared once published"
        );
    }

    /// Repeated reconcile passes with no new admits must not re-push the same
    /// delta: the shared counter reflects each admit exactly once, even if a
    /// pass's aggregate read had failed on an earlier tick.
    #[tokio::test]
    async fn repeated_reconcile_does_not_double_push() {
        let Ok(url) = std::env::var("SHIELD_REDIS_TEST_URL") else {
            eprintln!(
                "SKIP repeated_reconcile_does_not_double_push: SHIELD_REDIS_TEST_URL not set"
            );
            return;
        };
        // Hour-long window so no epoch boundary is crossed mid-test.
        let win = Duration::from_secs(3600);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key = format!("it2:{}:{nonce}", std::process::id());

        let a = GlobalCounters::build(&url, Duration::from_millis(200)).unwrap();
        a.record(&key, win);
        a.record(&key, win);
        // Three passes: only the first has a non-zero delta to push.
        a.reconcile().await;
        a.reconcile().await;
        a.reconcile().await;

        let epoch = window::epoch(unix_now(), win);
        let redis_key = epoch_key(&key, epoch);
        let client = redis::Client::open(url).unwrap();
        let mut conn = client.get_multiplexed_async_connection().await.unwrap();
        let count: i64 = redis::cmd("GET")
            .arg(&redis_key)
            .query_async(&mut conn)
            .await
            .unwrap_or(0);
        assert_eq!(
            count, 2,
            "shared counter must reflect the 2 admits exactly once"
        );
    }
}
