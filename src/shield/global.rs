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

use dashmap::mapref::entry::Entry;

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

/// Hard cap on tracked keys. [`evict_stale`](GlobalCounters::evict_stale) bounds
/// retention *time*, but only runs once per reconcile tick; a burst of distinct
/// keys between ticks could still grow the map. Past this cap, a *new* key is not
/// fleet-tracked and simply degrades to per-instance limiting (the local
/// [`GcraStore`](super::store::GcraStore) still caps it) rather than being fleet
/// under-counted; this is the same best-effort tolerance as a dropped push.
/// Already-tracked keys are unaffected, so a real principal's budget is kept.
const MAX_KEYS: usize = 500_000;

/// Per-key reconciliation state.
///
/// Admit accounting uses a claim model: `local_count` holds only admits *not yet
/// claimed* by a reconcile pass. A pass claims the count (zeroes it under the
/// lock) before the async push, so a concurrent epoch roll or a push failure
/// can't double-publish or drop it.
#[derive(Debug, Clone)]
struct KeyState {
    epoch: u64,
    /// Window length in seconds (from the resolved profile).
    window_secs: u64,
    /// Admits in the current epoch not yet claimed for a push.
    local_count: u64,
    /// Unclaimed admits owed to a prior epoch (`carryover_epoch`) that rolled
    /// before they were claimed, so a boundary crossing doesn't drop them.
    carryover: u64,
    /// The epoch `carryover` is owed to.
    carryover_epoch: u64,
    /// The fleet's sliding consumption (including this instance's own claimed
    /// admits, which now live in the shared counter), from the last pull.
    remote_estimate: u64,
    /// When `remote_estimate` was last refreshed from the store. If it goes
    /// stale (the store is unreachable for several intervals), the gate stops
    /// trusting it and degrades to per-instance limiting.
    estimate_at: Instant,
    last_seen: Instant,
}

impl KeyState {
    fn new(epoch: u64, window_secs: u64) -> Self {
        let now = Instant::now();
        Self {
            epoch,
            window_secs,
            local_count: 0,
            carryover: 0,
            carryover_epoch: 0,
            remote_estimate: 0,
            estimate_at: now,
            last_seen: now,
        }
    }

    /// Advance to `epoch`, moving any unclaimed admits to `carryover` owed to the
    /// epoch being left so the reconciler still publishes them to that epoch's
    /// counter. The remote estimate is kept (the background task refreshes it) so
    /// a fresh epoch does not briefly open the full budget fleet-wide.
    ///
    /// A single carryover slot assumes the reconcile interval is much shorter
    /// than the window (the default 500ms vs seconds+), so at most one unclaimed
    /// prior epoch exists between reconciles.
    fn roll_to(&mut self, epoch: u64) {
        if self.epoch != epoch {
            if self.local_count > 0 {
                if self.carryover > 0 && self.carryover_epoch != self.epoch {
                    // An unclaimed carryover from an earlier epoch still exists:
                    // reconcile has not run across two boundaries (interval
                    // misconfigured longer than the window). Keep only the most
                    // recent window rather than collapsing two epochs' counts
                    // under one label, which would corrupt both. Dropping the
                    // older is a bounded under-count consistent with best-effort.
                    self.carryover = self.local_count;
                } else {
                    self.carryover += self.local_count;
                }
                self.carryover_epoch = self.epoch;
            }
            self.epoch = epoch;
            self.local_count = 0;
        }
    }
}

/// Cross-instance counter reconciliation over a shared Redis-protocol store.
pub struct GlobalCounters {
    client: redis::Client,
    conn: tokio::sync::OnceCell<redis::aio::ConnectionManager>,
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

    /// Fleet budget still available for `key` (0 = over budget). Read-only: the
    /// cached remote estimate plus this instance's unclaimed count, subtracted
    /// from `budget`. Does not touch the store and does not record the admit
    /// (call [`record`](Self::record) after the local check also passes).
    ///
    /// This is deliberately a read then a separate record, not an atomic
    /// reserve/rollback. The per-instance [`GcraStore`](super::store::GcraStore)
    /// is the hard local cap and is atomic per key; this fleet gate is only an
    /// approximate cross-instance cap. A race where concurrent requests all pass
    /// the gate before any records is bounded by the local burst plus the
    /// documented one-interval overshoot, which is the accepted trade-off for
    /// keeping the hot path lock-free and non-blocking.
    pub fn fleet_remaining(&self, key: &str, budget: u64, window: Duration) -> u64 {
        // When the map is full and this key is new, don't fleet-gate it: report
        // the full budget so the local limiter alone decides (degrade-to-
        // per-instance). Tracking it would breach the memory cap under a flood.
        let Some(state) = self.state_for(key, window) else {
            return budget;
        };
        // Ignore the remote estimate once it is stale (store unreachable for
        // several intervals): keep gating on this instance's own counts only,
        // which is the documented degrade-to-per-instance behaviour, instead of
        // subtracting a frozen estimate forever.
        let stale_after = (self.interval * 4).max(Duration::from_secs(2));
        let remote = if state.estimate_at.elapsed() < stale_after {
            state.remote_estimate
        } else {
            0
        };
        // Subtract carryover too: unpushed previous-window admits still count in
        // the sliding window until the next tick publishes them.
        let used = remote + state.local_count + state.carryover;
        budget.saturating_sub(used)
    }

    /// Record one admitted request for `key`, to be pushed to the store on the
    /// next background tick.
    pub fn record(&self, key: &str, window: Duration) {
        // If the map is full and this key is untracked, skip: the admit is
        // enforced locally and simply isn't published to the fleet (bounded
        // under-count), which is preferable to breaching the memory cap.
        if let Some(mut state) = self.state_for(key, window) {
            state.local_count += 1;
        }
    }

    /// Look up (or create) the per-key state, rolled to the current epoch and
    /// stamped as seen. If the resolved `window` differs from the one the entry
    /// was created with, the entry is reset: a different window is a different
    /// accounting unit, so mixing counts across it would corrupt the estimate.
    fn state_for(
        &self,
        key: &str,
        window: Duration,
    ) -> Option<dashmap::mapref::one::RefMut<'_, String, KeyState>> {
        let now = unix_now();
        let window_secs = window.as_secs().max(1);
        let ep = window::epoch(now, window);
        // Soft cap check before the entry: a new key past the cap is not tracked.
        // The `len()` read races with concurrent inserts, but the cap is a memory
        // guard, not an exact limit, so a few entries of overshoot are harmless.
        let over_cap = self.states.len() >= MAX_KEYS;
        let mut state = match self.states.entry(key.to_string()) {
            Entry::Occupied(o) => o.into_ref(),
            Entry::Vacant(_) if over_cap => return None,
            Entry::Vacant(v) => v.insert(KeyState::new(ep, window_secs)),
        };
        if state.window_secs != window_secs {
            // A window change is a different accounting unit, so the entry resets.
            // Any unpushed admits from the old window are dropped rather than
            // remapped (a different window can't share a counter). The window only
            // changes when the resolved tier does, and the tier comes from the
            // signed JWT, the limit service, or config, never from client input,
            // so this is not client-triggerable: it is a rare, bounded one-window
            // under-count on a legitimate tier change, consistent with the fleet
            // layer's best-effort, never-double contract.
            *state = KeyState::new(ep, window_secs);
        }
        state.roll_to(ep);
        state.last_seen = Instant::now();
        Some(state)
    }

    /// Spawn the background reconciliation loop. Returns `false` (without
    /// spawning) when called outside a Tokio runtime, so the caller can drop the
    /// fleet gate and fall back to per-instance limiting rather than gating on a
    /// view that would never be reconciled.
    #[must_use]
    pub fn spawn(self: &Arc<Self>) -> bool {
        if tokio::runtime::Handle::try_current().is_err() {
            tracing::warn!("rate-limit reconciler not started: no Tokio runtime in this context");
            return false;
        }
        let this = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(this.interval);
            loop {
                ticker.tick().await;
                this.reconcile().await;
            }
        });
        true
    }

    /// A cloneable, self-reconnecting handle to the shared store. `ConnectionManager`
    /// re-establishes the underlying connection internally after a drop (e.g. a
    /// Redis restart), so reconciled mode recovers without a proxy restart.
    async fn connection(&self) -> redis::RedisResult<redis::aio::ConnectionManager> {
        self.conn
            .get_or_try_init(|| redis::aio::ConnectionManager::new(self.client.clone()))
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

        let plans = self.claim_plans(now);
        if plans.is_empty() {
            return;
        }

        // Claimed deltas are fire-and-forget: once claimed (zeroed), a push that
        // fails (connection or transaction) simply drops them rather than
        // restoring. This is deliberate, not a leak:
        //   * Restoring risks publishing a committed-but-unacked batch twice (a
        //     false 429), and across a sustained outage it would accumulate
        //     unbounded local_count and then dump a huge spike on recovery.
        //   * Dropping instead under-counts only this instance's last interval,
        //     which is exactly the documented "store unreachable → degrade to
        //     per-instance limiting" behaviour, and never over-counts.
        // So the failure mode is a bounded, self-correcting under-count (slight
        // over-admit), never a false rejection or a recovery spike.
        let mut conn = match self.connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("rate-limit shared store unavailable, staying local: {e}");
                return;
            }
        };

        // Push each claimed delta as an atomic INCRBY inside MULTI/EXEC (never a
        // SET, so concurrent instances' increments accumulate).
        if let Err(e) = self.push_deltas(&mut conn, &plans).await {
            tracing::warn!("rate-limit delta push failed, dropping this interval: {e}");
            return;
        }

        // Claimed admits are now in the shared counter; there is nothing to
        // commit. A read failure below just skips this tick's estimate refresh.
        let reads = match self.read_epochs(&mut conn, &plans).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("rate-limit aggregate read failed: {e}");
                return;
            }
        };
        self.apply_estimates(now, &plans, &reads);
    }

    /// Phase 1 (locked per key, brief): CLAIM each key's unclaimed admits by
    /// zeroing them now, so a concurrent epoch roll or a push failure can't
    /// double-publish or drop them. Emit a plan for every tracked key (delta may
    /// be 0) so its estimate is refreshed even when the key is only being rejected
    /// on a stale remote estimate. The delta is pushed to the epoch it was
    /// accumulated in (`push_epoch`); the estimate reads the current epoch
    /// (`read_epoch`).
    fn claim_plans(&self, now: Duration) -> Vec<PushPlan> {
        let keys: Vec<String> = self.states.iter().map(|e| e.key().clone()).collect();
        let mut plans: Vec<PushPlan> = Vec::new();
        for key in keys {
            if let Some(mut s) = self.states.get_mut(&key) {
                let window = Duration::from_secs(s.window_secs);
                let read_epoch = window::epoch(now, window);
                let claim = s.local_count;
                s.local_count = 0;
                plans.push(PushPlan {
                    key: key.clone(),
                    push_epoch: s.epoch,
                    read_epoch,
                    window,
                    delta: claim,
                    is_carryover: false,
                });
                if s.carryover > 0 {
                    let carry = s.carryover;
                    s.carryover = 0;
                    plans.push(PushPlan {
                        key: key.clone(),
                        push_epoch: s.carryover_epoch,
                        read_epoch,
                        window,
                        delta: carry,
                        is_carryover: true,
                    });
                }
            }
        }
        plans
    }

    /// Refresh each key's cached estimate of the fleet's consumption.
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
                // The counter already includes this instance's claimed admits;
                // the gate adds only the still-unclaimed `local_count` on top, so
                // the full sliding estimate is used with no self-subtraction.
                let est = window::sliding_estimate(*cur, *prev, elapsed, p.window);
                // Round the fractional sliding estimate UP: under-counting the
                // fleet would let the gate admit past the budget, so bias to the
                // conservative side.
                s.remote_estimate = est.ceil().max(0.0) as u64;
                s.estimate_at = Instant::now();
            }
        }
    }

    /// `INCRBY` each key with a claimed delta and re-arm its TTL. Wrapped in a
    /// `MULTI`/`EXEC` transaction so the batch applies all-or-nothing: a
    /// mid-pipeline failure can't leave some `INCRBY`s applied while the caller
    /// restores the claims and re-pushes the same deltas next tick.
    async fn push_deltas(
        &self,
        conn: &mut redis::aio::ConnectionManager,
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
        conn: &mut redis::aio::ConnectionManager,
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

    /// Drop per-key state that is idle and carries no unpublished admits. The
    /// idle threshold is at least two windows, so a key on a long window (e.g.
    /// `100/hour`) is not evicted mid-window; a key with pending `local_count` or
    /// `carryover` is always kept so a store outage can't lose fleet counts.
    fn evict_stale(&self) {
        let now = Instant::now();
        self.states.retain(|_, s| {
            if s.local_count > 0 || s.carryover > 0 {
                return true;
            }
            let threshold = KEY_TTL.max(Duration::from_secs(s.window_secs.saturating_mul(2)));
            now.duration_since(s.last_seen) < threshold
        });
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
    fn budget_admits_until_local_count_reaches_it() {
        let g = counters();
        // Budget 3: three admits leave room, the fourth is over budget.
        for _ in 0..3 {
            assert!(g.fleet_remaining("k", 3, W) > 0);
            g.record("k", W);
        }
        assert_eq!(g.fleet_remaining("k", 3, W), 0);
    }

    #[test]
    fn budget_accounts_for_remote_estimate() {
        let g = counters();
        // Simulate the background task having observed 2 requests elsewhere.
        let now = unix_now();
        let ep = window::epoch(now, W);
        let mut state = KeyState::new(ep, W.as_secs());
        state.remote_estimate = 2;
        g.states.insert("k".to_string(), state);
        // Budget 3, remote 2 → one local admit fits, the next is over budget.
        assert!(g.fleet_remaining("k", 3, W) > 0);
        g.record("k", W);
        assert_eq!(g.fleet_remaining("k", 3, W), 0);
    }

    #[test]
    fn roll_preserves_unclaimed_deltas_as_carryover() {
        // Admits accumulated in an epoch that rolls before a reconcile claims
        // them must survive as carryover owed to the old epoch, not be dropped.
        let mut s = KeyState::new(10, 60);
        s.local_count = 5;
        s.roll_to(11);
        assert_eq!(s.carryover, 5);
        assert_eq!(s.carryover_epoch, 10);
        assert_eq!(s.local_count, 0);
        assert_eq!(s.epoch, 11);
    }

    #[test]
    fn consecutive_rolls_do_not_collapse_epochs() {
        // If reconcile does not run between two boundary crossings (interval
        // misconfigured longer than the window), a second roll must not add a new
        // epoch's count onto the previous carryover under one epoch label. It
        // keeps the most recent window (dropping the older) rather than corrupting
        // both with a collapsed count.
        let mut s = KeyState::new(10, 60);
        s.local_count = 3;
        s.roll_to(11); // carryover = 3 owed to epoch 10
        s.local_count = 4;
        s.roll_to(12); // second roll before any reconcile claimed the carryover
        assert_eq!(
            s.carryover, 4,
            "keeps the latest window, not 3 + 4 collapsed"
        );
        assert_eq!(s.carryover_epoch, 11);
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
        assert!(g.fleet_remaining("a", 1, W) > 0);
        g.record("a", W);
        assert_eq!(g.fleet_remaining("a", 1, W), 0);
        // A different key is unaffected.
        assert!(g.fleet_remaining("b", 1, W) > 0);
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
        assert!(
            b.fleet_remaining(&key, 3, W) > 0,
            "B admits its first request for the key"
        );
        b.record(&key, W);

        // After a reconcile pass B has pushed its own admit and pulled the
        // aggregate: the combined view is 3 (A's 2 + B's 1) = the budget, so B
        // rejects the next request. The two instances enforce one combined limit.
        b.reconcile().await;
        assert_eq!(
            b.fleet_remaining(&key, 3, W),
            0,
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

    /// A key with no local admits (only being rejected on a stale remote
    /// estimate) must still have its estimate refreshed by a reconcile pass, so
    /// it can recover once the fleet stops spending the budget.
    #[tokio::test]
    async fn estimate_refreshes_without_local_deltas() {
        let Ok(url) = std::env::var("SHIELD_REDIS_TEST_URL") else {
            eprintln!(
                "SKIP estimate_refreshes_without_local_deltas: SHIELD_REDIS_TEST_URL not set"
            );
            return;
        };
        let win = Duration::from_secs(3600);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let key = format!("it4:{}:{nonce}", std::process::id());

        let g = GlobalCounters::build(&url, Duration::from_millis(200)).unwrap();
        // Seed a stale-high remote estimate with no local admits (delta 0). The
        // shared counter for this fresh key is empty, so a reconcile must pull it
        // and decay the estimate to 0 rather than leaving the key stuck.
        let cur = window::epoch(unix_now(), win);
        let mut st = KeyState::new(cur, win.as_secs());
        st.remote_estimate = 99;
        g.states.insert(key.clone(), st);

        g.reconcile().await;

        assert_eq!(
            g.states.get(&key).unwrap().remote_estimate,
            0,
            "estimate must be refreshed even with no local deltas"
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
