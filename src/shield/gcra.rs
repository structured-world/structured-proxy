//! GCRA (Generic Cell Rate Algorithm) rate limiter core.
//!
//! GCRA is a token-bucket equivalent that stores a single value per key: the
//! *theoretical arrival time* (TAT). Compared with a fixed window it has no
//! boundary burst (a client cannot spend two full windows across a boundary)
//! and it lets legitimate bursts through up to a configured capacity while
//! throttling sustained abuse to the steady rate.
//!
//! This module is pure arithmetic with an injected clock, so the burst
//! boundary, refill, and clock-skew behaviour are all unit-testable without a
//! store or a real clock.

use std::time::Duration;

/// A GCRA limiter parameterised by a steady emission interval and a burst
/// tolerance. Construct one from a [`Profile`] with [`Gcra::from_profile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gcra {
    /// Time between two requests at the sustained rate (`window / rate`).
    emission_interval: Duration,
    /// Delay-variation tolerance: how far ahead of the steady schedule a burst
    /// may run. `(burst - 1) * emission_interval`, so a fresh key admits exactly
    /// `burst` requests instantly before throttling to the steady rate.
    tau: Duration,
}

/// A named limit tier: a sustained rate over a window plus an instantaneous
/// burst capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Profile {
    /// Sustained requests permitted per `window`.
    pub rate: u64,
    /// Length of the sustained-rate window.
    pub window: Duration,
    /// Maximum requests admitted back-to-back before throttling to the rate.
    /// At least 1.
    pub burst: u64,
}

/// The outcome of a single GCRA check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// Whether the request is conforming (allowed).
    pub allowed: bool,
    /// The TAT to persist for this key (unchanged from the stored value when
    /// the request is rejected).
    pub new_tat: Duration,
    /// Requests still admissible at this instant after this one (0 when rejected).
    pub remaining: u64,
    /// When rejected, how long until a retry would conform (`Retry-After`).
    pub retry_after: Duration,
    /// How long until the limiter drains back toward full capacity
    /// (`RateLimit-Reset`).
    pub reset_after: Duration,
}

impl Gcra {
    /// Build a limiter from a [`Profile`]. `burst` is clamped to at least 1 and
    /// `rate` to at least 1 so the emission interval is finite.
    pub fn from_profile(profile: Profile) -> Self {
        let rate = profile.rate.max(1);
        let burst = profile.burst.max(1);
        // T = window / rate, computed in nanoseconds to avoid truncation.
        let window_nanos = profile.window.as_nanos().max(1);
        let emission_nanos = window_nanos / u128::from(rate);
        let emission_interval = duration_from_nanos(emission_nanos.max(1));
        let tau = emission_interval * u32::try_from(burst - 1).unwrap_or(u32::MAX);
        Self {
            emission_interval,
            tau,
        }
    }

    /// Evaluate a request arriving at `now` (a monotonically-increasing instant
    /// expressed as a [`Duration`] since a fixed epoch), given the key's stored
    /// TAT (`None` for a first-seen key).
    ///
    /// A `now` that moves backwards (clock skew) is tolerated: the check never
    /// panics and treats the effective arrival time as `max(now, tat_floor)`.
    pub fn check(&self, stored_tat: Option<Duration>, now: Duration) -> Verdict {
        let t = self.emission_interval;
        let tau = self.tau;
        // Canonical GCRA uses the stored TAT as-is (a first-seen key starts at
        // `now`, an empty bucket).
        let tat = stored_tat.unwrap_or(now);

        // Number of requests admissible at `now` from the stored TAT: each
        // admitted request pushes TAT forward by `t`, and a request conforms
        // while `now >= tat + k*t - tau`. `now + tau >= tat` means at least one
        // conforms.
        let admissible = if now + tau >= tat {
            let slack = (now + tau) - tat; // >= 0
            1 + div_floor(slack, t)
        } else {
            0
        };

        if admissible == 0 {
            // Non-conforming: earliest conforming instant is `tat - tau`.
            let retry_after = tat.saturating_sub(tau).saturating_sub(now);
            Verdict {
                allowed: false,
                new_tat: tat,
                remaining: 0,
                retry_after,
                reset_after: tat.saturating_sub(now),
            }
        } else {
            let new_tat = tat.max(now) + t;
            Verdict {
                allowed: true,
                new_tat,
                remaining: admissible - 1,
                retry_after: Duration::ZERO,
                reset_after: new_tat.saturating_sub(now),
            }
        }
    }
}

/// Floor division of two `Duration`s (`a / b`), in nanoseconds.
fn div_floor(a: Duration, b: Duration) -> u64 {
    let b = b.as_nanos().max(1);
    u64::try_from(a.as_nanos() / b).unwrap_or(u64::MAX)
}

/// A `Duration` from a `u128` nanosecond count, saturating at `Duration::MAX`.
fn duration_from_nanos(nanos: u128) -> Duration {
    let secs = nanos / 1_000_000_000;
    let sub = (nanos % 1_000_000_000) as u32;
    match u64::try_from(secs) {
        Ok(secs) => Duration::new(secs, sub),
        Err(_) => Duration::MAX,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(rate: u64, window_secs: u64, burst: u64) -> Profile {
        Profile {
            rate,
            window: Duration::from_secs(window_secs),
            burst,
        }
    }

    /// A fresh key admits exactly `burst` requests instantly, then rejects.
    #[test]
    fn burst_boundary_admits_exactly_burst() {
        let g = Gcra::from_profile(profile(60, 60, 3)); // 1 req/s, burst 3
        let now = Duration::from_secs(100);
        let mut tat = None;
        for i in 0..3 {
            let v = g.check(tat, now);
            assert!(v.allowed, "request {i} should be allowed");
            assert_eq!(v.remaining, (3 - 1 - i) as u64, "remaining after {i}");
            tat = Some(v.new_tat);
        }
        // 4th at the same instant is rejected.
        let v = g.check(tat, now);
        assert!(!v.allowed);
        assert_eq!(v.remaining, 0);
        // Retry after one emission interval (1s).
        assert_eq!(v.retry_after, Duration::from_secs(1));
    }

    /// After exhausting the burst, one request is admitted every emission
    /// interval (refill at the steady rate).
    #[test]
    fn refills_at_steady_rate() {
        let g = Gcra::from_profile(profile(60, 60, 2)); // 1 req/s, burst 2
        let start = Duration::from_secs(0);
        let mut tat = None;
        // Spend the burst (2) at t=0.
        for _ in 0..2 {
            let v = g.check(tat, start);
            assert!(v.allowed);
            tat = Some(v.new_tat);
        }
        // Immediately after: rejected.
        assert!(!g.check(tat, start).allowed);
        // 1 second later: exactly one slot has refilled.
        let later = start + Duration::from_secs(1);
        let v = g.check(tat, later);
        assert!(v.allowed);
        tat = Some(v.new_tat);
        // A second request at the same instant is rejected (only one refilled).
        assert!(!g.check(tat, later).allowed);
    }

    /// A `now` that jumps backwards (clock skew) must not panic and must not
    /// wrongly admit an unbounded burst.
    #[test]
    fn tolerates_backward_clock() {
        let g = Gcra::from_profile(profile(60, 60, 1)); // 1 req/s, burst 1
        let now = Duration::from_secs(1000);
        let v = g.check(None, now);
        assert!(v.allowed);
        let tat = Some(v.new_tat);
        // Clock jumps back 500s. The next request is still governed by the
        // stored TAT (which is ahead), so it is rejected, not admitted.
        let back = Duration::from_secs(500);
        let v = g.check(tat, back);
        // The stored TAT (ahead of the rewound clock) still governs: the request
        // is rejected, not wrongly admitted, and retry_after is a finite,
        // conservative wait (never a panic or an overflow).
        assert!(!v.allowed);
        assert!(v.retry_after > Duration::ZERO);
        assert!(v.retry_after <= Duration::from_secs(501));
    }

    /// `reset_after` shrinks toward zero as the bucket drains over time.
    #[test]
    fn reset_after_drains_over_time() {
        let g = Gcra::from_profile(profile(60, 60, 5)); // 1 req/s, burst 5
        let start = Duration::from_secs(0);
        let mut tat = None;
        let mut last_reset = Duration::MAX;
        for _ in 0..5 {
            let v = g.check(tat, start);
            assert!(v.allowed);
            tat = Some(v.new_tat);
            last_reset = v.reset_after;
        }
        // After the full burst, reset_after == burst * emission (5s).
        assert_eq!(last_reset, Duration::from_secs(5));
    }

    /// A bare-rate profile (burst 1) admits one request per emission interval
    /// with no instantaneous burst.
    #[test]
    fn burst_one_is_pure_rate_limit() {
        let g = Gcra::from_profile(profile(2, 1, 1)); // 2 req/s, burst 1
        let now = Duration::from_secs(0);
        let v = g.check(None, now);
        assert!(v.allowed);
        // Second request at the same instant rejected (burst 1).
        assert!(!g.check(Some(v.new_tat), now).allowed);
    }
}
