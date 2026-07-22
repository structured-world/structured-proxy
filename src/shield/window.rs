//! Sliding-window counter math for the global (cross-instance) limit view.
//!
//! A fixed window has a boundary burst: a client can spend a full window's quota
//! just before the boundary and another just after. The sliding-window counter
//! smooths this by blending the current epoch's count with a decaying fraction
//! of the previous epoch's, which is why the fleet-wide gate has no boundary
//! burst even though the local shaper is GCRA.

use std::time::Duration;

/// The epoch (window index) for `now`, aligned to wall-clock so every instance
/// agrees on window boundaries.
pub fn epoch(now: Duration, window: Duration) -> u64 {
    now.as_secs() / window.as_secs().max(1)
}

/// How far into the current window `now` sits.
pub fn elapsed_in_window(now: Duration, window: Duration) -> Duration {
    let w = window.as_secs().max(1);
    Duration::from_secs(now.as_secs() % w) + Duration::from_nanos(u64::from(now.subsec_nanos()))
}

/// Blend the current-epoch count with the previous epoch's, weighted by how much
/// of the current window remains: a request early in the window still "sees"
/// most of the previous window's traffic, decaying to none by the boundary.
pub fn sliding_estimate(cur: u64, prev: u64, elapsed: Duration, window: Duration) -> f64 {
    let w = window.as_secs_f64().max(f64::MIN_POSITIVE);
    let frac = (elapsed.as_secs_f64() / w).clamp(0.0, 1.0);
    cur as f64 + prev as f64 * (1.0 - frac)
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: Duration = Duration::from_secs(60);

    #[test]
    fn epoch_advances_once_per_window() {
        assert_eq!(epoch(Duration::from_secs(0), W), 0);
        assert_eq!(epoch(Duration::from_secs(59), W), 0);
        assert_eq!(epoch(Duration::from_secs(60), W), 1);
        assert_eq!(epoch(Duration::from_secs(125), W), 2);
    }

    #[test]
    fn estimate_at_window_start_counts_full_previous() {
        // At the very start of the window, the whole previous epoch still counts.
        assert_eq!(sliding_estimate(0, 100, Duration::ZERO, W), 100.0);
    }

    #[test]
    fn estimate_at_window_end_drops_previous() {
        // At the end of the window, the previous epoch has fully decayed.
        let est = sliding_estimate(10, 100, W, W);
        assert!((est - 10.0).abs() < 1e-9);
    }

    #[test]
    fn estimate_midway_halves_previous() {
        let est = sliding_estimate(10, 100, Duration::from_secs(30), W);
        assert!((est - 60.0).abs() < 1e-9); // 10 + 100 * 0.5
    }
}
