//! Rate-limit rate parsing.
//!
//! A rate is a request count over a time window. It is written either as
//! `"<count>/<unit>"` (e.g. `"20/min"`) or as a bare count (e.g. `"20"`), in
//! which case the configured default window applies.

use std::time::Duration;

/// A parsed rate limit: at most `limit` requests per `window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rate {
    /// Maximum number of requests allowed within the window.
    pub limit: u64,
    /// Length of the window.
    pub window: Duration,
}

impl Rate {
    /// Parse a rate string.
    ///
    /// Accepts `"<count>/<unit>"` where unit is one of `s`/`sec`/`second`,
    /// `m`/`min`/`minute`, `h`/`hour` (and their plurals), or a bare
    /// `"<count>"` which uses `default_window`.
    ///
    /// # Errors
    /// Returns an error string when the count or unit cannot be parsed.
    pub fn parse(raw: &str, default_window: Duration) -> Result<Self, String> {
        let raw = raw.trim();
        match raw.split_once('/') {
            None => {
                let limit = raw
                    .parse::<u64>()
                    .map_err(|_| format!("invalid rate count: {raw:?}"))?;
                Ok(Rate {
                    limit,
                    window: default_window,
                })
            }
            Some((count, unit)) => {
                let limit = count
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| format!("invalid rate count: {count:?}"))?;
                let window = parse_unit(unit.trim())?;
                Ok(Rate { limit, window })
            }
        }
    }
}

/// Map a time unit token to its [`Duration`].
fn parse_unit(unit: &str) -> Result<Duration, String> {
    let secs = match unit.to_ascii_lowercase().as_str() {
        "s" | "sec" | "secs" | "second" | "seconds" => 1,
        "m" | "min" | "mins" | "minute" | "minutes" => 60,
        "h" | "hr" | "hour" | "hours" => 3600,
        other => return Err(format!("invalid rate unit: {other:?}")),
    };
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: Duration = Duration::from_secs(60);

    #[test]
    fn parse_count_per_unit() {
        assert_eq!(
            Rate::parse("20/min", DEFAULT).unwrap(),
            Rate {
                limit: 20,
                window: Duration::from_secs(60)
            }
        );
        assert_eq!(
            Rate::parse("5/s", DEFAULT).unwrap(),
            Rate {
                limit: 5,
                window: Duration::from_secs(1)
            }
        );
        assert_eq!(
            Rate::parse("100/hour", DEFAULT).unwrap(),
            Rate {
                limit: 100,
                window: Duration::from_secs(3600)
            }
        );
    }

    #[test]
    fn parse_bare_count_uses_default_window() {
        assert_eq!(
            Rate::parse("42", DEFAULT).unwrap(),
            Rate {
                limit: 42,
                window: DEFAULT
            }
        );
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Rate::parse("abc", DEFAULT).is_err());
        assert!(Rate::parse("10/fortnight", DEFAULT).is_err());
        assert!(Rate::parse("/min", DEFAULT).is_err());
    }
}
