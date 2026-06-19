//! HTTP → gRPC metadata, trace-context, and deadline propagation.
//!
//! Converts relevant HTTP headers into gRPC `MetadataMap` entries for upstream
//! calls (forwarded headers are configurable via YAML), propagates W3C
//! trace-context across the boundary, and carries a client deadline through as
//! the upstream call timeout.

use std::time::Duration;

use axum::http::HeaderMap;
use tonic::metadata::MetadataMap;

/// Extract HTTP headers into a gRPC `MetadataMap`.
///
/// Forwards the headers listed in `forwarded_headers`, then always propagates
/// W3C trace-context (forwarding an incoming `traceparent` or synthesizing one
/// so the upstream joins a single trace across the REST↔gRPC boundary).
pub fn http_headers_to_grpc_metadata(
    headers: &HeaderMap,
    forwarded_headers: &[String],
) -> MetadataMap {
    let mut metadata = MetadataMap::new();

    for header_name in forwarded_headers {
        if let Some(value) = headers.get(header_name.as_str()) {
            insert_ascii(&mut metadata, header_name, value.as_bytes());
        }
    }

    inject_trace_context(&mut metadata, headers);

    metadata
}

/// Insert an ASCII metadata entry, silently skipping non-ASCII keys/values.
fn insert_ascii(metadata: &mut MetadataMap, key: &str, value: &[u8]) {
    if let (Ok(k), Ok(v)) = (
        key.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>(),
        tonic::metadata::AsciiMetadataValue::try_from(value),
    ) {
        metadata.insert(k, v);
    }
}

/// Propagate W3C trace-context into gRPC metadata.
///
/// Forwards an incoming `traceparent` (and `tracestate`) verbatim; when no
/// `traceparent` is present, synthesizes one so a non-instrumented client still
/// produces a single joinable trace across the boundary.
fn inject_trace_context(metadata: &mut MetadataMap, headers: &HeaderMap) {
    if let Some(tp) = headers.get("traceparent") {
        insert_ascii(metadata, "traceparent", tp.as_bytes());
        if let Some(ts) = headers.get("tracestate") {
            insert_ascii(metadata, "tracestate", ts.as_bytes());
        }
    } else if let Some(tp) = new_traceparent() {
        insert_ascii(metadata, "traceparent", tp.as_bytes());
    }
}

/// Build a fresh W3C `traceparent`: `00-<16-byte trace-id>-<8-byte span-id>-01`
/// (sampled). Returns `None` only if the system RNG is unavailable.
fn new_traceparent() -> Option<String> {
    let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).ok()?;
    let trace_id = hex(&buf[..16]);
    let span_id = hex(&buf[16..]);
    Some(format!("00-{trace_id}-{span_id}-01"))
}

/// Lowercase-hex encode a byte slice.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Apply a client-supplied deadline to the upstream gRPC call.
///
/// Reads the gRPC-standard `grpc-timeout` header (`<int><unit>`, unit one of
/// `H`/`M`/`S`/`m`/`u`/`n`) and sets it as the request timeout. Absent or
/// malformed values leave the channel default in place. Returns the deadline
/// that was applied, if any.
pub fn apply_request_deadline<T>(
    request: &mut tonic::Request<T>,
    headers: &HeaderMap,
) -> Option<Duration> {
    let timeout = headers
        .get("grpc-timeout")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_grpc_timeout)?;
    request.set_timeout(timeout);
    Some(timeout)
}

/// Parse a gRPC `grpc-timeout` value (`<int><unit>`) into a [`Duration`].
///
/// Units: `H` hours, `M` minutes, `S` seconds, `m` milliseconds, `u`
/// microseconds, `n` nanoseconds. Returns `None` on a malformed value or on
/// arithmetic overflow.
fn parse_grpc_timeout(value: &str) -> Option<Duration> {
    let value = value.trim();
    let (digits, unit) = value.split_at(value.len().checked_sub(1)?);
    let n: u64 = digits.parse().ok()?;
    let dur = match unit {
        "H" => Duration::from_secs(n.checked_mul(3600)?),
        "M" => Duration::from_secs(n.checked_mul(60)?),
        "S" => Duration::from_secs(n),
        "m" => Duration::from_millis(n),
        "u" => Duration::from_micros(n),
        "n" => Duration::from_nanos(n),
        _ => return None,
    };
    Some(dur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn default_headers() -> Vec<String> {
        vec![
            "authorization".into(),
            "dpop".into(),
            "x-request-id".into(),
            "x-forwarded-for".into(),
            "x-forwarded-proto".into(),
            "x-real-ip".into(),
            "accept-language".into(),
            "user-agent".into(),
            "idempotency-key".into(),
        ]
    }

    #[test]
    fn test_authorization_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer tok123"));
        let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
        assert_eq!(
            meta.get("authorization").unwrap().to_str().unwrap(),
            "Bearer tok123"
        );
    }

    #[test]
    fn test_multiple_headers_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer tok"));
        headers.insert("x-request-id", HeaderValue::from_static("req-42"));
        headers.insert("accept-language", HeaderValue::from_static("en-US"));
        let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
        assert_eq!(
            meta.get("authorization").unwrap().to_str().unwrap(),
            "Bearer tok"
        );
        assert_eq!(
            meta.get("x-request-id").unwrap().to_str().unwrap(),
            "req-42"
        );
        assert_eq!(
            meta.get("accept-language").unwrap().to_str().unwrap(),
            "en-US"
        );
    }

    #[test]
    fn test_unknown_headers_not_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom-header", HeaderValue::from_static("value"));
        let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
        assert!(meta.get("x-custom-header").is_none());
    }

    #[test]
    fn test_custom_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-custom-header", HeaderValue::from_static("value"));
        let forwarded = vec!["x-custom-header".to_string()];
        let meta = http_headers_to_grpc_metadata(&headers, &forwarded);
        assert_eq!(
            meta.get("x-custom-header").unwrap().to_str().unwrap(),
            "value"
        );
    }

    #[test]
    fn test_empty_headers_still_inject_traceparent() {
        // No forwarded headers present, but a trace-context is synthesized so
        // the upstream joins a single trace.
        let headers = HeaderMap::new();
        let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
        let tp = meta.get("traceparent").unwrap().to_str().unwrap();
        assert!(is_valid_traceparent(tp), "bad traceparent: {tp}");
        // Nothing else leaks in.
        assert!(meta.get("authorization").is_none());
    }

    /// A W3C traceparent is `00-<32 hex>-<16 hex>-<2 hex>`.
    fn is_valid_traceparent(tp: &str) -> bool {
        let parts: Vec<&str> = tp.split('-').collect();
        parts.len() == 4
            && parts[0] == "00"
            && parts[1].len() == 32
            && parts[2].len() == 16
            && parts[3].len() == 2
            && parts[1..4]
                .iter()
                .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
    }

    #[test]
    fn traceparent_is_forwarded_when_present() {
        let mut headers = HeaderMap::new();
        let incoming = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        headers.insert("traceparent", HeaderValue::from_static(incoming));
        headers.insert("tracestate", HeaderValue::from_static("vendor=value"));
        let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
        assert_eq!(meta.get("traceparent").unwrap().to_str().unwrap(), incoming);
        assert_eq!(
            meta.get("tracestate").unwrap().to_str().unwrap(),
            "vendor=value"
        );
    }

    #[test]
    fn synthesized_traceparent_is_unique_per_call() {
        let headers = HeaderMap::new();
        let a = http_headers_to_grpc_metadata(&headers, &[]);
        let b = http_headers_to_grpc_metadata(&headers, &[]);
        assert_ne!(
            a.get("traceparent").unwrap().to_str().unwrap(),
            b.get("traceparent").unwrap().to_str().unwrap()
        );
    }

    #[test]
    fn grpc_timeout_parses_each_unit() {
        assert_eq!(parse_grpc_timeout("5S"), Some(Duration::from_secs(5)));
        assert_eq!(parse_grpc_timeout("100m"), Some(Duration::from_millis(100)));
        assert_eq!(parse_grpc_timeout("2M"), Some(Duration::from_secs(120)));
        assert_eq!(parse_grpc_timeout("1H"), Some(Duration::from_secs(3600)));
        assert_eq!(parse_grpc_timeout("250u"), Some(Duration::from_micros(250)));
        assert_eq!(parse_grpc_timeout("9n"), Some(Duration::from_nanos(9)));
    }

    #[test]
    fn grpc_timeout_rejects_malformed_and_overflow() {
        assert_eq!(parse_grpc_timeout(""), None);
        assert_eq!(parse_grpc_timeout("S"), None);
        assert_eq!(parse_grpc_timeout("10X"), None);
        assert_eq!(parse_grpc_timeout("abcS"), None);
        // n * 3600 overflows u64.
        assert_eq!(parse_grpc_timeout("99999999999999999999H"), None);
    }

    #[test]
    fn apply_request_deadline_sets_timeout_from_header() {
        let mut headers = HeaderMap::new();
        headers.insert("grpc-timeout", HeaderValue::from_static("3S"));
        let mut req = tonic::Request::new(());
        assert_eq!(
            apply_request_deadline(&mut req, &headers),
            Some(Duration::from_secs(3))
        );
    }

    #[test]
    fn apply_request_deadline_noop_without_header() {
        let headers = HeaderMap::new();
        let mut req = tonic::Request::new(());
        assert_eq!(apply_request_deadline(&mut req, &headers), None);
    }

    #[test]
    fn test_dpop_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("dpop", HeaderValue::from_static("eyJ0eXAiOiJkcG9wK2p3dCJ9"));
        let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
        assert!(meta.get("dpop").is_some());
    }
}
