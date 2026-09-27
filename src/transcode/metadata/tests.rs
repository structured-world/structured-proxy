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
fn grpc_timeout_rejects_malformed() {
    assert_eq!(parse_grpc_timeout(""), None);
    assert_eq!(parse_grpc_timeout("S"), None);
    assert_eq!(parse_grpc_timeout("10X"), None);
    assert_eq!(parse_grpc_timeout("abcS"), None);
}

#[test]
fn grpc_timeout_rejects_zero_duration() {
    // A zero deadline would make tonic's timeout expire immediately, failing
    // every such request with DEADLINE_EXCEEDED before it reaches upstream.
    assert_eq!(parse_grpc_timeout("0S"), None);
    assert_eq!(parse_grpc_timeout("0m"), None);
    assert_eq!(parse_grpc_timeout("0n"), None);
}

#[test]
fn grpc_timeout_enforces_8_digit_limit() {
    // The gRPC wire spec caps TimeoutValue at 8 digits.
    assert_eq!(
        parse_grpc_timeout("99999999S"),
        Some(Duration::from_secs(99_999_999))
    );
    assert_eq!(parse_grpc_timeout("999999999S"), None); // 9 digits
}

#[test]
fn versioned_traceparent_is_forwarded() {
    // W3C 3.2.1 requires accepting future versions (anything but ff); a
    // valid version-01 header must be propagated, not dropped + resynthesized.
    let incoming = "01-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let mut headers = HeaderMap::new();
    headers.insert("traceparent", HeaderValue::from_static(incoming));
    let meta = http_headers_to_grpc_metadata(&headers, &[]);
    assert_eq!(meta.get("traceparent").unwrap().to_str().unwrap(), incoming);
}

#[test]
fn ff_version_traceparent_is_rejected() {
    // The reserved "ff" version is invalid per W3C and must be replaced.
    let invalid = "ff-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let mut headers = HeaderMap::new();
    headers.insert("traceparent", HeaderValue::from_static(invalid));
    let meta = http_headers_to_grpc_metadata(&headers, &[]);
    let tp = meta.get("traceparent").unwrap().to_str().unwrap();
    assert_ne!(tp, invalid);
    assert!(is_valid_traceparent(tp));
}

#[test]
fn malformed_or_zero_traceparent_is_not_forwarded() {
    // An all-zeros traceparent is invalid per W3C §3.2.2 and must not be
    // propagated; a fresh one is synthesized instead.
    let zeros = "00-00000000000000000000000000000000-0000000000000000-01";
    let mut headers = HeaderMap::new();
    headers.insert("traceparent", HeaderValue::from_static(zeros));
    let meta = http_headers_to_grpc_metadata(&headers, &[]);
    let tp = meta.get("traceparent").unwrap().to_str().unwrap();
    assert_ne!(tp, zeros);
    assert!(
        is_valid_traceparent(tp),
        "synthesized traceparent invalid: {tp}"
    );
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

/// Every value of `name` in `meta`, in order, as raw bytes.
fn values(meta: &MetadataMap, name: &str) -> Vec<Vec<u8>> {
    meta.get_all(name)
        .iter()
        .map(|v| v.as_encoded_bytes().to_vec())
        .collect()
}

#[test]
fn every_value_of_a_repeated_header_is_forwarded_in_order() {
    // RFC 9449 §4.3 has the server reject a request with two DPoP headers;
    // the upstream can only do that if it sees both.
    let mut headers = HeaderMap::new();
    headers.append("dpop", HeaderValue::from_static("proof-a"));
    headers.append("dpop", HeaderValue::from_static("proof-b"));
    let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
    assert_eq!(
        values(&meta, "dpop"),
        [b"proof-a".to_vec(), b"proof-b".to_vec()]
    );
}

#[test]
fn a_value_outside_visible_ascii_still_counts() {
    // obs-text (RFC 9110 §5.5) is a valid field value; it travels next to the
    // plain one, so the count reaching the upstream is the count sent.
    let mut headers = HeaderMap::new();
    headers.append("dpop", HeaderValue::from_static("proof-a"));
    headers.append("dpop", HeaderValue::from_bytes(b"caf\xe9").unwrap());
    let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
    assert_eq!(
        values(&meta, "dpop"),
        [b"proof-a".to_vec(), b"caf\xe9".to_vec()]
    );
}

#[test]
fn a_binary_header_is_forwarded_as_sent() {
    // A `-bin` key carries base64 over HTTP/2 (gRPC PROTOCOL-HTTP2); it
    // passes through unchanged instead of being dropped.
    let mut headers = HeaderMap::new();
    headers.insert("x-trace-bin", HeaderValue::from_static("AAEC"));
    let meta = http_headers_to_grpc_metadata(&headers, &["x-trace-bin".to_string()]);
    assert_eq!(
        meta.get_bin("x-trace-bin")
            .unwrap()
            .to_bytes()
            .unwrap()
            .as_ref(),
        [0u8, 1, 2]
    );
}

#[test]
fn a_header_listed_twice_is_not_doubled() {
    let mut headers = HeaderMap::new();
    headers.insert("dpop", HeaderValue::from_static("proof-a"));
    let listed_twice = vec!["dpop".to_string(), "DPoP".to_string()];
    let meta = http_headers_to_grpc_metadata(&headers, &listed_twice);
    assert_eq!(values(&meta, "dpop"), [b"proof-a".to_vec()]);
}

#[test]
fn a_forwarded_traceparent_is_not_duplicated() {
    // Listing `traceparent` among the forwarded headers must not leave two
    // trace contexts for the upstream to choose between.
    let incoming = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
    let mut headers = HeaderMap::new();
    headers.insert("traceparent", HeaderValue::from_static(incoming));
    let meta = http_headers_to_grpc_metadata(&headers, &["traceparent".to_string()]);
    assert_eq!(values(&meta, "traceparent"), [incoming.as_bytes().to_vec()]);
}
