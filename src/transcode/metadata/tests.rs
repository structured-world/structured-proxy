use super::*;

/// The metadata for `headers`, for requests every value of which is valid.
fn http_headers_to_grpc_metadata(headers: &HeaderMap, forwarded: &[String]) -> MetadataMap {
    try_http_headers_to_grpc_metadata(headers, forwarded).expect("every forwarded value is valid")
}

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
fn synthesized_traceparents_are_valid_and_differ_across_threads() {
    // Each thread draws ids from its own generator, seeded from the system's:
    // two threads never repeat each other's trace, and every id is a valid
    // W3C traceparent.
    let draw = || {
        (0..64)
            .map(|_| String::from_utf8(new_traceparent().unwrap().to_vec()).unwrap())
            .collect::<Vec<_>>()
    };
    let here = draw();
    let there = std::thread::spawn(draw).join().unwrap();
    let mut all: Vec<&String> = here.iter().chain(&there).collect();
    for tp in &all {
        assert!(is_valid_traceparent(tp), "{tp}");
    }
    all.sort();
    all.dedup();
    assert_eq!(all.len(), 128);
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
fn a_value_grpc_metadata_cannot_carry_refuses_the_request() {
    // obs-text (RFC 9110 §5.5) and HTAB are valid HTTP field values but not
    // gRPC ASCII-Values, which a receiver may drop and so change the count:
    // the request is refused instead, naming the header.
    for bad in [&b"caf\xe9"[..], b"a\tb"] {
        let mut headers = HeaderMap::new();
        headers.append("dpop", HeaderValue::from_static("proof-a"));
        headers.append("dpop", HeaderValue::from_bytes(bad).unwrap());
        let err = try_http_headers_to_grpc_metadata(&headers, &default_headers()).unwrap_err();
        assert_eq!(err.header, "dpop");
        assert!(err.to_string().contains("dpop"), "{err}");
    }
}

#[test]
fn a_space_is_forwarded_but_an_empty_text_value_refuses_the_request() {
    // `ASCII-Value → 1*( %x20-%x7E )`: space is allowed, an empty value is
    // not, and a receiver dropping it would let `DPoP: proof` plus an empty
    // `DPoP:` pass as a single proof.
    let mut headers = HeaderMap::new();
    headers.append("dpop", HeaderValue::from_static("a b"));
    let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
    assert_eq!(values(&meta, "dpop"), [b"a b".to_vec()]);

    headers.append("dpop", HeaderValue::from_static(""));
    let err = try_http_headers_to_grpc_metadata(&headers, &default_headers()).unwrap_err();
    assert_eq!(err.header, "dpop");
}

#[test]
fn a_binary_value_must_be_base64() {
    // gRPC PROTOCOL-HTTP2: `-bin` values are base64 (RFC 4648 §4), padded or
    // not, possibly several joined by commas.
    for good in ["", "AAEC", "AA", "AA==", "AAE", "AAE=", "AAEC, AA=="] {
        assert!(is_base64_value(good.as_bytes()), "{good:?}");
    }
    for bad in ["A", "A===", "=", "AA=A", "AA*C", "AAEC,A", "caf\u{e9}"] {
        assert!(!is_base64_value(bad.as_bytes()), "{bad:?}");
    }
    let mut headers = HeaderMap::new();
    headers.insert("x-trace-bin", HeaderValue::from_static("not base64!"));
    let err =
        try_http_headers_to_grpc_metadata(&headers, &["x-trace-bin".to_string()]).unwrap_err();
    assert_eq!(err.header, "x-trace-bin");
}

#[test]
fn a_binary_value_must_be_canonical_base64() {
    // RFC 4648 §3.5: the bits past the last byte must be zero, and decoders
    // (tonic's among them) reject a value where they are not.
    for bad in ["AB==", "AB", "AAF=", "AAF"] {
        assert!(!is_base64_value(bad.as_bytes()), "{bad:?}");
    }
    for good in ["AQ==", "AQ", "AAE=", "AAE", "/w==", "//8="] {
        assert!(is_base64_value(good.as_bytes()), "{good:?}");
    }
}

#[test]
fn comma_joined_binary_values_reach_the_upstream_as_separate_values() {
    // gRPC PROTOCOL-HTTP2 lets binary values be joined by commas; tonic does
    // not split them, so each part is forwarded as its own value.
    let mut headers = HeaderMap::new();
    headers.insert("x-trace-bin", HeaderValue::from_static("AAEC, AA=="));
    let meta = http_headers_to_grpc_metadata(&headers, &["x-trace-bin".to_string()]);
    let decoded: Vec<Vec<u8>> = meta
        .get_all_bin("x-trace-bin")
        .iter()
        .map(|v| v.to_bytes().unwrap().to_vec())
        .collect();
    assert_eq!(decoded, [vec![0u8, 1, 2], vec![0u8]]);
}

#[test]
fn a_listed_trace_context_header_is_left_to_trace_propagation() {
    // A malformed traceparent is replaced by a fresh one whether or not it is
    // listed, rather than refusing the request.
    let mut headers = HeaderMap::new();
    headers.insert("traceparent", HeaderValue::from_static("00-bad\tvalue"));
    headers.insert("tracestate", HeaderValue::from_bytes(b"caf\xe9").unwrap());
    let listed = vec!["traceparent".to_string(), "tracestate".to_string()];
    let meta = try_http_headers_to_grpc_metadata(&headers, &listed).unwrap();
    let tp = meta.get("traceparent").unwrap().to_str().unwrap();
    assert!(is_valid_traceparent(tp), "{tp}");
    assert!(meta.get("tracestate").is_none());
}

#[test]
fn a_name_outside_the_grpc_key_grammar_is_not_forwarded() {
    // gRPC keys are lowercase letters, digits, `_`, `-` and `.`; `+` is a
    // valid HTTP field-name character but not a gRPC one.
    assert!(is_grpc_key("x-request-id"));
    assert!(is_grpc_key("DPoP"));
    assert!(!is_grpc_key("x+proof-bin"));
    assert!(!is_grpc_key(""));
    let mut headers = HeaderMap::new();
    headers.insert("x+proof", HeaderValue::from_static("a"));
    let meta = http_headers_to_grpc_metadata(&headers, &["x+proof".to_string()]);
    assert!(meta.get("x+proof").is_none());
}

#[test]
#[expect(deprecated, reason = "the forwarding-as-is API stays available")]
fn the_unchecked_conversion_still_forwards_every_value() {
    let mut headers = HeaderMap::new();
    headers.append("dpop", HeaderValue::from_static("proof-a"));
    headers.append("dpop", HeaderValue::from_bytes(b"caf\xe9").unwrap());
    let meta = super::http_headers_to_grpc_metadata(&headers, &default_headers());
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

#[test]
fn a_forwarded_tracestate_does_not_outlive_its_trace() {
    // The incoming traceparent is invalid, so a fresh one is synthesized; the
    // client's tracestate annotates a trace the upstream never sees.
    let mut headers = HeaderMap::new();
    headers.insert("traceparent", HeaderValue::from_static("garbage"));
    headers.insert("tracestate", HeaderValue::from_static("congo=t61rcWkgMzE"));
    let meta = http_headers_to_grpc_metadata(&headers, &["tracestate".to_string()]);
    assert!(meta.get("tracestate").is_none());
}

#[test]
fn every_tracestate_line_travels_with_its_trace() {
    // W3C Trace Context §3.3: `tracestate` may arrive split over several
    // header lines, which together form one list; dropping any line loses
    // vendor entries.
    let mut headers = HeaderMap::new();
    headers.insert(
        "traceparent",
        HeaderValue::from_static("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"),
    );
    headers.append("tracestate", HeaderValue::from_static("congo=t61rcWkgMzE"));
    headers.append(
        "tracestate",
        HeaderValue::from_static("rojo=00f067aa0ba902b7"),
    );
    for forwarded in [vec![], vec!["tracestate".to_string()]] {
        let meta = http_headers_to_grpc_metadata(&headers, &forwarded);
        assert_eq!(
            values(&meta, "tracestate"),
            [
                b"congo=t61rcWkgMzE".to_vec(),
                b"rojo=00f067aa0ba902b7".to_vec()
            ],
            "forwarded: {forwarded:?}"
        );
    }
}
