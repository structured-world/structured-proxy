use super::*;
use tonic::metadata::{AsciiMetadataValue, BinaryMetadataValue};

fn metadata(entries: &[(&'static str, &'static str)]) -> MetadataMap {
    let mut md = MetadataMap::new();
    for (key, value) in entries {
        md.append(*key, AsciiMetadataValue::from_static(value));
    }
    md
}

fn values<'a>(headers: &'a HeaderMap, name: &str) -> Vec<&'a str> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect()
}

#[test]
fn application_metadata_becomes_headers() {
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(
        metadata(&[
            ("cache-control", "no-store"),
            ("www-authenticate", "Bearer error=\"invalid_token\""),
            ("dpop-nonce", "n-1"),
        ]),
        &[],
    );
    let headers = upstream.into_headers();
    assert_eq!(values(&headers, "cache-control"), ["no-store"]);
    assert_eq!(
        values(&headers, "www-authenticate"),
        ["Bearer error=\"invalid_token\""]
    );
    assert_eq!(values(&headers, "dpop-nonce"), ["n-1"]);
}

#[test]
fn grpc_and_connection_keys_are_withheld() {
    // gRPC's own keys, content-type (the transcoder sets it) and the
    // hop-by-hop / framing fields describe the upstream stream, not the
    // HTTP response.
    let withheld = [
        ("grpc-status", "0"),
        ("grpc-message", "ok"),
        ("grpc-encoding", "gzip"),
        ("grpc-accept-encoding", "gzip"),
        ("content-type", "application/grpc"),
        ("connection", "close"),
        ("keep-alive", "timeout=5"),
        ("proxy-connection", "keep-alive"),
        ("te", "trailers"),
        ("trailer", "grpc-status"),
        ("transfer-encoding", "chunked"),
        ("upgrade", "h2c"),
        ("content-length", "12"),
        ("x-http-code", "302"),
    ];
    let mut md = metadata(&withheld);
    md.append_bin("trace-bin", BinaryMetadataValue::from_bytes(b"\x00\x01"));
    md.append("x-kept", AsciiMetadataValue::from_static("yes"));
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(md, &[]);
    let headers = upstream.into_headers();
    assert_eq!(
        headers.keys().map(|k| k.as_str()).collect::<Vec<_>>(),
        ["x-kept"]
    );
}

#[test]
fn deny_list_drops_its_keys_only() {
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(
        metadata(&[
            ("x-debug-trace", "t"),
            ("x-debug-trace", "u"),
            ("location", "/next"),
        ]),
        &[HeaderName::from_static("x-debug-trace")],
    );
    let headers = upstream.into_headers();
    assert!(headers.get("x-debug-trace").is_none());
    assert_eq!(values(&headers, "location"), ["/next"]);
}

#[test]
fn repeated_values_and_trailers_keep_every_value_in_order() {
    // Repeated metadata values are repeated header fields; a key sent in
    // initial metadata and trailers keeps both values, initial first.
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(
        metadata(&[("set-cookie", "a=1"), ("set-cookie", "b=2"), ("x-one", "1")]),
        &[],
    );
    upstream.absorb(metadata(&[("set-cookie", "c=3"), ("x-two", "2")]), &[]);
    let headers = upstream.into_headers();
    assert_eq!(values(&headers, "set-cookie"), ["a=1", "b=2", "c=3"]);
    assert_eq!(values(&headers, "x-one"), ["1"]);
    assert_eq!(values(&headers, "x-two"), ["2"]);
}

#[test]
fn http_code_sets_the_status_and_is_not_forwarded() {
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(
        metadata(&[("x-http-code", "302"), ("location", "/cb")]),
        &[],
    );
    assert_eq!(upstream.status(), Ok(Some(StatusCode::FOUND)));
    assert!(upstream.into_headers().get("x-http-code").is_none());
}

#[test]
fn absent_http_code_leaves_the_status_alone() {
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(metadata(&[("x-other", "1")]), &[]);
    assert_eq!(upstream.status(), Ok(None));
}

#[test]
fn http_code_range_edges() {
    for (value, expected) in [
        ("200", Some(StatusCode::OK)),
        ("599", Some(StatusCode::from_u16(599).unwrap())),
        ("400", Some(StatusCode::BAD_REQUEST)),
        ("199", None),
        ("600", None),
        ("100", None),
        ("000", None),
    ] {
        let mut upstream = UpstreamHeaders::default();
        upstream.absorb(metadata(&[("x-http-code", value)]), &[]);
        let status = upstream.status();
        match expected {
            Some(code) => assert_eq!(status, Ok(Some(code)), "{value}"),
            None => assert_eq!(status, Err(InvalidHttpCode), "{value}"),
        }
    }
}

#[test]
fn http_code_that_is_not_three_digits_is_invalid() {
    for value in ["+200", "20", "2000", " 200", "200 ", "2x0", "", "0x1f"] {
        let mut md = MetadataMap::new();
        md.append("x-http-code", AsciiMetadataValue::try_from(value).unwrap());
        let mut upstream = UpstreamHeaders::default();
        upstream.absorb(md, &[]);
        assert_eq!(upstream.status(), Err(InvalidHttpCode), "{value:?}");
    }
}

#[test]
fn http_code_given_twice_is_invalid_even_if_equal() {
    // Twice in one map, and once in initial metadata plus once in trailers.
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(
        metadata(&[("x-http-code", "400"), ("x-http-code", "400")]),
        &[],
    );
    assert_eq!(upstream.status(), Err(InvalidHttpCode));

    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(metadata(&[("x-http-code", "400")]), &[]);
    upstream.absorb(metadata(&[("x-http-code", "401")]), &[]);
    assert_eq!(upstream.status(), Err(InvalidHttpCode));
}

#[test]
fn http_code_cannot_be_denied_into_forwarding() {
    // The deny-list only removes more; x-http-code is consumed either way.
    let mut upstream = UpstreamHeaders::default();
    upstream.absorb(
        metadata(&[("x-http-code", "201")]),
        &[HeaderName::from_static("x-http-code")],
    );
    assert_eq!(upstream.status(), Ok(Some(StatusCode::CREATED)));
    assert!(upstream.into_headers().is_empty());
}

#[test]
fn own_headers_replace_same_named_upstream_values() {
    let mut upstream = HeaderMap::new();
    upstream.append("cache-control", HeaderValue::from_static("max-age=60"));
    upstream.append("cache-control", HeaderValue::from_static("public"));
    upstream.append("x-upstream", HeaderValue::from_static("1"));
    let mut response = Response::new(Body::empty());
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-cache"));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
    let response = with_upstream_headers(response, upstream);
    let headers = response.headers();
    assert_eq!(values(headers, "cache-control"), ["no-cache"]);
    assert_eq!(values(headers, "content-type"), ["text/event-stream"]);
    assert_eq!(values(headers, "x-upstream"), ["1"]);
}

#[test]
fn own_multi_valued_header_keeps_all_its_values() {
    let mut response = Response::new(Body::empty());
    response
        .headers_mut()
        .append("vary", HeaderValue::from_static("accept"));
    response
        .headers_mut()
        .append("vary", HeaderValue::from_static("origin"));
    let mut upstream = HeaderMap::new();
    upstream.insert("vary", HeaderValue::from_static("cookie"));
    let response = with_upstream_headers(response, upstream);
    assert_eq!(values(response.headers(), "vary"), ["accept", "origin"]);
}

async fn body_bytes(response: Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec()
}

#[tokio::test]
async fn build_sets_status_headers_and_content_type() {
    let mut headers = HeaderMap::new();
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    let response = build(
        StatusCode::BAD_REQUEST,
        headers,
        Some(HeaderValue::from_static("application/json")),
        Body::from("{}"),
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
    assert_eq!(body_bytes(response).await, b"{}");
}

#[tokio::test]
async fn build_without_content_type_sets_none() {
    let response = build(StatusCode::FOUND, HeaderMap::new(), None, Body::empty());
    assert!(response.headers().get(CONTENT_TYPE).is_none());
    assert!(body_bytes(response).await.is_empty());
}

#[tokio::test]
async fn no_content_statuses_drop_body_and_content_type() {
    // RFC 9110 §15.3.5 / §15.3.6 / §15.4.5: 204, 205 and 304 carry no content.
    for status in [
        StatusCode::NO_CONTENT,
        StatusCode::RESET_CONTENT,
        StatusCode::NOT_MODIFIED,
    ] {
        let response = build(
            status,
            HeaderMap::new(),
            Some(HeaderValue::from_static("application/json")),
            Body::from("{}"),
        );
        assert_eq!(response.status(), status);
        assert!(response.headers().get(CONTENT_TYPE).is_none(), "{status}");
        assert!(body_bytes(response).await.is_empty(), "{status}");
    }
}
