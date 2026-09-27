// `parse_body` is deprecated but still public, so its behavior stays pinned.
#![expect(deprecated)]

use super::*;

#[test]
fn test_empty_body() {
    let result = parse_body(Some("application/json"), b"").unwrap();
    assert_eq!(result, serde_json::json!({}));
}

#[test]
fn test_json_body() {
    let body = br#"{"username":"alice","password":"secret"}"#;
    let result = parse_body(Some("application/json"), body).unwrap();
    assert_eq!(result["username"], "alice");
    assert_eq!(result["password"], "secret");
}

#[test]
fn test_form_urlencoded_body() {
    let body = b"grant_type=authorization_code&code=abc123&redirect_uri=https%3A%2F%2Fexample.com";
    let result = parse_body(Some("application/x-www-form-urlencoded"), body).unwrap();
    assert_eq!(result["grant_type"], "authorization_code");
    assert_eq!(result["code"], "abc123");
    assert_eq!(result["redirect_uri"], "https://example.com");
}

#[test]
fn test_form_with_charset() {
    let body = b"key=value";
    let result = parse_body(
        Some("application/x-www-form-urlencoded; charset=utf-8"),
        body,
    )
    .unwrap();
    assert_eq!(result["key"], "value");
}

#[test]
fn test_no_content_type_parses_as_json() {
    let body = br#"{"foo":"bar"}"#;
    let result = parse_body(None, body).unwrap();
    assert_eq!(result["foo"], "bar");
}

#[test]
fn test_invalid_json() {
    let body = b"not json";
    assert!(parse_body(Some("application/json"), body).is_err());
}

#[test]
fn test_content_type_extraction() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        "application/json; charset=utf-8".parse().unwrap(),
    );
    assert_eq!(content_type(&headers), Some("application/json"));
}

#[test]
fn test_content_type_missing() {
    let headers = HeaderMap::new();
    assert_eq!(content_type(&headers), None);
}
