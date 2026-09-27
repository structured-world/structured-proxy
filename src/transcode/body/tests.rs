use super::*;

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
