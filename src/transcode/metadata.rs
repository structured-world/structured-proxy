//! HTTP → gRPC metadata forwarding.
//!
//! Converts relevant HTTP headers into gRPC `MetadataMap` entries
//! for upstream calls. Forwarded headers are configurable via YAML.

use axum::http::HeaderMap;
use tonic::metadata::MetadataMap;

/// Extract HTTP headers into a gRPC `MetadataMap`.
/// Only forwards headers listed in `forwarded_headers`.
pub fn http_headers_to_grpc_metadata(
    headers: &HeaderMap,
    forwarded_headers: &[String],
) -> MetadataMap {
    let mut metadata = MetadataMap::new();

    for header_name in forwarded_headers {
        if let Some(value) = headers.get(header_name.as_str()) {
            if let Ok(meta_value) = tonic::metadata::AsciiMetadataValue::try_from(value.as_bytes())
            {
                if let Ok(key) =
                    header_name.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>()
                {
                    metadata.insert(key, meta_value);
                }
            }
        }
    }

    metadata
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
    fn test_empty_headers() {
        let headers = HeaderMap::new();
        let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
        assert!(meta.is_empty());
    }

    #[test]
    fn test_dpop_forwarded() {
        let mut headers = HeaderMap::new();
        headers.insert("dpop", HeaderValue::from_static("eyJ0eXAiOiJkcG9wK2p3dCJ9"));
        let meta = http_headers_to_grpc_metadata(&headers, &default_headers());
        assert!(meta.get("dpop").is_some());
    }
}
