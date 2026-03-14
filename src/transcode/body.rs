//! Request body parsing.
//!
//! Supports JSON (`application/json`) and form-urlencoded
//! (`application/x-www-form-urlencoded`) request bodies.
//! Empty bodies are treated as empty JSON objects.

use axum::http::HeaderMap;
use serde_json::Value;

/// Parse request body bytes into a JSON `Value` based on content type.
///
/// - `application/x-www-form-urlencoded` → parse form fields into JSON object
/// - `application/json` or anything else → parse as JSON
/// - Empty body → `{}`
pub fn parse_body(content_type: Option<&str>, body: &[u8]) -> Result<Value, BodyError> {
    if body.is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }

    match content_type {
        Some(ct) if ct.starts_with("application/x-www-form-urlencoded") => {
            let pairs: Vec<(String, String)> = serde_urlencoded::from_bytes(body)
                .map_err(|e| BodyError::FormDecode(e.to_string()))?;
            let mut map = serde_json::Map::new();
            for (key, value) in pairs {
                map.insert(key, Value::String(value));
            }
            Ok(Value::Object(map))
        }
        _ => serde_json::from_slice(body).map_err(|e| BodyError::JsonDecode(e.to_string())),
    }
}

/// Extract content type from headers (just the media type, no parameters).
pub fn content_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.split(';').next().unwrap_or(ct).trim())
}

#[derive(Debug, thiserror::Error)]
pub enum BodyError {
    #[error("invalid JSON: {0}")]
    JsonDecode(String),
    #[error("invalid form data: {0}")]
    FormDecode(String),
}

#[cfg(test)]
mod tests {
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
        let body =
            b"grant_type=authorization_code&code=abc123&redirect_uri=https%3A%2F%2Fexample.com";
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
}
