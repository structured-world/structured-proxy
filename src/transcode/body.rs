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
#[deprecated(
    note = "the transcoder reads the body straight into the request message; \
            use request::Body with request::build_request_message"
)]
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
mod tests;
