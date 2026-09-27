//! Request body media type.
//!
//! The body itself is read straight into the request message by
//! [`super::request::build_request_message`], as JSON or as a
//! `application/x-www-form-urlencoded` form.

use axum::http::HeaderMap;

/// Extract content type from headers (just the media type, no parameters).
pub fn content_type(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.split(';').next().unwrap_or(ct).trim())
}

#[cfg(test)]
mod tests;
