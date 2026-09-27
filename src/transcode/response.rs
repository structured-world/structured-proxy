//! Upstream response metadata → HTTP response headers and status.
//!
//! The upstream's response metadata is its HTTP response headers, as in Envoy's
//! transcoder, where gRPC and HTTP share one HTTP/2 stream. Only what belongs
//! to gRPC itself or to the upstream connection is held back, plus
//! `x-http-code`, which sets the status of a successful unary answer
//! (grpc-gateway's convention).

use axum::body::Body;
use axum::http::header::{Entry, OccupiedEntry, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use tonic::metadata::MetadataMap;

/// Response metadata key whose value sets the HTTP status of a successful
/// unary call.
pub(crate) const HTTP_CODE_KEY: &str = "x-http-code";

/// Whether a response metadata key never becomes an HTTP response header:
/// gRPC's own keys (`grpc-*`, the binary `-bin` encoding, `content-type`, which
/// the transcoder sets), and the hop-by-hop and framing fields that describe
/// the upstream connection rather than the response (RFC 9110 §7.6.1,
/// RFC 9110 §8.6 for `content-length`).
fn is_withheld(name: &str) -> bool {
    name.starts_with("grpc-")
        || name.ends_with("-bin")
        || matches!(
            name,
            "content-type"
                | "connection"
                | "keep-alive"
                | "proxy-connection"
                | "te"
                | "trailer"
                | "transfer-encoding"
                | "upgrade"
                | "content-length"
        )
}

/// What `x-http-code` said across the metadata absorbed so far.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum HttpCode {
    #[default]
    Absent,
    Set(StatusCode),
    /// Not an integer in 200-599, or given more than once.
    Invalid,
}

/// The `x-http-code` value is not a single integer in 200-599.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct InvalidHttpCode;

/// HTTP response headers collected from the upstream's response metadata.
#[derive(Debug, Default)]
pub(crate) struct UpstreamHeaders {
    headers: HeaderMap,
    http_code: HttpCode,
}

/// How [`UpstreamHeaders::absorb`] treats the values of the key it is on.
enum Current<'a> {
    Forward(OccupiedEntry<'a, HeaderValue>),
    HttpCode,
    Drop,
}

impl UpstreamHeaders {
    /// Add the forwardable entries of `metadata`, in order, after the ones
    /// already absorbed: a key present in both initial metadata and trailers
    /// keeps both values. Keys in `deny` are dropped like withheld ones.
    pub(crate) fn absorb(&mut self, metadata: MetadataMap, deny: &[HeaderName]) {
        let headers = &mut self.headers;
        let http_code = &mut self.http_code;
        let mut current = Current::Drop;
        // A header map yields a name only with the first value of each key.
        for (name, value) in metadata.into_headers() {
            if let Some(name) = name {
                // Release the previous key's entry before borrowing the map again.
                current = Current::Drop;
                if name.as_str() == HTTP_CODE_KEY {
                    record_http_code(http_code, &value);
                    current = Current::HttpCode;
                } else if !is_withheld(name.as_str()) && !deny.contains(&name) {
                    current = Current::Forward(match headers.entry(name) {
                        Entry::Occupied(mut entry) => {
                            entry.append(value);
                            entry
                        }
                        Entry::Vacant(entry) => entry.insert_entry(value),
                    });
                }
                continue;
            }
            match &mut current {
                Current::Forward(entry) => entry.append(value),
                Current::HttpCode => record_http_code(http_code, &value),
                Current::Drop => {}
            }
        }
    }

    /// The status `x-http-code` sets, if any.
    pub(crate) fn status(&self) -> Result<Option<StatusCode>, InvalidHttpCode> {
        match self.http_code {
            HttpCode::Absent => Ok(None),
            HttpCode::Set(status) => Ok(Some(status)),
            HttpCode::Invalid => Err(InvalidHttpCode),
        }
    }

    pub(crate) fn into_headers(self) -> HeaderMap {
        self.headers
    }
}

/// Fold one `x-http-code` value into `slot`: the first valid one sets it, a
/// second one of any kind makes it invalid (two statuses cannot both apply).
fn record_http_code(slot: &mut HttpCode, value: &HeaderValue) {
    *slot = match (*slot, parse_http_code(value)) {
        (HttpCode::Absent, Some(status)) => HttpCode::Set(status),
        _ => HttpCode::Invalid,
    };
}

/// An `x-http-code` value: exactly three ASCII digits naming a status in
/// 200-599. `1xx` is excluded because an interim response cannot be the final
/// answer (RFC 9110 §15.2).
fn parse_http_code(value: &HeaderValue) -> Option<StatusCode> {
    let bytes = value.as_bytes();
    if bytes.len() != 3 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let code = bytes
        .iter()
        .fold(0u16, |code, digit| code * 10 + u16::from(digit - b'0'));
    if !(200..=599).contains(&code) {
        return None;
    }
    StatusCode::from_u16(code).ok()
}

/// `response` with `upstream` as its headers, the ones it already carries
/// (`Content-Type`, an SSE `Cache-Control`) replacing same-named upstream
/// values: what the proxy writes describes the body it writes.
pub(crate) fn with_upstream_headers(response: Response, upstream: HeaderMap) -> Response {
    if upstream.is_empty() {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let own = std::mem::replace(&mut parts.headers, upstream);
    let mut last: Option<HeaderName> = None;
    for (name, value) in own {
        match name {
            Some(name) => {
                parts.headers.insert(&name, value);
                last = Some(name);
            }
            None => {
                if let Some(name) = &last {
                    parts.headers.append(name, value);
                }
            }
        }
    }
    Response::from_parts(parts, body)
}

/// A response with `status`, `headers` and `body`, typed by `content_type`.
/// `204` and `304` carry neither content nor a `Content-Type`, whatever the
/// upstream returned (RFC 9110 §15.3.5, §15.4.5).
pub(crate) fn build(
    status: StatusCode,
    mut headers: HeaderMap,
    content_type: Option<HeaderValue>,
    body: Body,
) -> Response {
    let no_content = matches!(status, StatusCode::NO_CONTENT | StatusCode::NOT_MODIFIED);
    let body = if no_content { Body::empty() } else { body };
    if let (Some(content_type), false) = (content_type, no_content) {
        headers.insert(CONTENT_TYPE, content_type);
    }
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[cfg(test)]
mod tests;
