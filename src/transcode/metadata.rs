//! HTTP → gRPC metadata, trace-context, and deadline propagation.
//!
//! Converts relevant HTTP headers into gRPC `MetadataMap` entries for upstream
//! calls (forwarded headers are configurable via YAML), propagates W3C
//! trace-context across the boundary, and carries a client deadline through as
//! the upstream call timeout.

use std::convert::Infallible;
use std::time::Duration;

use axum::http::header::Entry;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use tonic::metadata::MetadataMap;

/// A forwarded request header whose value gRPC metadata cannot carry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("header `{header}` has a value gRPC metadata cannot carry")]
pub struct InvalidForwardedHeader {
    /// The header, as the request named it.
    pub header: HeaderName,
}

/// Extract HTTP headers into a gRPC `MetadataMap`, or refuse the request.
///
/// Forwards every value of each header listed in `forwarded_headers`, in
/// order and byte for byte, as Envoy's gRPC-JSON transcoder and grpc-gateway
/// do: the upstream sees how many times the client sent a header, which some
/// checks depend on (RFC 9449 §4.3 rejects a request with more than one
/// `DPoP`). Then always propagates W3C trace-context (forwarding an incoming
/// `traceparent` or synthesizing one so the upstream joins a single trace
/// across the REST↔gRPC boundary). That step owns `traceparent` and
/// `tracestate` even when they are listed: the upstream gets exactly one
/// valid `traceparent`, and every `tracestate` line only with the trace it
/// belongs to.
///
/// # Errors
/// A forwarded value gRPC metadata cannot carry: outside visible ASCII and
/// space for a text key, not base64 for a `-bin` key (gRPC PROTOCOL-HTTP2,
/// "Custom-Metadata"). gRPC lets a receiver drop such a value, which would
/// change how many values the upstream sees, so the request is refused
/// rather than forwarded altered.
pub fn try_http_headers_to_grpc_metadata(
    headers: &HeaderMap,
    forwarded_headers: &[String],
) -> Result<MetadataMap, InvalidForwardedHeader> {
    forward(headers, forwarded_headers, |name, value| {
        if carries(name, value.as_bytes()) {
            Ok(())
        } else {
            Err(InvalidForwardedHeader {
                header: name.clone(),
            })
        }
    })
}

/// Extract HTTP headers into a gRPC `MetadataMap`, forwarding every value as
/// it arrived, including one gRPC metadata cannot carry.
#[deprecated(
    note = "forwards values gRPC metadata cannot carry, which a receiver may drop; \
            use try_http_headers_to_grpc_metadata"
)]
pub fn http_headers_to_grpc_metadata(
    headers: &HeaderMap,
    forwarded_headers: &[String],
) -> MetadataMap {
    match forward::<Infallible>(headers, forwarded_headers, |_, _| Ok(())) {
        Ok(metadata) => metadata,
        Err(never) => match never {},
    }
}

/// The metadata for `headers`, with `check` deciding on each forwarded value.
fn forward<E>(
    headers: &HeaderMap,
    forwarded_headers: &[String],
    mut check: impl FnMut(&HeaderName, &HeaderValue) -> Result<(), E>,
) -> Result<MetadataMap, E> {
    let mut forwarded = HeaderMap::new();
    for name in forwarded_headers {
        let mut values = headers.get_all(name.as_str()).iter();
        let Some(first) = values.next() else {
            continue;
        };
        let name = HeaderName::from_bytes(name.as_bytes())
            .expect("a name the request carries a header under is a valid header name");
        // A name listed twice is forwarded once, so its values are not doubled.
        if let Entry::Vacant(entry) = forwarded.entry(name) {
            check(entry.key(), first)?;
            let mut entry = entry.insert_entry(first.clone());
            for value in values {
                check(entry.key(), value)?;
                entry.append(value.clone());
            }
        }
    }
    let mut metadata = MetadataMap::from_headers(forwarded);

    inject_trace_context(&mut metadata, headers);

    Ok(metadata)
}

/// Whether gRPC metadata can carry `value` under `name` (gRPC PROTOCOL-HTTP2,
/// "Custom-Metadata"): base64 for a `-bin` key, visible ASCII and space for a
/// text key.
fn carries(name: &HeaderName, value: &[u8]) -> bool {
    if name.as_str().ends_with("-bin") {
        is_base64_value(value)
    } else {
        is_ascii_value(value)
    }
}

/// `ASCII-Value → 1*( %x20-%x7E )`. An empty value is allowed: HTTP allows an
/// empty field value, and dropping it would change the count.
fn is_ascii_value(value: &[u8]) -> bool {
    value.iter().all(|b| (0x20..=0x7e).contains(b))
}

/// A `-bin` value: base64 (RFC 4648 §4), padded or not, possibly several
/// comma-separated values, which a receiver must split before decoding.
fn is_base64_value(value: &[u8]) -> bool {
    value.split(|&b| b == b',').all(|part| {
        let part = part.trim_ascii();
        let data = part.strip_suffix(b"==").or_else(|| part.strip_suffix(b"="));
        let alphabet = |data: &[u8]| {
            data.iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        };
        match data {
            // Padding closes a four-digit group.
            Some(data) => alphabet(data) && part.len() % 4 == 0,
            // A lone last digit cannot encode a byte (RFC 4648 §4).
            None => alphabet(part) && part.len() % 4 != 1,
        }
    })
}

/// Insert an ASCII metadata entry, silently skipping a key or value gRPC
/// metadata cannot carry.
fn insert_ascii(metadata: &mut MetadataMap, key: &str, value: &[u8]) {
    if !is_ascii_value(value) {
        return;
    }
    if let (Ok(k), Ok(v)) = (
        key.parse::<tonic::metadata::MetadataKey<tonic::metadata::Ascii>>(),
        tonic::metadata::AsciiMetadataValue::try_from(value),
    ) {
        metadata.insert(k, v);
    }
}

/// Append an ASCII metadata entry, silently skipping a value gRPC metadata
/// cannot carry; W3C Trace Context lets a vendor discard such a `tracestate`.
fn append_ascii(metadata: &mut MetadataMap, key: &'static str, value: &[u8]) {
    if !is_ascii_value(value) {
        return;
    }
    if let Ok(v) = tonic::metadata::AsciiMetadataValue::try_from(value) {
        metadata.append(key, v);
    }
}

/// Propagate W3C trace-context into gRPC metadata.
///
/// Forwards an incoming `traceparent` (and `tracestate`) only when it is
/// well-formed per W3C §3.2.2; otherwise (missing or malformed) synthesizes a
/// fresh one so the upstream always receives a single valid, joinable trace.
fn inject_trace_context(metadata: &mut MetadataMap, headers: &HeaderMap) {
    // tracestate only travels with the trace it annotates, so a forwarded one
    // is replaced here in both branches.
    metadata.remove("tracestate");
    if let Some(tp) = headers.get("traceparent").and_then(|v| v.to_str().ok()) {
        if is_valid_traceparent(tp) {
            insert_ascii(metadata, "traceparent", tp.as_bytes());
            // Every line: W3C Trace Context §3.3 lets tracestate be split
            // over several header lines that together form one list.
            for ts in headers.get_all("tracestate") {
                append_ascii(metadata, "tracestate", ts.as_bytes());
            }
            return;
        }
    }
    if let Some(tp) = new_traceparent() {
        insert_ascii(metadata, "traceparent", tp.as_bytes());
    }
}

/// Validate a W3C `traceparent`: `<version>-<32 hex>-<16 hex>-<2 hex>` with a
/// non-zero trace-id and parent-id (all-zero IDs are forbidden by W3C §3.2.2).
///
/// Per W3C §3.2.1 any 2-hex version except `ff` is accepted; future versions may
/// append extra `-`-delimited fields, while the baseline `00` must be exactly
/// the four fields.
fn is_valid_traceparent(tp: &str) -> bool {
    let parts: Vec<&str> = tp.split('-').collect();
    if parts.len() < 4 {
        return false;
    }
    let (version, trace_id, parent_id, flags) = (parts[0], parts[1], parts[2], parts[3]);
    if version == "00" && parts.len() != 4 {
        return false;
    }
    let is_hex = |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit());
    is_hex(version, 2)
        && !version.eq_ignore_ascii_case("ff")
        && is_hex(trace_id, 32)
        && is_hex(parent_id, 16)
        && is_hex(flags, 2)
        && trace_id.bytes().any(|b| b != b'0')
        && parent_id.bytes().any(|b| b != b'0')
}

/// Build a fresh W3C `traceparent`: `00-<16-byte trace-id>-<8-byte span-id>-01`
/// (sampled). Returns `None` only if the system RNG is unavailable.
fn new_traceparent() -> Option<String> {
    let mut buf = [0u8; 24];
    getrandom::fill(&mut buf).ok()?;
    let trace_id = hex(&buf[..16]);
    let span_id = hex(&buf[16..]);
    Some(format!("00-{trace_id}-{span_id}-01"))
}

/// Lowercase-hex encode a byte slice.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Apply a client-supplied deadline to the upstream gRPC call.
///
/// Reads the gRPC-standard `grpc-timeout` header (`<int><unit>`, unit one of
/// `H`/`M`/`S`/`m`/`u`/`n`) and sets it as the request timeout. Absent or
/// malformed values leave the channel default in place. Returns the deadline
/// that was applied, if any.
pub fn apply_request_deadline<T>(
    request: &mut tonic::Request<T>,
    headers: &HeaderMap,
) -> Option<Duration> {
    let timeout = headers
        .get("grpc-timeout")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_grpc_timeout)?;
    request.set_timeout(timeout);
    Some(timeout)
}

/// Parse a gRPC `grpc-timeout` value (`<int><unit>`) into a [`Duration`].
///
/// Units: `H` hours, `M` minutes, `S` seconds, `m` milliseconds, `u`
/// microseconds, `n` nanoseconds. Per the gRPC wire spec the value is at most 8
/// digits. Returns `None` on a malformed value, an over-long digit run, or a
/// zero duration (which would expire the call immediately, so the channel
/// default is used instead).
fn parse_grpc_timeout(value: &str) -> Option<Duration> {
    let value = value.trim();
    let (digits, unit) = value.split_at(value.len().checked_sub(1)?);
    // The gRPC spec caps TimeoutValue at 8 ASCII digits.
    if digits.is_empty() || digits.len() > 8 {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    // With at most 8 digits, n <= 99_999_999, so n * 3600 < 4e11 << u64::MAX:
    // the multiplications cannot overflow.
    let dur = match unit {
        "H" => Duration::from_secs(n * 3600),
        "M" => Duration::from_secs(n * 60),
        "S" => Duration::from_secs(n),
        "m" => Duration::from_millis(n),
        "u" => Duration::from_micros(n),
        "n" => Duration::from_nanos(n),
        _ => return None,
    };
    if dur.is_zero() {
        return None;
    }
    Some(dur)
}

#[cfg(test)]
mod tests;
