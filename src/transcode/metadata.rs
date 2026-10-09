//! HTTP → gRPC metadata, trace-context, and deadline propagation.
//!
//! Converts relevant HTTP headers into gRPC `MetadataMap` entries for upstream
//! calls (forwarded headers are configurable via YAML), propagates W3C
//! trace-context across the boundary, and carries a client deadline through as
//! the upstream call timeout.

use std::convert::Infallible;
use std::time::Duration;

use axum::http::header::{Entry, OccupiedEntry};
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use tonic::metadata::MetadataMap;

/// A forwarded request header whose value gRPC metadata cannot carry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("header `{header}` has a value gRPC metadata cannot carry")]
#[non_exhaustive]
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
/// `x-forwarded-for`, `x-real-ip` and `forwarded` are never forwarded, listed
/// or not: they carry what the client asserts about its address, which only
/// the proxy's client-address resolution may turn into an address
/// ([`ClientAddress`](crate::ClientAddress)).
///
/// # Errors
/// A forwarded value gRPC metadata cannot carry: empty or outside visible
/// ASCII and space for a text key, not base64 for a `-bin` key (gRPC PROTOCOL-HTTP2,
/// "Custom-Metadata"). gRPC lets a receiver drop such a value, which would
/// change how many values the upstream sees, so the request is refused
/// rather than forwarded altered.
pub fn try_http_headers_to_grpc_metadata(
    headers: &HeaderMap,
    forwarded_headers: &[String],
) -> Result<MetadataMap, InvalidForwardedHeader> {
    checked(headers, forwarded_headers, Source::Client)
}

/// [`try_http_headers_to_grpc_metadata`] for a request whose client-address
/// headers the proxy already rewrote: `forwarded_headers` names them too, and
/// they are forwarded as the rewrite left them.
pub(crate) fn rewritten_headers_to_grpc_metadata(
    headers: &HeaderMap,
    forwarded_headers: &[String],
) -> Result<MetadataMap, InvalidForwardedHeader> {
    checked(headers, forwarded_headers, Source::Rewritten)
}

/// Who last wrote a request's client-address headers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The client: they carry its own assertions and are not forwarded.
    Client,
    /// The proxy's client-address resolution.
    Rewritten,
}

fn checked(
    headers: &HeaderMap,
    forwarded_headers: &[String],
    source: Source,
) -> Result<MetadataMap, InvalidForwardedHeader> {
    forward(headers, forwarded_headers, source, |name, value| {
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
    match forward::<Infallible>(headers, forwarded_headers, Source::Client, |_, _| Ok(())) {
        Ok(metadata) => metadata,
        Err(never) => match never {},
    }
}

/// The metadata for `headers`, with `check` deciding on each forwarded value.
fn forward<E>(
    headers: &HeaderMap,
    forwarded_headers: &[String],
    source: Source,
    mut check: impl FnMut(&HeaderName, &HeaderValue) -> Result<(), E>,
) -> Result<MetadataMap, E> {
    let mut forwarded = HeaderMap::new();
    for name in forwarded_headers {
        // Trace-context propagation owns these, listed or not, and
        // client-address resolution owns the address headers a client sent.
        if is_trace_context(name) || (source == Source::Client && crate::client_address::owns(name))
        {
            continue;
        }
        let values = headers.get_all(name.as_str());
        if values.iter().next().is_none() {
            continue;
        }
        let name = HeaderName::from_bytes(name.as_bytes())
            .expect("a name the request carries a header under is a valid header name");
        // A name gRPC metadata cannot carry is refused when the proxy is built;
        // a direct caller that lists one gets nothing forwarded under it.
        if !is_grpc_key(name.as_str()) {
            continue;
        }
        // A name listed twice is forwarded once, so its values are not doubled.
        let Entry::Vacant(vacant) = forwarded.entry(name) else {
            continue;
        };
        let key = vacant.key().clone();
        let binary = key.as_str().ends_with("-bin");
        let mut vacant = Some(vacant);
        let mut entry = None;
        let mut push = |value: HeaderValue| match entry.as_mut() {
            Some(entry) => {
                OccupiedEntry::append(entry, value);
            }
            None => {
                let vacant = vacant
                    .take()
                    .expect("only the first value finds the entry vacant");
                entry = Some(vacant.insert_entry(value));
            }
        };
        for value in values {
            check(&key, value)?;
            // gRPC PROTOCOL-HTTP2 lets binary values be joined by commas, and
            // tonic does not split them before decoding: each part travels as
            // its own value.
            if binary && value.as_bytes().contains(&b',') {
                for part in value.as_bytes().split(|&b| b == b',') {
                    push(
                        HeaderValue::from_bytes(part.trim_ascii())
                            .expect("a trimmed part of a header value is a header value"),
                    );
                }
            } else {
                push(value.clone());
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

/// Whether `name` is a gRPC metadata key (gRPC PROTOCOL-HTTP2,
/// "Header-Name → 1*( %x30-39 / %x61-7A / "_" / "-" / "." )"), compared the
/// way HTTP compares field names, without case.
pub(crate) fn is_grpc_key(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            let b = b.to_ascii_lowercase();
            b.is_ascii_digit() || b.is_ascii_lowercase() || matches!(b, b'_' | b'-' | b'.')
        })
}

/// Whether `name` is a W3C trace-context header, which propagation owns.
fn is_trace_context(name: &str) -> bool {
    name.eq_ignore_ascii_case("traceparent") || name.eq_ignore_ascii_case("tracestate")
}

/// `ASCII-Value → 1*( %x20-%x7E )`. An empty value is valid HTTP but not a
/// gRPC value, so a receiver may drop it and change the count.
fn is_ascii_value(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().all(|b| (0x20..=0x7e).contains(b))
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
        let (data, well_formed) = match data {
            // Padding closes a four-digit group.
            Some(data) => (data, part.len() % 4 == 0),
            // A lone last digit cannot encode a byte (RFC 4648 §4).
            None => (part, part.len() % 4 != 1),
        };
        well_formed && alphabet(data) && canonical_tail(data)
    })
}

/// RFC 4648 §3.5: the bits of the last digit past the final byte are zero, as
/// strict decoders (tonic's among them) require. `data` is unpadded base64.
fn canonical_tail(data: &[u8]) -> bool {
    let unused_bits_mask = match data.len() % 4 {
        // Two digits carry one byte and four spare bits; three carry two bytes
        // and two spare bits.
        2 => 0b1111,
        3 => 0b0011,
        _ => return true,
    };
    data.last()
        .is_some_and(|&digit| base64_digit(digit) & unused_bits_mask == 0)
}

/// The value of a base64 digit (RFC 4648 §4, Table 1); only called on digits
/// already checked against the alphabet.
fn base64_digit(digit: u8) -> u8 {
    match digit {
        b'A'..=b'Z' => digit - b'A',
        b'a'..=b'z' => digit - b'a' + 26,
        b'0'..=b'9' => digit - b'0' + 52,
        b'+' => 62,
        _ => 63,
    }
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
    // `metadata` holds no trace-context header of its own: forwarding skips
    // them, so tracestate travels only here, with the trace it annotates.
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
        let value = tonic::metadata::AsciiMetadataValue::try_from(&tp[..])
            .expect("a traceparent is visible ASCII");
        metadata.insert(
            tonic::metadata::MetadataKey::from_static("traceparent"),
            value,
        );
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
fn new_traceparent() -> Option<[u8; 55]> {
    let (high, low, span) = (random_id()?, random_id()?, random_id()?);
    // All-zero ids are invalid (W3C Trace Context §3.2.2.3, §3.2.2.4).
    let low = if high == 0 && low == 0 { 1 } else { low };
    let span = if span == 0 { 1 } else { span };
    let mut tp = *b"00-00000000000000000000000000000000-0000000000000000-01";
    write_hex(&mut tp[3..19], high);
    write_hex(&mut tp[19..35], low);
    write_hex(&mut tp[36..52], span);
    Some(tp)
}

/// `value` as 16 lower-case hex digits into `digits`.
fn write_hex(digits: &mut [u8], value: u64) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (at, digit) in digits.iter_mut().enumerate() {
        let shift = 60 - 4 * at;
        *digit = DIGITS[usize::try_from((value >> shift) & 0xf).expect("a nibble")];
    }
}

/// 64 random bits for a trace id. W3C Trace Context asks for random ids, not
/// unpredictable ones (§3.2.2.3; an id is no secret), so they come from a
/// generator (wyrand) each thread seeds once from the system's, as
/// OpenTelemetry's SDKs make them, rather than a system call per request.
/// `None` only when the system cannot seed it.
fn random_id() -> Option<u64> {
    thread_local! {
        static STATE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    }
    STATE.with(|state| {
        let seed = match state.get() {
            Some(seed) => seed,
            None => {
                let mut bytes = [0u8; 8];
                getrandom::fill(&mut bytes).ok()?;
                u64::from_ne_bytes(bytes)
            }
        };
        let next = seed.wrapping_add(0xa076_1d64_78bd_642f);
        state.set(Some(next));
        let wide = u128::from(next) * u128::from(next ^ 0xe703_7ed1_a0b4_28db);
        // The two halves of the product, folded.
        Some((wide >> 64) as u64 ^ wide as u64)
    })
}

/// Apply a client-supplied deadline to the upstream gRPC call.
///
/// Reads the gRPC-standard `grpc-timeout` header (`<int><unit>`, unit one of
/// `H`/`M`/`S`/`m`/`u`/`n`) and sets it as the request timeout, which travels
/// to the upstream as its `grpc-timeout`. Absent or malformed values set
/// nothing, leaving the proxy's own
/// [`UPSTREAM_DEADLINE`](super::UPSTREAM_DEADLINE). Returns the deadline that
/// was applied, if any.
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
/// zero duration (which would expire the call immediately, so the proxy's
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
