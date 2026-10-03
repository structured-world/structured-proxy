//! The client's address: resolved once per request, before any guard, and
//! forwarded to the upstream by an explicit policy.
//!
//! # Resolution
//!
//! The connection's peer is the client, unless it is listed in
//! [`trusted_proxies`](ClientAddressConfig::trusted_proxies). Forwarding
//! information is not trustworthy by itself (RFC 7239 §8.1), so only then is
//! the header the trusted proxy reports in read:
//!
//! - `X-Forwarded-For` (the default): every field line, in order, as one list
//!   (RFC 9110 §5.3), walked from the right through the trusted proxies to the
//!   first address outside them. What lies left of that address is the
//!   client's own claim and is never read. When every hop is trusted, the
//!   leftmost is the client.
//! - `X-Real-IP`, when chosen: one address, the trusted proxy's own peer.
//!
//! The result is a [`ClientAddress`] on the request, and every consumer reads
//! that one value: the rate limits, the auth decider, extra routes, the
//! fallback and an upstream in process. When nothing can be resolved (no
//! connection information, or a trusted proxy's report that cannot be read)
//! the [`Resolution`] says why, and no address is ever made up: a trusted
//! proxy's own address never stands in for its client's.
//!
//! # What the upstream receives
//!
//! [`ForwardConfig`](crate::config::ForwardConfig) decides, independently of
//! the resolution:
//!
//! | `x_forwarded_for` | `X-Forwarded-For` upstream | Its first element |
//! |---|---|---|
//! | `verified` (default) | the client, the trusted proxies after it, this proxy's peer | the client |
//! | `resolved` | the client alone | the client |
//! | `append` | the list as it arrived, then this proxy's peer | whatever the client wrote |
//! | `preserve` | the list as it arrived (`X-Real-IP` and `Forwarded` too) | whatever the client wrote |
//! | `remove` | nothing | none |
//!
//! Next to it, `client_header` (`X-Real-IP` by default) carries the resolved
//! address alone, and `audit_header` (off by default) the list exactly as it
//! arrived, for logs. These headers are the proxy's: the request cannot set
//! them, and neither can a guard (JWT claim headers, ext_authz, the auth
//! decider). Native gRPC, gRPC-Web and transcoded calls receive the same
//! values, remote or in process, and so does the fallback.
//!
//! With `append` and `preserve` the first element of `X-Forwarded-For` is
//! whatever the client chose to write: an upstream should then read the
//! client header, or walk the list from the right trusting this proxy.
//!
//! # Examples
//!
//! Behind a load balancer in `10.0.0.0/8`, forwarding as nginx does with
//! `$proxy_add_x_forwarded_for`, and keeping what arrived for the access log:
//!
//! ```yaml
//! client_address:
//!   trusted_proxies: ["10.0.0.0/8"]
//!   forward:
//!     x_forwarded_for: append
//!     client_header: x-real-ip
//!     audit_header: x-original-forwarded-for
//! ```
//!
//! The same in code, with the address read back in a tonic handler:
//!
//! ```
//! use structured_proxy::client_address::Resolution;
//! use structured_proxy::config::{ClientAddressConfig, XForwardedFor};
//! use structured_proxy::{ClientAddress, ProxyServer};
//!
//! # fn build() -> anyhow::Result<()> {
//! let mut client_address = ClientAddressConfig::default();
//! client_address.trusted_proxies = vec!["10.0.0.0/8".into()];
//! client_address.forward.x_forwarded_for = XForwardedFor::Append;
//! client_address.forward.audit_header = Some("x-original-forwarded-for".into());
//! let service = ProxyServer::new()
//!     .with_client_address(client_address)
//!     .service(tonic::service::Routes::default())?;
//! # let _ = service;
//! # Ok(())
//! # }
//! # build().unwrap();
//!
//! fn caller(request: &tonic::Request<()>) -> String {
//!     match request.extensions().get::<ClientAddress>().map(ClientAddress::resolution) {
//!         Some(Resolution::Peer(ip) | Resolution::Forwarded(ip)) => ip.to_string(),
//!         _ => "unknown".into(),
//!     }
//! }
//! # let _ = caller;
//! ```
//!
//! Routers of your own that mount proxy parts such as the
//! [`shield`](crate::shield) middleware get the same resolution from
//! [`ClientAddressLayer`].

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::extract::{ConnectInfo, Request};
use axum::middleware::Next;
use axum::response::Response;
use http::header::{HeaderName, FORWARDED};
use http::{HeaderMap, HeaderValue};
use ipnet::IpNet;
use tower::{Layer, Service};

use crate::config::{ClientAddressConfig, ForwardingHeader, XForwardedFor};

/// `X-Forwarded-For`.
pub(crate) const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
/// `X-Real-IP`.
pub(crate) const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Whether `name` is a header carrying a client's address: `X-Forwarded-For`,
/// `X-Real-IP` or `Forwarded`. The forwarding policy decides what they hold
/// upstream, so no guard (claim headers, ext_authz, the auth decider) may set
/// them.
pub(crate) fn owns(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("x-real-ip")
        || name.eq_ignore_ascii_case("forwarded")
}

/// Most list elements of `X-Forwarded-For` read before an address outside the
/// trusted proxies turns up. Only trusted hops and empty elements count
/// towards it, and no real chain of proxies comes near it.
const MAX_HOPS: usize = 32;

/// Longest list element read, spaces around it included. The longest address
/// with a port, `[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535`, is 53
/// bytes; anything longer is not an address. With [`MAX_HOPS`] it bounds the
/// bytes of a header read at all, whatever its size.
const MAX_ELEMENT: usize = 128;

/// The client address the proxy resolved for a request.
///
/// A request extension on every request the proxy serves: an
/// [`AuthDecider`](crate::hooks::AuthDecider) and an
/// [`ExtraRouteHandler`](crate::hooks::ExtraRouteHandler) get it in their
/// request view, a fallback and a tonic upstream in process read it with
/// `request.extensions().get::<ClientAddress>()`. The connection's own record
/// (`Request::remote_addr`, `Request::peer_certs`) stays as it is.
///
/// # Examples
///
/// ```
/// use structured_proxy::client_address::{ClientAddress, Resolution};
///
/// // What a tonic handler behind the proxy does with it.
/// fn caller(request: &tonic::Request<()>) -> Option<std::net::IpAddr> {
///     request.extensions().get::<ClientAddress>()?.ip()
/// }
///
/// let client = ClientAddress::from_peer(Some("203.0.113.7:51234".parse().unwrap()));
/// assert_eq!(client.resolution(), Resolution::Peer("203.0.113.7".parse().unwrap()));
/// let mut request = tonic::Request::new(());
/// request.extensions_mut().insert(client);
/// assert_eq!(caller(&request), Some("203.0.113.7".parse().unwrap()));
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientAddress {
    peer: Option<SocketAddr>,
    resolution: Resolution,
    /// The resolved address as a header value, made once for every header
    /// and metadata entry that carries it.
    value: Option<HeaderValue>,
}

/// How the client address was resolved, or why it was not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resolution {
    /// The connection's peer is the client: it is not a trusted proxy, or it
    /// is one that forwarded no address.
    Peer(IpAddr),
    /// A trusted proxy forwarded the address: the first one outside the
    /// trusted proxies, read right to left, or the leftmost when every hop is
    /// trusted.
    Forwarded(IpAddr),
    /// A trusted proxy forwarded something that cannot be read where the
    /// client's address should be. No address resolves: the peer is a proxy,
    /// not the client.
    Invalid(InvalidForwarding),
    /// The server recorded no connection information, so there is no peer to
    /// start from.
    Unavailable,
}

/// Why a trusted proxy's forwarded address cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidForwarding {
    /// An element that is not an IP address with an optional port.
    Malformed,
    /// More trusted hops than the proxy reads before reaching the client.
    TooManyHops,
    /// More than one `X-Real-IP` field.
    Repeated,
}

impl std::fmt::Display for InvalidForwarding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed",
            Self::TooManyHops => "beyond too many trusted hops",
            Self::Repeated => "repeated",
        })
    }
}

impl ClientAddress {
    /// The address of a request from `peer` through no trusted proxy: the
    /// peer itself, or [`Resolution::Unavailable`] without one. The view a
    /// hook's own tests hand it.
    pub fn from_peer(peer: Option<SocketAddr>) -> Self {
        let resolution = match peer {
            Some(peer) => Resolution::Peer(peer.ip().to_canonical()),
            None => Resolution::Unavailable,
        };
        Self::new(peer, resolution)
    }

    fn new(peer: Option<SocketAddr>, resolution: Resolution) -> Self {
        let value = match resolution {
            Resolution::Peer(ip) | Resolution::Forwarded(ip) => Some(header_value(ip)),
            Resolution::Invalid(_) | Resolution::Unavailable => None,
        };
        Self {
            peer,
            resolution,
            value,
        }
    }

    /// The client's address, when one resolved.
    pub fn ip(&self) -> Option<IpAddr> {
        match self.resolution {
            Resolution::Peer(ip) | Resolution::Forwarded(ip) => Some(ip),
            Resolution::Invalid(_) | Resolution::Unavailable => None,
        }
    }

    /// The connection's peer: the client, or the last proxy before this one.
    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// How the address was resolved, or why it was not.
    pub fn resolution(&self) -> Resolution {
        self.resolution
    }

    /// The resolved address as a header value: the client header's, and
    /// `X-Forwarded-For`'s in the `resolved` mode.
    pub(crate) fn header_value(&self) -> Option<&HeaderValue> {
        self.value.as_ref()
    }
}

/// `ip` as a header value: one allocation, for the bytes the value owns.
fn header_value(ip: IpAddr) -> HeaderValue {
    use std::io::Write;
    // The longest text form, an IPv6 address ending in IPv4 notation, is 45
    // bytes.
    let mut buf = [0u8; 48];
    let mut rest: &mut [u8] = &mut buf;
    write!(rest, "{ip}").expect("an IP address fits in 48 bytes");
    let len = 48 - rest.len();
    HeaderValue::from_bytes(&buf[..len]).expect("an IP address is a header value")
}

/// [`ClientAddressConfig`], compiled.
#[derive(Debug, Default)]
pub(crate) struct Resolver {
    trusted: Box<[IpNet]>,
    header: ForwardingHeader,
    required: bool,
    forward: XForwardedFor,
    /// Receives the resolved address.
    client_header: Option<HeaderName>,
    /// Receives the request's `X-Forwarded-For` as it arrived.
    audit_header: Option<HeaderName>,
}

impl Resolver {
    /// # Errors
    ///
    /// A `trusted_proxies` entry that is neither a CIDR range nor an address,
    /// or a `forward` header name that is not a gRPC metadata key or names a
    /// header the forwarding already writes.
    pub(crate) fn build(config: &ClientAddressConfig) -> Result<Self, String> {
        let trusted = config
            .trusted_proxies
            .iter()
            .map(|entry| parse_trusted(entry))
            .collect::<Result<_, _>>()?;
        let forward = &config.forward;
        let client_header = forward
            .client_header
            .as_deref()
            .map(|name| forward_header("client_header", name, &["x-forwarded-for", "forwarded"]))
            .transpose()?;
        let audit_header = forward
            .audit_header
            .as_deref()
            .map(|name| {
                let mut taken = vec!["x-forwarded-for", "x-real-ip", "forwarded"];
                taken.extend(client_header.as_ref().map(HeaderName::as_str));
                forward_header("audit_header", name, &taken)
            })
            .transpose()?;
        Ok(Self {
            trusted,
            header: config.header,
            required: config.required,
            forward: forward.x_forwarded_for,
            client_header,
            audit_header,
        })
    }

    /// Whether a request whose address does not resolve is refused.
    pub(crate) fn required(&self) -> bool {
        self.required
    }

    /// Whether the proxy alone writes `name`: a client-address header, or a
    /// header the forwarding policy writes. A guard may not set it.
    pub(crate) fn reserves(&self, name: &str) -> bool {
        owns(name)
            || self
                .configured_headers()
                .any(|own| name.eq_ignore_ascii_case(own.as_str()))
    }

    /// The headers named in `forward`, the ones [`owns`] does not cover.
    pub(crate) fn configured_headers(&self) -> impl Iterator<Item = &HeaderName> {
        self.client_header.iter().chain(&self.audit_header)
    }

    /// Every header the forwarding policy may leave on a request: what a
    /// transcoded call forwards as metadata in their place.
    pub(crate) fn forwarded_headers(&self) -> impl Iterator<Item = &str> {
        ["x-forwarded-for", "x-real-ip", "forwarded"]
            .into_iter()
            .chain(self.configured_headers().map(HeaderName::as_str))
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// The client address of a request from `peer` carrying `headers`, without
    /// touching the request: what [`apply`](Self::apply) puts on it.
    #[cfg(test)]
    pub(crate) fn resolve(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> ClientAddress {
        self.resolve_noting(peer, headers, None)
    }

    /// [`resolve`](Self::resolve), noting in `hops` the trusted proxies
    /// between the client and this proxy, nearest first.
    fn resolve_noting(
        &self,
        peer: Option<SocketAddr>,
        headers: &HeaderMap,
        hops: Option<&mut Vec<IpAddr>>,
    ) -> ClientAddress {
        let Some(peer) = peer else {
            return ClientAddress::new(None, Resolution::Unavailable);
        };
        let peer_ip = peer.ip().to_canonical();
        if !self.trusts(peer_ip) {
            // Whatever an untrusted peer forwarded is its own assertion.
            return ClientAddress::new(Some(peer), Resolution::Peer(peer_ip));
        }
        let forwarded = match self.header {
            ForwardingHeader::XForwardedFor => {
                self.walk(headers.get_all(X_FORWARDED_FOR).iter(), hops)
            }
            ForwardingHeader::XRealIp => real_ip(headers.get_all(X_REAL_IP).iter()),
        };
        let resolution = match forwarded {
            Ok(Some(ip)) => Resolution::Forwarded(ip),
            Ok(None) => Resolution::Peer(peer_ip),
            Err(invalid) => Resolution::Invalid(invalid),
        };
        ClientAddress::new(Some(peer), resolution)
    }

    /// Resolve the address of `request` from `peer`, put it on the request as
    /// a [`ClientAddress`], and rewrite its forwarding headers by the
    /// `forward` policy, so every consumer past this point (the guards, the
    /// fallback, the upstream) sees exactly what the upstream will:
    ///
    /// - the audit header, when set, gets the request's `X-Forwarded-For`
    ///   lines as they arrived, and nothing the client sent under its name;
    /// - `X-Forwarded-For` as the mode says (see [`XForwardedFor`]);
    /// - `X-Real-IP` and `Forwarded` as they arrived with `preserve`, removed
    ///   otherwise, since they would contradict it;
    /// - the client header, last, the resolved address, so it overrides even
    ///   a preserved `X-Real-IP`; absent when nothing resolved.
    pub(crate) fn apply<B>(&self, request: &mut http::Request<B>, peer: Option<SocketAddr>) {
        let mut hops = Vec::new();
        let noting = (self.forward == XForwardedFor::Verified).then_some(&mut hops);
        let client = self.resolve_noting(peer, request.headers(), noting);
        let headers = request.headers_mut();
        if let Some(audit) = &self.audit_header {
            let arrived: Vec<HeaderValue> =
                headers.get_all(X_FORWARDED_FOR).iter().cloned().collect();
            headers.remove(audit);
            for line in arrived {
                headers.append(audit.clone(), line);
            }
        }
        let xff = match self.forward {
            XForwardedFor::Verified => verified_chain(&client, &hops),
            XForwardedFor::Resolved => client.header_value().cloned(),
            XForwardedFor::Append => appended_chain(headers, client.peer),
            XForwardedFor::Preserve => None,
            XForwardedFor::Remove => None,
        };
        if self.forward != XForwardedFor::Preserve {
            headers.remove(X_FORWARDED_FOR);
            headers.remove(X_REAL_IP);
            headers.remove(FORWARDED);
            if let Some(xff) = xff {
                headers.insert(X_FORWARDED_FOR, xff);
            }
        }
        if let Some(name) = &self.client_header {
            headers.remove(name);
            if let Some(value) = client.header_value() {
                headers.insert(name.clone(), value.clone());
            }
        }
        request.extensions_mut().insert(client);
    }

    /// The client's address in `X-Forwarded-For`, `lines` in wire order
    /// (RFC 9110 §5.3: several field lines form one list): the first element
    /// outside the trusted proxies from the right, or the leftmost when all
    /// are trusted, or `None` without an element. Elements left of the client
    /// are the client's own assertions and are never read. An element that
    /// is not an address where the walk needs one makes the whole result
    /// invalid: skipping it would credit a hop the chain never vouched for.
    /// `hops`, when given, receives the trusted proxies right of the client,
    /// nearest first.
    fn walk<'a>(
        &self,
        lines: impl DoubleEndedIterator<Item = &'a HeaderValue>,
        mut hops: Option<&mut Vec<IpAddr>>,
    ) -> Result<Option<IpAddr>, InvalidForwarding> {
        let mut read = 0;
        let mut leftmost = None;
        for line in lines.rev() {
            let mut rest = line.as_bytes();
            loop {
                read += 1;
                if read > MAX_HOPS {
                    return Err(InvalidForwarding::TooManyHops);
                }
                let (element, before) = last_element(rest)?;
                // RFC 9110 §5.6.1: a recipient ignores empty list elements.
                if !element.is_empty() {
                    let ip = parse_address(element)
                        .ok_or(InvalidForwarding::Malformed)?
                        .to_canonical();
                    if !self.trusts(ip) {
                        return Ok(Some(ip));
                    }
                    if let Some(hops) = hops.as_deref_mut() {
                        hops.push(ip);
                    }
                    leftmost = Some(ip);
                }
                match before {
                    Some(before) => rest = before,
                    None => break,
                }
            }
        }
        // Every hop trusted: the leftmost is the client, not a hop.
        if leftmost.is_some() {
            if let Some(hops) = hops {
                hops.pop();
            }
        }
        Ok(leftmost)
    }
}

/// The verified `X-Forwarded-For`: the resolved client, the trusted proxies
/// `hops` (nearest first) in the order they forwarded, then this proxy's peer,
/// each in canonical form; `None` when nothing resolved. A client that is the
/// peer itself is listed once.
fn verified_chain(client: &ClientAddress, hops: &[IpAddr]) -> Option<HeaderValue> {
    use std::fmt::Write;
    let value = client.header_value()?;
    let Resolution::Forwarded(ip) = client.resolution else {
        // The peer is the client: nothing else is verified.
        return Some(value.clone());
    };
    let peer = client.peer?.ip().to_canonical();
    let mut chain = ip.to_string();
    for hop in hops.iter().rev().chain([&peer]) {
        write!(chain, ", {hop}").expect("writing to a String cannot fail");
    }
    Some(HeaderValue::try_from(chain).expect("addresses and commas are a header value"))
}

/// The request's `X-Forwarded-For` as it arrived, its field lines joined in
/// order, with `peer` appended; the lines alone without a peer, and `None`
/// with neither.
fn appended_chain(headers: &HeaderMap, peer: Option<SocketAddr>) -> Option<HeaderValue> {
    use std::io::Write;
    let mut lines = headers.get_all(X_FORWARDED_FOR).iter();
    let Some(peer) = peer else {
        // Nothing to append: one line stays as it is, several are joined.
        let first = lines.next()?;
        let mut joined = first.as_bytes().to_vec();
        for line in lines {
            joined.extend_from_slice(b", ");
            joined.extend_from_slice(line.as_bytes());
        }
        return Some(
            HeaderValue::from_maybe_shared(bytes::Bytes::from(joined))
                .expect("joined header values are a header value"),
        );
    };
    let mut chain = Vec::new();
    for line in lines {
        chain.extend_from_slice(line.as_bytes());
        chain.extend_from_slice(b", ");
    }
    write!(chain, "{}", peer.ip().to_canonical()).expect("writing to a Vec cannot fail");
    Some(
        HeaderValue::from_maybe_shared(bytes::Bytes::from(chain))
            .expect("header values, commas and an address are a header value"),
    )
}

/// A `forward` header name: a text gRPC metadata key, so a transcoded call can
/// carry it, other than the headers in `taken`. A `-bin` key would need base64
/// values (gRPC PROTOCOL-HTTP2, "Custom-Metadata"), and an address or an
/// address list is text.
fn forward_header(setting: &str, name: &str, taken: &[&str]) -> Result<HeaderName, String> {
    let header = HeaderName::from_bytes(name.as_bytes())
        .ok()
        .filter(|header| crate::transcode::metadata::is_grpc_key(header.as_str()))
        .ok_or_else(|| {
            format!("forward.{setting} {name:?} is not a gRPC metadata key (letters, digits, '_', '-' and '.')")
        })?;
    if header.as_str().ends_with("-bin") {
        return Err(format!(
            "forward.{setting} {name:?} is a binary metadata key, whose values must be base64; \
             the address is text"
        ));
    }
    if taken.contains(&header.as_str()) {
        return Err(format!(
            "forward.{setting} {name:?} names a header the forwarding already writes"
        ));
    }
    Ok(header)
}

/// The last element of the list `bytes`, trimmed of the spaces and tabs
/// around it (RFC 9110 §5.6.1), and what precedes its comma, if any. At most
/// [`MAX_ELEMENT`] bytes are read.
fn last_element(bytes: &[u8]) -> Result<(&[u8], Option<&[u8]>), InvalidForwarding> {
    let window = bytes.len().saturating_sub(MAX_ELEMENT + 1);
    let (element, before) = match bytes[window..].iter().rposition(|&b| b == b',') {
        Some(comma) => (&bytes[window + comma + 1..], Some(&bytes[..window + comma])),
        None if window == 0 => (bytes, None),
        None => return Err(InvalidForwarding::Malformed),
    };
    Ok((trim_whitespace(element), before))
}

fn trim_whitespace(bytes: &[u8]) -> &[u8] {
    let is_ows = |b: &u8| matches!(b, b' ' | b'\t');
    let start = bytes.iter().position(|b| !is_ows(b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_ows(b))
        .map_or(start, |end| end + 1);
    &bytes[start..end]
}

/// The client's address in `X-Real-IP`: one field with one address, written
/// by the trusted proxy for its own peer, or `None` without the field.
fn real_ip<'a>(
    mut lines: impl Iterator<Item = &'a HeaderValue>,
) -> Result<Option<IpAddr>, InvalidForwarding> {
    let Some(line) = lines.next() else {
        return Ok(None);
    };
    if lines.next().is_some() {
        return Err(InvalidForwarding::Repeated);
    }
    // Bounded before trimming, so the spaces around the address count too and
    // no value is read past `MAX_ELEMENT`, as for an `X-Forwarded-For` element.
    let raw = line.as_bytes();
    if raw.len() > MAX_ELEMENT {
        return Err(InvalidForwarding::Malformed);
    }
    parse_address(trim_whitespace(raw))
        .map(|ip| Some(ip.to_canonical()))
        .ok_or(InvalidForwarding::Malformed)
}

/// An address as forwarding headers carry it: bare, IPv6 in brackets, or
/// either with a port, which is dropped. Nothing else, so a name, `unknown`
/// or an obfuscated identifier (RFC 7239 §6.3) never counts as an address.
fn parse_address(bytes: &[u8]) -> Option<IpAddr> {
    let text = std::str::from_utf8(bytes).ok()?;
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(socket) = text.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    let v6 = text.strip_prefix('[')?.strip_suffix(']')?;
    v6.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
}

/// A `trusted_proxies` entry: a CIDR range, or an address for one host.
fn parse_trusted(entry: &str) -> Result<IpNet, String> {
    let net = match entry.parse::<IpNet>() {
        Ok(net) => net,
        Err(_) => match entry.parse::<IpAddr>() {
            Ok(ip) => IpNet::from(ip),
            Err(_) => {
                return Err(format!(
                    "trusted_proxies entry {entry:?} is neither a CIDR range nor an IP address"
                ))
            }
        },
    };
    Ok(canonical_net(net))
}

/// `net` in the form peers are compared in: a range inside the IPv4-mapped
/// block `::ffff:0:0/96` (RFC 4291 §2.5.5.2) becomes the IPv4 range it maps,
/// since peers are canonicalized to IPv4 before matching. A wider IPv6 range
/// stays IPv6, so trusting `::/0` does not trust every IPv4 peer.
fn canonical_net(net: IpNet) -> IpNet {
    if let IpNet::V6(v6) = net {
        if let (Some(v4), Some(prefix)) = (
            v6.network().to_ipv4_mapped(),
            v6.prefix_len().checked_sub(96),
        ) {
            return ipnet::Ipv4Net::new(v4, prefix)
                .expect("a prefix of at most 128 - 96 fits IPv4")
                .into();
        }
    }
    net
}

/// Resolves the client address of every request before the service it wraps
/// sees it: puts the [`ClientAddress`] on the request and rewrites its
/// forwarding headers, as the proxy does before its own guards.
///
/// The proxy applies it itself. Use it in a router of your own that mounts
/// proxy parts such as the [`shield`](crate::shield) middleware directly, so
/// they key by the client behind your trusted proxies rather than by the
/// proxies' own address. The peer comes from the `ConnectInfo<SocketAddr>` an
/// axum server records (`into_make_service_with_connect_info`); without one
/// the address is [`Resolution::Unavailable`]. `required` is not enforced
/// here: read [`ClientAddress::resolution`] where it matters.
///
/// # Examples
///
/// ```
/// use structured_proxy::client_address::ClientAddressLayer;
/// use structured_proxy::config::ClientAddressConfig;
///
/// let mut trust = ClientAddressConfig::default();
/// trust.trusted_proxies = vec!["10.0.0.0/8".into()];
/// let app: axum::Router = axum::Router::new()
///     .route("/", axum::routing::get(|| async { "ok" }))
///     .layer(ClientAddressLayer::new(&trust).unwrap());
/// # let _ = app;
/// ```
#[derive(Clone, Debug)]
pub struct ClientAddressLayer {
    resolver: Arc<Resolver>,
}

impl ClientAddressLayer {
    /// The resolution `config` describes.
    ///
    /// # Errors
    ///
    /// A `trusted_proxies` entry that is neither a CIDR range nor an address.
    pub fn new(config: &ClientAddressConfig) -> anyhow::Result<Self> {
        let resolver = Resolver::build(config)
            .map_err(|e| anyhow::anyhow!("invalid client_address config: {e}"))?;
        Ok(Self::with(Arc::new(resolver)))
    }

    /// The layer over a resolver the proxy already compiled.
    pub(crate) fn with(resolver: Arc<Resolver>) -> Self {
        Self { resolver }
    }
}

impl<S> Layer<S> for ClientAddressLayer {
    type Service = ClientAddressService<S>;

    fn layer(&self, inner: S) -> ClientAddressService<S> {
        ClientAddressService {
            inner,
            resolver: self.resolver.clone(),
        }
    }
}

/// The service of [`ClientAddressLayer`].
#[derive(Clone, Debug)]
pub struct ClientAddressService<S> {
    inner: S,
    resolver: Arc<Resolver>,
}

impl<S, B> Service<http::Request<B>> for ClientAddressService<S>
where
    S: Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: http::Request<B>) -> Self::Future {
        let peer = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(peer)| *peer);
        self.resolver.apply(&mut request, peer);
        self.inner.call(request)
    }
}

/// The guard of `client_address.required`: a request whose address did not
/// resolve is refused, `INVALID_ARGUMENT` when a trusted proxy forwarded
/// something unreadable, `INTERNAL` when the server recorded no connection.
pub(crate) async fn require(request: Request, next: Next) -> Response {
    let resolution = request
        .extensions()
        .get::<ClientAddress>()
        .map_or(Resolution::Unavailable, ClientAddress::resolution);
    match resolution {
        Resolution::Peer(_) | Resolution::Forwarded(_) => next.run(request).await,
        Resolution::Invalid(invalid) => crate::guard::reject(
            tonic::Code::InvalidArgument,
            format!("the client address a trusted proxy forwarded is {invalid}"),
        ),
        Resolution::Unavailable => crate::guard::reject(
            tonic::Code::Internal,
            "no connection information to resolve the client address from",
        ),
    }
}

#[cfg(test)]
mod tests;
