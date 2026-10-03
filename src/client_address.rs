//! The client's address, resolved once per request from the connection's peer
//! and, when that peer is a trusted proxy, the address it forwarded.
//!
//! Every consumer reads the one result: the rate limits, the auth decider,
//! extra routes, the fallback and an upstream in process as the
//! [`ClientAddress`] request extension; a remote upstream as the single
//! `X-Forwarded-For` and `X-Real-IP` address the proxy writes in place of
//! whatever the request carried. Forwarding information is not trustworthy by
//! itself (RFC 7239 §8.1), so it counts only from a peer listed in
//! [`ClientAddressConfig::trusted_proxies`].

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

use crate::config::{ClientAddressConfig, ForwardingHeader};
use crate::guard::Guards;

/// `X-Forwarded-For`.
pub(crate) const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
/// `X-Real-IP`.
pub(crate) const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

/// Whether `name` is a header carrying a client's address: `X-Forwarded-For`,
/// `X-Real-IP` or `Forwarded`. The proxy writes these from the resolved
/// address alone, so neither the request nor a guard (claim headers,
/// ext_authz, the auth decider) may set them.
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

    /// The resolved address as the value of `X-Forwarded-For` and
    /// `X-Real-IP`.
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
}

impl Resolver {
    /// # Errors
    ///
    /// A `trusted_proxies` entry that is neither a CIDR range nor an address.
    pub(crate) fn build(config: &ClientAddressConfig) -> Result<Self, String> {
        let trusted = config
            .trusted_proxies
            .iter()
            .map(|entry| parse_trusted(entry))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            trusted,
            header: config.header,
            required: config.required,
        })
    }

    /// Whether a request whose address does not resolve is refused.
    pub(crate) fn required(&self) -> bool {
        self.required
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&ip))
    }

    /// The client address of a request from `peer` carrying `headers`.
    pub(crate) fn resolve(&self, peer: Option<SocketAddr>, headers: &HeaderMap) -> ClientAddress {
        let Some(peer) = peer else {
            return ClientAddress::new(None, Resolution::Unavailable);
        };
        let peer_ip = peer.ip().to_canonical();
        if !self.trusts(peer_ip) {
            // Whatever an untrusted peer forwarded is its own assertion.
            return ClientAddress::new(Some(peer), Resolution::Peer(peer_ip));
        }
        let forwarded = match self.header {
            ForwardingHeader::XForwardedFor => self.walk(headers.get_all(X_FORWARDED_FOR).iter()),
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
    /// a [`ClientAddress`], and replace the request's forwarding headers with
    /// it, so no consumer past this point reads an address the client
    /// asserted: one `X-Forwarded-For` and one `X-Real-IP` carrying the
    /// address, none when it did not resolve, and no `Forwarded` (RFC 7239),
    /// whose `for=` would contradict them.
    pub(crate) fn apply<B>(&self, request: &mut http::Request<B>, peer: Option<SocketAddr>) {
        let client = self.resolve(peer, request.headers());
        let headers = request.headers_mut();
        headers.remove(X_FORWARDED_FOR);
        headers.remove(X_REAL_IP);
        headers.remove(FORWARDED);
        if let Some(value) = client.header_value() {
            headers.insert(X_FORWARDED_FOR, value.clone());
            headers.insert(X_REAL_IP, value.clone());
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
    fn walk<'a>(
        &self,
        lines: impl DoubleEndedIterator<Item = &'a HeaderValue>,
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
                    leftmost = Some(ip);
                }
                match before {
                    Some(before) => rest = before,
                    None => break,
                }
            }
        }
        Ok(leftmost)
    }
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
    if let Ok(net) = entry.parse::<IpNet>() {
        return Ok(net);
    }
    match entry.parse::<IpAddr>() {
        Ok(ip) => Ok(IpNet::from(ip)),
        Err(_) => Err(format!(
            "trusted_proxies entry {entry:?} is neither a CIDR range nor an IP address"
        )),
    }
}

/// Resolves the client address of every request before `S` sees it, from the
/// peer an axum server recorded as `ConnectInfo`.
#[derive(Clone)]
pub(crate) struct ResolveLayer {
    pub(crate) guards: Arc<Guards>,
}

impl<S> Layer<S> for ResolveLayer {
    type Service = Resolve<S>;

    fn layer(&self, inner: S) -> Resolve<S> {
        Resolve {
            inner,
            guards: self.guards.clone(),
        }
    }
}

/// The service of [`ResolveLayer`].
#[derive(Clone)]
pub(crate) struct Resolve<S> {
    inner: S,
    /// The resolver lives with the guards, which key on its result.
    guards: Arc<Guards>,
}

impl<S, B> Service<http::Request<B>> for Resolve<S>
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
        self.guards.client_address.apply(&mut request, peer);
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
