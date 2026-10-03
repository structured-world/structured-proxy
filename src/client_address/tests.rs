use super::*;
use crate::config::XForwardedFor;

/// A resolver trusting `trusted`, reading `header`.
fn resolver(trusted: &[&str], header: ForwardingHeader) -> Resolver {
    Resolver::build(&ClientAddressConfig {
        trusted_proxies: trusted.iter().map(|t| (*t).to_string()).collect(),
        header,
        required: false,
        forward: Default::default(),
    })
    .unwrap()
}

/// Trusts the load balancers of 10.0.0.0/8, reading `X-Forwarded-For`.
fn behind_lb() -> Resolver {
    resolver(&["10.0.0.0/8"], ForwardingHeader::XForwardedFor)
}

fn peer(addr: &str) -> Option<SocketAddr> {
    Some(addr.parse().unwrap())
}

/// `lines` as field lines of `name`, in order.
fn headers(name: &str, lines: &[&str]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in lines {
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(line).unwrap(),
        );
    }
    headers
}

fn xff(lines: &[&str]) -> HeaderMap {
    headers("x-forwarded-for", lines)
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// What `resolver` resolves for a request from `from` with `lines` of XFF.
fn resolve_xff(resolver: &Resolver, from: &str, lines: &[&str]) -> Resolution {
    resolver.resolve(peer(from), &xff(lines)).resolution()
}

#[test]
fn an_untrusted_peer_is_the_client_whatever_it_forwards() {
    // RFC 7239 §8.1: forwarding information from an untrusted party proves
    // nothing, so a client cannot pick its own address.
    let lb = behind_lb();
    let mut forged = xff(&["198.51.100.1"]);
    forged.insert("x-real-ip", HeaderValue::from_static("198.51.100.2"));
    let client = lb.resolve(peer("203.0.113.7:51234"), &forged);
    assert_eq!(client.resolution(), Resolution::Peer(ip("203.0.113.7")));
    assert_eq!(client.ip(), Some(ip("203.0.113.7")));
    assert_eq!(client.peer(), peer("203.0.113.7:51234"));
}

#[test]
fn without_trusted_proxies_every_peer_is_the_client() {
    let edge = Resolver::build(&ClientAddressConfig::default()).unwrap();
    assert_eq!(
        resolve_xff(&edge, "10.0.0.1:4000", &["198.51.100.1"]),
        Resolution::Peer(ip("10.0.0.1"))
    );
}

#[test]
fn one_trusted_proxy_forwards_the_client() {
    assert_eq!(
        resolve_xff(&behind_lb(), "10.0.0.1:4000", &["203.0.113.7"]),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
}

#[test]
fn two_trusted_proxies_are_walked_through() {
    // The edge LB appended the client, the internal one appended the edge.
    assert_eq!(
        resolve_xff(&behind_lb(), "10.0.0.1:4000", &["203.0.113.7, 10.0.0.2"]),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
}

#[test]
fn a_forged_prefix_is_not_read() {
    // Whatever the client sent sits left of the address its proxy appended.
    assert_eq!(
        resolve_xff(
            &behind_lb(),
            "10.0.0.1:4000",
            &["198.51.100.1, 198.51.100.2, 203.0.113.7"]
        ),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
}

#[test]
fn the_walk_stops_at_the_first_untrusted_hop() {
    // An untrusted intermediate is the closest party no trusted proxy can
    // vouch past: it is the client, and what it claims to forward is not.
    assert_eq!(
        resolve_xff(
            &behind_lb(),
            "10.0.0.1:4000",
            &["203.0.113.7, 198.51.100.9, 10.0.0.2"]
        ),
        Resolution::Forwarded(ip("198.51.100.9"))
    );
}

#[test]
fn repeated_field_lines_are_one_list_in_wire_order() {
    // RFC 9110 §5.3: field lines combine in order, so the last line holds
    // the rightmost hops.
    let lb = behind_lb();
    assert_eq!(
        resolve_xff(
            &lb,
            "10.0.0.1:4000",
            &["198.51.100.1", "203.0.113.7, 10.0.0.2"]
        ),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &["203.0.113.7", "10.0.0.2"]),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
    // The order decides: swapped, the untrusted hop is the rightmost.
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &["10.0.0.2", "203.0.113.7"]),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &["203.0.113.7", "198.51.100.1"]),
        Resolution::Forwarded(ip("198.51.100.1"))
    );
}

#[test]
fn every_address_form_forwarding_headers_use_is_read() {
    let lb = behind_lb();
    for (element, client) in [
        ("2001:db8::1", "2001:db8::1"),
        ("[2001:db8::1]", "2001:db8::1"),
        ("[2001:db8::1]:443", "2001:db8::1"),
        ("203.0.113.7:51234", "203.0.113.7"),
        ("  203.0.113.7\t", "203.0.113.7"),
        // An IPv4-mapped address is the IPv4 one.
        ("::ffff:203.0.113.7", "203.0.113.7"),
    ] {
        assert_eq!(
            resolve_xff(&lb, "10.0.0.1:4000", &[element]),
            Resolution::Forwarded(ip(client)),
            "{element:?}"
        );
    }
}

#[test]
fn ipv6_proxies_and_a_mapped_peer_are_trusted_by_their_ranges() {
    let lb = resolver(
        &["10.0.0.0/8", "2001:db8:ffff::/48"],
        ForwardingHeader::XForwardedFor,
    );
    // A dual-stack socket reports an IPv4 peer as IPv4-mapped IPv6.
    assert_eq!(
        resolve_xff(&lb, "[::ffff:10.0.0.1]:4000", &["203.0.113.7"]),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
    assert_eq!(
        resolve_xff(
            &lb,
            "[2001:db8:ffff::5]:4000",
            &["2001:db8::7, 2001:db8:ffff::6"]
        ),
        Resolution::Forwarded(ip("2001:db8::7"))
    );
}

#[test]
fn a_trusted_peer_that_forwards_nothing_is_the_client() {
    // An internal service calling directly from a trusted range.
    let lb = behind_lb();
    assert_eq!(
        lb.resolve(peer("10.0.0.1:4000"), &HeaderMap::new())
            .resolution(),
        Resolution::Peer(ip("10.0.0.1"))
    );
    // A list of nothing but empty elements forwards nothing either.
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &[" , ,"]),
        Resolution::Peer(ip("10.0.0.1"))
    );
}

#[test]
fn empty_list_elements_are_ignored() {
    // RFC 9110 §5.6.1.
    assert_eq!(
        resolve_xff(
            &behind_lb(),
            "10.0.0.1:4000",
            &[", 203.0.113.7,, 10.0.0.2 ,"]
        ),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
}

#[test]
fn when_every_hop_is_trusted_the_leftmost_is_the_client() {
    // The first trusted proxy recorded its own peer, a client inside the
    // trusted range.
    assert_eq!(
        resolve_xff(&behind_lb(), "10.0.0.1:4000", &["10.0.0.5, 10.0.0.2"]),
        Resolution::Forwarded(ip("10.0.0.5"))
    );
}

#[test]
fn a_malformed_trusted_hop_resolves_nothing() {
    // The proxy that wrote it is trusted but its report is broken: the
    // address is unknown, never the proxy's own.
    let lb = behind_lb();
    for element in [
        "garbage",
        "unknown",
        "_hidden",
        "203.0.113.7:",
        "[2001:db8::1",
        "fe80::1%eth0",
    ] {
        let client = lb.resolve(peer("10.0.0.1:4000"), &xff(&[element]));
        assert_eq!(
            client.resolution(),
            Resolution::Invalid(InvalidForwarding::Malformed),
            "{element:?}"
        );
        assert_eq!(client.ip(), None);
        assert_eq!(client.peer(), peer("10.0.0.1:4000"));
    }
    // Behind another trusted hop it is just as broken.
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &["203.0.113.7, garbage, 10.0.0.2"]),
        Resolution::Invalid(InvalidForwarding::Malformed)
    );
}

#[test]
fn malformed_data_left_of_the_client_is_never_read() {
    // The client is established right of it: nothing the client wrote can
    // change or break the result.
    let lb = behind_lb();
    let long = "x".repeat(10_000);
    let many = vec!["garbage"; 1_000].join(",");
    for prefix in ["garbage", "unknown, ,", long.as_str(), many.as_str()] {
        let line = format!("{prefix}, 203.0.113.7");
        assert_eq!(
            resolve_xff(&lb, "10.0.0.1:4000", &[&line]),
            Resolution::Forwarded(ip("203.0.113.7")),
            "{line:.40}"
        );
    }
    // Nor in an earlier field line.
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &[&long, "203.0.113.7"]),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
}

#[test]
fn a_chain_past_the_hop_limit_resolves_nothing() {
    let lb = behind_lb();
    let trusted = vec!["10.0.0.2"; MAX_HOPS].join(", ");
    // At the limit, every hop trusted: the leftmost.
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &[&trusted]),
        Resolution::Forwarded(ip("10.0.0.2"))
    );
    // One more hop to read before the client: past the limit.
    let line = format!("203.0.113.7, {trusted}");
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &[&line]),
        Resolution::Invalid(InvalidForwarding::TooManyHops)
    );
    // Empty elements count too, so they cannot stretch the read.
    let empties = format!("203.0.113.7{}", ",".repeat(MAX_HOPS));
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &[&empties]),
        Resolution::Invalid(InvalidForwarding::TooManyHops)
    );
}

#[test]
fn an_overlong_trusted_hop_is_malformed_without_being_read() {
    let lb = behind_lb();
    let long = format!("{}203.0.113.7", " ".repeat(MAX_ELEMENT));
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &[&long]),
        Resolution::Invalid(InvalidForwarding::Malformed)
    );
    // The longest real element, with spaces around it, still fits.
    let longest = "  [ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535  ";
    assert_eq!(
        resolve_xff(&lb, "10.0.0.1:4000", &[longest]),
        Resolution::Forwarded(ip("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"))
    );
}

#[test]
fn x_real_ip_is_not_a_fallback_for_a_broken_x_forwarded_for() {
    let mut both = xff(&["garbage"]);
    both.insert("x-real-ip", HeaderValue::from_static("203.0.113.7"));
    assert_eq!(
        behind_lb()
            .resolve(peer("10.0.0.1:4000"), &both)
            .resolution(),
        Resolution::Invalid(InvalidForwarding::Malformed)
    );
    // Nor for a missing one: the trusted peer forwarded nothing.
    let real_ip = headers("x-real-ip", &["203.0.113.7"]);
    assert_eq!(
        behind_lb()
            .resolve(peer("10.0.0.1:4000"), &real_ip)
            .resolution(),
        Resolution::Peer(ip("10.0.0.1"))
    );
}

#[test]
fn x_real_ip_is_read_when_selected() {
    let lb = resolver(&["10.0.0.0/8"], ForwardingHeader::XRealIp);
    let from = peer("10.0.0.1:4000");
    let resolve = |lines: &[&str]| lb.resolve(from, &headers("x-real-ip", lines)).resolution();
    assert_eq!(
        resolve(&["203.0.113.7"]),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
    // The proxy's own peer, trusted range or not: no walk.
    assert_eq!(
        resolve(&["10.0.0.9"]),
        Resolution::Forwarded(ip("10.0.0.9"))
    );
    assert_eq!(resolve(&[]), Resolution::Peer(ip("10.0.0.1")));
    assert_eq!(
        resolve(&["203.0.113.7", "198.51.100.1"]),
        Resolution::Invalid(InvalidForwarding::Repeated)
    );
    for bad in ["", "203.0.113.7, 198.51.100.1", "garbage"] {
        assert_eq!(
            resolve(&[bad]),
            Resolution::Invalid(InvalidForwarding::Malformed),
            "{bad:?}"
        );
    }
    // X-Forwarded-For is not read in this mode.
    assert_eq!(
        lb.resolve(from, &xff(&["198.51.100.1"])).resolution(),
        Resolution::Peer(ip("10.0.0.1"))
    );
    // And an untrusted peer's X-Real-IP is its own assertion.
    assert_eq!(
        lb.resolve(
            peer("203.0.113.9:4000"),
            &headers("x-real-ip", &["198.51.100.1"])
        )
        .resolution(),
        Resolution::Peer(ip("203.0.113.9"))
    );
}

#[test]
fn an_overlong_x_real_ip_is_malformed_without_being_read() {
    // The bound covers the spaces around the address, as for an
    // X-Forwarded-For element: padding cannot make the proxy scan an
    // arbitrarily long value, nor get a short address accepted inside it.
    let lb = resolver(&["10.0.0.0/8"], ForwardingHeader::XRealIp);
    let padded = format!("{}203.0.113.7", " ".repeat(MAX_ELEMENT));
    assert_eq!(
        lb.resolve(peer("10.0.0.1:4000"), &headers("x-real-ip", &[&padded]))
            .resolution(),
        Resolution::Invalid(InvalidForwarding::Malformed)
    );
    // Spaces within the bound still trim away.
    assert_eq!(
        lb.resolve(
            peer("10.0.0.1:4000"),
            &headers("x-real-ip", &["  203.0.113.7  "])
        )
        .resolution(),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
}

#[test]
fn the_proxy_owns_the_client_address_headers() {
    for name in ["x-forwarded-for", "X-Real-IP", "Forwarded"] {
        assert!(owns(name), "{name}");
    }
    for name in ["x-forwarded-proto", "x-forwarded-host", "x-user-id"] {
        assert!(!owns(name), "{name}");
    }
}

#[test]
fn without_a_peer_nothing_resolves() {
    // No connection information: the forwarding headers cannot be trusted,
    // since nobody is known to have sent them.
    let client = behind_lb().resolve(None, &xff(&["203.0.113.7"]));
    assert_eq!(client.resolution(), Resolution::Unavailable);
    assert_eq!(client.ip(), None);
    assert_eq!(client.peer(), None);
    assert_eq!(
        ClientAddress::from_peer(None).resolution(),
        Resolution::Unavailable
    );
}

/// A resolver trusting 10.0.0.0/8 that forwards as `forward` says.
fn forwarding(forward: crate::config::ForwardConfig) -> Resolver {
    Resolver::build(&ClientAddressConfig {
        trusted_proxies: vec!["10.0.0.0/8".into()],
        header: ForwardingHeader::XForwardedFor,
        required: false,
        forward,
    })
    .unwrap()
}

/// `forward` with `mode`, the default client header and no audit header.
fn mode(mode: XForwardedFor) -> crate::config::ForwardConfig {
    crate::config::ForwardConfig {
        x_forwarded_for: mode,
        ..Default::default()
    }
}

/// A request through the load balancer at 10.0.0.1, whose client wrote a
/// forged prefix and every other forwarding header, plus two DPoP proofs.
fn forged_request() -> http::Request<()> {
    let mut request = http::Request::new(());
    let headers = request.headers_mut();
    headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
    headers.append(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.7:51234, 10.0.0.2"),
    );
    headers.append("x-real-ip", HeaderValue::from_static("198.51.100.2"));
    headers.append("forwarded", HeaderValue::from_static("for=198.51.100.3"));
    headers.append("dpop", HeaderValue::from_static("proof-a"));
    headers.append("dpop", HeaderValue::from_static("proof-b"));
    request
}

/// Every value of `name` on `request`, in order.
fn all<'a>(request: &'a http::Request<()>, name: &str) -> Vec<&'a str> {
    request
        .headers()
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect()
}

#[test]
fn verified_forwards_the_checked_chain_from_the_client() {
    // The client's forged prefix is gone; what remains is what the trusted
    // proxies vouched for, in canonical form, then this proxy's peer.
    let mut request = forged_request();
    forwarding(Default::default()).apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(
        all(&request, "x-forwarded-for"),
        ["203.0.113.7, 10.0.0.2, 10.0.0.1"]
    );
    assert_eq!(all(&request, "x-real-ip"), ["203.0.113.7"]);
    assert!(all(&request, "forwarded").is_empty());
    // Unrelated headers keep every value (RFC 9449 §4.3 counts DPoP).
    assert_eq!(all(&request, "dpop"), ["proof-a", "proof-b"]);
    let client = request.extensions().get::<ClientAddress>().unwrap();
    assert_eq!(
        client.resolution(),
        Resolution::Forwarded(ip("203.0.113.7"))
    );
}

#[test]
fn verified_lists_a_client_that_is_the_peer_once() {
    // An untrusted peer, and a trusted one that forwarded nothing, are the
    // client and the whole verified chain.
    for (from, client) in [
        ("203.0.113.9:4000", "203.0.113.9"),
        ("10.0.0.1:4000", "10.0.0.1"),
    ] {
        let mut request = http::Request::new(());
        if from.starts_with("203") {
            request
                .headers_mut()
                .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        }
        forwarding(Default::default()).apply(&mut request, peer(from));
        assert_eq!(all(&request, "x-forwarded-for"), [client], "{from}");
    }
    // Every hop trusted: the leftmost is the client, listed once.
    let mut request = http::Request::new(());
    request.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_static("10.0.0.5, 10.0.0.2"),
    );
    forwarding(Default::default()).apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(
        all(&request, "x-forwarded-for"),
        ["10.0.0.5, 10.0.0.2, 10.0.0.1"]
    );
}

#[test]
fn verified_from_x_real_ip_is_the_client_and_the_peer() {
    let resolver = Resolver::build(&ClientAddressConfig {
        trusted_proxies: vec!["10.0.0.0/8".into()],
        header: ForwardingHeader::XRealIp,
        required: false,
        forward: Default::default(),
    })
    .unwrap();
    let mut request = forged_request();
    request
        .headers_mut()
        .insert("x-real-ip", HeaderValue::from_static("203.0.113.7"));
    resolver.apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(all(&request, "x-forwarded-for"), ["203.0.113.7, 10.0.0.1"]);
}

#[test]
fn resolved_forwards_the_address_alone() {
    let mut request = forged_request();
    forwarding(mode(XForwardedFor::Resolved)).apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(all(&request, "x-forwarded-for"), ["203.0.113.7"]);
    assert_eq!(all(&request, "x-real-ip"), ["203.0.113.7"]);
    assert!(all(&request, "forwarded").is_empty());
}

#[test]
fn append_keeps_the_arrived_list_and_adds_the_peer() {
    // As nginx's `$proxy_add_x_forwarded_for`, Envoy and HAProxy do: the
    // field lines joined in order, then the peer.
    let mut request = forged_request();
    forwarding(mode(XForwardedFor::Append)).apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(
        all(&request, "x-forwarded-for"),
        ["198.51.100.1, 203.0.113.7:51234, 10.0.0.2, 10.0.0.1"]
    );
    // The resolved address still has its own header, and the rest is gone.
    assert_eq!(all(&request, "x-real-ip"), ["203.0.113.7"]);
    assert!(all(&request, "forwarded").is_empty());
    // Nothing arrived: the peer alone. No peer: the lines alone.
    let mut request = http::Request::new(());
    forwarding(mode(XForwardedFor::Append)).apply(&mut request, peer("203.0.113.9:4000"));
    assert_eq!(all(&request, "x-forwarded-for"), ["203.0.113.9"]);
    let mut request = forged_request();
    forwarding(mode(XForwardedFor::Append)).apply(&mut request, None);
    assert_eq!(
        all(&request, "x-forwarded-for"),
        ["198.51.100.1, 203.0.113.7:51234, 10.0.0.2"]
    );
    assert!(all(&request, "x-real-ip").is_empty());
}

#[test]
fn preserve_leaves_what_arrived() {
    let mut request = forged_request();
    let mut forward = mode(XForwardedFor::Preserve);
    forward.client_header = Some("cf-connecting-ip".into());
    forwarding(forward).apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(
        all(&request, "x-forwarded-for"),
        ["198.51.100.1", "203.0.113.7:51234, 10.0.0.2"]
    );
    assert_eq!(all(&request, "x-real-ip"), ["198.51.100.2"]);
    assert_eq!(all(&request, "forwarded"), ["for=198.51.100.3"]);
    assert_eq!(all(&request, "cf-connecting-ip"), ["203.0.113.7"]);
    // The client header still wins over a preserved X-Real-IP.
    let mut request = forged_request();
    forwarding(mode(XForwardedFor::Preserve)).apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(all(&request, "x-real-ip"), ["203.0.113.7"]);
}

#[test]
fn remove_forwards_no_list() {
    let mut request = forged_request();
    forwarding(mode(XForwardedFor::Remove)).apply(&mut request, peer("10.0.0.1:4000"));
    assert!(all(&request, "x-forwarded-for").is_empty());
    assert!(all(&request, "forwarded").is_empty());
    assert_eq!(all(&request, "x-real-ip"), ["203.0.113.7"]);
}

#[test]
fn the_client_header_is_named_by_the_config_and_never_by_the_client() {
    let forward = crate::config::ForwardConfig {
        client_header: Some("CF-Connecting-IP".into()),
        ..Default::default()
    };
    let mut request = forged_request();
    request
        .headers_mut()
        .insert("cf-connecting-ip", HeaderValue::from_static("198.51.100.9"));
    forwarding(forward.clone()).apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(all(&request, "cf-connecting-ip"), ["203.0.113.7"]);
    assert!(all(&request, "x-real-ip").is_empty());
    // Nothing resolved: the client's copy is gone, and none is written.
    let mut request = forged_request();
    request
        .headers_mut()
        .insert("cf-connecting-ip", HeaderValue::from_static("198.51.100.9"));
    forwarding(forward).apply(&mut request, None);
    assert!(all(&request, "cf-connecting-ip").is_empty());
    // No client header at all.
    let forward = crate::config::ForwardConfig {
        client_header: None,
        ..Default::default()
    };
    let mut request = forged_request();
    forwarding(forward).apply(&mut request, peer("10.0.0.1:4000"));
    assert!(all(&request, "x-real-ip").is_empty());
}

#[test]
fn the_audit_header_holds_what_arrived_and_nothing_the_client_named_it() {
    let forward = crate::config::ForwardConfig {
        audit_header: Some("x-original-forwarded-for".into()),
        ..Default::default()
    };
    let mut request = forged_request();
    request.headers_mut().insert(
        "x-original-forwarded-for",
        HeaderValue::from_static("198.51.100.66"),
    );
    forwarding(forward.clone()).apply(&mut request, peer("10.0.0.1:4000"));
    assert_eq!(
        all(&request, "x-original-forwarded-for"),
        ["198.51.100.1", "203.0.113.7:51234, 10.0.0.2"]
    );
    // Nothing arrived: nothing is recorded, and the client's copy is gone.
    let mut request = http::Request::new(());
    request.headers_mut().insert(
        "x-original-forwarded-for",
        HeaderValue::from_static("198.51.100.66"),
    );
    forwarding(forward).apply(&mut request, peer("203.0.113.9:4000"));
    assert!(all(&request, "x-original-forwarded-for").is_empty());
}

#[test]
fn a_forward_header_must_be_a_new_grpc_key() {
    let cases: [(Option<&str>, Option<&str>, &str); 8] = [
        (Some("x-forwarded-for"), None, "client_header"),
        (Some("Forwarded"), None, "client_header"),
        (Some("not a header"), None, "client_header"),
        (Some("x+ip"), None, "client_header"),
        // A binary metadata key: the values are text, not base64, so every
        // transcoded call would be refused.
        (Some("client-ip-bin"), None, "client_header"),
        (None, Some("x-original-forwarded-for-bin"), "audit_header"),
        (Some("x-real-ip"), Some("X-Real-IP"), "audit_header"),
        (
            Some("cf-connecting-ip"),
            Some("cf-connecting-ip"),
            "audit_header",
        ),
    ];
    for (client, audit, setting) in cases {
        let err = Resolver::build(&ClientAddressConfig {
            forward: crate::config::ForwardConfig {
                client_header: client.map(str::to_owned),
                audit_header: audit.map(str::to_owned),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains(setting), "{client:?} {audit:?}: {err}");
    }
}

#[test]
fn the_forwarding_headers_are_reserved() {
    let resolver = forwarding(crate::config::ForwardConfig {
        client_header: Some("cf-connecting-ip".into()),
        audit_header: Some("x-original-forwarded-for".into()),
        ..Default::default()
    });
    for name in [
        "x-forwarded-for",
        "X-Real-IP",
        "forwarded",
        "CF-Connecting-IP",
        "x-original-forwarded-for",
    ] {
        assert!(resolver.reserves(name), "{name}");
    }
    assert!(!resolver.reserves("x-user-id"));
    assert_eq!(
        resolver.forwarded_headers().collect::<Vec<_>>(),
        [
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "cf-connecting-ip",
            "x-original-forwarded-for"
        ]
    );
}

#[test]
fn an_unresolved_address_leaves_no_forwarding_header() {
    for (from, forwarded) in [(peer("10.0.0.1:4000"), "garbage"), (None, "203.0.113.7")] {
        let mut request = http::Request::new(());
        request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static(forwarded));
        request
            .headers_mut()
            .insert("x-real-ip", HeaderValue::from_static("203.0.113.7"));
        behind_lb().apply(&mut request, from);
        assert!(request.headers().get("x-forwarded-for").is_none());
        assert!(request.headers().get("x-real-ip").is_none());
        assert!(request
            .extensions()
            .get::<ClientAddress>()
            .unwrap()
            .ip()
            .is_none());
    }
}

#[test]
fn the_header_value_is_the_canonical_text_form() {
    for (resolved, text) in [
        ("203.0.113.7", "203.0.113.7"),
        ("2001:0db8:0000::0001", "2001:db8::1"),
        (
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ),
    ] {
        assert_eq!(header_value(ip(resolved)), text);
    }
}

#[test]
fn a_trusted_proxy_written_as_ipv4_mapped_matches_its_ipv4_peer() {
    // Peers are compared in canonical form, so a range written in the
    // mapped form a dual-stack socket reports must match the same peers.
    let lb = resolver(
        &["::ffff:10.0.0.0/104", "::ffff:192.0.2.10"],
        ForwardingHeader::XForwardedFor,
    );
    for from in ["10.1.2.3:4000", "[::ffff:10.1.2.3]:4000", "192.0.2.10:4000"] {
        assert_eq!(
            resolve_xff(&lb, from, &["203.0.113.7"]),
            Resolution::Forwarded(ip("203.0.113.7")),
            "{from}"
        );
    }
    assert_eq!(
        resolve_xff(&lb, "192.0.2.11:4000", &["203.0.113.7"]),
        Resolution::Peer(ip("192.0.2.11"))
    );
    // A range wider than the mapped block stays IPv6: trusting `::/0` does
    // not trust every IPv4 peer.
    let v6 = resolver(&["::/0"], ForwardingHeader::XForwardedFor);
    assert_eq!(
        resolve_xff(&v6, "10.0.0.1:4000", &["203.0.113.7"]),
        Resolution::Peer(ip("10.0.0.1"))
    );
}

#[test]
fn a_trusted_proxy_is_a_range_or_one_address() {
    let lb = resolver(
        &["10.0.0.0/8", "192.0.2.10", "2001:db8::/32"],
        ForwardingHeader::XForwardedFor,
    );
    assert!(lb.trusts(ip("10.1.2.3")));
    assert!(lb.trusts(ip("192.0.2.10")));
    assert!(!lb.trusts(ip("192.0.2.11")));
    assert!(lb.trusts(ip("2001:db8::5")));
    for bad in ["10.0.0.0/33", "not-an-address", "10.0.0.0/8 ", ""] {
        let err = Resolver::build(&ClientAddressConfig {
            trusted_proxies: vec![bad.into()],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.contains("trusted_proxies"), "{bad:?}: {err}");
    }
}
