use super::*;

/// A resolver trusting `trusted`, reading `header`.
fn resolver(trusted: &[&str], header: ForwardingHeader) -> Resolver {
    Resolver::build(&ClientAddressConfig {
        trusted_proxies: trusted.iter().map(|t| (*t).to_string()).collect(),
        header,
        required: false,
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

#[test]
fn applying_rewrites_the_forwarding_headers_to_the_resolved_address() {
    let mut request = http::Request::new(());
    let headers = request.headers_mut();
    headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
    headers.append(
        "x-forwarded-for",
        HeaderValue::from_static("203.0.113.7, 10.0.0.2"),
    );
    headers.append("x-real-ip", HeaderValue::from_static("198.51.100.2"));
    headers.append("forwarded", HeaderValue::from_static("for=198.51.100.3"));
    headers.append("dpop", HeaderValue::from_static("proof-a"));
    headers.append("dpop", HeaderValue::from_static("proof-b"));
    behind_lb().apply(&mut request, peer("10.0.0.1:4000"));
    let headers = request.headers();
    let all = |name: &str| -> Vec<&str> {
        headers
            .get_all(name)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    };
    assert_eq!(all("x-forwarded-for"), ["203.0.113.7"]);
    assert_eq!(all("x-real-ip"), ["203.0.113.7"]);
    assert!(all("forwarded").is_empty());
    // Unrelated headers keep every value (RFC 9449 §4.3 counts DPoP).
    assert_eq!(all("dpop"), ["proof-a", "proof-b"]);
    let client = request.extensions().get::<ClientAddress>().unwrap();
    assert_eq!(
        client.resolution(),
        Resolution::Forwarded(ip("203.0.113.7"))
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
