use super::*;

/// The tables `path` matches in the router's ranking: matchit's match, then
/// its match among the paths left, until none matches. The router is built
/// anew each time: matchit 0.8.4 does not remove a catch-all route.
fn ranked_by_matchit(paths: &[&str], path: &str) -> Vec<usize> {
    let mut ranked = Vec::new();
    loop {
        let mut router = matchit::Router::new();
        for (table, pattern) in paths.iter().enumerate() {
            if !ranked.contains(&table) {
                router.insert(*pattern, table).unwrap();
            }
        }
        match router.at(path) {
            Ok(found) => ranked.push(*found.value),
            Err(_) => return ranked,
        }
    }
}

#[test]
fn a_received_text_compares_as_its_normalized_form() {
    // `same_octets` compares without building the normalized text, so it
    // must agree with comparing `normalize_escapes`: hex digits of an escape
    // in either case, anything else (a malformed escape, a `%` taken as a
    // digit) as written.
    let normalized = [
        "%3A", "a%3Ab", "%2F%2F", "%G1", "%%3a", "%", "%3", "plain", "é%3A", "",
    ];
    let received = [
        "%3a", "%3A", "a%3ab", "%2f%2F", "%g1", "%G1", "%%3a", "%%3A", "%", "%3", "PLAIN", "plain",
        "é%3a", "",
    ];
    for normalized in normalized {
        assert_eq!(normalize_escapes(normalized), normalized);
        for received in received {
            assert_eq!(
                same_octets(received, normalized),
                normalize_escapes(received) == normalized,
                "{received} as {normalized}"
            );
        }
    }
}

#[test]
fn the_index_ranks_the_tables_a_path_matches_as_the_router_does() {
    // Every table a method miss falls back to must come in the router's own
    // order: a literal before a variable before a catch-all at the first
    // segment where two paths differ, with backtracking past a branch that
    // does not match. The router holds no variable and catch-all at one
    // position, so a catch-all sits beside literals only.
    let paths = [
        "/a/b/c",
        "/a/{p2}/c",
        "/{p1}/b/{p3}",
        "/a/{p2}/{p3}",
        "/{p1}/{p2}/c",
        "/a/b",
        "/a/",
        "/v1/nodes:batch",
        "/{p1}/{p2}/{p3}/{p4}",
        "/{p1}",
        "/s/{*rest}",
        "/s/x/y",
        "/s/x",
        "/m/{key}",
    ];
    let mut index = Index::default();
    for (table, path) in paths.iter().enumerate() {
        index.insert(path, table);
    }
    for path in [
        "/a/b/c",
        "/a/x/c",
        "/q/b/z",
        "/a/b/z",
        "/a/b",
        "/a/",
        "/a",
        "/",
        "/x/y/c",
        "/a//c",
        "/v1/nodes:batch",
        "/v1/nodes",
        "/a/b/c/d",
        "/p/q/r/s",
        "/p/q/r/s/t",
        "/s/x",
        "/s/x/y",
        "/s/x/z",
        "/s/z",
        "/s/",
        "/s",
        "/s/x/y/z",
        // An empty last segment, which a variable takes there too (axum's
        // `captures_match_empty_trailing_segment`).
        "/m/",
        "/m",
        "/m/abc/",
        "",
        "a/b",
    ] {
        let mut listed = Vec::new();
        let ControlFlow::Continue(()) = index.each(path, |table| {
            listed.push(table);
            ControlFlow::<()>::Continue(())
        }) else {
            unreachable!("nothing breaks");
        };
        assert_eq!(listed, ranked_by_matchit(&paths, path), "{path}");
        assert_eq!(index.first(path), listed.first().copied(), "{path}");
    }
}
