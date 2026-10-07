//! The transcoded routes: the bindings mounted at each router path, and the
//! choice among them for a request, by the custom verb its path ends in and
//! by its method.
//!
//! A request's verb is its last segment from the first unencoded `:`. Neither
//! side of the verb holds one: a client percent-encodes every reserved
//! character of a variable's value, and a `LITERAL` writes its reserved
//! characters percent-encoded too (google/api/http.proto). A verb some binding
//! of the request's path binds owns that URL; a verb none binds stays part of
//! the last variable, as Envoy's transcoder and grpc-gateway leave an unbound
//! verb.

use std::borrow::Cow;
use std::collections::HashMap;

use axum::http::{HeaderValue, Method};

use super::path::MountedPath;
use super::rule::RouteMethod;
use super::{PathParams, RouteEntry};

/// Every transcoded route, and where each custom verb is bound.
pub(super) struct Routes {
    pub(super) tables: Vec<PathTable>,
    /// For each verb, the tables binding it. The router matches a request to
    /// one path whatever its verb, while the verb may be bound on a path of
    /// another shape the request also matches.
    verbs: HashMap<String, Index>,
    /// The tables with a binding without a verb: a path whose bindings all
    /// carry verbs must not hide one of these from a request that names no
    /// bound verb.
    plain: Index,
    /// Each table's path alone: whether a request matches a given table, and
    /// with which captures, whatever ranks above it.
    single: Vec<matchit::Router<()>>,
}

/// Some of the tables, ranked as the router ranks their paths.
#[derive(Default)]
struct Index {
    router: matchit::Router<usize>,
    tables: Vec<usize>,
}

impl Index {
    fn insert(&mut self, path: &str, table: usize) {
        let inserted = self.router.insert(path, table);
        debug_assert!(inserted.is_ok(), "{path}: {inserted:?}");
        self.tables.push(table);
    }
}

/// Every binding the router serves at one path.
pub(super) struct PathTable {
    /// The router path, written with the first binding's capture names.
    pub(super) path: String,
    /// The capture names of `path`, in path order.
    pub(super) captures: Vec<String>,
    bindings: Vec<Binding>,
}

/// One binding of a [`PathTable`].
struct Binding {
    entry: RouteEntry,
    /// This binding's names for the captures of the table's path, when they
    /// differ from the path's own.
    names: Option<Vec<String>>,
    verb: Option<Verb>,
    template: Option<Template>,
    /// The positions of the captures that stand for a bare `*` or `**`,
    /// which bind no field.
    unbound: Vec<usize>,
}

/// The field template of a last capture the router mounts as a catch-all.
struct Template {
    /// Its segments as written: what tells two bindings apart.
    raw: Vec<String>,
    /// Its segments, escapes in upper case: what a value is compared with.
    segments: Vec<String>,
    /// The index of the path segment the capture starts at.
    start: usize,
}

impl Template {
    fn of(mount: &MountedPath) -> Option<Self> {
        let raw = mount.last_template.clone()?;
        let segments = raw
            .iter()
            .map(|segment| normalize_escapes(segment).into_owned())
            .collect();
        Some(Self {
            raw,
            segments,
            start: mount.last_segment,
        })
    }
}

impl Binding {
    /// Whether the value of the last capture in `path` (a request this
    /// binding's path matched) follows the binding's field template.
    fn fits(&self, path: &str) -> bool {
        let Some(template) = &self.template else {
            return true;
        };
        // The capture starts after the `start`-th slash of the path.
        let mut at = 0;
        for _ in 0..template.start {
            match path[at..].find('/') {
                Some(slash) => at += slash + 1,
                None => return false,
            }
        }
        let end = match (&self.verb, split_verb(path)) {
            (Some(_), Some((rest, _))) => rest.len(),
            (Some(_), None) => return false,
            (None, _) => path.len(),
        };
        let Some(value) = path.get(at..end) else {
            return false;
        };
        let segments: Vec<&str> = if value.is_empty() {
            Vec::new()
        } else {
            value.split('/').collect()
        };
        follows(&template.segments, &segments)
    }
}

/// A custom verb after the last capture.
struct Verb {
    /// As written in the template, `:` included, escapes in upper case:
    /// compared with the request's path as received, likewise normalized.
    raw: String,
    /// `raw` percent-decoded: what ends the decoded value of the capture.
    decoded: String,
    /// Whether the capture before it may be empty (`**`).
    empty_ok: bool,
}

/// What answers a request.
pub(super) enum Choice {
    /// The binding at `index` of the table at `table`.
    Route { table: usize, index: usize },
    /// Bindings answer the URL, none with the request's method: the value of
    /// `Allow` lists their methods (RFC 9110 §15.5.6).
    MethodNotAllowed(HeaderValue),
    /// No binding answers the URL.
    NotFound,
}

/// The request path without its custom verb, and the verb (`:` included):
/// the last segment from its first unencoded colon.
pub(super) fn split_verb(path: &str) -> Option<(&str, &str)> {
    let start = path.rfind('/').map_or(0, |slash| slash + 1);
    let colon = start + path[start..].find(':')?;
    Some(path.split_at(colon))
}

/// `text` with the hex digits of its percent-escapes in upper case: `%3a` and
/// `%3A` are one octet (RFC 3986 §6.2.2.1). Borrowed when nothing changes.
pub(super) fn normalize_escapes(text: &str) -> Cow<'_, str> {
    let lower_hex = |b: &u8| b.is_ascii_hexdigit() && b.is_ascii_lowercase();
    let bytes = text.as_bytes();
    let lower_escape =
        |at: usize| bytes[at] == b'%' && bytes[at + 1..].iter().take(2).any(lower_hex);
    if !(0..bytes.len()).any(lower_escape) {
        return Cow::Borrowed(text);
    }
    let mut normalized = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        normalized.push(ch);
        if ch == '%' {
            for digit in chars.by_ref().take(2) {
                // Only a hex digit is part of the escape; anything else is
                // kept as it is, so a malformed escape is not rewritten.
                normalized.push(if digit.is_ascii_hexdigit() {
                    digit.to_ascii_uppercase()
                } else {
                    digit
                });
            }
        }
    }
    Cow::Owned(normalized)
}

/// What a binding claims on its path: the method, the verb and the field
/// template of its last capture.
pub(super) struct Claim<'a> {
    pub(super) method: &'a RouteMethod,
    pub(super) verb: Option<&'a str>,
    pub(super) template: Option<&'a [String]>,
}

/// Whether two bindings of one path cannot both serve: the same verb and
/// field template, and the same method or a `custom` `*` rule, which answers
/// every method. Bindings whose templates differ answer different values;
/// where their values overlap, the earlier binding answers.
pub(super) fn clash(claim: &Claim<'_>, other: &Claim<'_>) -> bool {
    claim.verb.map(normalize_escapes) == other.verb.map(normalize_escapes)
        && claim.template == other.template
        && (claim.method == other.method
            || *claim.method == RouteMethod::Any
            || *other.method == RouteMethod::Any)
}

/// The positions `unbound` marks.
fn unbound_positions(unbound: &[bool]) -> Vec<usize> {
    unbound
        .iter()
        .enumerate()
        .filter_map(|(position, &bare)| bare.then_some(position))
        .collect()
}

/// Whether the segments of `value` follow `template`: a literal itself, `*`
/// one non-empty segment, `**` any number of segments.
fn follows(template: &[String], value: &[&str]) -> bool {
    match template.split_first() {
        None => value.is_empty(),
        Some((first, rest)) if first == "**" => {
            (0..=value.len()).any(|taken| follows(rest, &value[taken..]))
        }
        Some((first, rest)) => value.split_first().is_some_and(|(segment, tail)| {
            let fits = if first == "*" {
                !segment.is_empty()
            } else {
                normalize_escapes(segment) == first.as_str()
            };
            fits && follows(rest, tail)
        }),
    }
}

impl Routes {
    /// The routes of `tables`, with their verbs indexed. Every path was
    /// already accepted by a router holding them all, so a router holding
    /// some of them accepts it too.
    pub(super) fn new(tables: Vec<PathTable>) -> Self {
        let mut verbs: HashMap<String, Index> = HashMap::new();
        let mut plain = Index::default();
        let mut single = Vec::with_capacity(tables.len());
        for (index, table) in tables.iter().enumerate() {
            let mut alone = matchit::Router::new();
            let inserted = alone.insert(table.path.as_str(), ());
            debug_assert!(inserted.is_ok(), "{}: {inserted:?}", table.path);
            single.push(alone);
            if table.bindings.iter().any(|b| b.verb.is_none()) {
                plain.insert(&table.path, index);
            }
            let mut seen: Vec<&str> = Vec::new();
            for verb in table.bindings.iter().filter_map(|b| b.verb.as_ref()) {
                if seen.contains(&verb.raw.as_str()) {
                    continue;
                }
                seen.push(&verb.raw);
                verbs
                    .entry(verb.raw.clone())
                    .or_default()
                    .insert(&table.path, index);
            }
        }
        Self {
            tables,
            verbs,
            plain,
            single,
        }
    }

    /// The router's match of `path` on the table at `table`, which [`choose`]
    /// picked for it: its captures, still percent-encoded.
    ///
    /// [`choose`]: Self::choose
    pub(super) fn params_of<'r, 'p>(
        &'r self,
        table: usize,
        path: &'p str,
    ) -> Option<matchit::Params<'r, 'p>> {
        self.single[table].at(path).ok().map(|found| found.params)
    }

    /// What answers `method` on `path` among the tables of `index`, starting
    /// from `first`, the index's own pick: the first table, in the router's
    /// ranking, that `admits` a binding of. A table whose bindings all refuse
    /// the request (a field template the value does not follow) leaves it to
    /// the next one the path also matches. `None` when no table admits one.
    fn answer(
        &self,
        index: &Index,
        first: usize,
        method: &Method,
        path: &str,
        admits: impl Fn(&Binding) -> bool,
    ) -> Option<Choice> {
        if let Some(choice) = self.tables[first].choose(first, method, &admits) {
            return Some(choice);
        }
        // Rare: only a refused template gets here. Rank what is left by
        // building the router of the remaining tables this path matches.
        let mut refused = vec![first];
        loop {
            let mut router = matchit::Router::new();
            for &table in &index.tables {
                if !refused.contains(&table) && self.single[table].at(path).is_ok() {
                    let inserted = router.insert(self.tables[table].path.as_str(), table);
                    debug_assert!(inserted.is_ok(), "{inserted:?}");
                }
            }
            let next = *router.at(path).ok()?.value;
            if let Some(choice) = self.tables[next].choose(next, method, &admits) {
                return Some(choice);
            }
            refused.push(next);
        }
    }

    /// Which binding answers `method` on `path`, a request the router matched
    /// to the table at `table`.
    ///
    /// - A path ending in a literal matched exactly: its bindings answer, as a
    ///   static route wins over a variable everywhere.
    /// - A verb some table binds for this path owns the URL: only the
    ///   bindings of that verb answer it.
    /// - Otherwise the bindings without a verb answer, of the best path that
    ///   has some, the verb text being part of the last variable.
    pub(super) fn choose(&self, table: usize, method: &Method, path: &str) -> Choice {
        let plain = |binding: &Binding| binding.verb.is_none() && binding.fits(path);
        if self.tables[table].literal_end() {
            return self.tables[table]
                .choose(table, method, plain)
                .unwrap_or(Choice::NotFound);
        }
        if let Some((rest, verb)) = split_verb(path) {
            let verb = normalize_escapes(verb);
            if let Some(index) = self.verbs.get(verb.as_ref()) {
                if let Ok(found) = index.router.at(path) {
                    let bound = |binding: &Binding| {
                        binding.verb.as_ref().is_some_and(|own| {
                            own.raw == verb && (own.empty_ok || !rest.ends_with('/'))
                        }) && binding.fits(path)
                    };
                    if let Some(choice) = self.answer(index, *found.value, method, path, bound) {
                        return choice;
                    }
                }
            }
        }
        // The router's own table, when it has bindings without a verb, ranks
        // first among those that have: no second lookup for the common
        // request.
        let first = if self.tables[table].bindings.iter().any(|b| b.verb.is_none()) {
            table
        } else {
            match self.plain.router.at(path) {
                Ok(found) => *found.value,
                Err(_) => return Choice::NotFound,
            }
        };
        self.answer(&self.plain, first, method, path, plain)
            .unwrap_or(Choice::NotFound)
    }
}

impl PathTable {
    /// A table for `mount`, served first by `entry`.
    pub(super) fn new(mount: MountedPath, entry: RouteEntry) -> Self {
        let template = Template::of(&mount);
        let unbound = unbound_positions(&mount.unbound);
        let MountedPath {
            axum,
            captures,
            verb,
            empty_last,
            ..
        } = mount;
        Self {
            path: axum,
            captures,
            bindings: vec![Binding {
                entry,
                names: None,
                verb: verb.map(|raw| Verb::new(raw, empty_last)),
                template,
                unbound,
            }],
        }
    }

    /// Add `entry` mounted at `mount`, a path of this table's shape, unless it
    /// [`clash`]es with a binding already there.
    pub(super) fn add(&mut self, mount: MountedPath, entry: RouteEntry) {
        let claim = Claim {
            method: &entry.http_method,
            verb: mount.verb.as_deref(),
            template: mount.last_template.as_deref(),
        };
        let taken = self.bindings.iter().any(|existing| {
            let existing_claim = Claim {
                method: &existing.entry.http_method,
                verb: existing.verb.as_ref().map(|v| v.raw.as_str()),
                template: existing.template.as_ref().map(|t| t.raw.as_slice()),
            };
            clash(&existing_claim, &claim)
        });
        if taken {
            tracing::error!(
                method = entry.http_method.as_str(),
                path = %mount.display(),
                rpc = %entry.grpc_path,
                "HTTP method and path already bound to another RPC; skipping this binding"
            );
            return;
        }
        let template = Template::of(&mount);
        let unbound = unbound_positions(&mount.unbound);
        let names = (mount.captures != self.captures).then_some(mount.captures);
        self.bindings.push(Binding {
            entry,
            names,
            verb: mount.verb.map(|raw| Verb::new(raw, mount.empty_last)),
            template,
            unbound,
        });
    }

    /// Whether the path ends in a literal (a verb after a literal is part of
    /// it), so the router matched the request's last segment exactly.
    fn literal_end(&self) -> bool {
        !self.path.ends_with('}')
    }

    /// The route entry of the binding at `index`.
    pub(super) fn entry(&self, index: usize) -> &RouteEntry {
        &self.bindings[index].entry
    }

    /// Among the bindings `answers` admits, the one serving `method`: its own
    /// (or a `custom` `*` rule) before a GET binding answering HEAD. `None`
    /// when `answers` admits none.
    fn choose(
        &self,
        table: usize,
        method: &Method,
        answers: impl Fn(&Binding) -> bool,
    ) -> Option<Choice> {
        let mut head: Option<usize> = None;
        let mut answered = false;
        for (index, binding) in self.bindings.iter().enumerate() {
            if !answers(binding) {
                continue;
            }
            answered = true;
            match &binding.entry.http_method {
                RouteMethod::Any => return Some(Choice::Route { table, index }),
                RouteMethod::One(bound) if bound == method => {
                    return Some(Choice::Route { table, index })
                }
                // A GET binding answers HEAD too, after one bound to HEAD.
                RouteMethod::One(bound) if *bound == Method::GET && *method == Method::HEAD => {
                    head.get_or_insert(index);
                }
                RouteMethod::One(_) => {}
            }
        }
        match head {
            Some(index) => Some(Choice::Route { table, index }),
            None if answered => Some(Choice::MethodNotAllowed(self.allow(&answers))),
            None => None,
        }
    }

    /// The methods of the bindings `answers` admits, in binding order, with
    /// HEAD after them when a GET binding answers it.
    fn allow(&self, answers: &impl Fn(&Binding) -> bool) -> HeaderValue {
        let mut methods: Vec<&str> = Vec::new();
        for binding in self.bindings.iter().filter(|b| answers(b)) {
            let method = binding.entry.http_method.as_str();
            if !methods.contains(&method) {
                methods.push(method);
            }
        }
        if methods.contains(&"GET") && !methods.contains(&"HEAD") {
            methods.push("HEAD");
        }
        HeaderValue::from_str(&methods.join(", "))
            .expect("method tokens are valid header value characters")
    }

    /// Turn the path parameters matched on this table's path into those of
    /// the binding at `index`: its verb taken off the last capture, and the
    /// captures under its own names. A parameter the table's path does not
    /// capture (a prefix the router is nested under) is left as it is.
    pub(super) fn bind_params(&self, index: usize, params: &mut PathParams) {
        let binding = &self.bindings[index];
        if let (Some(verb), Some(last)) = (&binding.verb, self.captures.last()) {
            if let Some(value) = params.get_mut(last) {
                if let Some(len) = value.strip_suffix(verb.decoded.as_str()).map(str::len) {
                    value.truncate(len);
                }
            }
        }
        // A bare wildcard was named for the router only.
        for &position in &binding.unbound {
            params.remove(&self.captures[position]);
        }
        if let Some(names) = &binding.names {
            // Taken out before any goes back in: one binding's name may be
            // another capture's name on the table's path.
            let renamed: Vec<(&String, Option<String>)> = self
                .captures
                .iter()
                .zip(names)
                .filter(|(path_name, own)| path_name != own)
                .map(|(path_name, own)| (own, params.remove(path_name)))
                .collect();
            for (own, value) in renamed {
                if let Some(value) = value {
                    params.insert(own.clone(), value);
                }
            }
        }
    }
}

impl Verb {
    fn new(raw: String, empty_ok: bool) -> Self {
        let decoded = percent_encoding::percent_decode_str(&raw)
            .decode_utf8_lossy()
            .into_owned();
        Self {
            raw: normalize_escapes(&raw).into_owned(),
            decoded,
            empty_ok,
        }
    }
}
