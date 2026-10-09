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
use std::ops::ControlFlow;

use axum::http::{HeaderValue, Method};
use rustc_hash::FxHashMap;

use super::path::{decode_multi_segment, Composite, MountedPath, Part};
use super::rule::RouteMethod;
use super::{PathParams, RouteEntry};

/// Every transcoded route, and where each custom verb is bound.
pub(super) struct Routes {
    pub(super) tables: Vec<PathTable>,
    /// For each verb, the tables binding it. The router matches a request to
    /// one path whatever its verb, while the verb may be bound on a path of
    /// another shape the request also matches.
    verbs: FxHashMap<String, Index>,
    /// The tables with a binding without a verb: a path whose bindings all
    /// carry verbs must not hide one of these from a request that names no
    /// bound verb.
    plain: Index,
    /// Every table: the one the router matches a request to.
    all: Index,
    /// Each table by its router path, as the router reports the route it
    /// matched.
    by_path: FxHashMap<String, usize>,
    /// Each table's path alone: with which captures a request matches it.
    single: Vec<matchit::Router<()>>,
}

/// Some of the tables, by the segments of their router paths: whole-segment
/// literals, variables and a last catch-all, nothing else (`mountable`).
///
/// It lists the tables a path matches in the order the router ranks them, a
/// literal before a variable before a catch-all at the first segment where
/// two differ, and backtracking past a branch that does not match, as matchit
/// does. Each segment of a request follows at most three branches, so the
/// work is bounded by the request's path, not by the number of tables.
struct Index {
    /// `nodes[0]` is the root, before the first segment.
    nodes: Vec<Node>,
}

#[derive(Default)]
struct Node {
    literals: FxHashMap<String, usize>,
    variable: Option<usize>,
    /// The table whose path ends in a catch-all here.
    rest: Option<usize>,
    /// The table whose path ends here.
    table: Option<usize>,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }
}

impl Index {
    fn insert(&mut self, path: &str, table: usize) {
        let mut node = 0;
        for segment in path.strip_prefix('/').unwrap_or(path).split('/') {
            if segment.starts_with("{*") {
                debug_assert!(self.nodes[node].rest.is_none(), "{path}");
                self.nodes[node].rest = Some(table);
                return;
            }
            let next = self.nodes.len();
            let child = if segment.starts_with('{') {
                *self.nodes[node].variable.get_or_insert(next)
            } else {
                *self.nodes[node]
                    .literals
                    .entry(segment.to_owned())
                    .or_insert(next)
            };
            if child == next {
                self.nodes.push(Node::default());
            }
            node = child;
        }
        debug_assert!(self.nodes[node].table.is_none(), "{path}");
        self.nodes[node].table = Some(table);
    }

    /// The best-ranked table `path` matches.
    fn first(&self, path: &str) -> Option<usize> {
        match self.each(path, ControlFlow::Break) {
            ControlFlow::Break(table) => Some(table),
            ControlFlow::Continue(()) => None,
        }
    }

    /// Hand `found` the tables `path` matches, best-ranked first, until it
    /// breaks with a value.
    fn each<B>(
        &self,
        path: &str,
        mut found: impl FnMut(usize) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        match path.strip_prefix('/') {
            Some(rest) => self.visit(0, Some(rest), &mut found),
            None => ControlFlow::Continue(()),
        }
    }

    /// `rest` is what follows the segments `node` stands for, `None` past the
    /// last one. As in the router, a variable takes an empty segment only
    /// before another one, and a catch-all a non-empty rest.
    fn visit<B>(
        &self,
        node: usize,
        rest: Option<&str>,
        found: &mut impl FnMut(usize) -> ControlFlow<B>,
    ) -> ControlFlow<B> {
        let node = &self.nodes[node];
        let Some(rest) = rest else {
            return node.table.map_or(ControlFlow::Continue(()), found);
        };
        let (segment, tail) = match rest.split_once('/') {
            Some((segment, tail)) => (segment, Some(tail)),
            None => (rest, None),
        };
        if let Some(&next) = node.literals.get(segment) {
            self.visit(next, tail, found)?;
        }
        if let Some(next) = node
            .variable
            .filter(|_| !segment.is_empty() || tail.is_some())
        {
            self.visit(next, tail, found)?;
        }
        match node.rest.filter(|_| !rest.is_empty()) {
            Some(table) => found(table),
            None => ControlFlow::Continue(()),
        }
    }
}

/// Every binding the router serves at one path.
pub(super) struct PathTable {
    /// The router path, written with the first binding's capture names.
    pub(super) path: String,
    /// The capture names of `path`, in path order.
    pub(super) captures: Vec<String>,
    bindings: Vec<Binding>,
    /// Whether a binding has no verb.
    plain: bool,
}

/// One binding of a [`PathTable`].
struct Binding {
    entry: RouteEntry,
    /// This binding's names for the captures of the table's path, when they
    /// differ from the path's own.
    names: Option<Vec<String>>,
    verb: Option<Verb>,
    template: Option<Template>,
    /// The positions of the captures that bind no field of their own: a bare
    /// `*` or `**`, or a segment of a [`Composite`].
    unbound: Vec<usize>,
    /// The positions of the captures of a variable matching several
    /// segments, whose `%2F` stays encoded.
    multi_segment: Vec<usize>,
    /// The fields put back together from several captures.
    composites: Vec<Composite>,
    /// The literals of those fields mounted as captures, escapes in upper
    /// case, with the index of their path segment: what that segment must
    /// equal.
    literals: Vec<(usize, String)>,
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
    /// Whether the binding answers only some of the values its router path
    /// matches: it has an escaped literal or a field template to follow.
    fn constrained(&self) -> bool {
        !self.literals.is_empty() || self.template.is_some()
    }

    /// Whether `path` (a request this binding's path matched) has the
    /// binding's literals mounted as captures, and the value of its last
    /// capture follows the binding's field template.
    fn fits(&self, path: &str) -> bool {
        // The literals come in path order: one pass over the segments.
        let mut segments = path.split('/');
        let mut next = 0;
        for (at, literal) in &self.literals {
            let segment = segments.nth(at - next);
            next = at + 1;
            if segment.is_none_or(|segment| !same_octets(segment, literal)) {
                return false;
            }
        }
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
        follows(&template.segments, Some(value).filter(|v| !v.is_empty()))
    }
}

/// A custom verb after the last capture.
struct Verb {
    /// As written in the template, `:` included, escapes in upper case:
    /// compared with the request's path as received, likewise normalized.
    raw: String,
    /// `raw` percent-decoded: what ends the decoded value of the capture.
    decoded: String,
    /// `raw` decoded as a variable over several segments is, `%2F` kept in
    /// upper case: what ends the value of such a capture, escapes' case aside.
    multi_segment: String,
    /// Whether the capture before it may be empty (`**`).
    empty_ok: bool,
}

/// What answers a request.
#[derive(Clone)]
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

/// The bytes of `text` with the hex digits of its percent-escapes in upper
/// case: the two bytes after a `%` are its digits, and only a hex digit among
/// them changes, so a malformed escape is not rewritten.
fn normalized_bytes(text: &str) -> impl Iterator<Item = u8> + '_ {
    let mut digits = 0u8;
    text.bytes().map(move |byte| {
        if digits > 0 {
            digits -= 1;
            if byte.is_ascii_hexdigit() {
                byte.to_ascii_uppercase()
            } else {
                byte
            }
        } else {
            if byte == b'%' {
                digits = 2;
            }
            byte
        }
    })
}

/// `text` with the hex digits of its percent-escapes in upper case: `%3a` and
/// `%3A` are one octet (RFC 3986 §6.2.2.1). Borrowed when nothing changes.
pub(super) fn normalize_escapes(text: &str) -> Cow<'_, str> {
    if normalized_bytes(text).eq(text.bytes()) {
        return Cow::Borrowed(text);
    }
    // Only ASCII letters change, never a byte of a multi-byte character.
    Cow::Owned(
        String::from_utf8(normalized_bytes(text).collect())
            .expect("upper-casing ASCII letters keeps UTF-8 valid"),
    )
}

/// Whether `received` is `normalized`, a text with its escapes in upper case,
/// up to the case of its own escapes: `normalize_escapes(received) ==
/// normalized`, without building the normalized text.
fn same_octets(received: &str, normalized: &str) -> bool {
    received.len() == normalized.len() && normalized_bytes(received).eq(normalized.bytes())
}

/// What a binding claims on its path: the method, the verb, the field
/// template of its last capture and the literals mounted as captures.
pub(super) struct Claim<'a> {
    pub(super) method: &'a RouteMethod,
    pub(super) verb: Option<&'a str>,
    pub(super) template: Option<&'a [String]>,
    pub(super) literals: &'a [(usize, String)],
}

/// Whether two bindings of one path cannot both serve: the same verb, field
/// template and literals, and the same method or a `custom` `*` rule, which
/// answers every method. Bindings whose templates differ answer different
/// values; where their values overlap, the earlier binding answers.
pub(super) fn clash(claim: &Claim<'_>, other: &Claim<'_>) -> bool {
    claim.verb.map(normalize_escapes) == other.verb.map(normalize_escapes)
        && normalized(claim.template) == normalized(other.template)
        && claim.literals.len() == other.literals.len()
        && claim
            .literals
            .iter()
            .zip(other.literals)
            .all(|((at, a), (other_at, b))| {
                at == other_at && normalize_escapes(a) == normalize_escapes(b)
            })
        && (claim.method == other.method
            || *claim.method == RouteMethod::Any
            || *other.method == RouteMethod::Any)
}

/// The segments of a field template with their escapes in upper case: two
/// spellings of one octet are one template.
fn normalized(template: Option<&[String]>) -> Option<Vec<Cow<'_, str>>> {
    template.map(|segments| segments.iter().map(|s| normalize_escapes(s)).collect())
}

/// `literals` with their escapes in upper case, as request segments are
/// compared with them.
fn normalized_literals(literals: &[(usize, String)]) -> Vec<(usize, String)> {
    literals
        .iter()
        .map(|(at, literal)| (*at, normalize_escapes(literal).into_owned()))
        .collect()
}

/// The positions `marked` marks.
fn positions(marked: &[bool]) -> Vec<usize> {
    marked
        .iter()
        .enumerate()
        .filter_map(|(position, &bare)| bare.then_some(position))
        .collect()
}

/// Whether the segments of `value` follow `template`: a literal itself, `*`
/// one non-empty segment, `**` any number of segments. `value` is `None` with
/// no segments left, otherwise one or more separated by `/`.
fn follows(template: &[String], value: Option<&str>) -> bool {
    match template.split_first() {
        None => value.is_none(),
        Some((first, rest)) if first == "**" => {
            // Taking none, then one segment more each time.
            let mut left = value;
            loop {
                if follows(rest, left) {
                    return true;
                }
                match left {
                    Some(segments) => left = segments.split_once('/').map(|(_, tail)| tail),
                    None => return false,
                }
            }
        }
        Some((first, rest)) => value.is_some_and(|segments| {
            let (segment, tail) = match segments.split_once('/') {
                Some((segment, tail)) => (segment, Some(tail)),
                None => (segments, None),
            };
            let fits = if first == "*" {
                !segment.is_empty()
            } else {
                same_octets(segment, first)
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
        let mut verbs: FxHashMap<String, Index> = FxHashMap::default();
        let mut plain = Index::default();
        let mut all = Index::default();
        let mut by_path =
            FxHashMap::with_capacity_and_hasher(tables.len(), rustc_hash::FxBuildHasher);
        let mut single = Vec::with_capacity(tables.len());
        for (index, table) in tables.iter().enumerate() {
            let mut alone = matchit::Router::new();
            let inserted = alone.insert(table.path.as_str(), ());
            debug_assert!(inserted.is_ok(), "{}: {inserted:?}", table.path);
            single.push(alone);
            all.insert(&table.path, index);
            by_path.insert(table.path.clone(), index);
            if table.plain {
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
            all,
            by_path,
            single,
        }
    }

    /// The table mounted at `router_path`.
    pub(super) fn table_at(&self, router_path: &str) -> Option<usize> {
        self.by_path.get(router_path).copied()
    }

    /// The table the router matches `path` to, before it routes the request:
    /// the best-ranked one among the transcoded paths.
    pub(super) fn table_of(&self, path: &str) -> Option<usize> {
        self.all.first(path)
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
    /// ranking, with an admitted binding of that method. A table whose
    /// bindings all refuse the request (a field template the value does not
    /// follow), or answer it only for other methods, leaves it to the next
    /// one the path also matches, as a transcoder matching the method first
    /// does; the best-ranked 405 stands when none answers. `None` when no
    /// table admits a binding.
    fn answer(
        &self,
        index: &Index,
        first: usize,
        method: &Method,
        path: &str,
        admits: impl Fn(&Binding) -> bool,
    ) -> Option<Choice> {
        let mut not_allowed = None;
        match self.tables[first].choose(first, method, &admits) {
            Some(choice @ Choice::MethodNotAllowed(_)) => not_allowed = Some(choice),
            Some(choice) => return Some(choice),
            None => {}
        }
        // Rare: only a refused template or method gets here. The other tables
        // this path matches follow `first`, the best-ranked one, in order.
        let answered = index.each(path, |table| {
            if table == first {
                return ControlFlow::Continue(());
            }
            match self.tables[table].choose(table, method, &admits) {
                Some(choice @ Choice::MethodNotAllowed(_)) => {
                    not_allowed.get_or_insert(choice);
                    ControlFlow::Continue(())
                }
                Some(choice) => ControlFlow::Break(choice),
                None => ControlFlow::Continue(()),
            }
        });
        match answered {
            ControlFlow::Break(choice) => Some(choice),
            ControlFlow::Continue(()) => not_allowed,
        }
    }

    /// Which binding answers `method` on `path`, a request the router matched
    /// to the table at `table`.
    ///
    /// - A path ending in a literal matched exactly: its bindings answer, as a
    ///   static route wins over a variable everywhere, unless none of them
    ///   fits (an escaped literal of a field template is a capture to the
    ///   router): then the URL is the other paths'.
    /// - A verb some table binds for this path owns the URL: only the
    ///   bindings of that verb answer it.
    /// - Otherwise the bindings without a verb answer, of the best path that
    ///   has some, the verb text being part of the last variable.
    pub(super) fn choose(&self, table: usize, method: &Method, path: &str) -> Choice {
        let plain = |binding: &Binding| binding.verb.is_none() && binding.fits(path);
        if self.tables[table].literal_end() {
            if let Some(choice) = self.tables[table].choose(table, method, plain) {
                return choice;
            }
        }
        if let Some((rest, verb)) = split_verb(path) {
            let verb = normalize_escapes(verb);
            if let Some(index) = self.verbs.get(verb.as_ref()) {
                if let Some(first) = index.first(path) {
                    let bound = |binding: &Binding| {
                        binding.verb.as_ref().is_some_and(|own| {
                            own.raw == verb && (own.empty_ok || !rest.ends_with('/'))
                        }) && binding.fits(path)
                    };
                    if let Some(choice) = self.answer(index, first, method, path, bound) {
                        return choice;
                    }
                }
            }
        }
        // The router's own table, when it has bindings without a verb, ranks
        // first among those that have: no second lookup for the common
        // request.
        let first = if self.tables[table].plain {
            table
        } else {
            match self.plain.first(path) {
                Some(first) => first,
                None => return Choice::NotFound,
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
        let unbound = positions(&mount.unbound);
        let multi_segment = positions(&mount.multi_segment);
        let literals = normalized_literals(&mount.literals);
        let MountedPath {
            axum,
            captures,
            verb,
            empty_last,
            composites,
            ..
        } = mount;
        Self {
            path: axum,
            captures,
            plain: verb.is_none(),
            bindings: vec![Binding {
                entry,
                names: None,
                verb: verb.map(|raw| Verb::new(raw, empty_last)),
                template,
                unbound,
                multi_segment,
                composites,
                literals,
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
            literals: &mount.literals,
        };
        let taken = self.bindings.iter().any(|existing| {
            let existing_claim = Claim {
                method: &existing.entry.http_method,
                verb: existing.verb.as_ref().map(|v| v.raw.as_str()),
                template: existing.template.as_ref().map(|t| t.raw.as_slice()),
                literals: &existing.literals,
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
        let unbound = positions(&mount.unbound);
        let multi_segment = positions(&mount.multi_segment);
        let literals = normalized_literals(&mount.literals);
        let names = (mount.captures != self.captures).then_some(mount.captures);
        let binding = Binding {
            entry,
            names,
            verb: mount.verb.map(|raw| Verb::new(raw, mount.empty_last)),
            template,
            unbound,
            multi_segment,
            literals,
            composites: mount.composites,
        };
        // A binding constrained by a literal or a field template answers
        // only the values it claims: it goes before the open bindings of the
        // path, which would otherwise take those values by declaration order.
        let at = if binding.constrained() {
            self.bindings
                .iter()
                .position(|existing| !existing.constrained())
                .unwrap_or(self.bindings.len())
        } else {
            self.bindings.len()
        };
        self.plain |= binding.verb.is_none();
        self.bindings.insert(at, binding);
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
        // The admitted bindings among the first 64, for the `Allow` of a 405;
        // a later one is asked again then.
        let mut admitted = 0u64;
        let mut answered = false;
        for (index, binding) in self.bindings.iter().enumerate() {
            if !answers(binding) {
                continue;
            }
            answered = true;
            if index < 64 {
                admitted |= 1 << index;
            }
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
            None if answered => Some(Choice::MethodNotAllowed(self.allow(|index| {
                if index < 64 {
                    admitted & (1 << index) != 0
                } else {
                    answers(&self.bindings[index])
                }
            }))),
            None => None,
        }
    }

    /// The methods of the bindings at the indexes `admitted` takes, in
    /// binding order, with HEAD after them when a GET binding answers it.
    fn allow(&self, admitted: impl Fn(usize) -> bool) -> HeaderValue {
        let mut value = String::new();
        let (mut get, mut head) = (false, false);
        for (index, binding) in self.bindings.iter().enumerate() {
            if !admitted(index) {
                continue;
            }
            let method = binding.entry.http_method.as_str();
            let listed = self.bindings[..index]
                .iter()
                .enumerate()
                .any(|(earlier, b)| b.entry.http_method.as_str() == method && admitted(earlier));
            if listed {
                continue;
            }
            if !value.is_empty() {
                value.push_str(", ");
            }
            value.push_str(method);
            get |= method == "GET";
            head |= method == "HEAD";
        }
        if get && !head {
            value.push_str(", HEAD");
        }
        // Taken as it is, not copied.
        HeaderValue::try_from(value).expect("method tokens are valid header value characters")
    }

    /// The positions of the binding at `index`'s captures that keep `%2F`
    /// encoded: decoded from the request's path by the transcoder, since the
    /// router decodes every escape.
    pub(super) fn multi_segment(&self, index: usize) -> &[usize] {
        &self.bindings[index].multi_segment
    }

    /// Turn the path parameters matched on this table's path into those of
    /// the binding at `index`: its verb taken off the last capture, and the
    /// captures under its own names. A parameter the table's path does not
    /// capture (a prefix the router is nested under) is left as it is.
    pub(super) fn bind_params<'p>(&'p self, index: usize, params: &mut PathParams<'p>) {
        let binding = &self.bindings[index];
        let value_of =
            |params: &PathParams<'p>, name: &str| params.iter().position(|(own, _)| *own == name);
        if let (Some(verb), Some(last)) = (&binding.verb, self.captures.last()) {
            // The verb comes off decoded as the capture was; a kept `%2F` may
            // be spelled in either case.
            let multi = binding.multi_segment.contains(&(self.captures.len() - 1));
            if let Some(at) = value_of(params, last) {
                let value = &mut params[at].1;
                let len = if multi {
                    let suffix = verb.multi_segment.len();
                    value.len().checked_sub(suffix).filter(|&start| {
                        value
                            .get(start..)
                            .is_some_and(|tail| same_octets(tail, &verb.multi_segment))
                    })
                } else {
                    value.strip_suffix(verb.decoded.as_str()).map(str::len)
                };
                match (len, value) {
                    (Some(len), Cow::Borrowed(value)) => *value = &value[..len],
                    (Some(len), Cow::Owned(value)) => value.truncate(len),
                    (None, _) => {}
                }
            }
        }
        let matched = params.len();
        // A field spelled out over several segments, put back together from
        // them before they go, after the captures.
        for composite in &binding.composites {
            let mut value = String::new();
            for (at, part) in composite.parts.iter().enumerate() {
                if at > 0 {
                    value.push('/');
                }
                value.push_str(match part {
                    Part::Literal(literal) => literal,
                    Part::Capture(position) => {
                        value_of(params, &self.captures[*position]).map_or("", |at| &params[at].1)
                    }
                });
            }
            params.push((composite.field.as_str(), Cow::Owned(value)));
        }
        // Each capture of the table's path takes the binding's name for it, in
        // place: names are compared before any changes, so one binding's name,
        // or a composite's field, may be another capture's name on that path.
        // A bare wildcard, or a part of a composite, was named for the router
        // only and goes. Kept parameters keep their order.
        let mut kept = 0;
        for at in 0..matched {
            let name = params[at].0;
            let keep = match self.captures.iter().position(|capture| capture == name) {
                // A prefix the router is nested under.
                None => true,
                Some(position) if binding.unbound.contains(&position) => false,
                Some(position) => {
                    params[at].0 = binding
                        .names
                        .as_ref()
                        .map_or(&self.captures[position], |names| &names[position])
                        .as_str();
                    true
                }
            };
            if keep {
                params.swap(kept, at);
                kept += 1;
            }
        }
        params.drain(kept..matched);
    }
}

impl Verb {
    fn new(raw: String, empty_ok: bool) -> Self {
        let decoded = percent_encoding::percent_decode_str(&raw)
            .decode_utf8_lossy()
            .into_owned();
        let multi_segment =
            normalize_escapes(&String::from_utf8_lossy(&decode_multi_segment(&raw))).into_owned();
        Self {
            raw: normalize_escapes(&raw).into_owned(),
            decoded,
            multi_segment,
            empty_ok,
        }
    }
}

#[cfg(test)]
mod tests;
