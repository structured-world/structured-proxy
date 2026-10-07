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

use std::collections::HashMap;

use axum::http::{HeaderValue, Method};

use super::path::MountedPath;
use super::rule::RouteMethod;
use super::{PathParams, RouteEntry};

/// Every transcoded route, and where each custom verb is bound.
pub(super) struct Routes {
    pub(super) tables: Vec<PathTable>,
    /// For each verb, the paths of the tables binding it. The router matches a
    /// request to one path whatever its verb, while the verb may be bound on
    /// a path of another shape the request also matches.
    verbs: HashMap<String, matchit::Router<usize>>,
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
}

/// A custom verb after the last capture.
struct Verb {
    /// As written in the template, `:` included: compared with the request's
    /// path as received.
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

/// Whether two bindings of one path cannot both serve: the same verb and the
/// same method, or the same verb and a `custom` `*` rule, which answers every
/// method.
pub(super) fn clash(
    method: &RouteMethod,
    verb: Option<&str>,
    other_method: &RouteMethod,
    other_verb: Option<&str>,
) -> bool {
    verb == other_verb
        && (method == other_method
            || *method == RouteMethod::Any
            || *other_method == RouteMethod::Any)
}

impl Routes {
    /// The routes of `tables`, with their verbs indexed. Every path was
    /// already accepted by a router holding them all, so a router holding
    /// some of them accepts it too.
    pub(super) fn new(tables: Vec<PathTable>) -> Self {
        let mut verbs: HashMap<String, matchit::Router<usize>> = HashMap::new();
        for (index, table) in tables.iter().enumerate() {
            let mut seen: Vec<&str> = Vec::new();
            for verb in table.bindings.iter().filter_map(|b| b.verb.as_ref()) {
                if seen.contains(&verb.raw.as_str()) {
                    continue;
                }
                seen.push(&verb.raw);
                let inserted = verbs
                    .entry(verb.raw.clone())
                    .or_default()
                    .insert(table.path.as_str(), index);
                debug_assert!(inserted.is_ok(), "{}: {inserted:?}", table.path);
            }
        }
        Self { tables, verbs }
    }

    /// The table binding the verb `path` ends in, when one of the request's
    /// path does: its index and the router's match, whose captures are that
    /// table's.
    pub(super) fn verb_match<'r, 'p>(
        &'r self,
        path: &'p str,
    ) -> Option<matchit::Match<'r, 'p, &'r usize>> {
        let (_, verb) = split_verb(path)?;
        self.verbs.get(verb)?.at(path).ok()
    }

    /// Which binding answers `method` on `path`, a request the router matched
    /// to the table at `table`. A verb some table binds for this path owns the
    /// URL: only the bindings of that verb answer it. Otherwise the bindings
    /// without a verb of `table` do, the verb text being part of the last
    /// variable.
    pub(super) fn choose(&self, table: usize, method: &Method, path: &str) -> Choice {
        if let Some((rest, verb)) = split_verb(path) {
            if let Some(found) = self.verb_match(path) {
                let index = *found.value;
                let bound = |binding: &Binding| {
                    binding.verb.as_ref().is_some_and(|own| {
                        own.raw == verb && (own.empty_ok || !rest.ends_with('/'))
                    })
                };
                if let Some(choice) = self.tables[index].choose(index, method, bound) {
                    return choice;
                }
            }
        }
        self.tables[table]
            .choose(table, method, |binding| binding.verb.is_none())
            .unwrap_or(Choice::NotFound)
    }
}

impl PathTable {
    /// A table for `mount`, served first by `entry`.
    pub(super) fn new(mount: MountedPath, entry: RouteEntry) -> Self {
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
            }],
        }
    }

    /// Add `entry` mounted at `mount`, a path of this table's shape, unless it
    /// [`clash`]es with a binding already there.
    pub(super) fn add(&mut self, mount: MountedPath, entry: RouteEntry) {
        let taken = self.bindings.iter().any(|existing| {
            clash(
                &existing.entry.http_method,
                existing.verb.as_ref().map(|v| v.raw.as_str()),
                &entry.http_method,
                mount.verb.as_deref(),
            )
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
        let names = (mount.captures != self.captures).then_some(mount.captures);
        self.bindings.push(Binding {
            entry,
            names,
            verb: mount.verb.map(|raw| Verb::new(raw, mount.empty_last)),
        });
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
            raw,
            decoded,
            empty_ok,
        }
    }
}
