//! The bindings mounted at one router path, and the choice among them for a
//! request: by its method and by the custom verb its path ends in.

use axum::http::{HeaderValue, Method};

use super::path::MountedPath;
use super::rule::RouteMethod;
use super::{PathParams, RouteEntry};

/// Every binding the router serves at one path.
pub(super) struct PathTable {
    /// The router path, written with the first binding's capture names.
    pub(super) path: String,
    /// The capture names of `path`, in path order.
    captures: Vec<String>,
    bindings: Vec<Binding>,
}

/// One binding of a [`PathTable`].
struct Binding {
    entry: RouteEntry,
    /// This binding's names for the captures of the table's path, when they
    /// differ from the path's own.
    names: Option<Vec<String>>,
    /// The custom verb after the last capture, `:` included.
    verb: Option<String>,
}

/// What answers a request on a table's path.
pub(super) enum Choice {
    /// The binding at this index.
    Route(usize),
    /// Bindings answer the URL, none with the request's method: the value of
    /// `Allow` lists their methods (RFC 9110 §15.5.6).
    MethodNotAllowed(HeaderValue),
    /// No binding answers the URL: its verb is none of theirs.
    NotFound,
}

impl Binding {
    /// Whether this binding answers a request for `path` (as received, still
    /// percent-encoded): with a verb, only a path whose last segment ends in
    /// it after at least one character of the variable. An encoded colon
    /// (`%3A`) is data, never the verb's delimiter (RFC 3986 §2.2).
    fn answers(&self, path: &str) -> bool {
        match &self.verb {
            None => true,
            Some(verb) => path
                .strip_suffix(verb.as_str())
                .is_some_and(|rest| !rest.is_empty() && !rest.ends_with('/')),
        }
    }

    fn verb_len(&self) -> usize {
        self.verb.as_ref().map_or(0, String::len)
    }
}

impl PathTable {
    /// A table for `mount`, served first by `entry`.
    pub(super) fn new(mount: MountedPath, entry: RouteEntry) -> Self {
        let MountedPath {
            axum,
            captures,
            verb,
            ..
        } = mount;
        Self {
            path: axum,
            captures,
            bindings: vec![Binding {
                entry,
                names: None,
                verb,
            }],
        }
    }

    /// Add `entry` mounted at `mount`, a path of this table's shape, unless a
    /// binding with its verb already answers its method (a `custom` `*` rule
    /// answers every one).
    pub(super) fn add(&mut self, mount: MountedPath, entry: RouteEntry) {
        let taken = self.bindings.iter().any(|existing| {
            existing.verb == mount.verb
                && (existing.entry.http_method == entry.http_method
                    || existing.entry.http_method == RouteMethod::Any
                    || entry.http_method == RouteMethod::Any)
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
            verb: mount.verb,
        });
    }

    /// The route entry of the binding at `index`.
    pub(super) fn entry(&self, index: usize) -> &RouteEntry {
        &self.bindings[index].entry
    }

    /// Which binding answers `method` on `path`. Among the bindings whose
    /// verb the path ends in, the longest verb wins, so a binding without one
    /// takes only what no verb claims; within that, the request's own method
    /// (or a `*` rule) before a GET binding answering HEAD.
    pub(super) fn choose(&self, method: &Method, path: &str) -> Choice {
        // (index, verb length, own method) of the best binding so far.
        let mut best: Option<(usize, usize, bool)> = None;
        let mut answered = false;
        for (index, binding) in self.bindings.iter().enumerate() {
            if !binding.answers(path) {
                continue;
            }
            answered = true;
            let own = match &binding.entry.http_method {
                RouteMethod::Any => true,
                RouteMethod::One(bound) if bound == method => true,
                // A GET binding answers HEAD too.
                RouteMethod::One(bound) if *bound == Method::GET && *method == Method::HEAD => {
                    false
                }
                RouteMethod::One(_) => continue,
            };
            let rank = (binding.verb_len(), own);
            if best.is_none_or(|(_, len, best_own)| (len, best_own) < rank) {
                best = Some((index, rank.0, rank.1));
            }
        }
        match best {
            Some((index, ..)) => Choice::Route(index),
            None if answered => Choice::MethodNotAllowed(self.allow(path)),
            None => Choice::NotFound,
        }
    }

    /// The methods of the bindings answering `path`, in binding order, with
    /// HEAD after them when a GET binding answers it.
    fn allow(&self, path: &str) -> HeaderValue {
        let mut methods: Vec<&str> = Vec::new();
        for binding in self.bindings.iter().filter(|b| b.answers(path)) {
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

    /// Turn the path parameters the router matched on this table's path into
    /// those of the binding at `index`: its verb taken off the last capture,
    /// and the captures under its own names. A parameter the table's path does
    /// not capture (a prefix the router is nested under) is left as it is.
    pub(super) fn bind_params(&self, index: usize, params: &mut PathParams) {
        let binding = &self.bindings[index];
        if let (Some(verb), Some(last)) = (&binding.verb, self.captures.last()) {
            if let Some(value) = params.get_mut(last) {
                // The verb ends the raw path and holds no escape, so the
                // decoded value ends in it too.
                if let Some(len) = value.strip_suffix(verb.as_str()).map(str::len) {
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
