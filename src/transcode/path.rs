//! `google.api.http` path templates in the form the router mounts them.
//!
//! The template grammar (google/api/http.proto) is
//! `Template = "/" Segments [ Verb ]` with `Verb = ":" LITERAL`. axum (matchit)
//! matches a literal after a variable in no segment, so a verb that follows a
//! variable or a wildcard is split off here and matched by the transcoded
//! router itself; a verb after a literal stays part of that literal.

use std::borrow::Cow;

/// Where one binding is mounted.
#[derive(Debug, Clone)]
pub(crate) struct MountedPath {
    /// The axum path (`/v1/{name}`), without a verb that follows a variable.
    pub(crate) axum: String,
    /// `axum` with every capture unnamed: the bindings that share it share one
    /// route, since the router tells their paths apart by shape only.
    pub(crate) shape: String,
    /// The capture names of `axum`, in path order.
    pub(crate) captures: Vec<String>,
    /// The custom verb after the last segment's variable, `:` included.
    pub(crate) verb: Option<String>,
    /// Whether the last capture may be empty: a `**` matches zero or more
    /// segments (google/api/http.proto), any other variable at least one.
    pub(crate) empty_last: bool,
}

impl MountedPath {
    /// Mount `template`, a `google.api.http` path template.
    pub(crate) fn new(template: &str) -> Self {
        let (base, verb) = split_verb(template);
        let segments = split_top_level(base);
        let last = segments.len() - 1;
        let mut axum = String::with_capacity(base.len());
        let mut shape = String::with_capacity(base.len());
        let mut captures = Vec::new();
        let empty_last = is_double_wildcard(segments[last]);
        for (idx, segment) in segments.iter().enumerate() {
            if idx > 0 {
                axum.push('/');
                shape.push('/');
            }
            match convert_segment(segment, idx, idx == last) {
                Segment::Literal(literal) => {
                    axum.push_str(literal);
                    shape.push_str(literal);
                }
                Segment::Capture { name, catch_all } => {
                    let open = if catch_all { "{*" } else { "{" };
                    axum.push_str(open);
                    axum.push_str(&name);
                    axum.push('}');
                    shape.push_str(open);
                    shape.push('}');
                    captures.push(name);
                }
            }
        }
        Self {
            axum,
            shape,
            captures,
            verb: verb.map(str::to_owned),
            empty_last,
        }
    }

    /// The route as written, verb included: what route policies match and
    /// what the log names.
    pub(crate) fn display(&self) -> Cow<'_, str> {
        match &self.verb {
            None => Cow::Borrowed(&self.axum),
            Some(verb) => Cow::Owned(format!("{}{verb}", self.axum)),
        }
    }
}

/// Convert a `google.api.http` path template to axum 0.8 path syntax.
///
/// The proto `{param}` form IS axum 0.8's native capture syntax, so plain
/// single-segment params pass through verbatim. Only field-path templates and
/// bare wildcards need rewriting (axum 0.7 used `:param`; 0.8 uses `{param}`
/// and rejects any segment starting with `:`):
/// - `{name=*}`  (single segment)      -> `{name}`
/// - `{name=**}` (multi-segment) -> `{*name}` (axum catch-all)
/// - bare `*` segment            -> `{wildcardN}`
/// - bare `**` segment           -> `{*wildcardN}` (axum catch-all)
///
/// A custom verb after a variable or wildcard (`{name}:cancel`) is not part of
/// the result: axum cannot match it, so the transcoded router checks it
/// itself. A verb after a literal (`/v1/nodes:batch`) stays in that literal.
pub fn proto_path_to_axum(path: &str) -> String {
    MountedPath::new(path).axum
}

/// Whether axum can register `axum_path` on its own: what `Router::route`
/// checks before it inserts, then the insertion into an empty matchit router,
/// the router axum matches with. A path that fails would panic at
/// `Router::route`. Conflicts between paths are a separate check.
pub(crate) fn mountable(axum_path: &str) -> Result<(), String> {
    if !axum_path.starts_with('/') {
        return Err("a path template must start with '/'".to_string());
    }
    if axum_path
        .split('/')
        .any(|segment| segment.starts_with(':') || segment.starts_with('*'))
    {
        return Err("a path segment must not start with ':' or '*'".to_string());
    }
    matchit::Router::new()
        .insert(axum_path, ())
        .map_err(|e| e.to_string())
}

/// Split the custom verb off `template` when its last segment is a variable
/// or a wildcard: `/v1/{name}:cancel` is `/v1/{name}` and `:cancel`. An empty
/// verb is not one (`Verb = ":" LITERAL`), and anything else after a variable
/// stays in the template for the router to reject.
fn split_verb(template: &str) -> (&str, Option<&str>) {
    let segments = split_top_level(template);
    let last = segments[segments.len() - 1];
    let start = template.len() - last.len();
    let colon = if last.starts_with('{') {
        closing_brace(last).map(|close| close + 1)
    } else if last.starts_with("**") {
        Some(2)
    } else if last.starts_with('*') {
        Some(1)
    } else {
        None
    };
    match colon {
        Some(colon) if last[colon..].starts_with(':') && last.len() > colon + 1 => {
            let at = start + colon;
            (&template[..at], Some(&template[at..]))
        }
        _ => (template, None),
    }
}

/// Whether `segment` is `**` or a variable bound to it (`{name=**}`).
fn is_double_wildcard(segment: &str) -> bool {
    segment == "**"
        || segment
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .and_then(|inner| inner.split_once('='))
            .is_some_and(|(_, template)| template == "**")
}

/// The index of the `}` closing the `{` that opens `segment`.
fn closing_brace(segment: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (i, ch) in segment.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Split a path on `/` boundaries that are NOT inside a `{...}` brace span.
///
/// google.api.http field templates can embed slashes inside a single capture
/// (e.g. the AIP-127 resource name `{name=shelves/*/books/*}`), so a naive
/// `str::split('/')` would fracture the brace span into invalid fragments.
/// Tracking brace depth keeps each capture intact. Never empty.
fn split_top_level(path: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;

    for (i, ch) in path.char_indices() {
        match ch {
            '{' => depth += 1,
            // Decrement only on a matched brace; a stray `}` (malformed input)
            // is treated as a literal rather than driving depth negative.
            '}' if depth > 0 => depth -= 1,
            '/' if depth == 0 => {
                segments.push(&path[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    segments.push(&path[start..]);
    segments
}

/// One top-level path segment in axum form.
enum Segment<'a> {
    Literal(&'a str),
    Capture { name: String, catch_all: bool },
}

/// Convert a single top-level path segment from proto template to axum 0.8 form.
///
/// `is_last` indicates the terminal segment: axum permits a catch-all capture
/// (`{*name}`) only there, so catch-alls in any other position must degrade.
fn convert_segment(segment: &str, idx: usize, is_last: bool) -> Segment<'_> {
    if let Some(inner) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        // Brace capture, possibly with a `name=template` field path.
        if let Some((name, template)) = inner.split_once('=') {
            return match template {
                // Single-segment field path collapses to a plain capture.
                "*" => capture(name, false),
                // Multi-segment catch-all maps to axum's `{*name}` (terminal only).
                "**" => catch_all(name, is_last),
                // Templates with interspersed literals (`{name=shelves/*/books/*}`)
                // have no faithful axum form: axum cannot bind literal segments
                // into one capture. Collapse to a catch-all so routing stays
                // deterministic and the field still binds to the matched tail,
                // and warn so the limitation surfaces instead of mis-routing.
                _ => {
                    tracing::warn!(
                        template = %inner,
                        "google.api.http multi-segment field template is not fully \
                         supported; routing it as a catch-all capture"
                    );
                    catch_all(name, is_last)
                }
            };
        }
        // Plain `{name}` is already valid axum 0.8 syntax.
        return capture(inner, false);
    }

    // Bare wildcards: name them by position so multiple wildcards never collide.
    match segment {
        "**" => catch_all(&format!("wildcard{idx}"), is_last),
        "*" => capture(&format!("wildcard{idx}"), false),
        literal => Segment::Literal(literal),
    }
}

fn capture(name: &str, catch_all: bool) -> Segment<'static> {
    Segment::Capture {
        name: name.to_owned(),
        catch_all,
    }
}

/// A catch-all capture when `is_last`, else a single-segment one.
///
/// axum accepts a catch-all only in the final path segment; a mid-path
/// `{*name}` is rejected at `Router::route()`. A non-terminal catch-all comes
/// from a malformed or unsupported google.api.http template, so we degrade
/// (capturing one segment) and warn rather than panic the whole router.
fn catch_all(name: &str, is_last: bool) -> Segment<'static> {
    if !is_last {
        tracing::warn!(
            capture = %name,
            "catch-all in a non-terminal path segment is unrepresentable in axum; \
             degrading to a single-segment capture"
        );
    }
    capture(name, is_last)
}
