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
    /// For each capture, whether it stands for a bare `*` or `**`: the router
    /// needs a name for it, but it binds no field (google/api/http.proto).
    pub(crate) unbound: Vec<bool>,
    /// For each capture, whether it is (part of) a variable matching several
    /// segments, whose value keeps `%2F` encoded (google/api/http.proto).
    pub(crate) multi_segment: Vec<bool>,
    /// The custom verb after the last segment's variable, `:` included.
    pub(crate) verb: Option<String>,
    /// Whether the last capture may be empty: a `**` matches zero or more
    /// segments (google/api/http.proto), any other variable at least one.
    pub(crate) empty_last: bool,
    /// The field template of the last capture when the router cannot hold it
    /// (`{name=shelves/*/books/*}` mounted as a catch-all): its segments, which
    /// the matched value must follow.
    pub(crate) last_template: Option<Vec<String>>,
    /// The index of the last segment, the one the last capture starts at.
    pub(crate) last_segment: usize,
    /// Why the router cannot hold this template faithfully, when it cannot.
    pub(crate) unsupported: Option<String>,
    /// The fields bound to a multi-segment template before the last segment,
    /// spelled out in the path: each is put back together from its parts.
    pub(crate) composites: Vec<Composite>,
    /// The literals of those templates that hold a percent-escape, as
    /// written, with the index of their path segment. The router compares a
    /// literal byte for byte, while `%3a` and `%3A` are one octet (RFC 3986
    /// §6.2.2.1), so such a segment is mounted as a capture and compared by
    /// the transcoded routes.
    pub(crate) literals: Vec<(usize, String)>,
}

/// A field whose template (`{parent=publishers/*}`) the path spells out
/// segment by segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Composite {
    pub(crate) field: String,
    pub(crate) parts: Vec<Part>,
}

/// One segment of a [`Composite`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Part {
    /// A literal of the template without a percent-escape.
    Literal(String),
    /// A `*` of the template, or a literal with a percent-escape: the capture
    /// at this position of the path.
    Capture(usize),
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
        let mut unbound = Vec::new();
        let mut multi_segment = Vec::new();
        let mut composites = Vec::new();
        let mut literals = Vec::new();
        let mut unsupported = None;
        // Segments written so far: the last capture starts at this index.
        let mut written = 0;
        let empty_last = is_double_wildcard(segments[last]);
        let last_template = field_template(segments[last])
            .filter(|template| *template != "*" && *template != "**")
            .map(|template| {
                split_top_level(template)
                    .into_iter()
                    .map(str::to_owned)
                    .collect()
            });
        let mut last_segment = 0;
        for (idx, segment) in segments.iter().enumerate() {
            if idx == last {
                last_segment = written;
            }
            let mut push_segment = |axum: &mut String, shape: &mut String| {
                if written > 0 {
                    axum.push('/');
                    shape.push('/');
                }
                written += 1;
            };
            // A multi-segment template before the last segment: the router
            // holds no capture across segments there, so its segments are
            // written out; `**` among them has no such form.
            if field_template(segment).is_some_and(|template| template.contains(['{', '}'])) {
                unsupported = Some(format!(
                    "`{segment}` nests a variable in a field template, which holds none"
                ));
            }
            // `**` must be the last part of the path (google/api/http.proto);
            // anywhere else it would also make matching try every split.
            if idx == last
                && field_template(segment)
                    .is_some_and(|template| template.split('/').rev().skip(1).any(|p| p == "**"))
            {
                unsupported = Some(format!(
                    "`{segment}` puts `**` before another segment; it must be the last one"
                ));
            }
            let inner = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}'));
            if let Some((field, template)) = inner
                .and_then(|inner| inner.split_once('='))
                .filter(|(_, template)| idx != last && *template != "*")
            {
                if template.split('/').any(|part| part == "**") {
                    unsupported = Some(format!(
                        "`**` in `{segment}` before the last segment matches any number of \
                         segments, which the router cannot hold there"
                    ));
                } else {
                    // A template of one segment (`{name=foo}`) is a variable of
                    // one segment, decoded in full.
                    let multi = template.contains('/');
                    let mut parts = Vec::new();
                    for (k, part) in template.split('/').enumerate() {
                        push_segment(&mut axum, &mut shape);
                        // An escaped literal is a capture to the router, so its
                        // case does not matter (RFC 3986 §6.2.2.1); like any
                        // capture, it cannot share its position with a
                        // catch-all, which the router then refuses.
                        let escaped = part.contains('%');
                        if part == "*" || escaped {
                            let name = format!("{field}.{k}");
                            axum.push('{');
                            axum.push_str(&name);
                            axum.push('}');
                            shape.push_str("{}");
                            captures.push(name);
                            unbound.push(true);
                            multi_segment.push(multi);
                        } else {
                            axum.push_str(part);
                            shape.push_str(part);
                        }
                        if escaped {
                            // The index of this segment: one per `/` before it.
                            let at = axum.bytes().filter(|&b| b == b'/').count();
                            literals.push((at, part.to_owned()));
                        }
                        // An escaped literal is taken from the request, decoded
                        // as the variable is: a kept `%2F` keeps its case there.
                        parts.push(if part == "*" || escaped {
                            Part::Capture(captures.len() - 1)
                        } else {
                            Part::Literal(part.to_owned())
                        });
                    }
                    composites.push(Composite {
                        field: field.to_owned(),
                        parts,
                    });
                    continue;
                }
            } else if idx != last && is_double_wildcard(segment) {
                unsupported = Some(format!(
                    "`{segment}` before the last segment matches any number of segments, \
                     which the router cannot hold there"
                ));
            }
            push_segment(&mut axum, &mut shape);
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
                    unbound.push(*segment == "*" || *segment == "**");
                    // A catch-all may hold a template of one segment; what
                    // counts is the template.
                    multi_segment.push(catch_all && spans_segments(segment));
                }
            }
        }
        Self {
            axum,
            shape,
            captures,
            unbound,
            multi_segment,
            verb: verb.map(str::to_owned),
            empty_last,
            last_template,
            last_segment,
            unsupported,
            composites,
            literals,
        }
    }

    /// Whether the router can serve this template as written: a template it
    /// cannot hold faithfully, or a path axum would refuse, is not served.
    pub(crate) fn routable(&self) -> Result<(), String> {
        match &self.unsupported {
            Some(reason) => Err(reason.clone()),
            None => mountable(&self.axum),
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
/// - bare `*` segment            -> `{N}`, N its segment index
/// - bare `**` segment           -> `{*N}` (axum catch-all)
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
    // A variable is a whole segment (google/api/http.proto `Segment`), checked
    // here rather than left to the router, which may accept text around one.
    let mut captures = 0usize;
    for segment in axum_path.split('/') {
        let Some(at) = segment.find(['{', '}']) else {
            continue;
        };
        let inner = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}'));
        if at != 0 || inner.is_none_or(|inner| inner.contains(['{', '}'])) {
            return Err(format!("`{segment}` is not a whole-segment variable"));
        }
        if !segment.starts_with("{*") {
            captures += 1;
        }
    }
    // The router renames captures `a` to `z` and panics on a 26th (catch-alls
    // are not renamed).
    if captures > 25 {
        return Err(format!(
            "{captures} variables; the router holds at most 25 before the last"
        ));
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

/// `raw` percent-decoded as the value of a variable matching several segments
/// is: every escape but `%2F` and `%2f`, which stay as written
/// (google/api/http.proto). Borrowed when there is nothing to decode.
pub(crate) fn decode_multi_segment(raw: &str) -> Cow<'_, [u8]> {
    let is_slash =
        |escape: &[u8]| escape[0] == b'%' && escape[1] == b'2' && escape[2] | 0x20 == b'f';
    let bytes = raw.as_bytes();
    if !bytes.windows(3).any(is_slash) {
        return percent_encoding::percent_decode(bytes).into();
    }
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut rest = bytes;
    while let Some(at) = rest.windows(3).position(is_slash) {
        decoded.extend(percent_encoding::percent_decode(&rest[..at]));
        decoded.extend_from_slice(&rest[at..at + 3]);
        rest = &rest[at + 3..];
    }
    decoded.extend(percent_encoding::percent_decode(rest));
    Cow::Owned(decoded)
}

/// Whether `segment` is a variable over several segments: `**`, or a field
/// template with more than one segment or a `**`.
fn spans_segments(segment: &str) -> bool {
    segment == "**"
        || field_template(segment)
            .is_some_and(|template| template.contains('/') || template == "**")
}

/// Whether `segment` is `**` or a variable bound to it (`{name=**}`).
fn is_double_wildcard(segment: &str) -> bool {
    segment == "**" || field_template(segment) == Some("**")
}

/// The template a variable segment binds its field to: `shelves/*` of
/// `{name=shelves/*}`, none for a plain `{name}` or a literal.
fn field_template(segment: &str) -> Option<&str> {
    segment
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .and_then(|inner| inner.split_once('='))
        .map(|(_, template)| template)
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
                // have no axum form: axum cannot bind literal segments into one
                // capture. The last segment is mounted as a catch-all and the
                // transcoded routes check the value against the template; in
                // any other position it degrades to one segment, which the
                // template cannot match, so that is warned about.
                _ => catch_all(name, is_last),
            };
        }
        // Plain `{name}` is already valid axum 0.8 syntax.
        return capture(inner, false);
    }

    // Bare wildcards: named by position, so they never collide with each
    // other, and starting with a digit, so never with a field path (whose
    // names are identifiers) or a spelled-out template's `{field}.{k}`.
    match segment {
        "**" => catch_all(&idx.to_string(), is_last),
        "*" => capture(&idx.to_string(), false),
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
