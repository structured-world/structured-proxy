//! `google.api.http` rule parsing: the HTTP method and path template of every
//! binding of an RPC, with its `body` and `response_body` settings. The
//! transcoded routes and the OpenAPI document both read bindings from here, so
//! the two cannot disagree on what an RPC is mounted at.

use axum::http::Method;
use prost_reflect::{DynamicMessage, ExtensionDescriptor, MethodDescriptor, Value};

use super::request::BodyMapping;

/// The HTTP method a binding answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteMethod {
    /// One method: a standard pattern, or a `custom` rule naming any token.
    One(Method),
    /// Every method: a `custom` rule with `kind: "*"`.
    Any,
}

impl RouteMethod {
    /// The method token, or `*` for [`RouteMethod::Any`].
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self::One(method) => method.as_str(),
            Self::Any => "*",
        }
    }
}

/// One HTTP binding of an RPC.
#[derive(Debug, Clone)]
pub(crate) struct HttpBinding {
    pub(crate) method: RouteMethod,
    /// Path template, as written in the rule.
    pub(crate) path: String,
    pub(crate) body: BodyMapping,
    /// `response_body`, when set.
    pub(crate) response_body: Option<String>,
}

/// Every binding of `method`: its `google.api.http` rule plus the rule's
/// `additional_bindings`, in that order. Empty when the RPC has no rule.
pub(crate) fn http_bindings(
    method: &MethodDescriptor,
    http_ext: &ExtensionDescriptor,
) -> Vec<HttpBinding> {
    let options = method.options();
    if !options.has_extension(http_ext) {
        return Vec::new();
    }
    match options.get_extension(http_ext).as_ref() {
        Value::Message(rule) => collect_bindings(rule),
        _ => Vec::new(),
    }
}

/// The binding of an `HttpRule` message plus every `additional_bindings` entry.
pub(crate) fn collect_bindings(rule: &DynamicMessage) -> Vec<HttpBinding> {
    let mut bindings = Vec::new();
    bindings.extend(parse_http_rule(rule));

    // additional_bindings is a repeated HttpRule; each carries its own
    // pattern, body and response_body. The proto forbids nesting them further.
    if let Some(field) = rule.get_field_by_name("additional_bindings") {
        if let Value::List(list) = field.as_ref() {
            for item in list {
                if let Value::Message(sub) = item {
                    bindings.extend(parse_http_rule(sub));
                }
            }
        }
    }

    bindings
}

/// The binding one `HttpRule` describes, or `None` when it sets no pattern (or
/// an unusable `custom` one).
fn parse_http_rule(rule: &DynamicMessage) -> Option<HttpBinding> {
    let (method, path) = standard_pattern(rule).or_else(|| custom_pattern(rule))?;
    let body = string_field(rule, "body")
        .map(|body| BodyMapping::parse(&body))
        .unwrap_or(BodyMapping::None);
    Some(HttpBinding {
        method,
        path,
        body,
        response_body: string_field(rule, "response_body"),
    })
}

/// The `get` / `put` / `post` / `delete` / `patch` member of the `pattern`
/// oneof, when one is set.
fn standard_pattern(rule: &DynamicMessage) -> Option<(RouteMethod, String)> {
    [
        ("get", Method::GET),
        ("put", Method::PUT),
        ("post", Method::POST),
        ("delete", Method::DELETE),
        ("patch", Method::PATCH),
    ]
    .into_iter()
    .find_map(|(name, method)| Some((RouteMethod::One(method), string_field(rule, name)?)))
}

/// The `custom` member of the `pattern` oneof (`CustomHttpPattern {kind,
/// path}`). `google/api/http.proto` defines `kind: "*"` as "every method"; any
/// other kind is the method token itself, case-sensitive (RFC 9110 §9.1), so
/// `"head"` is an extension method, not `HEAD`.
fn custom_pattern(rule: &DynamicMessage) -> Option<(RouteMethod, String)> {
    let custom = rule.get_field_by_name("custom")?;
    let Value::Message(custom) = custom.as_ref() else {
        return None;
    };
    let kind = string_field(custom, "kind")?;
    let path = string_field(custom, "path")?;
    let method = if kind == "*" {
        RouteMethod::Any
    } else {
        match Method::from_bytes(kind.as_bytes()) {
            Ok(method) => RouteMethod::One(method),
            Err(_) => {
                tracing::warn!(%kind, %path, "custom HTTP rule kind is not a method token; skipping it");
                return None;
            }
        }
    };
    Some((method, path))
}

/// A string field of `msg` that is present and non-empty.
fn string_field(msg: &DynamicMessage, name: &str) -> Option<String> {
    match msg.get_field_by_name(name)?.as_ref() {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
