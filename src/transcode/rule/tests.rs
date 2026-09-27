use super::*;
use prost_reflect::DescriptorPool;

/// A standalone `HttpRule`-shaped descriptor (self-referential
/// `additional_bindings`, a `CustomHttpPattern` for `custom`) so the binding
/// parser can be tested without the google.api extension wiring.
fn http_rule_descriptor() -> prost_reflect::MessageDescriptor {
    use prost_reflect::prost::Message;
    use prost_reflect::prost_types::{
        field_descriptor_proto::{Label, Type},
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    let str_field = |name: &str, num: i32| FieldDescriptorProto {
        name: Some(name.to_string()),
        number: Some(num),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::String as i32),
        ..Default::default()
    };
    let message_field =
        |name: &str, num: i32, label: Label, type_name: &str| FieldDescriptorProto {
            name: Some(name.to_string()),
            number: Some(num),
            label: Some(label as i32),
            r#type: Some(Type::Message as i32),
            type_name: Some(type_name.to_string()),
            ..Default::default()
        };
    let custom = DescriptorProto {
        name: Some("CustomHttpPattern".to_string()),
        field: vec![str_field("kind", 1), str_field("path", 2)],
        ..Default::default()
    };
    let rule = DescriptorProto {
        name: Some("HttpRule".to_string()),
        field: vec![
            str_field("get", 2),
            str_field("put", 3),
            str_field("post", 4),
            str_field("delete", 5),
            str_field("patch", 6),
            str_field("body", 7),
            message_field("custom", 8, Label::Optional, ".gapi.CustomHttpPattern"),
            str_field("response_body", 12),
            message_field("additional_bindings", 11, Label::Repeated, ".gapi.HttpRule"),
        ],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("http.proto".to_string()),
        package: Some("gapi".to_string()),
        message_type: vec![rule, custom],
        syntax: Some("proto3".to_string()),
        ..Default::default()
    };
    let fds = FileDescriptorSet { file: vec![file] };
    let pool = DescriptorPool::decode(fds.encode_to_vec().as_slice()).unwrap();
    pool.get_message_by_name("gapi.HttpRule").unwrap()
}

/// An `HttpRule` with the `custom` pattern `{kind, path}`.
fn custom_rule(kind: &str, path: &str) -> DynamicMessage {
    let rule_desc = http_rule_descriptor();
    let custom_desc = rule_desc
        .parent_pool()
        .get_message_by_name("gapi.CustomHttpPattern")
        .unwrap();
    let mut custom = DynamicMessage::new(custom_desc);
    custom.set_field_by_name("kind", Value::String(kind.into()));
    custom.set_field_by_name("path", Value::String(path.into()));
    let mut rule = DynamicMessage::new(rule_desc);
    rule.set_field_by_name("custom", Value::Message(custom));
    rule
}

#[test]
fn collect_bindings_reads_body_response_and_additional() {
    let desc = http_rule_descriptor();

    // additional_bindings entry: POST /v1/items with whole-body mapping.
    let mut extra = DynamicMessage::new(desc.clone());
    extra.set_field_by_name("post", Value::String("/v1/items".into()));
    extra.set_field_by_name("body", Value::String("*".into()));

    // primary rule: GET /v1/items/{id}, returns only the `result` subfield.
    let mut rule = DynamicMessage::new(desc);
    rule.set_field_by_name("get", Value::String("/v1/items/{id}".into()));
    rule.set_field_by_name("response_body", Value::String("result".into()));
    rule.set_field_by_name(
        "additional_bindings",
        Value::List(vec![Value::Message(extra)]),
    );

    let bindings = collect_bindings(&rule);
    assert_eq!(bindings.len(), 2);

    // Primary: GET, no body, response_body = result.
    assert_eq!(bindings[0].method, RouteMethod::One(Method::GET));
    assert_eq!(bindings[0].path, "/v1/items/{id}");
    assert_eq!(bindings[0].body, BodyMapping::None);
    assert_eq!(bindings[0].response_body.as_deref(), Some("result"));

    // Additional: POST, whole-body mapping, no response_body.
    assert_eq!(bindings[1].method, RouteMethod::One(Method::POST));
    assert_eq!(bindings[1].path, "/v1/items");
    assert_eq!(bindings[1].body, BodyMapping::Root);
    assert_eq!(bindings[1].response_body, None);
}

#[test]
fn custom_rule_binds_its_kind_as_the_method() {
    let bindings = collect_bindings(&custom_rule("HEAD", "/v1/items/{id}"));
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].method, RouteMethod::One(Method::HEAD));
    assert_eq!(bindings[0].path, "/v1/items/{id}");
    assert_eq!(bindings[0].method.as_str(), "HEAD");
}

#[test]
fn custom_rule_with_star_kind_binds_every_method() {
    let bindings = collect_bindings(&custom_rule("*", "/v1/auth/verify"));
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].method, RouteMethod::Any);
    assert_eq!(bindings[0].method.as_str(), "*");
}

#[test]
fn custom_rule_kind_is_case_sensitive() {
    // RFC 9110 §9.1: method tokens are case-sensitive, so a lowercase kind is
    // an extension method of that exact spelling, never folded into HEAD.
    let bindings = collect_bindings(&custom_rule("head", "/v1/items"));
    assert_eq!(bindings.len(), 1);
    assert_ne!(bindings[0].method, RouteMethod::One(Method::HEAD));
    assert_eq!(bindings[0].method.as_str(), "head");
}

#[test]
fn custom_rule_with_an_invalid_kind_is_skipped() {
    // A space is not a token character; such a rule cannot be routed at all.
    assert!(collect_bindings(&custom_rule("NOT A METHOD", "/v1/items")).is_empty());
}

#[test]
fn custom_rule_without_kind_or_path_is_skipped() {
    assert!(collect_bindings(&custom_rule("", "/v1/items")).is_empty());
    assert!(collect_bindings(&custom_rule("HEAD", "")).is_empty());
}

#[test]
fn custom_rule_in_additional_bindings_is_collected() {
    let mut rule = DynamicMessage::new(http_rule_descriptor());
    rule.set_field_by_name("get", Value::String("/v1/items".into()));
    rule.set_field_by_name(
        "additional_bindings",
        Value::List(vec![Value::Message(custom_rule("OPTIONS", "/v1/items"))]),
    );
    let bindings = collect_bindings(&rule);
    let methods: Vec<&str> = bindings.iter().map(|b| b.method.as_str()).collect();
    assert_eq!(methods, ["GET", "OPTIONS"]);
}

#[test]
fn rule_without_a_pattern_yields_no_binding() {
    let mut rule = DynamicMessage::new(http_rule_descriptor());
    rule.set_field_by_name("body", Value::String("*".into()));
    assert!(collect_bindings(&rule).is_empty());
}
