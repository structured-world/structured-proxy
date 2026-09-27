use super::*;
use prost_reflect::DescriptorPool;

/// A pool with the canonical HttpBody and `test.Wrapper { HttpBody body = 1;
/// repeated HttpBody many = 2; string name = 3; Inner inner = 4; }`,
/// `test.Inner { HttpBody body = 1; }`, and a product type named like HttpBody
/// but missing `data`.
fn pool() -> DescriptorPool {
    use prost_reflect::prost_types::field_descriptor_proto::{Label, Type};
    use prost_reflect::prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto};

    let field = |name: &str, number: i32, label: Label, ty: Type, type_name: Option<&str>| {
        FieldDescriptorProto {
            name: Some(name.to_owned()),
            number: Some(number),
            label: Some(label as i32),
            r#type: Some(ty as i32),
            type_name: type_name.map(str::to_owned),
            ..Default::default()
        }
    };
    let mut pool = DescriptorPool::global();
    pool.add_file_descriptor_proto(file_descriptor()).unwrap();
    pool.add_file_descriptor_proto(FileDescriptorProto {
        name: Some("test/wrapper.proto".to_owned()),
        package: Some("test".to_owned()),
        dependency: vec!["google/api/httpbody.proto".to_owned()],
        message_type: vec![
            DescriptorProto {
                name: Some("Wrapper".to_owned()),
                field: vec![
                    field(
                        "body",
                        1,
                        Label::Optional,
                        Type::Message,
                        Some(".google.api.HttpBody"),
                    ),
                    field(
                        "many",
                        2,
                        Label::Repeated,
                        Type::Message,
                        Some(".google.api.HttpBody"),
                    ),
                    field("name", 3, Label::Optional, Type::String, None),
                    field(
                        "inner",
                        4,
                        Label::Optional,
                        Type::Message,
                        Some(".test.Inner"),
                    ),
                ],
                ..Default::default()
            },
            DescriptorProto {
                name: Some("Inner".to_owned()),
                field: vec![field(
                    "body",
                    1,
                    Label::Optional,
                    Type::Message,
                    Some(".google.api.HttpBody"),
                )],
                ..Default::default()
            },
        ],
        syntax: Some("proto3".to_owned()),
        ..Default::default()
    })
    .unwrap();
    pool
}

fn message(pool: &DescriptorPool, name: &str) -> MessageDescriptor {
    pool.get_message_by_name(name).unwrap()
}

#[test]
fn canonical_http_body_is_recognized() {
    let pool = pool();
    assert!(is_http_body(&message(&pool, HTTP_BODY)));
    assert!(!is_http_body(&message(&pool, "test.Wrapper")));
}

#[test]
fn http_body_named_type_without_its_fields_is_an_ordinary_message() {
    // A product revision of google.api.HttpBody that lacks `data` cannot be
    // filled or read as a raw body, so it is transcoded as JSON instead of
    // panicking on the missing field.
    use prost_reflect::prost_types::field_descriptor_proto::{Label, Type};
    use prost_reflect::prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto};
    let mut pool = DescriptorPool::new();
    pool.add_file_descriptor_proto(FileDescriptorProto {
        name: Some("google/api/httpbody.proto".to_owned()),
        package: Some("google.api".to_owned()),
        message_type: vec![DescriptorProto {
            name: Some("HttpBody".to_owned()),
            field: vec![FieldDescriptorProto {
                name: Some("content_type".to_owned()),
                number: Some(1),
                label: Some(Label::Optional as i32),
                r#type: Some(Type::String as i32),
                ..Default::default()
            }],
            ..Default::default()
        }],
        syntax: Some("proto3".to_owned()),
        ..Default::default()
    })
    .unwrap();
    assert!(!is_http_body(&message(&pool, HTTP_BODY)));
}

#[test]
fn http_body_field_finds_singular_http_body_fields_only() {
    let pool = pool();
    let wrapper = message(&pool, "test.Wrapper");
    let (field, desc) = http_body_field(&wrapper, "body").unwrap();
    assert_eq!(field.name(), "body");
    assert_eq!(desc.full_name(), HTTP_BODY);
    // Repeated, scalar and missing fields are not an HttpBody body target.
    assert!(http_body_field(&wrapper, "many").is_none());
    assert!(http_body_field(&wrapper, "name").is_none());
    assert!(http_body_field(&wrapper, "missing").is_none());
}

#[test]
fn http_body_path_resolves_nested_fields() {
    let pool = pool();
    let wrapper = message(&pool, "test.Wrapper");
    let path = http_body_path(&wrapper, "inner.body").unwrap();
    assert_eq!(
        path.iter().map(|f| f.name()).collect::<Vec<_>>(),
        ["inner", "body"]
    );
    assert_eq!(http_body_path(&wrapper, "body").unwrap().len(), 1);
    // Paths ending elsewhere, through a scalar, a repeated field or a missing
    // name are not HttpBody responses.
    assert!(http_body_path(&wrapper, "inner").is_none());
    assert!(http_body_path(&wrapper, "name").is_none());
    assert!(http_body_path(&wrapper, "many").is_none());
    assert!(http_body_path(&wrapper, "inner.missing").is_none());
}

#[test]
fn fill_then_take_round_trips_without_copying_the_data() {
    let pool = pool();
    let mut msg = DynamicMessage::new(message(&pool, HTTP_BODY));
    let data = Bytes::from_static(b"\x89PNG raw");
    fill(&mut msg, "image/png".to_owned(), data.clone());
    let raw = take(msg, &[]);
    assert_eq!(raw.content_type, "image/png");
    assert_eq!(raw.data, data);
    // Same allocation: the bytes were moved, not copied.
    assert_eq!(raw.data.as_ptr(), data.as_ptr());
}

#[test]
fn take_walks_a_field_path() {
    let pool = pool();
    let mut body = DynamicMessage::new(message(&pool, HTTP_BODY));
    fill(
        &mut body,
        "text/plain".to_owned(),
        Bytes::from_static(b"hi"),
    );
    let mut inner = DynamicMessage::new(message(&pool, "test.Inner"));
    inner.set_field_by_name("body", Value::Message(body));
    let wrapper_desc = message(&pool, "test.Wrapper");
    let mut wrapper = DynamicMessage::new(wrapper_desc.clone());
    wrapper.set_field_by_name("inner", Value::Message(inner));
    let raw = take(
        wrapper,
        &http_body_path(&wrapper_desc, "inner.body").unwrap(),
    );
    assert_eq!(raw.content_type, "text/plain");
    assert_eq!(&raw.data[..], b"hi");
}

#[test]
fn take_of_an_unset_field_is_an_empty_body() {
    let pool = pool();
    let wrapper_desc = message(&pool, "test.Wrapper");
    let raw = take(
        DynamicMessage::new(wrapper_desc.clone()),
        &http_body_path(&wrapper_desc, "inner.body").unwrap(),
    );
    assert!(raw.content_type.is_empty());
    assert!(raw.data.is_empty());
}

#[test]
fn canonical_descriptor_matches_google_api_httpbody() {
    let pool = pool();
    let desc = message(&pool, HTTP_BODY);
    let fields: Vec<(u32, String, bool)> = desc
        .fields()
        .map(|f| (f.number(), f.name().to_owned(), f.is_list()))
        .collect();
    assert_eq!(
        fields,
        [
            (1, "content_type".to_owned(), false),
            (2, "data".to_owned(), false),
            (3, "extensions".to_owned(), true)
        ]
    );
    assert_eq!(desc.get_field(2).unwrap().json_name(), "data");
    assert_eq!(desc.get_field(1).unwrap().json_name(), "contentType");
}
