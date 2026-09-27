//! `google.api.HttpBody`: an RPC that takes or returns one carries the raw HTTP
//! body and its `Content-Type` instead of JSON, as in `google/api/httpbody.proto`.

use bytes::Bytes;
use prost_reflect::{DynamicMessage, FieldDescriptor, Kind, MessageDescriptor, Value};

/// Full name of `google.api.HttpBody`.
pub(crate) const HTTP_BODY: &str = "google.api.HttpBody";

/// Whether `desc` is `google.api.HttpBody` with the `content_type` (string) and
/// `data` (bytes) fields the transcoder reads and writes. A product revision of
/// the type that lacks either is transcoded as an ordinary message.
pub(crate) fn is_http_body(desc: &MessageDescriptor) -> bool {
    let field_is = |name: &str, kind: Kind| {
        desc.get_field_by_name(name)
            .is_some_and(|field| field.kind() == kind && !field.is_list())
    };
    desc.full_name() == HTTP_BODY
        && field_is("content_type", Kind::String)
        && field_is("data", Kind::Bytes)
}

/// The singular message field `name` of `desc`, and its type, when that type
/// is an HttpBody.
pub(crate) fn http_body_field(
    desc: &MessageDescriptor,
    name: &str,
) -> Option<(FieldDescriptor, MessageDescriptor)> {
    let field = desc.get_field_by_name(name)?;
    match field.kind() {
        Kind::Message(inner) if !field.is_list() && is_http_body(&inner) => Some((field, inner)),
        _ => None,
    }
}

/// The chain of singular message fields a dotted `response_body` path names in
/// `desc`, when it ends at an HttpBody.
pub(crate) fn http_body_path(desc: &MessageDescriptor, path: &str) -> Option<Vec<FieldDescriptor>> {
    let mut fields = Vec::new();
    let mut current = desc.clone();
    for segment in path.split('.') {
        let field = current.get_field_by_name(segment)?;
        let Kind::Message(inner) = field.kind() else {
            return None;
        };
        if field.is_list() {
            return None;
        }
        fields.push(field);
        current = inner;
    }
    is_http_body(&current).then_some(fields)
}

/// The raw body an HttpBody carries.
#[derive(Debug, Default)]
pub(crate) struct RawBody {
    /// `content_type`; empty when the upstream left it unset.
    pub(crate) content_type: String,
    pub(crate) data: Bytes,
}

/// Move the HttpBody at `path` (the message itself when empty) out of `msg`.
/// An unset field on the way is an empty body, as ProtoJSON renders an unset
/// message field as absent.
pub(crate) fn take(mut msg: DynamicMessage, path: &[FieldDescriptor]) -> RawBody {
    for field in path {
        match msg.take_field(field) {
            Some(Value::Message(inner)) => msg = inner,
            _ => return RawBody::default(),
        }
    }
    let content_type = match msg.take_field_by_name("content_type") {
        Some(Value::String(content_type)) => content_type,
        _ => String::new(),
    };
    let data = match msg.take_field_by_name("data") {
        Some(Value::Bytes(data)) => data,
        _ => Bytes::new(),
    };
    RawBody { content_type, data }
}

/// Set the `content_type` and `data` of the HttpBody `msg`.
pub(crate) fn fill(msg: &mut DynamicMessage, content_type: String, data: Bytes) {
    msg.set_field_by_name("content_type", Value::String(content_type));
    msg.set_field_by_name("data", Value::Bytes(data));
}

/// `google/api/httpbody.proto`, so error details of this type render even when
/// the product descriptors do not import it.
pub(crate) fn file_descriptor() -> prost_reflect::prost_types::FileDescriptorProto {
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
    FileDescriptorProto {
        name: Some("google/api/httpbody.proto".to_owned()),
        package: Some("google.api".to_owned()),
        dependency: vec!["google/protobuf/any.proto".to_owned()],
        message_type: vec![DescriptorProto {
            name: Some("HttpBody".to_owned()),
            field: vec![
                field("content_type", 1, Label::Optional, Type::String, None),
                field("data", 2, Label::Optional, Type::Bytes, None),
                field(
                    "extensions",
                    3,
                    Label::Repeated,
                    Type::Message,
                    Some(".google.protobuf.Any"),
                ),
            ],
            ..Default::default()
        }],
        syntax: Some("proto3".to_owned()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests;
