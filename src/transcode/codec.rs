//! Dynamic gRPC codec for `prost-reflect::DynamicMessage`.
//!
//! Allows sending/receiving protobuf messages without compile-time type information,
//! using `MessageDescriptor` for runtime encoding/decoding.

use prost::Message;
use prost_reflect::{Cardinality, DynamicMessage, Kind, MessageDescriptor, ReflectMessage, Value};
use tonic::codec::{BufferSettings, Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::Status;

/// Encoder for `DynamicMessage` → wire bytes.
#[derive(Debug, Clone)]
pub struct DynamicEncoder;

impl Encoder for DynamicEncoder {
    type Item = DynamicMessage;
    type Error = Status;

    fn encode(&mut self, item: Self::Item, buf: &mut EncodeBuf<'_>) -> Result<(), Status> {
        item.encode(buf)
            .map_err(|e| Status::internal(format!("encode error: {e}")))
    }

    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::default()
    }
}

/// Decoder for wire bytes → `DynamicMessage`.
#[derive(Debug, Clone)]
pub struct DynamicDecoder {
    desc: MessageDescriptor,
    /// Whether `desc` has a proto2 `required` field at any depth, so decoded
    /// messages must be checked for it; false for every proto3 type.
    check_required: bool,
}

impl DynamicDecoder {
    pub fn new(desc: MessageDescriptor) -> Self {
        let check_required = has_required_fields(&desc);
        Self {
            desc,
            check_required,
        }
    }
}

impl Decoder for DynamicDecoder {
    type Item = DynamicMessage;
    type Error = Status;

    /// Decode one gRPC frame. tonic calls this once per complete frame, so an
    /// empty buffer is a message whose fields all hold their defaults (e.g.
    /// `google.protobuf.Empty`), not the absence of one. A message missing a
    /// proto2 `required` field is rejected, as protobuf parsers do by default
    /// (Go `proto.Unmarshal`, C++ `ParseFromString`); the decoder itself
    /// accepts it partially.
    fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        let msg = DynamicMessage::decode(self.desc.clone(), buf)
            .map_err(|e| Status::internal(format!("decode error: {e}")))?;
        if self.check_required {
            if let Some(field) = missing_required(&msg) {
                return Err(Status::internal(format!(
                    "decode error: required field {field} is missing"
                )));
            }
        }
        Ok(Some(msg))
    }

    fn buffer_settings(&self) -> BufferSettings {
        BufferSettings::default()
    }
}

/// Codec that encodes/decodes `DynamicMessage` using runtime descriptors.
#[derive(Debug, Clone)]
pub struct DynamicCodec {
    response_desc: MessageDescriptor,
    check_required: bool,
}

impl DynamicCodec {
    pub fn new(response_desc: MessageDescriptor) -> Self {
        let check_required = has_required_fields(&response_desc);
        Self::with_required_check(response_desc, check_required)
    }

    /// [`new`](Self::new) with [`has_required_fields`] of `response_desc`
    /// already known, so a route computes it once rather than per call.
    pub(crate) fn with_required_check(
        response_desc: MessageDescriptor,
        check_required: bool,
    ) -> Self {
        Self {
            response_desc,
            check_required,
        }
    }
}

impl Codec for DynamicCodec {
    type Encode = DynamicMessage;
    type Decode = DynamicMessage;
    type Encoder = DynamicEncoder;
    type Decoder = DynamicDecoder;

    fn encoder(&mut self) -> Self::Encoder {
        DynamicEncoder
    }

    fn decoder(&mut self) -> Self::Decoder {
        DynamicDecoder {
            desc: self.response_desc.clone(),
            check_required: self.check_required,
        }
    }
}

/// Whether a message of `desc`, or one it can contain at any depth (fields,
/// repeated and map values, extensions), has a proto2 `required` field.
pub(crate) fn has_required_fields(desc: &MessageDescriptor) -> bool {
    let mut seen = std::collections::HashSet::new();
    let mut pending = vec![desc.clone()];
    while let Some(desc) = pending.pop() {
        if !seen.insert(desc.full_name().to_owned()) {
            continue;
        }
        for field in desc.fields() {
            if field.cardinality() == Cardinality::Required {
                return true;
            }
            if let Kind::Message(inner) = field.kind() {
                pending.push(inner);
            }
        }
        for extension in desc.extensions() {
            if let Kind::Message(inner) = extension.kind() {
                pending.push(inner);
            }
        }
    }
    false
}

/// The full name of the first proto2 `required` field left unset in `msg` or
/// a message nested in it, if any.
pub(crate) fn missing_required(msg: &DynamicMessage) -> Option<String> {
    let desc = msg.descriptor();
    if let Some(field) = desc
        .fields()
        .find(|field| field.cardinality() == Cardinality::Required && !msg.has_field(field))
    {
        return Some(field.full_name().to_owned());
    }
    let values = msg
        .fields()
        .map(|(_, value)| value)
        .chain(msg.extensions().map(|(_, value)| value));
    for value in values {
        let missing = match value {
            Value::Message(inner) => missing_required(inner),
            Value::List(items) => items.iter().find_map(|item| match item {
                Value::Message(inner) => missing_required(inner),
                _ => None,
            }),
            Value::Map(entries) => entries.values().find_map(|entry| match entry {
                Value::Message(inner) => missing_required(inner),
                _ => None,
            }),
            _ => None,
        };
        if missing.is_some() {
            return missing;
        }
    }
    None
}

#[cfg(test)]
mod tests;
