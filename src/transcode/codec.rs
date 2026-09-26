//! Dynamic gRPC codec for `prost-reflect::DynamicMessage`.
//!
//! Allows sending/receiving protobuf messages without compile-time type information,
//! using `MessageDescriptor` for runtime encoding/decoding.

use prost::Message;
use prost_reflect::{DynamicMessage, MessageDescriptor};
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
}

impl DynamicDecoder {
    pub fn new(desc: MessageDescriptor) -> Self {
        Self { desc }
    }
}

impl Decoder for DynamicDecoder {
    type Item = DynamicMessage;
    type Error = Status;

    /// Decode one gRPC frame. tonic calls this once per complete frame, so an
    /// empty buffer is a message whose fields all hold their defaults (e.g.
    /// `google.protobuf.Empty`), not the absence of one.
    fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        let msg = DynamicMessage::decode(self.desc.clone(), buf)
            .map_err(|e| Status::internal(format!("decode error: {e}")))?;
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
}

impl DynamicCodec {
    pub fn new(response_desc: MessageDescriptor) -> Self {
        Self { response_desc }
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
        DynamicDecoder::new(self.response_desc.clone())
    }
}

#[cfg(test)]
mod tests;
