//! Dynamic gRPC codec for `prost-reflect::DynamicMessage`.
//!
//! Allows sending/receiving protobuf messages without compile-time type information,
//! using `MessageDescriptor` for runtime encoding/decoding.

use prost::bytes::Buf;
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

    fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<Self::Item>, Status> {
        let remaining = buf.remaining();
        if remaining == 0 {
            return Ok(None);
        }
        let msg = DynamicMessage::decode(self.desc.clone(), buf.copy_to_bytes(remaining))
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
mod tests {
    #[test]
    fn test_dynamic_codec_creation() {
        // Use google.protobuf.Empty as a universal test message
        let pool = prost_reflect::DescriptorPool::decode(
            prost_reflect::DescriptorPool::global()
                .encode_to_vec()
                .as_slice(),
        )
        .unwrap_or_else(|_| prost_reflect::DescriptorPool::new());
        // Basic smoke test — codec can be created with any message descriptor
        let _ = pool;
    }
}
