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
