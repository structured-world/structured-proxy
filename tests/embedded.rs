//! Guards the embedded-construction contract.
//!
//! Downstream products embed the proxy by building a [`ProxyConfig`]
//! programmatically (runtime upstream port, listen address, baked-in
//! descriptors) rather than loading a YAML file. This test lives in a separate
//! crate, so it sees the config types exactly as an external consumer does: if
//! any wiring struct gains `#[non_exhaustive]`, this stops compiling and the
//! embedded API regression is caught here.

use structured_proxy::config::{
    DescriptorSource, ListenConfig, ProxyConfig, ServiceConfig, UpstreamConfig,
};
use structured_proxy::ProxyServer;

#[test]
fn embedded_config_is_constructible() {
    static DESCRIPTOR_BYTES: &[u8] = &[];
    let config = ProxyConfig {
        upstream: UpstreamConfig {
            default: "http://127.0.0.1:50051".into(),
        },
        descriptors: vec![DescriptorSource::Embedded {
            bytes: DESCRIPTOR_BYTES,
        }],
        listen: ListenConfig {
            http: "0.0.0.0:8080".into(),
        },
        service: ServiceConfig {
            name: "embedded-test".into(),
        },
        aliases: vec![],
        openapi: None,
        auth: None,
        shield: None,
        oidc_discovery: None,
        maintenance: Default::default(),
        cors: Default::default(),
        logging: Default::default(),
        metrics_classes: vec![],
        // Arbitrary: this test only exercises that the config is constructible,
        // not header forwarding. NOTE for real embeddings: a programmatic literal
        // bypasses the serde defaults, so set every header you need here (or load
        // the config via from_file / from_yaml_str, where the default list applies).
        forwarded_headers: vec!["authorization".into()],
        streaming: Default::default(),
    };
    // The server accepts a programmatically-built config (the embedded path).
    let _server = ProxyServer::from_config(config);
}

#[test]
fn from_yaml_str_loads_config() {
    let config = ProxyConfig::from_yaml_str(
        r#"
upstream:
  default: "http://127.0.0.1:50051"
descriptors:
  - file: "/x.bin"
service:
  name: "yaml-test"
"#,
    )
    .unwrap();
    assert_eq!(config.service.name, "yaml-test");
}
