//! Guards the embedded-construction contract.
//!
//! Downstream products embed the proxy by building a [`ProxyConfig`]
//! programmatically (runtime upstream port, listen address, baked-in
//! descriptors) rather than loading a YAML file. The config types are
//! `#[non_exhaustive]`, so a new setting is not a breaking change; this test
//! lives in a separate crate and sees them as an external consumer does, so
//! it fails if any of them can no longer be built from its default or its
//! constructor.

use structured_proxy::config::{
    AliasConfig, ClientAddressConfig, ConcurrencyConfig, DescriptorSource, ListenTlsConfig,
    ProxyConfig, ScopeConfig, Traffic, UpstreamConfig,
};
use structured_proxy::ProxyServer;

#[test]
fn embedded_config_is_constructible() {
    static DESCRIPTOR_BYTES: &[u8] = &[];
    let mut config = ProxyConfig::default();
    config.upstream = Some(UpstreamConfig::new("http://127.0.0.1:50051"));
    config.descriptors = vec![DescriptorSource::Embedded {
        bytes: DESCRIPTOR_BYTES,
    }];
    config.listen.http = "0.0.0.0:8080".into();
    config.listen.max_connections = Some(1000);
    config.listen.tls = Some(ListenTlsConfig::new("/etc/tls.crt", "/etc/tls.key"));
    config.service.name = "embedded-test".into();
    config.aliases = vec![AliasConfig::new("/oauth2/{path}", "/v1/oauth2/{path}")];
    config.concurrency =
        Some(ConcurrencyConfig::new(512).with_scope(ScopeConfig::traffic([Traffic::Grpc])));
    let mut client_address = ClientAddressConfig::default();
    client_address.trusted_proxies = vec!["10.0.0.0/8".into()];
    config.client_address = client_address;
    // The default list, unlike a literal, keeps the serde defaults.
    assert!(config
        .forwarded_headers
        .iter()
        .any(|h| h == "authorization"));
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
