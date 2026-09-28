use super::*;

#[test]
fn normalize_route_shape_collapses_param_names() {
    // Same shape, different param names → same key.
    assert_eq!(
        normalize_route_shape("/v1/x/{profile_id}"),
        normalize_route_shape("/v1/x/{id}")
    );
    // Wildcard vs named capture stay distinct; literals are untouched.
    assert_eq!(normalize_route_shape("/a/{p}/b"), "/a/{}/b");
    assert_eq!(normalize_route_shape("/a/{*rest}"), "/a/{*}");
    assert_ne!(
        normalize_route_shape("/a/{p}"),
        normalize_route_shape("/a/b")
    );
}

#[test]
fn test_minimal_config_server() {
    let yaml = r#"
upstream:
  default: "http://127.0.0.1:50051"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    let server = ProxyServer::from_config(config);
    assert!(server.descriptor_pool.is_none());
}

#[test]
fn no_configured_upstream_is_an_error_naming_the_key() {
    // An embedder with an in-process upstream needs no address; asking for
    // the remote channel without one is a startup error, not a panic.
    let server = ProxyServer::from_yaml_str("service:\n  name: demo\n").unwrap();
    let err = server.upstream().unwrap_err();
    assert!(err.to_string().contains("upstream.default"), "{err}");
    let Err(err) = server.router() else {
        panic!("router() needs an upstream address");
    };
    assert!(err.to_string().contains("upstream.default"), "{err}");
}

#[test]
fn an_invalid_upstream_address_is_an_error() {
    let server = ProxyServer::from_yaml_str("upstream:\n  default: \"not a uri\"\n").unwrap();
    let err = server.upstream().unwrap_err();
    assert!(
        err.to_string().contains("invalid gRPC upstream URL"),
        "{err}"
    );
}
