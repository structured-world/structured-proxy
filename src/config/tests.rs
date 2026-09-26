use super::*;

#[test]
fn test_minimal_config_deserialize() {
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.upstream.default, "grpc://localhost:4180");
    assert_eq!(config.listen.http, "0.0.0.0:8080");
    assert_eq!(config.service.name, "structured-proxy");
    assert_eq!(config.streaming.sse_keep_alive_secs, 15);
    assert!(config.descriptors.is_empty());
    assert!(config.auth.is_none());
    assert!(config.shield.is_none());
}

#[test]
fn health_and_metrics_defaults_and_overrides() {
    // Defaults: enabled, conventional paths.
    let min: ProxyConfig = serde_yaml::from_str("upstream:\n  default: \"grpc://x:1\"\n").unwrap();
    assert!(min.health.enabled);
    assert_eq!(min.health.path, "/health");
    assert_eq!(min.health.ready_path, "/health/ready");
    assert!(min.metrics.enabled);
    assert_eq!(min.metrics.path, "/metrics");

    // Overrides apply; unspecified sub-paths keep their defaults.
    let yaml = r#"
upstream:
  default: "grpc://x:1"
health:
  path: "/internal/health"
metrics:
  enabled: false
  path: "/internal/metrics"
"#;
    let cfg: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.health.path, "/internal/health");
    // live_path was not overridden, so it stays at the default.
    assert_eq!(cfg.health.live_path, "/health/live");
    assert!(!cfg.metrics.enabled);
    assert_eq!(cfg.metrics.path, "/internal/metrics");
}

#[test]
fn duplicate_probe_paths_are_rejected() {
    // health.path set to the default live_path collides on a single GET
    // route; reject at load instead of panicking in the router.
    let yaml = r#"
upstream:
  default: "grpc://x:1"
health:
  path: "/health/live"
"#;
    let err = ProxyConfig::from_yaml_str(yaml).unwrap_err();
    assert!(err.to_string().contains("duplicate endpoint path"));

    // A health path colliding with the metrics path is also rejected.
    let yaml2 = r#"
upstream:
  default: "grpc://x:1"
metrics:
  path: "/health"
"#;
    let err2 = ProxyConfig::from_yaml_str(yaml2).unwrap_err();
    assert!(err2.to_string().contains("duplicate endpoint path"));

    // Disabling a group frees its paths from the collision check.
    let yaml3 = r#"
upstream:
  default: "grpc://x:1"
health:
  enabled: false
  path: "/metrics"
"#;
    assert!(ProxyConfig::from_yaml_str(yaml3).is_ok());
}

#[test]
fn malformed_edge_path_is_rejected() {
    // A path without a leading '/' would make axum reject the route at
    // construction; catch it at config load with a clear message.
    let yaml = r#"
upstream:
  default: "grpc://x:1"
health:
  path: "health"
"#;
    let err = ProxyConfig::from_yaml_str(yaml).unwrap_err();
    assert!(err.to_string().contains("must start with '/'"));
}

#[test]
fn test_zero_sse_keep_alive_is_rejected() {
    // A zero keep-alive would make axum's SSE timer fire continuously
    // instead of acting as a periodic heartbeat — reject it at load time.
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
streaming:
  sse_keep_alive_secs: 0
"#;
    let err = ProxyConfig::from_yaml_str(yaml).unwrap_err();
    assert!(err.to_string().contains("sse_keep_alive_secs"));
}

#[test]
fn test_full_config_deserialize() {
    let yaml = r#"
upstream:
  default: "grpc://sid-identity:4180"

descriptors:
  - file: "/etc/proxy/sid.descriptor.bin"

listen:
  http: "0.0.0.0:9090"

service:
  name: "sid-proxy"

aliases:
  - from: "/oauth2/{path}"
    to: "/v1/oauth2/{path}"

auth:
  mode: "jwt"
  jwt:
    issuer: "https://auth.example.com"
    public_key_pem_file: "/etc/proxy/signing.pub"
    claims_headers:
      sub: "x-forwarded-user"
      acr: "x-sid-auth-level"
  forward_auth:
    enabled: true
    path: "/auth/verify"
    policies:
      - path: "/v1/admin/**"
        require_auth: true
        required_roles: ["admin"]
      - path: "/v1/public/**"
        require_auth: false
  authz:
    enabled: true
    endpoint: "http://opa:9191"   # Envoy ext_authz server (gRPC)
    timeout_ms: 200
    failure_mode_allow: false      # fail closed: deny if authz is unreachable

shield:
  enabled: true
  profiles:
    auth: { rate: "20/min", burst: 5 }
    default: { rate: "100/min" }
    premium: { rate: "1000/min", burst: 50 }
  default_profile: "default"
  jwt_limits:
    tier_claim: "ratelimit_tier"
  rules:
    - pattern: "/v1/auth/**"
      key: { type: ip }
      profile: "auth"
    - pattern: "/v1/**"
      key: { type: jwt_claim, claim: "sub" }
  trusted_proxies: ["10.0.0.0/8"]

oidc_discovery:
  enabled: true
  issuer: "https://auth.example.com"

maintenance:
  enabled: false
  exempt_paths:
    - "/health/**"
    - "/.well-known/**"

cors:
  origins:
    - "https://app.example.com"

metrics_classes:
  - pattern: "/v1/auth/**"
    class: "auth"
  - pattern: "/v1/admin/**"
    class: "admin"

forwarded_headers:
  - "authorization"
  - "dpop"
  - "x-request-id"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.upstream.default, "grpc://sid-identity:4180");
    assert_eq!(config.listen.http, "0.0.0.0:9090");
    assert_eq!(config.service.name, "sid-proxy");
    assert_eq!(config.aliases.len(), 1);
    assert!(config.auth.is_some());
    let authz = config.auth.as_ref().unwrap().authz.as_ref().unwrap();
    assert!(authz.enabled);
    assert_eq!(authz.endpoint, "http://opa:9191");
    assert_eq!(authz.timeout_ms, 200);
    assert!(!authz.failure_mode_allow);
    assert!(config.shield.is_some());
    assert!(config.oidc_discovery.is_some());
    assert_eq!(config.cors.origins.len(), 1);
    assert_eq!(config.metrics_classes.len(), 2);
    assert_eq!(config.forwarded_headers.len(), 3);
}

#[test]
fn authz_disabled_without_endpoint_parses() {
    // A disabled authz block need not supply an endpoint.
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
descriptors:
  - file: "/x.bin"
auth:
  mode: "jwt"
  authz:
    enabled: false
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    let authz = config.auth.unwrap().authz.unwrap();
    assert!(!authz.enabled);
    assert_eq!(authz.endpoint, "");
}

#[test]
fn test_descriptor_source_file() {
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
descriptors:
  - file: "/etc/proxy/service.descriptor.bin"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.descriptors.len(), 1);
    match &config.descriptors[0] {
        DescriptorSource::File { file } => {
            assert_eq!(file.to_str().unwrap(), "/etc/proxy/service.descriptor.bin");
        }
        _ => panic!("expected File descriptor source"),
    }
}

#[test]
fn test_descriptor_source_reflection() {
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
descriptors:
  - reflection: "grpc://localhost:4180"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    match &config.descriptors[0] {
        DescriptorSource::Reflection { reflection } => {
            assert_eq!(reflection, "grpc://localhost:4180");
        }
        _ => panic!("expected Reflection descriptor source"),
    }
}

#[test]
fn test_parse_rate() {
    assert_eq!(ProxyConfig::parse_rate("20/min"), Some(20));
    assert_eq!(ProxyConfig::parse_rate("100/min"), Some(100));
    assert_eq!(ProxyConfig::parse_rate("5/min"), Some(5));
    assert_eq!(ProxyConfig::parse_rate("invalid"), None);
}

#[test]
fn shield_rejects_unknown_field() {
    // A typo in a shield-config field (here `profil` for `profile`) must be a
    // hard error, not silently ignored: a misspelled security-control key
    // would otherwise leave the intended limit unapplied. `deny_unknown_fields`
    // on the shield structs turns the typo into a startup failure.
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
shield:
  enabled: true
  profiles:
    auth: { rate: "20/min", burst: 5 }
  rules:
    - pattern: "/v1/**"
      key: { type: ip }
      profil: "auth"
"#;
    let err = serde_yaml::from_str::<ProxyConfig>(yaml);
    assert!(err.is_err(), "unknown shield field must be rejected");
}

#[test]
fn shield_rejects_unknown_field_in_rule_key() {
    // A stray field inside a rule key (here `name` on an `ip` key, a copy-edit
    // leftover) must be a hard error. Silently ignoring it would keep the rule
    // IP-keyed instead of the intended per-header limit, weakening the control.
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
shield:
  enabled: true
  profiles:
    auth: { rate: "20/min", burst: 5 }
  rules:
    - pattern: "/v1/**"
      key: { type: ip, name: x-api-key }
      profile: "auth"
"#;
    let err = serde_yaml::from_str::<ProxyConfig>(yaml);
    assert!(err.is_err(), "unknown field in a rule key must be rejected");
}

#[test]
fn test_openapi_config_deserialize() {
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
openapi:
  enabled: true
  path: "/api/openapi.json"
  docs_path: "/api/docs"
  title: "Test API"
  version: "2.0.0"
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    let openapi = config.openapi.unwrap();
    assert!(openapi.enabled);
    assert_eq!(openapi.path, "/api/openapi.json");
    assert_eq!(openapi.docs_path, "/api/docs");
    assert_eq!(openapi.title.unwrap(), "Test API");
    assert_eq!(openapi.version.unwrap(), "2.0.0");
}

#[test]
fn test_openapi_config_defaults() {
    let yaml = r#"
upstream:
  default: "grpc://localhost:4180"
openapi:
  enabled: true
"#;
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    let openapi = config.openapi.unwrap();
    assert!(openapi.enabled);
    assert_eq!(openapi.path, "/openapi.json");
    assert_eq!(openapi.docs_path, "/docs");
    assert!(openapi.title.is_none());
    assert!(openapi.version.is_none());
}

/// The transcoding options a YAML document compiles to.
fn transcode_options(yaml: &str) -> Result<crate::transcode::TranscodeOptions, String> {
    serde_yaml::from_str::<TranscodeFileConfig>(yaml)
        .map_err(|e| e.to_string())?
        .options()
}

#[test]
fn transcode_settings_default_to_details_everywhere_and_no_envelope() {
    // A file that names neither key keeps the defaults: details on every
    // route, bare NDJSON lines.
    let options = transcode_options("upstream:\n  default: \"grpc://x:1\"\n").unwrap();
    assert!(options.error_details.enabled_for("/v1/users/{id}"));
    assert!(!options.ndjson_envelope);
}

#[test]
fn transcode_settings_read_error_details_and_the_ndjson_envelope() {
    // Both keys come from the same file as the ProxyConfig, next to its own
    // `streaming` keys, and the route rules keep their order.
    let yaml = r#"
upstream:
  default: "grpc://x:1"
streaming:
  sse_keep_alive_secs: 30
  ndjson_envelope: true
error_details:
  enabled: false
  routes:
    - pattern: "/v1/public/internal/*"
      enabled: false
    - pattern: "/v1/public/**"
      enabled: true
"#;
    let options = transcode_options(yaml).unwrap();
    assert!(options.ndjson_envelope);
    assert!(options.error_details.enabled_for("/v1/public/items"));
    assert!(!options
        .error_details
        .enabled_for("/v1/public/internal/{id}"));
    assert!(!options.error_details.enabled_for("/v1/admin/items"));
    // The ProxyConfig still reads its own streaming key from the same section.
    let config: ProxyConfig = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(config.streaming.sse_keep_alive_secs, 30);
}

#[test]
fn transcode_settings_reject_unknown_error_details_key() {
    // `enable` for `enabled` would otherwise leave details on silently.
    let err = transcode_options(
        "upstream:\n  default: \"grpc://x:1\"\nerror_details:\n  enable: false\n",
    )
    .unwrap_err();
    assert!(err.contains("enable"), "{err}");
}

#[test]
fn transcode_settings_require_enabled_on_a_route_rule() {
    // A rule without `enabled` states no decision.
    let err = transcode_options(
        "upstream:\n  default: \"grpc://x:1\"\nerror_details:\n  routes:\n    - pattern: \"/v1/**\"\n",
    )
    .unwrap_err();
    assert!(err.contains("enabled"), "{err}");
}

#[test]
fn transcode_settings_reject_a_relative_route_pattern() {
    // `v1/admin/**` never matches a route path; accepting it would leave
    // details on where the operator meant to turn them off.
    let err = transcode_options(
        "upstream:\n  default: \"grpc://x:1\"\nerror_details:\n  routes:\n    - pattern: \"v1/admin/**\"\n      enabled: false\n",
    )
    .unwrap_err();
    assert!(err.contains("must start with '/'"), "{err}");
}
