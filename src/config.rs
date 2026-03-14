//! YAML-based proxy configuration.
//!
//! All product-specific behavior is driven by config, not code.
//! Same binary, different YAML = different product proxy.

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level proxy configuration (loaded from YAML).
#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    /// Upstream gRPC service(s).
    pub upstream: UpstreamConfig,

    /// Proto descriptor sources.
    #[serde(default, deserialize_with = "deserialize_descriptor_sources")]
    pub descriptors: Vec<DescriptorSource>,

    /// Listen addresses.
    #[serde(default)]
    pub listen: ListenConfig,

    /// Service identity (for health endpoint, metrics namespace).
    #[serde(default)]
    pub service: ServiceConfig,

    /// Path aliases (e.g., /oauth2/* → /v1/oauth2/*).
    #[serde(default)]
    pub aliases: Vec<AliasConfig>,

    /// OpenAPI generation.
    #[serde(default)]
    pub openapi: Option<OpenApiConfig>,

    /// Auth configuration (JWT, forward auth, AuthZ).
    #[serde(default)]
    pub auth: Option<AuthConfig>,

    /// Rate limiting (Shield).
    #[serde(default)]
    pub shield: Option<ShieldConfig>,

    /// OIDC discovery (optional — for IdP proxies).
    #[serde(default)]
    pub oidc_discovery: Option<OidcDiscoveryConfig>,

    /// Maintenance mode.
    #[serde(default)]
    pub maintenance: MaintenanceConfig,

    /// CORS configuration.
    #[serde(default)]
    pub cors: CorsConfig,

    /// Logging.
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Metrics endpoint classification (path patterns → class labels).
    #[serde(default)]
    pub metrics_classes: Vec<MetricsClassConfig>,

    /// Headers to forward from HTTP to gRPC metadata.
    #[serde(default = "default_forwarded_headers")]
    pub forwarded_headers: Vec<String>,
}

fn default_forwarded_headers() -> Vec<String> {
    vec![
        "authorization".into(),
        "dpop".into(),
        "x-request-id".into(),
        "x-forwarded-for".into(),
        "x-forwarded-proto".into(),
        "x-real-ip".into(),
        "accept-language".into(),
        "user-agent".into(),
        "idempotency-key".into(),
    ]
}

/// Upstream gRPC service configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    /// gRPC upstream address (e.g., "http://localhost:4180").
    pub default: String,
}

/// Descriptor loading source.
#[derive(Debug, Clone)]
pub enum DescriptorSource {
    /// Pre-compiled descriptor file.
    File { file: PathBuf },
    /// gRPC server reflection (development mode).
    Reflection { reflection: String },
    /// Embedded bytes (set programmatically, not from YAML).
    Embedded { bytes: &'static [u8] },
}

/// Helper for YAML deserialization (only File and Reflection variants).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum DescriptorSourceYaml {
    File { file: PathBuf },
    Reflection { reflection: String },
}

impl From<DescriptorSourceYaml> for DescriptorSource {
    fn from(yaml: DescriptorSourceYaml) -> Self {
        match yaml {
            DescriptorSourceYaml::File { file } => DescriptorSource::File { file },
            DescriptorSourceYaml::Reflection { reflection } => {
                DescriptorSource::Reflection { reflection }
            }
        }
    }
}

fn deserialize_descriptor_sources<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<DescriptorSource>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let yaml_sources: Vec<DescriptorSourceYaml> = Vec::deserialize(deserializer)?;
    Ok(yaml_sources.into_iter().map(Into::into).collect())
}

/// Listen address configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    /// HTTP listen address (default: "0.0.0.0:8080").
    #[serde(default = "default_http_listen")]
    pub http: String,
}

fn default_http_listen() -> String {
    "0.0.0.0:8080".into()
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            http: default_http_listen(),
        }
    }
}

/// Service identity.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceConfig {
    /// Service name (appears in /health response and metrics namespace).
    #[serde(default = "default_service_name")]
    pub name: String,
}

fn default_service_name() -> String {
    "structured-proxy".into()
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: default_service_name(),
        }
    }
}

/// Path alias (rewrite before routing).
#[derive(Debug, Clone, Deserialize)]
pub struct AliasConfig {
    pub from: String,
    pub to: String,
}

/// OpenAPI generation config.
#[derive(Debug, Clone, Deserialize)]
pub struct OpenApiConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Path for OpenAPI JSON spec (default: "/openapi.json").
    #[serde(default = "default_openapi_path")]
    pub path: String,
    /// Path for interactive API docs UI (default: "/docs").
    #[serde(default = "default_docs_path")]
    pub docs_path: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

fn default_openapi_path() -> String {
    "/openapi.json".into()
}

fn default_docs_path() -> String {
    "/docs".into()
}

fn default_true() -> bool {
    true
}

/// Auth configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Auth mode: "none", "jwt", "api_key".
    #[serde(default = "default_auth_mode")]
    pub mode: String,

    /// JWT validation config.
    #[serde(default)]
    pub jwt: Option<JwtConfig>,

    /// Forward auth endpoint.
    #[serde(default)]
    pub forward_auth: Option<ForwardAuthConfig>,

    /// AuthZ integration (optional gRPC call).
    #[serde(default)]
    pub authz: Option<AuthzConfig>,

    /// BFF (Backend-for-Frontend) session config.
    #[serde(default)]
    pub bff: Option<BffConfig>,
}

fn default_auth_mode() -> String {
    "none".into()
}

/// JWT validation config.
#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    /// JWKS URI for key discovery.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Expected issuer.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Expected audience.
    #[serde(default)]
    pub audience: Option<String>,
    /// Path to Ed25519 public key PEM file (alternative to JWKS URI).
    #[serde(default)]
    pub public_key_pem_file: Option<PathBuf>,
    /// Claims → HTTP headers mapping.
    #[serde(default)]
    pub claims_headers: std::collections::HashMap<String, String>,
}

/// Forward auth config.
#[derive(Debug, Clone, Deserialize)]
pub struct ForwardAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_forward_auth_path")]
    pub path: String,
    /// Route policies.
    #[serde(default)]
    pub policies: Vec<RoutePolicyConfig>,
    /// Login URL for 401 redirects.
    #[serde(default)]
    pub login_url: Option<String>,
    /// Applications YAML file path.
    #[serde(default)]
    pub applications_path: Option<PathBuf>,
}

fn default_forward_auth_path() -> String {
    "/auth/verify".into()
}

/// Route policy entry.
#[derive(Debug, Clone, Deserialize)]
pub struct RoutePolicyConfig {
    pub path: String,
    #[serde(default = "default_methods_all")]
    pub methods: Vec<String>,
    #[serde(default)]
    pub require_auth: bool,
    #[serde(default)]
    pub required_roles: Vec<String>,
}

fn default_methods_all() -> Vec<String> {
    vec!["*".into()]
}

/// AuthZ gRPC integration.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthzConfig {
    #[serde(default)]
    pub enabled: bool,
    pub service: String,
    pub method: String,
    #[serde(default)]
    pub subject_template: Option<String>,
    #[serde(default)]
    pub resource_template: Option<String>,
    #[serde(default)]
    pub action_template: Option<String>,
}

/// BFF session config.
#[derive(Debug, Clone, Deserialize)]
pub struct BffConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_bff_cookie")]
    pub cookie_name: String,
    #[serde(default = "default_bff_max_age")]
    pub max_age: u64,
    #[serde(default = "default_bff_idle_timeout")]
    pub idle_timeout: u64,
    #[serde(default)]
    pub external_url: Option<String>,
}

fn default_bff_cookie() -> String {
    "__Host-proxy-bff".into()
}
fn default_bff_max_age() -> u64 {
    86400
}
fn default_bff_idle_timeout() -> u64 {
    3600
}

/// Shield (rate limiting) configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ShieldConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Endpoint classification (glob pattern → class → rate limit).
    #[serde(default)]
    pub endpoint_classes: Vec<EndpointClassConfig>,
    /// Per-identifier rate limiting.
    #[serde(default)]
    pub identifier_endpoints: Vec<IdentifierEndpointConfig>,
    /// Window size in seconds (default: 60).
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

fn default_window_secs() -> u64 {
    60
}

/// Endpoint classification for rate limiting.
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointClassConfig {
    /// Glob pattern (e.g., "/v1/auth/**").
    pub pattern: String,
    /// Class name (e.g., "auth").
    pub class: String,
    /// Rate limit string (e.g., "20/min").
    pub rate: String,
}

/// Per-identifier rate limiting config.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentifierEndpointConfig {
    pub path: String,
    pub body_field: String,
    pub rate: String,
}

/// OIDC discovery config.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscoveryConfig {
    #[serde(default)]
    pub enabled: bool,
    pub issuer: String,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub signing_key: Option<SigningKeyConfig>,
}

/// Signing key config for JWKS endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct SigningKeyConfig {
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    pub public_key_pem_file: PathBuf,
}

fn default_algorithm() -> String {
    "EdDSA".into()
}

/// Maintenance mode config.
#[derive(Debug, Clone, Deserialize)]
pub struct MaintenanceConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Paths exempt from maintenance mode (glob patterns).
    #[serde(default = "default_exempt_paths")]
    pub exempt_paths: Vec<String>,
    #[serde(default = "default_maintenance_message")]
    pub message: String,
}

fn default_exempt_paths() -> Vec<String> {
    vec![
        "/health/**".into(),
        "/.well-known/**".into(),
        "/metrics".into(),
        "/auth/verify".into(),
    ]
}

fn default_maintenance_message() -> String {
    "Service is under maintenance. Please try again later.".into()
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            exempt_paths: default_exempt_paths(),
            message: default_maintenance_message(),
        }
    }
}

/// CORS configuration.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CorsConfig {
    /// Allowed origins. Empty = permissive (dev mode).
    #[serde(default)]
    pub origins: Vec<String>,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

/// Metrics endpoint classification.
#[derive(Debug, Clone, Deserialize)]
pub struct MetricsClassConfig {
    /// Glob pattern for path matching.
    pub pattern: String,
    /// Label value for this class.
    pub class: String,
}

impl ProxyConfig {
    /// Load configuration from a YAML file.
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Parse rate string like "20/min" → requests per window.
    pub fn parse_rate(rate: &str) -> Option<u32> {
        let parts: Vec<&str> = rate.split('/').collect();
        if parts.len() != 2 {
            return None;
        }
        parts[0].trim().parse().ok()
    }
}

#[cfg(test)]
mod tests {
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
        assert!(config.descriptors.is_empty());
        assert!(config.auth.is_none());
        assert!(config.shield.is_none());
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

shield:
  enabled: true
  endpoint_classes:
    - pattern: "/v1/auth/**"
      class: "auth"
      rate: "20/min"
    - pattern: "/**"
      class: "default"
      rate: "100/min"
  identifier_endpoints:
    - path: "/v1/auth/opaque/login/start"
      body_field: "identifier"
      rate: "10/min"

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
        assert!(config.shield.is_some());
        assert!(config.oidc_discovery.is_some());
        assert_eq!(config.cors.origins.len(), 1);
        assert_eq!(config.metrics_classes.len(), 2);
        assert_eq!(config.forwarded_headers.len(), 3);
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
}
