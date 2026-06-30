//! YAML-based proxy configuration.
//!
//! All product-specific behavior is driven by config, not code.
//! Same binary, different YAML = different product proxy.

use serde::Deserialize;
use std::path::PathBuf;

/// Top-level proxy configuration (loaded from YAML).
///
/// This and the wiring structs below (`UpstreamConfig`, `ListenConfig`,
/// `ServiceConfig`, `DescriptorSource`) are intentionally NOT
/// `#[non_exhaustive]`: embedding consumers build them programmatically with
/// runtime values. The leaf auth/shield/oidc config structs are
/// `#[non_exhaustive]` instead, since those are deserialized, not hand-built.
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

    /// Health-probe endpoints (paths configurable; can be disabled).
    #[serde(default)]
    pub health: HealthConfig,

    /// Prometheus metrics endpoint (path configurable; can be disabled).
    #[serde(default)]
    pub metrics: MetricsConfig,

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

    /// Server-streaming response behavior.
    #[serde(default)]
    pub streaming: StreamingConfig,
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

/// Server-streaming response behavior.
///
/// Server-streaming RPCs are exposed as NDJSON by default and as Server-Sent
/// Events when the client sends `Accept: text/event-stream`. The keep-alive
/// interval applies only to the SSE path.
#[derive(Debug, Clone, Deserialize)]
pub struct StreamingConfig {
    /// SSE keep-alive interval in seconds. Comment frames are emitted on idle
    /// streams to keep intermediaries (load balancers, nginx) from closing the
    /// connection on read timeout. Default: 15.
    #[serde(default = "default_sse_keep_alive_secs")]
    pub sse_keep_alive_secs: u64,
}

fn default_sse_keep_alive_secs() -> u64 {
    15
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self {
            sse_keep_alive_secs: default_sse_keep_alive_secs(),
        }
    }
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
#[non_exhaustive]
pub struct AliasConfig {
    pub from: String,
    pub to: String,
}

/// OpenAPI generation config.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
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
}

fn default_auth_mode() -> String {
    "none".into()
}

/// JWT validation config.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
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
    /// Claim holding the user's roles (array of strings). Supports a dotted
    /// path for nested claims, e.g. "realm_access.roles". Default: "roles".
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
}

fn default_roles_claim() -> String {
    "roles".into()
}

/// Forward auth config.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
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

/// External authorization via the Envoy ext_authz gRPC contract
/// (`envoy.service.auth.v3.Authorization/Check`). Interops with OPA and any
/// ext_authz server.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct AuthzConfig {
    /// Enable external authorization for proxied API requests.
    #[serde(default)]
    pub enabled: bool,
    /// gRPC address of the ext_authz server, e.g. `http://opa:9191`. Required
    /// when enabled; defaults to empty so a disabled block can omit it.
    #[serde(default)]
    pub endpoint: String,
    /// Per-request authorization call timeout, in milliseconds.
    #[serde(default = "default_authz_timeout_ms")]
    pub timeout_ms: u64,
    /// When the authz call itself fails (unreachable / timeout), allow the
    /// request through instead of denying. Defaults to false (fail closed).
    #[serde(default)]
    pub failure_mode_allow: bool,
}

fn default_authz_timeout_ms() -> u64 {
    200
}

/// Shield (rate limiting) configuration.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
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
    /// Redis URL for shared counters across replicas (e.g. "redis://127.0.0.1/").
    /// When unset, an in-process per-replica store is used. Requires the `redis`
    /// build feature; otherwise the proxy logs a warning and uses the in-process
    /// store.
    #[serde(default)]
    pub redis_url: Option<String>,
    /// CIDR ranges of trusted reverse proxies / load balancers (e.g.
    /// "10.0.0.0/8"). `X-Forwarded-For` / `X-Real-IP` are honored only when the
    /// direct peer falls in one of these ranges; otherwise the peer socket
    /// address is used as the client identity. Empty (the default) means do not
    /// trust forwarding headers — set this behind a load balancer.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

fn default_window_secs() -> u64 {
    60
}

/// Endpoint classification for rate limiting.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct IdentifierEndpointConfig {
    pub path: String,
    pub body_field: String,
    pub rate: String,
}

/// OIDC discovery config.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct SigningKeyConfig {
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    pub public_key_pem_file: PathBuf,
}

fn default_algorithm() -> String {
    "EdDSA".into()
}

/// Health-probe endpoint configuration.
///
/// Paths are configurable so an embedder can relocate the probes (e.g. behind a
/// `/internal/` prefix) or disable them when a fronting platform supplies its
/// own. Defaults match the conventional `/health*` layout.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct HealthConfig {
    /// Mount the health endpoints. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Aggregate health endpoint. Default: `/health`.
    #[serde(default = "default_health_path")]
    pub path: String,
    /// Liveness probe. Default: `/health/live`.
    #[serde(default = "default_health_live_path")]
    pub live_path: String,
    /// Readiness probe (checks the upstream gRPC health). Default: `/health/ready`.
    #[serde(default = "default_health_ready_path")]
    pub ready_path: String,
    /// Startup probe. Default: `/health/startup`.
    #[serde(default = "default_health_startup_path")]
    pub startup_path: String,
}

fn default_health_path() -> String {
    "/health".into()
}
fn default_health_live_path() -> String {
    "/health/live".into()
}
fn default_health_ready_path() -> String {
    "/health/ready".into()
}
fn default_health_startup_path() -> String {
    "/health/startup".into()
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_health_path(),
            live_path: default_health_live_path(),
            ready_path: default_health_ready_path(),
            startup_path: default_health_startup_path(),
        }
    }
}

/// Prometheus metrics endpoint configuration.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct MetricsConfig {
    /// Mount the metrics endpoint. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Scrape path. Default: `/metrics`.
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_path() -> String {
    "/metrics".into()
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_metrics_path(),
        }
    }
}

/// Maintenance mode config.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct CorsConfig {
    /// Allowed origins. Empty = permissive (dev mode).
    #[serde(default)]
    pub origins: Vec<String>,
}

/// Logging configuration.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct MetricsClassConfig {
    /// Glob pattern for path matching.
    pub pattern: String,
    /// Label value for this class.
    pub class: String,
}

impl ProxyConfig {
    /// Load configuration from a YAML file.
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        Self::from_yaml_str(&std::fs::read_to_string(path)?)
    }

    /// Parse configuration from a YAML string.
    ///
    /// Useful for embedding the proxy: load a baked-in config (e.g. via
    /// `include_str!`) without touching the filesystem.
    pub fn from_yaml_str(yaml: &str) -> anyhow::Result<Self> {
        let config: Self = serde_yaml::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate cross-field constraints that the type system can't express.
    ///
    /// Called automatically by [`from_yaml_str`](Self::from_yaml_str); call it
    /// directly when building a [`ProxyConfig`] programmatically so the same
    /// invariants are enforced on the embedded path.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.streaming.sse_keep_alive_secs == 0 {
            anyhow::bail!("streaming.sse_keep_alive_secs must be greater than 0");
        }
        self.validate_edge_paths()?;
        Ok(())
    }

    /// Reject duplicate built-in edge paths up front, so the router does not
    /// panic at construction registering the same path twice (e.g. setting
    /// `health.path` to the default `live_path`).
    fn validate_edge_paths(&self) -> anyhow::Result<()> {
        let mut seen = std::collections::HashSet::new();
        let mut check = |label: &str, path: &str| -> anyhow::Result<()> {
            if !seen.insert(path.to_string()) {
                anyhow::bail!("duplicate endpoint path {path:?} ({label}); each built-in endpoint must have a distinct path");
            }
            Ok(())
        };
        if self.health.enabled {
            check("health.path", &self.health.path)?;
            check("health.live_path", &self.health.live_path)?;
            check("health.ready_path", &self.health.ready_path)?;
            check("health.startup_path", &self.health.startup_path)?;
        }
        if self.metrics.enabled {
            check("metrics.path", &self.metrics.path)?;
        }
        Ok(())
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
        assert_eq!(config.streaming.sse_keep_alive_secs, 15);
        assert!(config.descriptors.is_empty());
        assert!(config.auth.is_none());
        assert!(config.shield.is_none());
    }

    #[test]
    fn health_and_metrics_defaults_and_overrides() {
        // Defaults: enabled, conventional paths.
        let min: ProxyConfig =
            serde_yaml::from_str("upstream:\n  default: \"grpc://x:1\"\n").unwrap();
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
