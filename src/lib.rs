//! Universal gRPC→REST transcoding proxy.
//!
//! Config-driven: same binary, different YAML = different product proxy.
//! Works with ANY gRPC service via proto descriptors as config.
//!
//! ## Usage
//!
//! ```bash
//! structured-proxy --config sid-proxy.yaml
//! structured-proxy --config sflow-proxy.yaml
//! ```
//!
//! ## JWT verification
//!
//! The bearer-token check sits behind [`hooks::TokenVerifier`]. A build gets one
//! of two:
//!
//! - the **built-in** verifier (keys from `auth.jwt`), whose crypto backend is
//!   picked by a feature: `rust_crypto` (default, pure Rust) or `aws_lc_rs`
//!   (opt-in, constant-time / FIPS-capable, links aws-lc via C FFI). Both may be
//!   compiled in at once — Cargo features are additive, so a dependency graph
//!   with two dependents asking for different backends unifies into exactly that
//!   build. `aws_lc_rs` then wins: it is constant-time and free of the `rsa`
//!   advisory `rust_crypto` carries. [`ProxyServer::from_config`] settles that
//!   choice for the process; a process where another crate may reach
//!   `jsonwebtoken` before any server exists calls
//!   [`install_default_crypto_provider`] from `main` instead.
//! - an **injected** one, supplied by the embedder through
//!   [`ProxyServer::with_token_verifier`]. Since Cargo unifies features across a
//!   whole dependency graph, a backend feature cannot be chosen per binary —
//!   injection is how a consumer that needs a different one gets it without
//!   deciding for everyone else who links this crate. Such a build takes
//!   `default-features = false` and links no JWT crypto at all.
//!
//! ## Outbound TLS
//!
//! JWKS fetches and the rate-limit service go over rustls. The crypto provider
//! is the one the process installed with
//! `rustls::crypto::CryptoProvider::install_default`, else the one the crypto
//! backend feature brings (aws-lc for `aws_lc_rs`, RustCrypto for
//! `rust_crypto`). A build with neither feature links no TLS crypto, and a
//! config that needs an outbound client then fails at startup unless a
//! provider is installed first.

// `builtin_jwt` is implied by each backend and never meant to stand alone: on
// its own it would link jsonwebtoken with no provider, which panics at runtime.
#[cfg(all(
    feature = "builtin_jwt",
    not(any(feature = "rust_crypto", feature = "aws_lc_rs"))
))]
compile_error!(
    "feature `builtin_jwt` needs a crypto backend: enable `rust_crypto` or `aws_lc_rs` \
     (or neither, and inject a verifier with `ProxyServer::with_token_verifier`)"
);

/// The README's Rust examples, compiled as doc tests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub mod auth;
pub mod client_address;
pub mod config;
mod cors;
mod embed;
mod guard;
mod held;
pub mod hooks;
pub mod oidc;
pub mod openapi;
pub mod received;
mod serve;
pub mod service;
pub mod shield;
mod tls;
pub mod transcode;
pub mod upstream;

/// Settle the process-wide JWT crypto provider. See
/// [`install_default_crypto_provider`] for when a call is needed.
#[cfg(feature = "builtin_jwt")]
pub use auth::crypto::install_default_crypto_provider;
pub use client_address::ClientAddress;
pub use received::ReceivedRequest;
pub use serve::{serve, serve_with, serve_with_shutdown, ServeOptions};
pub use service::{ConnectionInfo, ProxyService};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use cors::CorsLayer;
use prost_reflect::DescriptorPool;
use std::net::SocketAddr;
use tower_http::trace::TraceLayer;

use std::sync::Arc;

use config::{DescriptorSource, ProxyConfig, ScopeConfig};
use hooks::{AuthDecider, ExtraRoute, OidcBackend, TokenVerifier};
use upstream::Upstream;

/// What the proxy's handlers share. Every request extracts its own clone, so
/// it holds the upstream handle and reference-counted settings only.
#[derive(Clone, Debug)]
pub(crate) struct ProxyState<U> {
    /// The gRPC service transcoded calls and readiness probes go to.
    pub(crate) upstream: U,
    /// Headers to forward from HTTP to gRPC.
    pub(crate) forwarded_headers: Arc<[String]>,
    /// The same, as header names.
    pub(crate) forwarded_names: Arc<[http::HeaderName]>,
    /// SSE keep-alive interval (seconds) for server-streaming responses.
    pub(crate) sse_keep_alive_secs: u64,
}

/// What [`ProxyServer::routes`] builds.
struct Built {
    /// Every route behind its layers, for a router.
    router: Router,
    /// The choice among the transcoded bindings, made outside the router's
    /// layers; `None` without transcoded routes.
    chooser: Option<transcode::Chooser>,
    /// The transcoded routes served past any router, and the other routes;
    /// `None` without transcoded routes, or when an other route's path is
    /// one they cannot be ranked among.
    direct: Option<(transcode::Direct, Router)>,
    /// The CORS policy the routes answer under.
    cors: CorsLayer,
    /// The guards, for the traffic outside the routes.
    guards: Arc<guard::Guards>,
}

/// Universal proxy server.
pub struct ProxyServer {
    config: ProxyConfig,
    /// Optional pre-loaded descriptor pool (for embedded mode).
    descriptor_pool: Option<DescriptorPool>,
    /// Optional in-process forward-auth/PDP gate (embedded Tier-2 hook).
    auth_decider: Option<Arc<dyn AuthDecider>>,
    /// The traffic the injected decider gates; `transcoded` when unset.
    auth_decider_scope: Option<ScopeConfig>,
    /// Optional stateless OIDC surface backing (embedded Tier-2 hook).
    oidc_backend: Option<Arc<dyn OidcBackend>>,
    /// Embedder-supplied extra stateless routes (embedded Tier-2 hook).
    extra_routes: Vec<ExtraRoute>,
    /// Override for the `/verify` forward-auth path of an injected AuthDecider.
    verify_path: Option<String>,
    /// Embedder-supplied JWT verifier, replacing the built-in one.
    token_verifier: Option<Arc<dyn TokenVerifier>>,
    /// How the transcoded routes render errors and frame NDJSON streams.
    transcode: transcode::TranscodeOptions,
}

impl Default for ProxyServer {
    /// [`ProxyServer::new`]: every capability off.
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyServer {
    /// Create from YAML config file.
    pub fn from_config(config: ProxyConfig) -> Self {
        // Earliest point this crate owns: settle the JWT crypto provider here,
        // long before the first token arrives. A process whose other crates
        // reach jsonwebtoken before any server exists calls
        // `install_default_crypto_provider` from `main` instead.
        #[cfg(feature = "builtin_jwt")]
        auth::crypto::install_default_crypto_provider();

        Self {
            config,
            descriptor_pool: None,
            auth_decider: None,
            auth_decider_scope: None,
            oidc_backend: None,
            extra_routes: Vec::new(),
            verify_path: None,
            token_verifier: None,
            transcode: transcode::TranscodeOptions::default(),
        }
    }

    /// Create from a YAML document: the [`ProxyConfig`] plus the transcoding
    /// settings it does not hold (`error_details:`,
    /// `streaming.ndjson_envelope` and `response_headers:`), applied as
    /// [`with_error_details`], [`with_ndjson_envelope`] and
    /// [`with_denied_response_headers`] would. A top-level or `streaming:` key
    /// no setting reads is logged as a warning.
    ///
    /// # Errors
    ///
    /// Invalid YAML, a [`ProxyConfig`] that fails
    /// [`validate`](ProxyConfig::validate), an `error_details` route pattern
    /// that is relative or not a valid glob, or a `response_headers.deny`
    /// entry that is not a header name.
    ///
    /// [`with_error_details`]: Self::with_error_details
    /// [`with_ndjson_envelope`]: Self::with_ndjson_envelope
    /// [`with_denied_response_headers`]: Self::with_denied_response_headers
    pub fn from_yaml_str(yaml: &str) -> anyhow::Result<Self> {
        let config = ProxyConfig::from_yaml_str(yaml)?;
        for key in config::unknown_config_keys(yaml) {
            tracing::warn!(%key, "unknown config key is ignored");
        }
        let settings: config::TranscodeFileConfig = serde_yaml::from_str(yaml)?;
        let options = settings
            .options()
            .map_err(|e| anyhow::anyhow!("invalid transcoding config: {e}"))?;
        let mut server = Self::from_config(config);
        server.transcode = options;
        Ok(server)
    }

    /// [`from_yaml_str`](Self::from_yaml_str) on the contents of a file.
    ///
    /// # Errors
    ///
    /// The file cannot be read, or its contents are rejected by
    /// [`from_yaml_str`](Self::from_yaml_str).
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        Self::from_yaml_str(&std::fs::read_to_string(path)?)
    }

    /// The configuration this server was created with.
    pub fn config(&self) -> &ProxyConfig {
        &self.config
    }

    /// A proxy with every capability off: native gRPC and gRPC-Web pass to
    /// the upstream, every other request to the fallback (`404` by default).
    /// Turn on what you need with the methods below; each sets the config
    /// section of the same name, so code and YAML describe one proxy.
    ///
    /// # Examples
    ///
    /// ```
    /// use structured_proxy::config::{ConcurrencyConfig, ScopeConfig, Traffic};
    /// use structured_proxy::ProxyServer;
    ///
    /// # fn build() -> anyhow::Result<()> {
    /// // Your gRPC API, with at most 1000 calls in flight and nothing else.
    /// let grpc = tonic::service::Routes::default();
    /// let service = ProxyServer::new()
    ///     .with_concurrency_limit(
    ///         ConcurrencyConfig::new(1000).with_scope(ScopeConfig::traffic([Traffic::Grpc])),
    ///     )
    ///     .service(grpc)?;
    /// # let _ = service;
    /// # Ok(())
    /// # }
    /// # build().unwrap();
    /// ```
    pub fn new() -> Self {
        let mut config = ProxyConfig::default();
        config.health.enabled = false;
        config.metrics.enabled = false;
        Self::from_config(config)
    }

    /// The remote gRPC upstream (`upstream.default`), for
    /// [`upstream`](Self::upstream) and [`serve`](Self::serve).
    pub fn with_upstream_address(mut self, address: impl Into<String>) -> Self {
        self.config.upstream = Some(config::UpstreamConfig {
            default: address.into(),
        });
        self
    }

    /// The listener of [`serve`](Self::serve): address, TLS, connection
    /// limit (`listen:`).
    pub fn with_listen(mut self, listen: config::ListenConfig) -> Self {
        self.config.listen = listen;
        self
    }

    /// Transcode only these services (`package.Service`) and methods
    /// (`package.Service/Method`) of the descriptors (`transcode.only`); every
    /// annotated RPC by default. A name the descriptors do not hold fails the
    /// build.
    pub fn with_transcoded_rpcs(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.config.transcode.only = names.into_iter().map(Into::into).collect();
        self
    }

    /// Path aliases rewritten before routing (`aliases:`).
    pub fn with_aliases(mut self, aliases: impl IntoIterator<Item = config::AliasConfig>) -> Self {
        self.config.aliases = aliases.into_iter().collect();
        self
    }

    /// The request headers transcoded calls forward as gRPC metadata
    /// (`forwarded_headers:`), replacing the default list.
    pub fn with_forwarded_headers(
        mut self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.config.forwarded_headers = names.into_iter().map(Into::into).collect();
        self
    }

    /// Health probe endpoints (`health:`).
    pub fn with_health(mut self, health: config::HealthConfig) -> Self {
        self.config.health = health;
        self
    }

    /// The Prometheus metrics endpoint (`metrics:`).
    pub fn with_metrics(mut self, metrics: config::MetricsConfig) -> Self {
        self.config.metrics = metrics;
        self
    }

    /// The OpenAPI spec and docs endpoints (`openapi:`).
    pub fn with_openapi(mut self, openapi: config::OpenApiConfig) -> Self {
        self.config.openapi = Some(openapi);
        self
    }

    /// Static OIDC discovery and JWKS endpoints (`oidc_discovery:`).
    pub fn with_oidc_discovery(mut self, oidc: config::OidcDiscoveryConfig) -> Self {
        self.config.oidc_discovery = Some(oidc);
        self
    }

    /// The CORS policy (`cors:`).
    pub fn with_cors(mut self, cors: config::CorsConfig) -> Self {
        self.config.cors = cors;
        self
    }

    /// Translate gRPC-Web to gRPC for an upstream that speaks only gRPC
    /// (`grpc_web.translate`).
    pub fn with_grpc_web_translation(mut self, translate: bool) -> Self {
        self.config.grpc_web.translate = translate;
        self
    }

    /// Server-streaming behavior (`streaming:`).
    pub fn with_streaming(mut self, streaming: config::StreamingConfig) -> Self {
        self.config.streaming = streaming;
        self
    }

    /// Maintenance mode (`maintenance:`).
    pub fn with_maintenance(mut self, maintenance: config::MaintenanceConfig) -> Self {
        self.config.maintenance = maintenance;
        self
    }

    /// The limit on requests in flight (`concurrency:`).
    pub fn with_concurrency_limit(mut self, concurrency: config::ConcurrencyConfig) -> Self {
        self.config.concurrency = Some(concurrency);
        self
    }

    /// How the client's address is resolved (`client_address:`): the proxies
    /// trusted to report it and the header they use. Every consumer reads the
    /// result, the rate limits as much as the upstream.
    ///
    /// # Examples
    ///
    /// ```
    /// use structured_proxy::config::{ClientAddressConfig, ForwardingHeader};
    /// use structured_proxy::ProxyServer;
    ///
    /// # fn build() -> anyhow::Result<()> {
    /// // Behind a load balancer in 10.0.0.0/8 that appends to X-Forwarded-For.
    /// let mut client_address = ClientAddressConfig::default();
    /// client_address.trusted_proxies = vec!["10.0.0.0/8".into()];
    /// client_address.header = ForwardingHeader::XForwardedFor;
    /// client_address.required = true;
    /// let service = ProxyServer::new()
    ///     .with_client_address(client_address)
    ///     .service(tonic::service::Routes::default())?;
    /// # let _ = service;
    /// # Ok(())
    /// # }
    /// # build().unwrap();
    /// ```
    pub fn with_client_address(mut self, client_address: config::ClientAddressConfig) -> Self {
        self.config.client_address = client_address;
        self
    }

    /// Rate limits (`shield:`); build the section with [`config::from_yaml`].
    pub fn with_rate_limits(mut self, shield: config::ShieldConfig) -> Self {
        self.config.shield = Some(shield);
        self
    }

    /// JWT auth, route policies, forward-auth and ext_authz (`auth:`); build
    /// the section with [`config::from_yaml`].
    pub fn with_auth(mut self, auth: config::AuthConfig) -> Self {
        self.config.auth = Some(auth);
        self
    }

    /// Create with an embedded descriptor pool (for sid-proxy backward compat).
    pub fn with_descriptors(mut self, pool: DescriptorPool) -> Self {
        self.descriptor_pool = Some(pool);
        self
    }

    /// Inject an in-process forward-auth / PDP decision (embedded Tier-2 hook).
    ///
    /// The decider gates the transcoded requests inline (other traffic with
    /// [`with_auth_decider_scope`](Self::with_auth_decider_scope)) and also
    /// backs the `/verify` forward-auth endpoint. Its signature is `axum`-free
    /// (see [`hooks::AuthDecider`]), so the embedder never names an HTTP
    /// framework.
    pub fn with_auth_decider(mut self, decider: Arc<dyn AuthDecider>) -> Self {
        self.auth_decider = Some(decider);
        self
    }

    /// Choose the traffic the injected [`AuthDecider`] gates, `transcoded`
    /// by default; the `/verify` endpoint is never behind it, since it answers
    /// for the decider.
    ///
    /// # Examples
    ///
    /// ```
    /// use structured_proxy::config::{ScopeConfig, Traffic};
    /// use structured_proxy::ProxyServer;
    ///
    /// # fn build() -> anyhow::Result<()> {
    /// // Gate native gRPC calls as well as the transcoded ones.
    /// let server = ProxyServer::from_yaml_str("service:\n  name: demo\n")?
    ///     .with_auth_decider_scope(ScopeConfig::traffic([Traffic::Transcoded, Traffic::Grpc]));
    /// # let _ = server;
    /// # Ok(())
    /// # }
    /// # build().unwrap();
    /// ```
    pub fn with_auth_decider_scope(mut self, scope: ScopeConfig) -> Self {
        self.auth_decider_scope = Some(scope);
        self
    }

    /// Back the stateless OIDC surface (discovery, JWKS, userinfo) with the
    /// embedder's key/client metadata (embedded Tier-2 hook).
    ///
    /// When set, this supersedes the config-driven static `oidc_discovery`
    /// routes. See [`hooks::OidcBackend`].
    pub fn with_oidc_backend(mut self, backend: Arc<dyn OidcBackend>) -> Self {
        self.oidc_backend = Some(backend);
        self
    }

    /// Register extra stateless routes through an `axum`-free adapter (embedded
    /// Tier-2 hook). See [`hooks::ExtraRoute`] / [`hooks::ExtraRouteHandler`].
    pub fn with_extra_routes(mut self, routes: impl IntoIterator<Item = ExtraRoute>) -> Self {
        self.extra_routes.extend(routes);
        self
    }

    /// Set the path at which the injected [`AuthDecider`] answers forward-auth
    /// sub-requests (`/verify`). Independent of any JWT `forward_auth` config, so
    /// a decider-only embedder can place it without a JWT block.
    ///
    /// Resolution order for the path: this override, then
    /// `auth.forward_auth.path` from config, then the default `/auth/verify`.
    pub fn with_verify_path(mut self, path: impl Into<String>) -> Self {
        self.verify_path = Some(path.into());
        self
    }

    /// Verify bearer tokens with the embedder's own verifier instead of the
    /// built-in one (embedded Tier-2 hook).
    ///
    /// The JWT middleware keeps everything around the signature check — route
    /// policies, the roles claim, claim→header forwarding — and takes the
    /// verdict from [`hooks::TokenVerifier`]. Use this when the built-in crypto
    /// backend is not the one this binary needs: a validated / FIPS module, an
    /// HSM, or a verifier the embedder already owns. It is also the way out of
    /// Cargo's feature unification, which makes `rust_crypto` / `aws_lc_rs` a
    /// property of the whole dependency graph rather than of one binary.
    ///
    /// `auth.mode` must still be `"jwt"` for the middleware to run; `auth.jwt`
    /// then only configures claim forwarding, and any key source in it is
    /// ignored (with a warning), since the verifier owns its own keys.
    pub fn with_token_verifier(mut self, verifier: Arc<dyn TokenVerifier>) -> Self {
        self.token_verifier = Some(verifier);
        self
    }

    /// Choose which transcoded routes return the upstream's
    /// `google.rpc.Status` details in their error bodies. Every route does by
    /// default; see [`transcode::error::ErrorDetailsPolicy`] to switch them
    /// off globally or per route.
    pub fn with_error_details(mut self, policy: transcode::error::ErrorDetailsPolicy) -> Self {
        self.transcode = self.transcode.with_error_details(policy);
        self
    }

    /// Wrap NDJSON stream lines in `{"result"}` / `{"error"}` envelopes; see
    /// [`transcode::TranscodeOptions::with_ndjson_envelope`].
    pub fn with_ndjson_envelope(mut self, enabled: bool) -> Self {
        self.transcode = self.transcode.with_ndjson_envelope(enabled);
        self
    }

    /// Keep these upstream response metadata keys off the HTTP responses of
    /// the transcoded routes; see
    /// [`transcode::TranscodeOptions::with_denied_response_headers`].
    pub fn with_denied_response_headers(
        mut self,
        names: impl IntoIterator<Item = http::HeaderName>,
    ) -> Self {
        self.transcode = self.transcode.with_denied_response_headers(names);
        self
    }

    /// Load descriptor pool from configured sources.
    ///
    /// Multiple descriptor files are merged into a single pool,
    /// enabling multi-service proxying from one binary.
    fn load_descriptors(&self) -> anyhow::Result<DescriptorPool> {
        if let Some(pool) = &self.descriptor_pool {
            return Ok(pool.clone());
        }

        let mut pool = DescriptorPool::new();

        for source in &self.config.descriptors {
            match source {
                DescriptorSource::File { file } => {
                    let bytes = std::fs::read(file).map_err(|e| {
                        anyhow::anyhow!("Failed to read descriptor file {:?}: {}", file, e)
                    })?;
                    pool.decode_file_descriptor_set(bytes.as_slice())
                        .map_err(|e| {
                            anyhow::anyhow!("Failed to decode descriptor file {:?}: {}", file, e)
                        })?;
                    tracing::info!("Loaded descriptor from {:?}", file);
                }
                DescriptorSource::Reflection { reflection } => {
                    tracing::warn!(
                        "gRPC reflection client not supported — use descriptor files instead (reflection endpoint: {})",
                        reflection
                    );
                }
                DescriptorSource::Embedded { bytes } => {
                    pool.decode_file_descriptor_set(*bytes).map_err(|e| {
                        anyhow::anyhow!("Failed to decode embedded descriptors: {}", e)
                    })?;
                }
            }
        }

        Ok(pool)
    }

    /// The path an injected [`AuthDecider`] answers `/verify` at: the
    /// `with_verify_path` override, then `auth.forward_auth.path`, then the
    /// default `/auth/verify`. Only meaningful when a decider is set (the
    /// override does not apply to config-driven JWT forward-auth).
    fn decider_verify_path(&self) -> String {
        self.verify_path.clone().unwrap_or_else(|| {
            self.config
                .auth
                .as_ref()
                .and_then(|a| a.forward_auth.as_ref())
                .map(|fa| fa.path.clone())
                .unwrap_or_else(|| "/auth/verify".to_string())
        })
    }

    /// The verify path that is ACTUALLY mounted, or `None` when no verify route
    /// is mounted. This is what the collision guard and maintenance-exempt list
    /// must use, since the two mount sites use different paths:
    /// - an injected decider mounts at [`decider_verify_path`](Self::decider_verify_path)
    ///   (the `with_verify_path` override applies), whereas
    /// - config-driven JWT forward-auth mounts `forward_auth.routes()` at
    ///   `auth.forward_auth.path` (the override does NOT apply, and it mounts
    ///   only when `auth.mode == "jwt"`, since the endpoint shares the built JWT
    ///   `Auth`).
    fn mounted_verify_path(&self) -> Option<String> {
        if self.auth_decider.is_some() {
            return Some(self.decider_verify_path());
        }
        self.config.auth.as_ref().and_then(|a| {
            if a.mode != "jwt" {
                return None;
            }
            a.forward_auth
                .as_ref()
                .filter(|fa| fa.enabled)
                .map(|fa| fa.path.clone())
        })
    }

    /// Every `(method, path)` route of the proxy's own endpoints and the
    /// embedder's extra routes, the verify endpoint aside. With the
    /// transcoded routes, it checks the mounted edge for a real collision,
    /// reported as a clear error instead of an axum duplicate-route panic,
    /// and ranks the transcoded paths among the others for the proxy
    /// service. `method` is the uppercase HTTP token; same-path routes with
    /// different methods do NOT collide (the extra-route adapter and axum
    /// merge them), so the key is the pair, not the path alone.
    ///
    /// Must stay exhaustive: health probes, metrics, OpenAPI spec/docs, the OIDC
    /// surface (injected backend or config-driven static discovery) and
    /// embedder extra routes. All built-in surfaces here are `GET`.
    fn endpoint_routes(&self) -> anyhow::Result<Vec<(String, String)>> {
        let mut routes = Vec::new();
        let mut get = |path: String| routes.push(("GET".to_string(), path));
        if self.config.health.enabled {
            get(self.config.health.path.clone());
            get(self.config.health.live_path.clone());
            get(self.config.health.ready_path.clone());
            get(self.config.health.startup_path.clone());
        }
        if self.config.metrics.enabled {
            get(self.config.metrics.path.clone());
        }
        if let Some(openapi) = self.config.openapi.as_ref().filter(|o| o.enabled) {
            get(openapi.path.clone());
            get(openapi.docs_path.clone());
        }
        // OIDC: an injected backend supersedes config-driven static discovery.
        if let Some(backend) = &self.oidc_backend {
            for doc in backend.metadata_documents() {
                get(doc.path);
            }
            get(backend.jwks().path);
            get(backend.userinfo_path());
        } else if let Some(cfg) = &self.config.oidc_discovery {
            if let Some(oidc) = oidc::Oidc::build(cfg)
                .map_err(|e| anyhow::anyhow!("invalid oidc_discovery config: {e}"))?
            {
                for path in oidc.paths() {
                    get(path);
                }
            }
        }
        for route in &self.extra_routes {
            routes.push((route.method.as_str().to_string(), route.path.clone()));
        }
        Ok(routes)
    }

    /// A lazy channel to the configured upstream address (`upstream.default`),
    /// the upstream of the standalone proxy. It connects on first use, giving
    /// up after five seconds.
    ///
    /// # Errors
    ///
    /// No upstream address is configured, or it is not a valid URI.
    pub fn upstream(&self) -> anyhow::Result<tonic::transport::Channel> {
        let Some(upstream) = &self.config.upstream else {
            anyhow::bail!("no gRPC upstream address is configured (upstream.default)");
        };
        Ok(
            tonic::transport::Channel::from_shared(upstream.default.clone())
                .map_err(|e| anyhow::anyhow!("invalid gRPC upstream URL: {e}"))?
                .connect_timeout(std::time::Duration::from_secs(5))
                .connect_lazy(),
        )
    }

    /// The proxy's HTTP routes in front of the configured upstream address
    /// (see [`upstream`](Self::upstream)), as an axum `Router` to serve or to
    /// merge into an axum application. It answers HTTP only; use
    /// [`service`](Self::service) for native gRPC on the same listener, or for
    /// an upstream in process.
    ///
    /// A URL whose path a transcoded route matches but which no binding
    /// answers (its field template or custom verb does not fit) goes to the
    /// proxy's other routes, extra routes included, and is answered `404`
    /// when none of them answers it. An axum router routes a request to one
    /// route, so routes merged after this one are not tried for it: serve the
    /// application's own routes through
    /// [`with_extra_routes`](Self::with_extra_routes), or use
    /// [`service`](Self::service) with
    /// [`with_fallback`](ProxyService::with_fallback).
    ///
    /// # Errors
    ///
    /// No valid upstream address, or a configuration [`service`](Self::service)
    /// rejects.
    pub fn router(&self) -> anyhow::Result<Router> {
        let Built {
            router, chooser, ..
        } = self.routes(self.upstream()?)?;
        Ok(match chooser {
            Some(chooser) => chooser.layer(router),
            None => router,
        })
    }

    /// The whole proxy as one tower service in front of `upstream`: native
    /// gRPC requests reach `upstream` unchanged, every other request the
    /// proxy's routes, whose transcoded calls go to `upstream` too. See
    /// [`ProxyService`].
    ///
    /// `upstream` is any gRPC service ([`upstream::Upstream`]): the embedder's
    /// own tonic services in process, with no socket between them and the
    /// proxy, or a remote [`Channel`](tonic::transport::Channel) such as
    /// [`upstream`](Self::upstream).
    ///
    /// # Errors
    ///
    /// An invalid configuration (see [`ProxyConfig::validate`]), descriptors
    /// that cannot be loaded, a route mounted twice, or a malformed auth,
    /// authz, shield or OIDC section.
    ///
    /// # Examples
    ///
    /// ```
    /// use structured_proxy::ProxyServer;
    ///
    /// # fn build() -> anyhow::Result<()> {
    /// let grpc = tonic::service::Routes::default(); // add your services here
    /// let service = ProxyServer::from_yaml_str("service:\n  name: demo\n")?.service(grpc)?;
    /// # let _ = service;
    /// # Ok(())
    /// # }
    /// # build().unwrap();
    /// ```
    pub fn service<U: Upstream>(&self, upstream: U) -> anyhow::Result<ProxyService<U>> {
        let Built {
            router,
            chooser,
            direct,
            cors,
            guards,
        } = self.routes(upstream.clone())?;
        // The routes answer a browser's preflight for gRPC-Web too, so its
        // call carries the same policy unless the upstream sets its own.
        let grpc_web_cors = self.config.cors.grpc_web.then_some(cors);
        let routing = match direct {
            Some((direct, others)) => service::Routing::Direct { direct, others },
            None => service::Routing::routed(router, chooser),
        };
        Ok(ProxyService::new(
            upstream,
            routing,
            grpc_web_cors,
            guards,
            self.config.grpc_web.translate,
        ))
    }

    /// Build the axum router with all endpoints, calling `upstream`; the
    /// choice among its transcoded bindings, made before its layers; the CORS
    /// policy it answers under; and the guards, for the traffic outside it.
    fn routes<U: Upstream>(&self, upstream: U) -> anyhow::Result<Built> {
        // Enforce cross-field invariants on the embedded path too, where the
        // config is built directly instead of through `from_yaml_str`.
        self.config.validate()?;
        let pool = self.load_descriptors()?;
        let selection = transcode::RpcSelection::new(&pool, &self.config.transcode.only)
            .map_err(|e| anyhow::anyhow!("invalid transcode.only: {e}"))?;

        let service_name = self.config.service.name.clone();

        // The verify path that is actually mounted (branch-correct), if any.
        let verify_path = self.mounted_verify_path();

        // Validate the WHOLE mounted edge BEFORE any router is built, so a
        // malformed path (missing leading '/') or a collision (between built-in
        // routes, the OIDC surface, embedder extra routes, transcoded paths, or
        // the verify endpoint) is a clear error instead of an axum panic at
        // `.route`/`.merge`. Collisions are keyed by (method, path): same-path
        // routes with different methods are legal (they merge), so only a
        // repeated (method, path) — or any overlap with the verify endpoint,
        // which answers ALL methods (`*`) — is a real conflict.
        let endpoints_mounted = self.endpoint_routes()?;
        let mut mounted = endpoints_mounted.clone();
        mounted.extend(transcode::route_paths(
            &pool,
            &self.config.aliases,
            &selection,
        ));
        if let Some(vp) = &verify_path {
            mounted.push(("*".to_string(), vp.clone()));
        }
        // Key by NORMALIZED shape, not raw text: axum/matchit treats two dynamic
        // routes with the same structure but different param names (e.g.
        // `/v1/x/{a}` and `/v1/x/{b}`) as a conflict, so they must collide here.
        let mut methods_by_shape: std::collections::HashMap<
            String,
            std::collections::HashSet<&str>,
        > = std::collections::HashMap::new();
        for (method, path) in &mounted {
            if !path.starts_with('/') {
                anyhow::bail!("route path {path:?} must start with '/'");
            }
            let methods = methods_by_shape
                .entry(normalize_route_shape(path))
                .or_default();
            // `*` (the verify endpoint) claims every method, so it conflicts with
            // any other route on the same shape, and vice versa.
            let conflict = if method == "*" {
                !methods.is_empty()
            } else {
                methods.contains("*") || methods.contains(method.as_str())
            };
            if conflict {
                anyhow::bail!("route path {path:?} is registered by more than one endpoint");
            }
            methods.insert(method.as_str());
        }

        // Keep the actually-configured probe / metrics / verify paths reachable
        // under maintenance mode. The default exempt list names the default
        // paths; once those are relocated via config, the relocated paths must
        // be exempted too, or maintenance would 503 probe and forward-auth
        // traffic that was intentionally exempt before.
        let mut maintenance_exempt = self.config.maintenance.exempt_paths.clone();
        if self.config.health.enabled {
            maintenance_exempt.push(self.config.health.path.clone());
            maintenance_exempt.push(self.config.health.live_path.clone());
            maintenance_exempt.push(self.config.health.ready_path.clone());
            maintenance_exempt.push(self.config.health.startup_path.clone());
        }
        if self.config.metrics.enabled {
            maintenance_exempt.push(self.config.metrics.path.clone());
        }
        if let Some(vp) = &verify_path {
            maintenance_exempt.push(vp.clone());
        }

        // A forwarded name gRPC metadata cannot carry would be rejected by a
        // conforming upstream on every request; refuse it here instead.
        if let Some(name) = self
            .config
            .forwarded_headers
            .iter()
            .find(|name| !transcode::metadata::is_grpc_key(name))
        {
            anyhow::bail!(
                "forwarded_headers entry {name:?} is not a gRPC metadata key \
                 (letters, digits, '_', '-' and '.')"
            );
        }

        let resolver = Arc::new(
            client_address::Resolver::build(&self.config.client_address)
                .map_err(|e| anyhow::anyhow!("invalid client_address config: {e}"))?,
        );
        // The client-address headers reach a transcoded call as the
        // forwarding policy wrote them on the request, whatever the list
        // says; the rest of the list is forwarded as configured.
        let forwarded_headers: Arc<[String]> = self
            .config
            .forwarded_headers
            .iter()
            .filter(|name| !resolver.reserves(name))
            .cloned()
            .chain(resolver.forwarded_headers().map(str::to_owned))
            .collect();
        // Parsed once rather than for every request; every entry is a gRPC
        // metadata key, so a header name.
        let forwarded_names = forwarded_headers
            .iter()
            .filter_map(|name| http::HeaderName::from_bytes(name.as_bytes()).ok())
            .collect();
        let state = ProxyState {
            upstream,
            forwarded_headers,
            forwarded_names,
            sse_keep_alive_secs: self.config.streaming.sse_keep_alive_secs,
        };

        let cors = self.build_cors()?;

        // Build transcoding routes from descriptor pool.
        let (transcode_routes, choices) = transcode::routes_and_choices(
            &pool,
            &self.config.aliases,
            &self.transcode.clone().with_selection(selection.clone()),
        );

        // JWT auth, if configured (auth.mode == "jwt").
        let auth = match &self.config.auth {
            Some(cfg) => auth::Auth::build(cfg, self.token_verifier.clone())
                .map_err(|e| anyhow::anyhow!("invalid auth config: {e}"))?,
            None => None,
        };
        // Forward-auth verification endpoint, sharing the built Auth.
        let forward_auth = auth.as_ref().and_then(|built| {
            auth::forward::ForwardAuth::build(self.config.auth.as_ref()?, built.clone())
        });
        // The methods a route answers: `*` is not a method. It marks the
        // verify endpoint and a `custom` `*` rule, which answer every method,
        // and a transcoded path with verbs, whose bindings still name theirs.
        let mut methods: Vec<http::Method> = mounted
            .iter()
            .filter(|(method, _)| method != "*")
            .filter_map(|(method, _)| http::Method::from_bytes(method.as_bytes()).ok())
            .collect();
        let bound = transcode::bound_methods(&pool, &self.config.aliases, &selection);
        methods.extend(bound.methods);
        let mut routed = guard::Routed::new(&methods);
        if bound.every {
            routed = routed.every(guard::Class::Transcoded);
        }
        if verify_path.is_some() {
            routed = routed.every(guard::Class::Verify);
        }
        let guards = Arc::new(self.guards(resolver, auth, maintenance_exempt, routed)?);

        // Health routes. Paths are configurable; the whole group is skippable.
        let health_routes = if self.config.health.enabled {
            let health = &self.config.health;
            let health_service_name = service_name.clone();
            Router::new()
                .route(
                    &health.path,
                    get({
                        let name = health_service_name.clone();
                        move || async move {
                            Json(serde_json::json!({
                                "status": "ok",
                                "service": name,
                            }))
                        }
                    }),
                )
                .route(&health.live_path, get(|| async { StatusCode::OK }))
                .route(
                    &health.ready_path,
                    get(|State(state): State<ProxyState<U>>| async move {
                        let mut client =
                            tonic_health::pb::health_client::HealthClient::new(state.upstream);
                        let check = client.check(tonic_health::pb::HealthCheckRequest {
                            service: String::new(),
                        });
                        // An upstream that does not answer in time is not ready.
                        match tokio::time::timeout(transcode::UPSTREAM_DEADLINE, check)
                            .await
                            .unwrap_or_else(|_| {
                                Err(tonic::Status::deadline_exceeded("health check timed out"))
                            }) {
                            Ok(resp) => {
                                let status = resp.into_inner().status;
                                if status
                                    == tonic_health::pb::health_check_response::ServingStatus::Serving
                                        as i32
                                {
                                    StatusCode::OK
                                } else {
                                    StatusCode::SERVICE_UNAVAILABLE
                                }
                            }
                            Err(_) => StatusCode::SERVICE_UNAVAILABLE,
                        }
                    }),
                )
                .route(&health.startup_path, get(|| async { StatusCode::OK }))
        } else {
            Router::new()
        };

        // Metrics route. Path is configurable; the endpoint is skippable.
        let metrics_routes = if self.config.metrics.enabled {
            Router::new().route(
                &self.config.metrics.path,
                get(|| async {
                    let encoder = prometheus::TextEncoder::new();
                    let metric_families = prometheus::default_registry().gather();
                    match encoder.encode_to_string(&metric_families) {
                        Ok(text) => (
                            StatusCode::OK,
                            [(
                                axum::http::header::CONTENT_TYPE,
                                "text/plain; version=0.0.4; charset=utf-8",
                            )],
                            text,
                        )
                            .into_response(),
                        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                    }
                }),
            )
        } else {
            Router::new()
        };

        // OpenAPI + docs routes (if enabled).
        let openapi_routes = self.build_openapi_routes(&pool, &selection);

        // OIDC routes (public, like the health endpoints). An injected
        // OidcBackend supersedes the config-driven static discovery: the proxy
        // hosts the HTTP surface, the embedder supplies the content.
        let oidc_routes = match &self.oidc_backend {
            Some(backend) => embed::oidc_backend_routes(backend.clone()),
            None => match &self.config.oidc_discovery {
                Some(cfg) => oidc::Oidc::build(cfg)
                    .map_err(|e| anyhow::anyhow!("invalid oidc_discovery config: {e}"))?
                    .map(|o| o.routes())
                    .unwrap_or_default(),
                None => Router::new(),
            },
        };

        let endpoints = Router::new()
            .merge(health_routes)
            .merge(metrics_routes)
            .merge(openapi_routes)
            .merge(oidc_routes)
            .merge(embed::extra_routes_router(&self.extra_routes));

        // Forward-auth `/verify` endpoint. An injected AuthDecider owns it when
        // present (in-process PDP); otherwise the config-driven JWT ForwardAuth
        // backs it. Its path was validated above.
        let verify = if let Some(decider) = &self.auth_decider {
            let decider = decider.clone();
            Router::new().route(
                &self.decider_verify_path(),
                axum::routing::any(move |req: axum::extract::Request| {
                    let decider = decider.clone();
                    async move { embed::verify_via_decider(decider, req).await }
                }),
            )
        } else if let Some(forward_auth) = &forward_auth {
            forward_auth.routes()
        } else {
            Router::new()
        };

        // Each class of traffic behind the guards that cover it, so a request
        // runs only the guards of its own class. A path no route answers
        // reaches the plain 404 (or the fallback's own guards).
        let endpoints = guards.router(endpoints, guard::Class::Endpoints);
        let verify = guards.router(verify, guard::Class::Verify);
        // One stack, outermost first, applied at once: each layer applied on
        // its own would box every route again, and the router clones a
        // route's boxes for every request.
        let layered = |router: Router<ProxyState<U>>| {
            router.layer((
                // Every request, preflights included.
                TraceLayer::new_for_http(),
                // Wraps every enforcement layer so short-circuited responses
                // keep CORS headers, and answers preflight before auth.
                cors.clone(),
                // Before every guard: they and the handlers read its result.
                client_address::ClientAddressLayer::with(guards.client_address.clone()),
            ))
        };
        let router = layered(
            Router::new()
                .merge(guards.router(transcode_routes, guard::Class::Transcoded))
                .merge(endpoints.clone())
                .merge(verify.clone()),
        );
        // The binding is chosen before every layer: a URL no binding answers
        // (its field template, its custom verb) is no transcoded request. It
        // goes to the proxy's other routes, which a router without the
        // transcoded ones ranks for it, and on to the fallback (or the plain
        // 404) when none answers it either, past the layers like any path no
        // route answers.
        let elsewhere =
            layered(Router::new().merge(endpoints).merge(verify)).with_state(state.clone());
        // Served by the proxy service, the transcoded routes are matched by
        // the proxy itself, among the paths of every other route, and reached
        // behind the same layers past any router.
        let direct = choices.as_ref().and_then(|choices| {
            let mut others: Vec<(Option<http::Method>, String)> = endpoints_mounted
                .iter()
                .map(|(method, path)| {
                    (
                        http::Method::from_bytes(method.as_bytes()).ok(),
                        path.clone(),
                    )
                })
                .collect();
            if let Some(path) = &verify_path {
                others.push((None, path.clone()));
            }
            let layered = |service: guard::BoxedService| {
                guard::BoxedService::new(
                    tower::ServiceBuilder::new()
                        .map_response(|response: http::Response<_>| {
                            response.map(axum::body::Body::new)
                        })
                        .layer((
                            TraceLayer::new_for_http(),
                            cors.clone(),
                            client_address::ClientAddressLayer::with(guards.client_address.clone()),
                        ))
                        .service(guards.service(service, guard::Class::Transcoded)),
                )
            };
            let direct = choices.direct(state.clone(), &others, layered)?;
            Some((direct, elsewhere.clone()))
        });
        let chooser = choices.map(|choices| choices.with_elsewhere(elsewhere.clone()));
        let router = router.with_state(state);

        Ok(Built {
            router,
            chooser,
            direct,
            cors,
            guards,
        })
    }

    /// The guards the configuration and the hooks turn on, each with its
    /// scope, after the client-address resolution `resolver`;
    /// `maintenance_exempt` lists the paths maintenance mode leaves
    /// reachable, `routed` the methods the routes answer.
    ///
    /// # Errors
    ///
    /// A malformed shield, authz or concurrency section, a JWT claim mapped
    /// onto a header the client-address forwarding writes, or a scope that
    /// covers no traffic, names an invalid path glob or an invalid method.
    fn guards(
        &self,
        resolver: Arc<client_address::Resolver>,
        auth: Option<Arc<auth::Auth>>,
        maintenance_exempt: Vec<String>,
        routed: guard::Routed<'_>,
    ) -> anyhow::Result<guard::Guards> {
        use config::Traffic::{Endpoints, Grpc, Transcoded};
        let scope = |config: Option<&ScopeConfig>, default: &[config::Traffic], what: &str| {
            guard::Scope::compile(config, default, what, routed).map_err(anyhow::Error::msg)
        };
        // A guard never sets what the client-address forwarding writes.
        let reserved: Arc<[http::HeaderName]> = resolver.configured_headers().cloned().collect();
        if let Some(header) = self
            .config
            .auth
            .as_ref()
            .and_then(|auth| auth.jwt.as_ref())
            .and_then(|jwt| jwt.claims_headers.values().find(|h| resolver.reserves(h)))
        {
            anyhow::bail!(
                "auth.jwt.claims_headers maps a claim onto {header:?}, which the \
                 client_address forwarding writes"
            );
        }
        let mut guards = guard::Guards {
            client_address: resolver,
            ..Default::default()
        };
        if guards.client_address.required() {
            guards.require_client = Some(scope(None, &[config::Traffic::All], "client_address")?);
        }
        // Mounted only while maintenance is on, so normal traffic pays nothing
        // for it.
        let maintenance = &self.config.maintenance;
        if maintenance.enabled {
            guards.maintenance = Some((
                Arc::new(guard::Maintenance {
                    exempt: maintenance_exempt,
                    message: maintenance.message.clone(),
                }),
                scope(
                    maintenance.scope.as_ref(),
                    &[Transcoded, Endpoints],
                    "maintenance",
                )?,
            ));
        }
        if let Some(cfg) = &self.config.concurrency {
            guards.concurrency = Some((
                guard::Concurrency::build(cfg).map_err(anyhow::Error::msg)?,
                // The proxy's own endpoints stay out by default: a health
                // probe refused under load gets a busy instance restarted.
                scope(cfg.scope.as_ref(), &[Transcoded, Grpc], "concurrency")?,
            ));
        }
        if let Some(cfg) = &self.config.shield {
            if let Some(shield) = shield::Shield::build(cfg)
                .map_err(|e| anyhow::anyhow!("invalid shield config: {e}"))?
            {
                guards.shield = Some((
                    shield,
                    scope(cfg.scope.as_ref(), &[Transcoded, Endpoints], "shield")?,
                ));
            }
        }
        let auth_config = self.config.auth.as_ref();
        if let Some(auth) = auth {
            guards.auth = Some((
                auth,
                scope(
                    auth_config.and_then(|a| a.scope.as_ref()),
                    &[Transcoded, Endpoints],
                    "auth",
                )?,
            ));
        }
        if let Some(cfg) = auth_config.and_then(|a| a.authz.as_ref()) {
            if let Some(authz) = auth::authz::Authz::build_reserving(cfg, reserved.clone())
                .map_err(|e| anyhow::anyhow!("invalid authz config: {e}"))?
            {
                guards.authz = Some((
                    authz,
                    scope(cfg.scope.as_ref(), &[Transcoded], "auth.authz")?,
                ));
            }
        }
        if let Some(decider) = &self.auth_decider {
            guards.decider = Some((
                Arc::new(embed::DeciderGate {
                    decider: decider.clone(),
                    reserved,
                }),
                scope(
                    self.auth_decider_scope.as_ref(),
                    &[Transcoded],
                    "auth_decider",
                )?,
            ));
        }
        Ok(guards)
    }

    fn build_openapi_routes<S>(
        &self,
        pool: &DescriptorPool,
        selection: &transcode::RpcSelection,
    ) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let openapi_config = match &self.config.openapi {
            Some(cfg) if cfg.enabled => cfg,
            _ => return Router::new(),
        };

        let spec = openapi::generate(pool, openapi_config, &self.config.aliases, selection);
        let spec_json = serde_json::to_string_pretty(&spec).unwrap_or_default();
        let openapi_path = openapi_config.path.clone();
        let docs_path = openapi_config.docs_path.clone();
        let title = openapi_config
            .title
            .clone()
            .unwrap_or_else(|| self.config.service.name.clone());
        let openapi_path_for_docs = openapi_path.clone();

        tracing::info!("OpenAPI spec at {}, docs at {}", openapi_path, docs_path,);

        Router::new()
            .route(
                &openapi_path,
                get(move || async move {
                    (
                        StatusCode::OK,
                        [(
                            axum::http::header::CONTENT_TYPE,
                            "application/json; charset=utf-8",
                        )],
                        spec_json,
                    )
                }),
            )
            .route(
                &docs_path,
                get(move || async move {
                    let html = openapi::docs_html(&openapi_path_for_docs, &title);
                    (
                        StatusCode::OK,
                        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        html,
                    )
                }),
            )
    }

    /// The CORS policy of `cors:`.
    ///
    /// # Errors
    ///
    /// An origin that is not a header value, or an `expose_headers` entry that
    /// is not a header name: dropping either would quietly narrow the policy.
    fn build_cors(&self) -> anyhow::Result<CorsLayer> {
        let config = &self.config.cors;
        // Checked in both modes, so a typo fails the same way whether or not
        // origins are set.
        let configured = config
            .expose_headers
            .iter()
            .map(|name| {
                http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                    anyhow::anyhow!("cors.expose_headers entry {name:?} is not a header name")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if config.origins.is_empty() {
            tracing::warn!("CORS origins not set — using permissive CORS (dev mode)");
            // Exposes every header already.
            Ok(CorsLayer::any(config.max_age_secs))
        } else {
            let origins = config
                .origins
                .iter()
                .map(|origin| {
                    http::HeaderValue::from_str(origin)
                        .map_err(|_| anyhow::anyhow!("cors.origins entry {origin:?} is not valid"))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let exposed = [
                // What a gRPC-Web client reads its status and details from.
                http::HeaderName::from_static("grpc-status"),
                http::HeaderName::from_static("grpc-message"),
                http::HeaderName::from_static("grpc-status-details-bin"),
                // Let browser clients read the rate-limit budget and back off.
                http::HeaderName::from_static("ratelimit-limit"),
                http::HeaderName::from_static("ratelimit-remaining"),
                http::HeaderName::from_static("ratelimit-reset"),
                http::HeaderName::from_static("retry-after"),
            ]
            .into_iter()
            .chain(configured);
            // With credentials the Fetch standard (§3.2.5) forbids `*` for
            // methods and headers, so the preflight's own request is echoed
            // back instead: what the browser asked for, from an allowed origin.
            Ok(CorsLayer::listed(
                origins,
                &exposed.collect::<Vec<_>>(),
                config.max_age_secs,
            ))
        }
    }

    /// The [`ServeOptions`] of `listen:`: TLS from `listen.tls` (mTLS with its
    /// `client_ca_file`), the `listen.max_connections` cap and the connection
    /// timeouts, for [`serve_with`] on a listener of your own.
    ///
    /// # Errors
    ///
    /// A `max_connections`, `header_read_timeout_secs` or
    /// `tls.handshake_timeout_secs` of zero, TLS files that cannot be loaded,
    /// or no rustls crypto provider for TLS.
    pub fn serve_options(&self) -> anyhow::Result<ServeOptions> {
        use std::time::Duration;
        let listen = &self.config.listen;
        anyhow::ensure!(
            listen.header_read_timeout_secs > 0,
            "listen.header_read_timeout_secs must be at least 1"
        );
        let mut options = ServeOptions::new()
            .idle_timeout(
                (listen.idle_timeout_secs > 0)
                    .then(|| Duration::from_secs(listen.idle_timeout_secs)),
            )
            .header_read_timeout(Duration::from_secs(listen.header_read_timeout_secs))
            .drain_timeout(
                (listen.drain_timeout_secs > 0)
                    .then(|| Duration::from_secs(listen.drain_timeout_secs)),
            );
        if let Some(max) = listen.max_connections {
            anyhow::ensure!(max > 0, "listen.max_connections must be at least 1");
            options = options.max_connections(max);
        }
        if let Some(tls) = &listen.tls {
            anyhow::ensure!(
                tls.handshake_timeout_secs > 0,
                "listen.tls.handshake_timeout_secs must be at least 1"
            );
            options = options
                .tls(
                    tls::server_config(tls)
                        .map_err(|e| anyhow::anyhow!("invalid listen.tls: {e}"))?,
                )
                .tls_handshake_timeout(Duration::from_secs(tls.handshake_timeout_secs));
        }
        Ok(options)
    }

    /// Serve the proxy on the configured listen address in front of the
    /// configured upstream address: REST and native gRPC on one port, with
    /// the TLS and connection limit of `listen:` (see
    /// [`serve_options`](Self::serve_options) and [`serve_with`]).
    ///
    /// # Errors
    ///
    /// What [`upstream`](Self::upstream), [`service`](Self::service) and
    /// [`serve_options`](Self::serve_options) reject, an invalid listen
    /// address, or a listener that fails.
    pub async fn serve(&self) -> anyhow::Result<()> {
        self.serve_with_shutdown(std::future::pending()).await
    }

    /// [`serve`](Self::serve) until `signal` completes, then shut down with
    /// the drain of `listen.drain_timeout_secs` (see [`serve_with_shutdown`]).
    ///
    /// # Errors
    ///
    /// What [`serve`](Self::serve) returns.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # async fn run(server: structured_proxy::ProxyServer) -> anyhow::Result<()> {
    /// server
    ///     .serve_with_shutdown(async {
    ///         tokio::signal::ctrl_c().await.ok();
    ///     })
    ///     .await
    /// # }
    /// ```
    pub async fn serve_with_shutdown(
        &self,
        signal: impl std::future::Future<Output = ()>,
    ) -> anyhow::Result<()> {
        let service = self.service(self.upstream()?)?;
        let options = self.serve_options()?;
        let addr: SocketAddr = self.config.listen.http.parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;

        tracing::info!(
            tls = self.config.listen.tls.is_some(),
            "{} listening on {}",
            self.config.service.name,
            addr
        );
        serve_with_shutdown(listener, service, options, signal).await?;
        tracing::info!("{} stopped", self.config.service.name);
        Ok(())
    }
}

/// Canonical shape of an axum route path for collision detection: every dynamic
/// segment (`{name}` capture or `{*name}` wildcard) is replaced by a
/// name-independent placeholder, so structurally identical routes that differ
/// only in parameter name (which axum/matchit rejects as a conflict) map to the
/// same key. Literal segments are unchanged.
fn normalize_route_shape(path: &str) -> String {
    path.split('/')
        .map(|seg| {
            if seg.starts_with("{*") && seg.ends_with('}') {
                "{*}"
            } else if seg.starts_with('{') && seg.ends_with('}') {
                "{}"
            } else {
                seg
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// A [`ProxyState`] for tests whose routers never call the upstream: a lazy
/// channel to a port nothing listens on.
#[cfg(test)]
pub(crate) fn test_state() -> ProxyState<tonic::transport::Channel> {
    ProxyState {
        upstream: tonic::transport::Channel::from_static("http://127.0.0.1:1")
            .connect_timeout(std::time::Duration::from_millis(100))
            .connect_lazy(),
        forwarded_headers: Arc::from([]),
        forwarded_names: Arc::from([]),
        sse_keep_alive_secs: 15,
    }
}

#[cfg(test)]
mod tests;
