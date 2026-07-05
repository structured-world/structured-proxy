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
//! ## JWT crypto backend
//!
//! Exactly one crypto backend feature must be enabled (they are mutually
//! exclusive): `rust_crypto` (default, pure Rust) or `aws_lc_rs` (opt-in,
//! constant-time / FIPS-capable, links aws-lc via C FFI). Enabling both or
//! neither is rejected at compile time by the guards below.

// jsonwebtoken selects its provider from these features and would otherwise
// panic at runtime on an invalid combination; turn that into a build error.
#[cfg(all(feature = "rust_crypto", feature = "aws_lc_rs"))]
compile_error!("features `rust_crypto` and `aws_lc_rs` are mutually exclusive; enable exactly one");

#[cfg(not(any(feature = "rust_crypto", feature = "aws_lc_rs")))]
compile_error!("exactly one JWT crypto backend must be enabled: `rust_crypto` or `aws_lc_rs`");

pub mod auth;
pub mod config;
mod embed;
pub mod hooks;
pub mod oidc;
pub mod openapi;
pub mod shield;
pub mod transcode;

use axum::extract::State;
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use prost_reflect::DescriptorPool;
use std::net::SocketAddr;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use std::sync::Arc;

use config::{DescriptorSource, ProxyConfig};
use hooks::{AuthDecider, ExtraRoute, OidcBackend};

/// Shared state for all proxy handlers.
#[derive(Clone, Debug)]
pub struct ProxyState {
    /// Service name from config.
    pub service_name: String,
    /// gRPC upstream address.
    pub grpc_upstream: String,
    /// Lazy gRPC channel to upstream service.
    pub grpc_channel: tonic::transport::Channel,
    /// Maintenance mode active.
    pub maintenance_mode: bool,
    /// Maintenance exempt path patterns.
    pub maintenance_exempt: Vec<String>,
    /// Maintenance message.
    pub maintenance_message: String,
    /// Headers to forward from HTTP to gRPC.
    pub forwarded_headers: Vec<String>,
    /// Metrics namespace (derived from service name).
    pub metrics_namespace: String,
    /// Path class patterns for metrics.
    pub metrics_classes: Vec<config::MetricsClassConfig>,
    /// SSE keep-alive interval (seconds) for server-streaming responses.
    pub sse_keep_alive_secs: u64,
}

/// Universal proxy server.
pub struct ProxyServer {
    config: ProxyConfig,
    /// Optional pre-loaded descriptor pool (for embedded mode).
    descriptor_pool: Option<DescriptorPool>,
    /// Optional in-process forward-auth/PDP gate (embedded Tier-2 hook).
    auth_decider: Option<Arc<dyn AuthDecider>>,
    /// Optional stateless OIDC surface backing (embedded Tier-2 hook).
    oidc_backend: Option<Arc<dyn OidcBackend>>,
    /// Embedder-supplied extra stateless routes (embedded Tier-2 hook).
    extra_routes: Vec<ExtraRoute>,
    /// Override for the `/verify` forward-auth path of an injected AuthDecider.
    verify_path: Option<String>,
}

impl ProxyServer {
    /// Create from YAML config file.
    pub fn from_config(config: ProxyConfig) -> Self {
        Self {
            config,
            descriptor_pool: None,
            auth_decider: None,
            oidc_backend: None,
            extra_routes: Vec::new(),
            verify_path: None,
        }
    }

    /// Create with an embedded descriptor pool (for sid-proxy backward compat).
    pub fn with_descriptors(mut self, pool: DescriptorPool) -> Self {
        self.descriptor_pool = Some(pool);
        self
    }

    /// Inject an in-process forward-auth / PDP decision (embedded Tier-2 hook).
    ///
    /// The decider gates every proxied request inline and also backs the
    /// `/verify` forward-auth endpoint. Its signature is `axum`-free (see
    /// [`hooks::AuthDecider`]), so the embedder never names an HTTP framework.
    pub fn with_auth_decider(mut self, decider: Arc<dyn AuthDecider>) -> Self {
        self.auth_decider = Some(decider);
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

    /// Every `(method, path)` route mounted before the verify endpoint, used to
    /// reject a real collision with a clear error instead of an axum
    /// duplicate-route panic. `method` is the uppercase HTTP token; same-path
    /// routes with different methods do NOT collide (the extra-route adapter and
    /// axum merge them), so the key is the pair, not the path alone.
    ///
    /// Must stay exhaustive: health probes, metrics, OpenAPI spec/docs, the OIDC
    /// surface (injected backend or config-driven static discovery), embedder
    /// extra routes, and the transcoded REST routes. All built-in surfaces here
    /// are `GET`.
    fn reserved_routes(&self, pool: &DescriptorPool) -> anyhow::Result<Vec<(String, String)>> {
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
        routes.extend(transcode::route_paths(pool, &self.config.aliases));
        Ok(routes)
    }

    /// Build the axum router with all endpoints.
    pub fn router(&self) -> anyhow::Result<Router> {
        // Enforce cross-field invariants on the embedded path too, where the
        // config is built directly instead of through `from_yaml_str`.
        self.config.validate()?;
        let pool = self.load_descriptors()?;

        let grpc_upstream = self.config.upstream.default.clone();
        let grpc_channel = tonic::transport::Channel::from_shared(grpc_upstream.clone())
            .map_err(|e| anyhow::anyhow!("invalid gRPC upstream URL: {}", e))?
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(5))
            .connect_lazy();

        let service_name = self.config.service.name.clone();
        let metrics_namespace = service_name.replace('-', "_");

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
        let mut mounted = self.reserved_routes(&pool)?;
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

        let state = ProxyState {
            service_name: service_name.clone(),
            grpc_upstream,
            grpc_channel,
            maintenance_mode: self.config.maintenance.enabled,
            maintenance_exempt,
            maintenance_message: self.config.maintenance.message.clone(),
            forwarded_headers: self.config.forwarded_headers.clone(),
            metrics_namespace,
            metrics_classes: self.config.metrics_classes.clone(),
            sse_keep_alive_secs: self.config.streaming.sse_keep_alive_secs,
        };

        let cors = self.build_cors();

        // Build transcoding routes from descriptor pool.
        let mut transcode_routes = transcode::routes(&pool, &self.config.aliases);

        // External authorization (Envoy ext_authz) gates only the proxied API
        // routes, never health / metrics / discovery. It runs inside the auth
        // layer below, so the Check call sees the identity headers the JWT
        // middleware injected.
        let authz = match self.config.auth.as_ref().and_then(|a| a.authz.as_ref()) {
            Some(cfg) => auth::authz::Authz::build(cfg)
                .map_err(|e| anyhow::anyhow!("invalid authz config: {e}"))?,
            None => None,
        };

        // Order matters: in axum the LAST-added layer is outermost and runs
        // FIRST. We want `authz -> AuthDecider -> handler`, so add the decider
        // layer first (inner) and the authz layer second (outer). That way, when
        // both are configured, ext_authz runs first and the in-process decider
        // sees any headers the authz Check injected.
        if let Some(decider) = &self.auth_decider {
            transcode_routes = transcode_routes.layer(axum::middleware::from_fn_with_state(
                decider.clone(),
                embed::auth_decider_gate,
            ));
        }
        if let Some(authz) = authz {
            transcode_routes = transcode_routes.layer(axum::middleware::from_fn_with_state(
                authz,
                auth::authz::middleware,
            ));
        }

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
                    get(|State(state): State<ProxyState>| async move {
                        let mut client =
                            tonic_health::pb::health_client::HealthClient::new(state.grpc_channel);
                        match client
                            .check(tonic_health::pb::HealthCheckRequest {
                                service: String::new(),
                            })
                            .await
                        {
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
        let openapi_routes = self.build_openapi_routes(&pool);

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

        // Rate limiting (Shield), if configured and enabled.
        let shield = match &self.config.shield {
            Some(cfg) => shield::Shield::build(cfg)
                .map_err(|e| anyhow::anyhow!("invalid shield config: {e}"))?,
            None => None,
        };

        // JWT auth, if configured (auth.mode == "jwt").
        let auth = match &self.config.auth {
            Some(cfg) => {
                auth::Auth::build(cfg).map_err(|e| anyhow::anyhow!("invalid auth config: {e}"))?
            }
            None => None,
        };

        let mut router = Router::new()
            .merge(health_routes)
            .merge(metrics_routes)
            .merge(openapi_routes)
            .merge(oidc_routes)
            .merge(embed::extra_routes_router(&self.extra_routes))
            .merge(transcode_routes)
            .layer(cors);

        // Forward-auth verification endpoint, sharing the built Auth. Mounted
        // after the auth layer below so the endpoint itself is not gated by the
        // JWT middleware (it answers the gate, it isn't behind it).
        let forward_auth = auth.as_ref().and_then(|built| {
            auth::forward::ForwardAuth::build(self.config.auth.as_ref()?, built.clone())
        });

        // Duplicate-route collisions (including the verify path) were already
        // rejected up front, before any router was built.

        // Auth runs inside Shield (added first = inner): rate limiting sheds
        // load before any signature verification work.
        if let Some(auth) = auth {
            router = router.layer(axum::middleware::from_fn_with_state(auth, auth::middleware));
        }

        // Forward-auth `/verify` endpoint. An injected AuthDecider owns it when
        // present (in-process PDP); otherwise the config-driven JWT ForwardAuth
        // backs it. Mounted after the auth layer so it is not itself JWT-gated.
        if let Some(decider) = &self.auth_decider {
            // Collision / shape of this path was already validated above.
            let decider = decider.clone();
            let path = self.decider_verify_path();
            router = router.route(
                &path,
                axum::routing::any(move |req: axum::extract::Request| {
                    let decider = decider.clone();
                    async move { embed::verify_via_decider(decider, req).await }
                }),
            );
        } else if let Some(forward_auth) = &forward_auth {
            router = router.merge(forward_auth.routes());
        }

        // Shield is added before maintenance so maintenance wraps it (outer
        // layers run first): a request rejected by the maintenance gate must
        // not be charged against its rate-limit budget.
        if let Some(shield) = shield {
            router = router.layer(axum::middleware::from_fn_with_state(
                shield,
                shield::middleware,
            ));
        }

        let router = router
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                maintenance_middleware,
            ))
            .layer(TraceLayer::new_for_http())
            .with_state(state);

        Ok(router)
    }

    fn build_openapi_routes(&self, pool: &DescriptorPool) -> Router<ProxyState> {
        let openapi_config = match &self.config.openapi {
            Some(cfg) if cfg.enabled => cfg,
            _ => return Router::new(),
        };

        let spec = openapi::generate(pool, openapi_config, &self.config.aliases);
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

    fn build_cors(&self) -> CorsLayer {
        if self.config.cors.origins.is_empty() {
            tracing::warn!("CORS origins not set — using permissive CORS (dev mode)");
            CorsLayer::permissive()
        } else {
            let origins: Vec<_> = self
                .config
                .cors
                .origins
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any)
                .allow_credentials(true)
                .expose_headers([
                    "grpc-status".parse().unwrap(),
                    "grpc-message".parse().unwrap(),
                ])
        }
    }

    /// Start serving on configured address.
    pub async fn serve(&self) -> anyhow::Result<()> {
        let router = self.router()?;
        let app = router.into_make_service_with_connect_info::<SocketAddr>();
        let addr: SocketAddr = self.config.listen.http.parse()?;
        let listener = tokio::net::TcpListener::bind(addr).await?;

        tracing::info!("{} listening on {}", self.config.service.name, addr);
        axum::serve(listener, app).await?;
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

/// Maintenance mode middleware.
async fn maintenance_middleware(
    State(state): State<ProxyState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if state.maintenance_mode {
        let path = request.uri().path();
        let exempt = state.maintenance_exempt.iter().any(|pattern| {
            if pattern.ends_with("/**") {
                let prefix = &pattern[..pattern.len() - 3];
                path.starts_with(prefix)
            } else {
                path == pattern
            }
        });
        if !exempt {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [("retry-after", "300")],
                state.maintenance_message.clone(),
            )
                .into_response();
        }
    }
    next.run(request).await
}

/// Create a lazy gRPC channel for testing (connects to nowhere).
#[cfg(test)]
pub(crate) fn test_channel() -> tonic::transport::Channel {
    tonic::transport::Channel::from_static("http://127.0.0.1:1")
        .connect_timeout(std::time::Duration::from_millis(100))
        .connect_lazy()
}

/// A minimal [`ProxyState`] for tests that only need a state to satisfy a
/// `Router<ProxyState>` (the hook routers do not read it).
#[cfg(test)]
pub(crate) fn test_state() -> ProxyState {
    ProxyState {
        service_name: "test".into(),
        grpc_upstream: "http://127.0.0.1:1".into(),
        grpc_channel: test_channel(),
        maintenance_mode: false,
        maintenance_exempt: vec![],
        maintenance_message: String::new(),
        forwarded_headers: vec![],
        metrics_namespace: "test".into(),
        metrics_classes: vec![],
        sse_keep_alive_secs: 15,
    }
}

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn test_maintenance_exempt_matching() {
        let state = ProxyState {
            service_name: "test".into(),
            grpc_upstream: "http://localhost:50051".into(),
            grpc_channel: test_channel(),
            maintenance_mode: true,
            maintenance_exempt: vec![
                "/health/**".into(),
                "/.well-known/**".into(),
                "/metrics".into(),
            ],
            maintenance_message: "Down".into(),
            forwarded_headers: vec![],
            metrics_namespace: "test".into(),
            metrics_classes: vec![],
            sse_keep_alive_secs: 15,
        };

        let check = |path: &str| -> bool {
            state.maintenance_exempt.iter().any(|pattern| {
                if pattern.ends_with("/**") {
                    let prefix = &pattern[..pattern.len() - 3];
                    path.starts_with(prefix)
                } else {
                    path == pattern
                }
            })
        };

        assert!(check("/health"));
        assert!(check("/health/ready"));
        assert!(check("/.well-known/openid-configuration"));
        assert!(check("/metrics"));
        assert!(!check("/v1/auth/login"));
        assert!(!check("/oauth2/token"));
    }
}
