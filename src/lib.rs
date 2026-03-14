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

pub mod config;
pub mod openapi;
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

use config::{DescriptorSource, ProxyConfig};

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
}

/// Universal proxy server.
pub struct ProxyServer {
    config: ProxyConfig,
    /// Optional pre-loaded descriptor pool (for embedded mode).
    descriptor_pool: Option<DescriptorPool>,
}

impl ProxyServer {
    /// Create from YAML config file.
    pub fn from_config(config: ProxyConfig) -> Self {
        Self {
            config,
            descriptor_pool: None,
        }
    }

    /// Create with an embedded descriptor pool (for sid-proxy backward compat).
    pub fn with_descriptors(mut self, pool: DescriptorPool) -> Self {
        self.descriptor_pool = Some(pool);
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
                    pool.decode_file_descriptor_set(bytes.as_slice()).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to decode descriptor file {:?}: {}",
                            file,
                            e
                        )
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

    /// Build the axum router with all endpoints.
    pub fn router(&self) -> anyhow::Result<Router> {
        let pool = self.load_descriptors()?;

        let grpc_upstream = self.config.upstream.default.clone();
        let grpc_channel =
            tonic::transport::Channel::from_shared(grpc_upstream.clone())
                .map_err(|e| anyhow::anyhow!("invalid gRPC upstream URL: {}", e))?
                .connect_timeout(std::time::Duration::from_secs(5))
                .timeout(std::time::Duration::from_secs(5))
                .connect_lazy();

        let service_name = self.config.service.name.clone();
        let metrics_namespace = service_name.replace('-', "_");

        let state = ProxyState {
            service_name: service_name.clone(),
            grpc_upstream,
            grpc_channel,
            maintenance_mode: self.config.maintenance.enabled,
            maintenance_exempt: self.config.maintenance.exempt_paths.clone(),
            maintenance_message: self.config.maintenance.message.clone(),
            forwarded_headers: self.config.forwarded_headers.clone(),
            metrics_namespace,
            metrics_classes: self.config.metrics_classes.clone(),
        };

        let cors = self.build_cors();

        // Build transcoding routes from descriptor pool
        let transcode_routes = transcode::routes(&pool, &self.config.aliases);

        // Health routes
        let health_service_name = service_name.clone();
        let health_routes = Router::new()
            .route(
                "/health",
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
            .route("/health/live", get(|| async { StatusCode::OK }))
            .route(
                "/health/ready",
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
            .route("/health/startup", get(|| async { StatusCode::OK }))
            .route(
                "/metrics",
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
            );

        // OpenAPI + docs routes (if enabled).
        let openapi_routes = self.build_openapi_routes(&pool);

        let router = Router::new()
            .merge(health_routes)
            .merge(openapi_routes)
            .merge(transcode_routes)
            .layer(cors)
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

        tracing::info!(
            "OpenAPI spec at {}, docs at {}",
            openapi_path,
            docs_path,
        );

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

        tracing::info!(
            "{} listening on {}",
            self.config.service.name,
            addr
        );
        axum::serve(listener, app).await?;
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
