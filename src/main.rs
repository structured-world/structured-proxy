//! Universal gRPC→REST transcoding proxy — standalone binary.
//!
//! ```bash
//! structured-proxy --config proxy.yaml
//! ```

mod runtime;

use anyhow::Context as _;
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "structured-proxy",
    version,
    about = "Universal gRPC→REST transcoding proxy"
)]
struct Cli {
    /// Path to YAML config file.
    #[arg(short, long, default_value = "proxy.yaml")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let yaml = std::fs::read_to_string(&cli.config)
        .with_context(|| format!("loading config {}", cli.config))?;
    // Reads the ProxyConfig and the transcoding settings kept outside it
    // (error_details, streaming.ndjson_envelope) from the same file. Loading
    // does no async work, so the runtime is built afterwards, from the same
    // file's `runtime:` section.
    let server = structured_proxy::ProxyServer::from_yaml_str(&yaml)
        .with_context(|| format!("loading config {}", cli.config))?;
    let file = runtime::FileConfig::from_yaml_str(&yaml)
        .with_context(|| format!("loading config {}", cli.config))?;
    let (rt, source) = file.runtime.build().context("starting the async runtime")?;

    let config = server.config();
    let upstream = config.upstream.as_ref().map_or("", |u| u.default.as_str());
    tracing::info!(
        service = %config.service.name,
        listen = %config.listen.http,
        upstream = %upstream,
        descriptors = config.descriptors.len(),
        worker_threads = rt.metrics().num_workers(),
        worker_threads_from = %source,
        "Starting structured-proxy"
    );

    rt.block_on(server.serve_with_shutdown(stop_requested()))
}

/// Completes on Ctrl-C, and on SIGTERM on Unix (what container runtimes and
/// service managers send to stop a process).
async fn stop_requested() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    () = ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "cannot listen for SIGTERM; stopping on Ctrl-C only");
                ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    ctrl_c().await;
    tracing::info!("stop requested; draining connections");
}

/// Completes on Ctrl-C. A handler that cannot be installed never completes:
/// failing to listen for the signal is no reason to stop serving.
async fn ctrl_c() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        tracing::warn!(error = %e, "cannot listen for Ctrl-C");
        std::future::pending::<()>().await;
    }
}
