//! Universal gRPC→REST transcoding proxy — standalone binary.
//!
//! ```bash
//! structured-proxy --config proxy.yaml
//! ```

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "structured-proxy",
    about = "Universal gRPC→REST transcoding proxy"
)]
struct Cli {
    /// Path to YAML config file.
    #[arg(short, long, default_value = "proxy.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    // Reads the ProxyConfig and the transcoding settings kept outside it
    // (error_details, streaming.ndjson_envelope) from the same file.
    let server = structured_proxy::ProxyServer::from_file(std::path::Path::new(&cli.config))?;
    let config = server.config();

    tracing::info!(
        service = %config.service.name,
        listen = %config.listen.http,
        upstream = %config.upstream.default,
        descriptors = config.descriptors.len(),
        "Starting structured-proxy"
    );

    server.serve().await
}
