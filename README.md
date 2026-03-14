# structured-proxy

Universal, config-driven gRPC→REST transcoding proxy. One binary, different YAML configs — different products.

Works with **any** gRPC service via proto descriptor files. No code generation, no custom handlers — just configuration.

## Features

- **Dynamic REST routes** from proto descriptors using `google.api.http` annotations
- **Auto-generated OpenAPI** documentation from proto messages
- **Server-streaming** RPC → SSE/chunked HTTP responses
- **Rate limiting (Shield)** — endpoint classification + per-identifier limiting via YAML
- **JWT/OIDC validation** — route-level auth policies with JWKS auto-discovery
- **Path aliasing** — configurable route remapping (e.g., `/oauth2/*` → `/v1/oauth2/*`)
- **Maintenance mode** — 503 with configurable exempt paths
- **Health endpoints** — `/health/live`, `/health/ready`, `/health/startup`
- **Prometheus metrics** — `/metrics` endpoint
- **Zero code changes** between services — same binary, different config

## Quick Start

```bash
# Install
cargo install structured-proxy

# Run with your service config
structured-proxy --config my-service.yaml
```

## Configuration

```yaml
# my-service.yaml
listen: "0.0.0.0:8080"

upstream:
  address: "http://127.0.0.1:50051"

descriptor:
  file: "my-service.descriptor.bin"
  # OR: reflection: true

cors:
  allow_origins: ["*"]

# Optional: path aliases
aliases:
  - from: "/api/v1/*"
    to: "/my.package.v1.MyService/*"

# Optional: rate limiting
shield:
  enabled: true
  default_rpm: 60
  endpoints:
    - pattern: "/api/v1/heavy-*"
      rpm: 10
      identifier: header:x-api-key
```

Generate the descriptor file from your proto:

```bash
buf build -o my-service.descriptor.bin
# or
protoc --descriptor_set_out=my-service.descriptor.bin --include_imports *.proto
```

## Library Usage

```rust
use structured_proxy::{ProxyConfig, build_proxy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ProxyConfig::from_file("my-service.yaml")?;
    let app = build_proxy(config).await?;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## How It Works

1. Load proto descriptor (file or gRPC reflection)
2. Parse `google.api.http` annotations → generate REST routes
3. Incoming HTTP request → transcode to gRPC (path params, query params, JSON body → protobuf)
4. Forward to upstream gRPC service
5. Response protobuf → transcode to JSON
6. Serve OpenAPI spec at `/openapi.json`

## Architecture

```
Client (HTTP/JSON)
    │
    ▼
┌─────────────────────┐
│  structured-proxy    │
│                      │
│  ┌────────────────┐  │
│  │ Shield (rate)  │  │
│  ├────────────────┤  │
│  │ Auth (JWT)     │  │
│  ├────────────────┤  │
│  │ Transcoder     │  │  REST → gRPC
│  │ (prost-reflect)│  │  JSON → Protobuf
│  ├────────────────┤  │
│  │ OpenAPI gen    │  │  /openapi.json
│  └────────────────┘  │
└─────────┬────────────┘
          │ gRPC
          ▼
   Upstream Service
```

## License

Apache-2.0
