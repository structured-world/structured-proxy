# structured-proxy

[![crates.io](https://img.shields.io/crates/v/structured-proxy.svg)](https://crates.io/crates/structured-proxy)
[![docs.rs](https://img.shields.io/docsrs/structured-proxy)](https://docs.rs/structured-proxy)
[![CI](https://github.com/structured-world/structured-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/structured-world/structured-proxy/actions/workflows/ci.yml)
[![downloads](https://img.shields.io/crates/d/structured-proxy.svg)](https://crates.io/crates/structured-proxy)
[![license](https://img.shields.io/crates/l/structured-proxy.svg)](https://github.com/structured-world/structured-proxy/blob/main/LICENSE)

Universal, config-driven gRPC→REST transcoding proxy. One binary, different YAML configs, different products.

Works with **any** gRPC service via proto descriptor files. No code generation, no custom handlers, just configuration.

## Features

- **Dynamic REST routes** from proto descriptors using `google.api.http` annotations (path params + JSON body)
- **Auto-generated OpenAPI** documentation from proto messages, served at `/openapi.json`
- **Server-streaming** RPC → chunked HTTP responses
- **gRPC → HTTP status mapping** following the standard `google.rpc.Code` table
- **Header forwarding** from HTTP requests to gRPC metadata (configurable allow-list)
- **Path aliasing** for route remapping (e.g. `/oauth2/*` → `/v1/oauth2/*`)
- **Maintenance mode** returning 503 with a configurable exempt-path list
- **Health endpoints** `/health/live`, `/health/ready` (upstream gRPC health probe), `/health/startup`
- **Prometheus metrics** at `/metrics`
- **CORS** with a configurable origin allow-list
- **Zero code changes** between services: same binary, different config

## Roadmap

These have config scaffolding in place but are not yet enforced by the proxy. Tracked for implementation; do not rely on them yet.

- **Rate limiting (Shield)**: endpoint classification + per-identifier limiting
- **JWT auth**: validation with JWKS auto-discovery + route-level policies
- **OIDC discovery**: `/.well-known/openid-configuration` + JWKS endpoint for IdP proxies
- **Forward-auth / external AuthZ / BFF sessions**
- **Transcoding completeness**: query-parameter binding, `response_body`, `additional_bindings`
- **Context propagation**: W3C trace-context and deadline (`grpc-timeout`) across the REST↔gRPC boundary

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
listen:
  http: "0.0.0.0:8080"

upstream:
  default: "http://127.0.0.1:50051"

# Pre-compiled proto descriptor sources (one or more, merged into one pool)
descriptors:
  - file: "my-service.descriptor.bin"

# Service identity (drives /health response and metrics namespace)
service:
  name: "my-service"

cors:
  origins: ["*"] # empty list = permissive (dev mode)

# Optional: path aliases (rewrite before routing)
aliases:
  - from: "/api/v1/*"
    to: "/my.package.v1.MyService/*"

# Optional: maintenance mode (returns 503 except for exempt paths)
maintenance:
  enabled: false
  message: "Service is under maintenance. Please try again later."

# Rate limiting (Shield) [roadmap]: config is parsed but not yet enforced
shield:
  enabled: true
  window_secs: 60
  # Classify endpoints by glob pattern → class → rate
  endpoint_classes:
    - pattern: "/api/v1/heavy-*"
      class: "heavy"
      rate: "10/min"
  # Per-identifier limits keyed by a request body field
  identifier_endpoints:
    - path: "/api/v1/login"
      body_field: "email"
      rate: "5/min"

# JWT auth [roadmap]: config is parsed but not yet enforced
auth:
  mode: "jwt"
  jwt:
    jwks_uri: "https://idp.example.com/.well-known/jwks.json"
    issuer: "https://idp.example.com"
    audience: "my-api"

# OIDC discovery [roadmap]: config is parsed but no endpoints are served yet
oidc_discovery:
  enabled: true
  issuer: "https://idp.example.com"
  signing_key:
    algorithm: "EdDSA"
    public_key_pem_file: "/etc/proxy/oidc-signing.pub.pem"
```

> Sections tagged **[roadmap]** (`shield`, `auth`, `oidc_discovery`) are accepted by the config loader today but not yet wired into the request path. See the [Roadmap](#roadmap) for status.

Generate the descriptor file from your proto:

```bash
buf build -o my-service.descriptor.bin
# or
protoc --descriptor_set_out=my-service.descriptor.bin --include_imports *.proto
```

## Library Usage

```rust
use std::path::Path;
use structured_proxy::{config::ProxyConfig, ProxyServer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ProxyConfig::from_file(Path::new("my-service.yaml"))?;

    // Run the proxy on the configured listen address.
    ProxyServer::from_config(config).serve().await?;
    Ok(())
}
```

Or build the axum `Router` yourself for custom serving / embedding:

```rust
use std::path::Path;
use structured_proxy::{config::ProxyConfig, ProxyServer};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = ProxyConfig::from_file(Path::new("my-service.yaml"))?;
    let app = ProxyServer::from_config(config).router()?;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
```

## How It Works

1. Load the proto descriptor from a pre-compiled descriptor file
2. Parse `google.api.http` annotations → generate REST routes
3. Incoming HTTP request → transcode to gRPC (path params + JSON body → protobuf)
4. Forward to the upstream gRPC service
5. Response protobuf → transcode to JSON
6. Serve the OpenAPI spec at `/openapi.json`

## Architecture

```
Client (HTTP/JSON)
    │
    ▼
┌──────────────────────┐
│  structured-proxy     │
│                       │
│  ┌─────────────────┐  │
│  │ CORS            │  │
│  ├─────────────────┤  │
│  │ Maintenance     │  │  503 gate (exempt paths)
│  ├─────────────────┤  │
│  │ Transcoder      │  │  REST → gRPC
│  │ (prost-reflect) │  │  JSON → Protobuf
│  ├─────────────────┤  │
│  │ OpenAPI gen     │  │  /openapi.json
│  └─────────────────┘  │
│  ┌─────────────────┐  │
│  │ Shield · Auth   │  │  (roadmap, not yet wired)
│  └─────────────────┘  │
└─────────┬─────────────┘
          │ gRPC
          ▼
   Upstream Service
```

## License

Apache-2.0
