# structured-proxy

[![crates.io](https://img.shields.io/crates/v/structured-proxy.svg)](https://crates.io/crates/structured-proxy)
[![docs.rs](https://img.shields.io/docsrs/structured-proxy)](https://docs.rs/structured-proxy)
[![CI](https://github.com/structured-world/structured-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/structured-world/structured-proxy/actions/workflows/ci.yml)
[![downloads](https://img.shields.io/crates/d/structured-proxy.svg)](https://crates.io/crates/structured-proxy)
[![license](https://img.shields.io/crates/l/structured-proxy.svg)](https://github.com/structured-world/structured-proxy/blob/main/LICENSE)

Universal, config-driven gRPC→REST transcoding proxy. One binary, different YAML configs, different products.

Works with **any** gRPC service via proto descriptor files. No code generation, no custom handlers, just configuration.

## Features

- **Dynamic REST routes** from proto descriptors using `google.api.http` annotations
- **Full request mapping**: path params, query parameters (typed + repeated + nested), and `body` (`*` / named field / none)
- **`response_body`** to return a single response subfield, and **`additional_bindings`** for multiple routes per RPC
- **Auto-generated OpenAPI** documentation from proto messages, served at `/openapi.json`
- **Server-streaming** RPC → NDJSON by default, or Server-Sent Events via `Accept: text/event-stream` negotiation
- **gRPC → HTTP status mapping** following the standard `google.rpc.Code` table
- **Header forwarding** from HTTP requests to gRPC metadata (configurable allow-list)
- **Context propagation**: W3C trace-context (`traceparent` forwarded or synthesized) and client deadlines (`grpc-timeout`) carried across the REST↔gRPC boundary
- **Path aliasing** for route remapping (e.g. `/oauth2/*` → `/v1/oauth2/*`)
- **Maintenance mode** returning 503 with a configurable exempt-path list
- **Health endpoints** `/health/live`, `/health/ready` (upstream gRPC health probe), `/health/startup`
- **Prometheus metrics** at `/metrics`
- **CORS** with a configurable origin allow-list
- **Rate limiting (Shield)**: per-client endpoint classes + per-identifier limits, in-process by default or Redis-backed (feature `redis`) for multi-instance
- **JWT auth**: validate `Bearer` tokens via an Ed25519 PEM key or JWKS auto-discovery, enforce per-route `require_auth` / `required_roles`, and forward claims as headers
- **OIDC discovery**: serve `/.well-known/openid-configuration` and a JWKS endpoint (Ed25519) built from config, to front an identity provider
- **Forward-auth**: a verification endpoint (`/auth/verify`) for a fronting proxy (nginx `auth_request`, Traefik `forwardAuth`) to delegate auth, returning the verified identity as headers
- **External AuthZ**: gate proxied requests through an Envoy ext_authz gRPC server (`envoy.service.auth.v3.Authorization/Check`), interoperating with OPA and any ext_authz server, with fail-open/closed control
- **Zero code changes** between services: same binary, different config

## Non-goals

- **Session / BFF management** (cookie-based login, server-side token storage, refresh flows) and **stateful OIDC** (`authorize` / `token` with auth codes / PKCE state). The **default build** is a stateless transcoding data plane with stateless auth primitives; session lifecycle is a separate, stateful concern. Put a dedicated BFF (e.g. `oauth2-proxy`, Pomerium) in front, or drive auth through the stateless forward-auth / external-authz hooks below. (A stateful surface behind an opt-in, default-off `bff` Cargo feature is planned; it does not affect the default data-plane build.)

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
  # Empty list = permissive CORS (dev mode, reflects any Origin).
  # A non-empty list allows those exact origins; there is no "*" wildcard
  # (browsers never send `Origin: *`, so listing "*" would block everything).
  origins: []
  # e.g. origins: ["https://app.example.com", "https://admin.example.com"]

# Optional: path aliases (rewrite before routing)
aliases:
  - from: "/api/v1/*"
    to: "/my.package.v1.MyService/*"

# Optional: health-probe endpoints. Paths are configurable (relocate behind an
# internal prefix) and the whole group can be disabled. Defaults shown.
health:
  enabled: true
  path: "/health"
  live_path: "/health/live"
  ready_path: "/health/ready" # checks the upstream gRPC health
  startup_path: "/health/startup"

# Optional: Prometheus metrics endpoint. Path configurable; can be disabled.
metrics:
  enabled: true
  path: "/metrics"

# Optional: maintenance mode (returns 503 except for exempt paths)
maintenance:
  enabled: false
  message: "Service is under maintenance. Please try again later."

# Optional: server-streaming response behavior.
# Streaming RPCs return NDJSON by default; clients sending
# `Accept: text/event-stream` get Server-Sent Events instead. An error
# mid-stream is delivered as an explicit terminal frame in both formats. For
# SSE it uses the `stream-error` event type (consumed via
# `addEventListener("stream-error", ...)`), distinct from the browser
# `EventSource` `onerror`, which fires only on transport failures.
streaming:
  # SSE keep-alive interval (seconds). Comment frames keep idle streams alive
  # through load balancers / nginx read timeouts. Default: 15.
  sse_keep_alive_secs: 15

# Rate limiting (Shield)
shield:
  enabled: true
  window_secs: 60 # default window for bare counts like "20"
  # Optional: shared counters across replicas (needs the `redis` build feature).
  # Omit for an in-process per-replica store.
  # redis_url: "redis://127.0.0.1/"
  # CIDR ranges of trusted proxies/LBs. X-Forwarded-For is honored only from
  # these peers; set this behind a load balancer for correct per-client limits.
  trusted_proxies: ["10.0.0.0/8"]
  # Classify endpoints by glob pattern → class → rate (limited per client IP)
  endpoint_classes:
    - pattern: "/api/v1/heavy-*"
      class: "heavy"
      rate: "10/min"
  # Per-identifier limits keyed by a request body field
  identifier_endpoints:
    - path: "/api/v1/login"
      body_field: "email"
      rate: "5/min"

# JWT auth
auth:
  mode: "jwt"
  jwt:
    jwks_uri: "https://idp.example.com/.well-known/jwks.json"
    # OR a static key: public_key_pem_file: "/etc/proxy/idp-ed25519.pub.pem"
    issuer: "https://idp.example.com"
    audience: "my-api"
    roles_claim: "roles" # array-of-strings claim used for required_roles
    claims_headers: # forward claims to the upstream as headers
      sub: "x-user-id"
  # Route-level policies (require_auth + required_roles → 401 / 403)
  forward_auth:
    policies:
      - path: "/v1/admin/**"
        methods: ["*"]
        require_auth: true
        required_roles: ["admin"]

# OIDC discovery: serves /.well-known/openid-configuration + a JWKS endpoint
oidc_discovery:
  enabled: true
  issuer: "https://idp.example.com"
  jwks_uri: "https://idp.example.com/.well-known/jwks.json" # path is served locally
  signing_key:
    algorithm: "EdDSA"
    public_key_pem_file: "/etc/proxy/oidc-signing.pub.pem"
```

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

### Embedding hooks (axum-free)

Inject *stateless* service-specific logic without naming an HTTP framework in
your own crate: implement the hook traits with foundational types (`http`,
`bytes`, `serde_json`) only, and `cargo tree -i axum` in your crate shows `axum`
solely under `structured-proxy`.

```rust
use std::sync::Arc;
use structured_proxy::{config::ProxyConfig, ProxyServer};
use structured_proxy::hooks::{AuthDecider, Decision, RequestParts};

struct MyPdp; // your forward-auth / policy decision

#[async_trait::async_trait]
impl AuthDecider for MyPdp {
    async fn decide(&self, req: &RequestParts<'_>) -> Decision {
        // method / path / headers / peer in, a decision out — no axum types
        Decision::Allow { inject_headers: http::HeaderMap::new() }
    }
}

# async fn run(config: ProxyConfig) -> anyhow::Result<()> {
ProxyServer::from_config(config)
    .with_auth_decider(Arc::new(MyPdp))   // inline gate + /verify endpoint
    // .with_oidc_backend(...)            // stateless discovery / JWKS / userinfo
    // .with_extra_routes(...)            // extra stateless routes, axum-free
    .serve()
    .await
# }
```

The hooks are:

- **`with_auth_decider`** — an in-process forward-auth / PDP decision, run inline
  on every proxied request and exposed at `/verify` (path configurable via
  `with_verify_path`).
- **`with_oidc_backend`** — backs the stateless OIDC surface (discovery, JWKS,
  userinfo) with your key/client metadata; supersedes the config-driven static
  discovery.
- **`with_extra_routes`** — registers extra stateless routes through a
  framework-agnostic adapter (request parts in, response parts out).

## How It Works

1. Load the proto descriptor from a pre-compiled descriptor file
2. Parse `google.api.http` annotations → generate REST routes
3. Incoming HTTP request → transcode to gRPC (path params + query params + JSON body → protobuf)
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
│  │ Shield          │  │  rate limiting (429)
│  ├─────────────────┤  │
│  │ Auth (JWT)      │  │  validate + policies (401/403)
│  ├─────────────────┤  │
│  │ Transcoder      │  │  REST → gRPC
│  │ (prost-reflect) │  │  JSON → Protobuf
│  ├─────────────────┤  │
│  │ OpenAPI gen     │  │  /openapi.json
│  └─────────────────┘  │
└─────────┬─────────────┘
          │ gRPC
          ▼
   Upstream Service
```

<div align="center">

## Support the Project

<img src="./assets/usdt-qr.svg" alt="USDT TRC-20 Donation QR Code" width="200">

USDT (TRC-20): `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`

</div>

## License

Apache-2.0
