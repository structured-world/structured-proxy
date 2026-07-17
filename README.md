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
- **Rate limiting (Shield)**: local GCRA shaper (no blocking latency) keyed by client IP, header, or validated JWT claim; named limit tiers as config data; optional async cross-instance reconciliation (feature `redis`) for an approximate fleet-wide limit
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
#
# Every decision is made locally with a GCRA shaper (no blocking latency).
# Named profiles define tiers as data; rules bind a path glob to a key and a
# limit. Rules keyed by a JWT claim run after auth (so the claim is verified);
# the rest run before auth so anonymous floods are shed cheaply.
shield:
  enabled: true
  # CIDR ranges of trusted proxies/LBs. X-Forwarded-For is honored only from
  # these peers; set this behind a load balancer for correct per-client limits.
  trusted_proxies: ["10.0.0.0/8"]
  # Limit tiers: sustained rate ("N/unit" or a bare count = per minute) + burst
  # (max back-to-back requests; defaults to one window of the rate).
  profiles:
    anon: { rate: "60/min", burst: 20 }
    premium: { rate: "1000/min", burst: 100 }
  # Applied when a matched rule resolves no other limit.
  default_profile: "anon"
  rules:
    # Anonymous heavy endpoints, keyed by client IP (runs before auth).
    - pattern: "/api/v1/heavy-*"
      key: { type: ip }
      profile: "anon"
    # Per-principal limit keyed by a validated JWT claim (runs after auth).
    - pattern: "/api/v1/**"
      key: { type: jwt_claim, claim: "sub" }
  # Optional: resolve a key's limit from the JWT itself (tier name → a profile,
  # or explicit ratelimit_rpm / ratelimit_burst claims).
  # jwt_limits: { tier_claim: "ratelimit_tier" }
  # Optional: async cross-instance reconciliation via a shared store for an
  # approximate fleet-wide limit (needs the `redis` build feature). The request
  # path never blocks on it; a store outage degrades to per-instance limits.
  # sync: { redis_url: "redis://127.0.0.1/", interval_ms: 500 }

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

## Rate limiting

Shield is an embedded, config-driven limiter designed for a data plane: every
decision is made in-process by a GCRA shaper, so it adds no blocking latency to
the request path. GCRA (a token-bucket equivalent storing one timestamp per key)
lets legitimate bursts through up to a configured `burst` while throttling
sustained abuse to the `rate`, with no fixed-window boundary burst.

**Keying and phases.** A rule keys on the client IP, a header value (API key),
or a validated JWT claim. The phase is derived from the key, not configured: an
IP/header rule needs no verified identity so it runs *before* auth (a fast,
purely local check that sheds anonymous floods before any signature verification,
and short-circuits so blocked clients never reach the auth layer); a `jwt_claim`
rule needs the verified principal so it runs *after* auth. A key falls back to
the client IP when its value is absent within its own phase, so a limit can't be
dodged by omitting a header. Note the fallback is phase-local: an anonymous
request under a `jwt_claim` rule keys by IP in the post-auth phase, but is *not*
shed pre-auth. For anonymous flood protection, add a separate pre-auth IP (or
header) rule covering the same paths; a path may match one rule per phase and
each is enforced independently (defense in depth).

**Limit sources.** A key's `{rate, burst}` resolves in order: the JWT itself
(a `ratelimit_tier` claim naming a profile, or explicit `ratelimit_rpm` /
`ratelimit_burst`), then an external service (cached and refreshed in the
background, never blocking), then the rule's pinned profile, then the default.
JWT-based resolution only applies to `jwt_claim` rules, since only they run with
verified claims available. Tier-name indirection lets you retune the numbers in
config without re-issuing tokens or changing the service.

**Response headers.** Every metered response carries the
[draft-ietf-httpapi-ratelimit-headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)
fields: `RateLimit-Limit` (the tier's per-window quota), `RateLimit-Remaining`
(requests still admissible now), and `RateLimit-Reset` (whole seconds until the
limiter drains toward full). A rejected request returns `429` with `Retry-After`
(whole seconds until a retry would conform). Clients should back off for
`Retry-After` seconds on a `429`, and may pace themselves using `RateLimit-*` on
allowed responses. Behind a browser, these are exposed via CORS.

**Deployment modes.**

- **Local (default).** No shared store. Each instance enforces the limit
  independently, so the fleet-wide effect is roughly `N × rate` for `N`
  instances. Zero dependencies, lowest latency. Set per-instance limits with
  that multiplier in mind.
- **Reconciled (`sync` + `redis` feature).** Instances asynchronously push their
  deltas to a shared store and pull the aggregate on an interval, converging on
  an approximate fleet-wide limit. The configured `rate` is then the *fleet*
  budget. The request path still never blocks on the store; if the store is
  unreachable, instances degrade to local limiting rather than failing requests.

**Sizing the overshoot.** In reconciled mode the aggregate lags by up to one
`sync.interval_ms`, so within that lag each of the other instances can admit up
to a `rate` fraction of the window. With the interval expressed in the same time
unit as the window, the worst-case fleet overshoot is about
`(N - 1) × rate × (interval / window)` requests. For example, `rate = 1000/min`,
`interval = 500 ms`, `N = 4` gives `3 × 1000 × (0.5 / 60) ≈ 25` extra requests.
Shorter intervals tighten the bound at the cost of more store traffic. The global
view uses a sliding-window counter, so there is no boundary burst on top of this
lag.

See the `shield:` block under [Configuration](#configuration) for the full
schema.

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
`bytes`, `serde_json`) plus `async-trait` (the traits are `#[async_trait]`),
none of which is an HTTP framework. `cargo tree -i axum` in your crate then
shows `axum` solely under `structured-proxy`.

```rust
use std::sync::Arc;
use structured_proxy::{config::ProxyConfig, ProxyServer};
use structured_proxy::hooks::{AuthDecider, Decision, RequestParts};

struct MyPdp; // your forward-auth / policy decision

#[async_trait::async_trait]
impl AuthDecider for MyPdp {
    async fn decide(&self, req: &RequestParts<'_>) -> Decision {
        // method / path / headers / peer in, a decision out (no axum types)
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
