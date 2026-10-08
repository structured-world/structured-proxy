# structured-proxy

[![crates.io](https://img.shields.io/crates/v/structured-proxy.svg)](https://crates.io/crates/structured-proxy)
[![docs.rs](https://img.shields.io/docsrs/structured-proxy)](https://docs.rs/structured-proxy)
[![CI](https://github.com/structured-world/structured-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/structured-world/structured-proxy/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/crates/msrv/structured-proxy)](https://crates.io/crates/structured-proxy)
[![downloads](https://img.shields.io/crates/d/structured-proxy.svg)](https://crates.io/crates/structured-proxy)
[![license](https://img.shields.io/crates/l/structured-proxy.svg)](https://github.com/structured-world/structured-proxy/blob/main/LICENSE)

A gRPC→REST transcoding proxy and edge for any gRPC service. Point it at your
proto descriptors and it serves REST/JSON next to native gRPC on one port,
with auth, rate limits and the rest of an edge configured in YAML. Run it as a
standalone binary, or embed it in your own Rust service in front of your own
tonic services.

## Features

**Transcoding**

- REST routes from the `google.api.http` annotations in your protos: path,
  query and JSON or form body mapped onto the request message
  ([Request mapping](#request-mapping)), `response_body`,
  `additional_bindings`, custom verbs (`/v1/{name}:cancel`), and `custom`
  rules for any HTTP method
- Server streaming as NDJSON, or Server-Sent Events when the client asks for
  `text/event-stream`
- Errors as `google.rpc.Status` JSON with the standard HTTP status mapping and
  typed error details ([Error responses](#error-responses))
- The upstream decides status, headers and raw bodies, so OAuth 2.0 / OIDC
  endpoints, redirects and file downloads can be written as gRPC
  ([Upstream controls](#upstream-controls))
- OpenAPI generated from the protos, served at `/openapi.json`
- Header forwarding, W3C trace context and client deadlines carried across
  REST↔gRPC; path aliases

**Edge**

- REST and native gRPC on one port, HTTP/1.1 and HTTP/2; gRPC-Web passed
  through, or translated to gRPC for an upstream that speaks only gRPC
- Built-in TLS and mTLS, and a cap on open connections; or your own TLS, with
  the client's address and certificate reaching the upstream
- The client's address resolved once from the connection and the proxies you
  trust, then shared by the rate limits, the hooks and the upstream, which
  gets a verified `X-Forwarded-For` by default, or the forwarding of nginx,
  Envoy or your load balancer ([Client address](#client-address))
- Graceful shutdown: calls and streams in flight finish within a bounded
  drain, HTTP/2 clients get a GOAWAY ([Shutting down](#shutting-down))
- Guards you scope to the traffic they cover (transcoded calls, the proxy's
  own endpoints, native gRPC, the fallback), rejecting in the protocol of the
  request ([Guards and scopes](#guards-and-scopes)):
  - rate limits keyed by IP, header or JWT claim, optionally shared across
    instances through Redis ([Rate limiting](#rate-limiting))
  - a limit on requests in flight
  - JWT auth with per-route policies, or your own token verifier
  - Envoy ext_authz (OPA and any other ext_authz server) and an in-process
    auth decider
  - maintenance mode
- CORS, applied to gRPC-Web calls too
- Health probes (`/health/live`, `/health/ready` against the upstream's gRPC
  health, `/health/startup`) and Prometheus metrics at `/metrics`
- Forward-auth endpoint for nginx `auth_request` / Traefik `forwardAuth`, and
  OIDC discovery with a JWKS endpoint

**Embedding**

- Your own tonic services as the upstream, called in process
  ([Library Usage](#library-usage))
- A builder that starts as a plain pass-through and turns on only the
  capabilities you ask for ([Building the proxy in code](#building-the-proxy-in-code))
- Requests the proxy does not serve go to your own fallback service
- Hooks for auth decisions, token verification, OIDC and extra routes, with no
  HTTP framework in your code

## Non-goals

- **Sessions and stateful OIDC** (cookie login, server-side tokens, refresh,
  `authorize` / `token` with PKCE state). The proxy is a stateless data plane:
  put a BFF such as `oauth2-proxy` or Pomerium in front, or decide auth
  through the forward-auth and ext_authz hooks.

## Quick Start

```bash
# Install the binary: the `cli` feature builds what the release packages ship,
# Redis-backed shared rate limits included
cargo install structured-proxy --features cli

# Run with your service config
structured-proxy --config my-service.yaml
```

Prebuilt static Linux binaries and deb/rpm packages are attached to each GitHub
release. To embed the proxy in your own service instead, add the library with
`cargo add structured-proxy` (see [Library Usage](#library-usage)).

`runtime.worker_threads` sets how many worker threads, and so CPU cores, the
binary uses. Unset, `TOKIO_WORKER_THREADS` decides, else the number of CPUs
available to the process. The startup log (`RUST_LOG=info`) shows the count
and where it came from.

SIGTERM or Ctrl-C stops the binary gracefully: it stops accepting, lets the
calls in flight finish for up to `listen.drain_timeout_secs`, and exits 0.

## Configuration

```yaml
# my-service.yaml
listen:
  http: "0.0.0.0:8080"
  # Optional: most connections served at once; past it the next one waits in
  # the listen backlog until a connection closes. Unset: no limit.
  # max_connections: 10000
  # Seconds a connection may go without a request in flight before it is
  # closed (HTTP/2 gets a GOAWAY), so idle clients do not hold connection
  # slots; 0 keeps idle connections open. A stream keeps its connection.
  idle_timeout_secs: 60
  # Seconds an HTTP/1.1 client has to send a request's headers.
  header_read_timeout_secs: 30
  # Seconds a shutdown (SIGTERM, Ctrl-C) waits for requests and streams in
  # flight to finish; the connections still open after it are closed.
  # 0 waits for all of them.
  drain_timeout_secs: 25
  # Optional: TLS on the listener (REST and gRPC share the port; ALPN offers
  # h2 and http/1.1). With client_ca_file, client certificates are verified
  # (mTLS) and reach an in-process tonic upstream as Request::peer_certs.
  # tls:
  #   cert_file: "/etc/proxy/tls.crt"      # PEM chain, leaf first
  #   key_file: "/etc/proxy/tls.key"       # PEM private key
  #   client_ca_file: "/etc/proxy/ca.crt"
  #   client_auth: required                # or `optional`; needs client_ca_file
  #   handshake_timeout_secs: 10

# The gRPC service behind the proxy. Required by the standalone binary; an
# embedder with an in-process upstream leaves it out.
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
  # A non-empty list allows those exact origins, with credentials; the
  # preflight echoes the methods and headers the browser asks for. There is
  # no "*" wildcard (browsers never send `Origin: *`, so listing "*" would
  # block everything).
  origins: []
  # e.g. origins: ["https://app.example.com", "https://admin.example.com"]
  # Response headers a browser script may read, on top of grpc-status,
  # grpc-message, grpc-status-details-bin and the rate-limit headers:
  # typically upstream metadata forwarded as a header.
  expose_headers: []
  # e.g. expose_headers: ["x-request-id"]
  # How long a browser caches a preflight answer (seconds). Unset: the
  # browser's default.
  # max_age_secs: 600
  # Apply this policy to gRPC-Web calls passed through to the upstream and to
  # their preflights. Turn off only when the upstream sets CORS on gRPC-Web
  # itself: its preflights then reach the upstream too.
  grpc_web: true

# Optional: convert gRPC-Web calls to gRPC for an upstream that speaks only
# gRPC (binary and text gRPC-Web, over HTTP/1.1 too). Off: gRPC-Web passes
# through for the upstream to answer. Needs cors.grpc_web.
grpc_web:
  translate: false

# Optional: transcode only these services and methods; every annotated RPC
# by default. A name the descriptors do not hold stops the proxy at startup.
transcode:
  only: ["my.package.v1.MyService", "my.package.v1.Admin/GetStatus"]

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

# Optional: the async runtime of the standalone binary (the library runs on its
# embedder's runtime and ignores this section).
runtime:
  # Worker threads, i.e. how many CPU cores the proxy keeps busy. Unset:
  # TOKIO_WORKER_THREADS, else the available parallelism (the cgroup CPU quota
  # on Linux). Must be at least 1.
  worker_threads: 2

# Optional: maintenance mode (returns 503 except for exempt paths)
maintenance:
  enabled: false
  message: "Service is under maintenance. Please try again later."
  # Which traffic it turns away (see "Guards and scopes"). Default:
  # [transcoded, endpoints].
  # scope: { traffic: [all] }

# Optional: request concurrency limit. Requests past max_in_flight get 503
# UNAVAILABLE with `Retry-After: 1` at once; a request holds its slot until its
# response body ends. Default scope: [transcoded, grpc], so health probes and
# metrics still answer while the proxy is saturated.
concurrency:
  max_in_flight: 512
  # scope: { traffic: [grpc], paths: ["/acme.v1.Orders/*"] }

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
  # Wrap every NDJSON line as {"result": ...} / {"error": ...} (see "Error
  # responses"). Default: false.
  ndjson_envelope: false

# Optional: google.rpc.Status details in error bodies (see "Error responses").
# On everywhere by default. `opaque` forwards details of types no descriptor
# describes as `opaqueDetails` instead of withholding them (off by default).
# Rules are checked in order; for each switch a rule sets, the first rule whose
# pattern matches the mounted route decides; `*` stays within one path segment
# (a path parameter counts as one), `**` spans segments.
error_details:
  enabled: true
  opaque: false
  routes:
    - pattern: "/v1/internal/**"
      enabled: false
    - pattern: "/v1/partner/**"
      opaque: true

# Optional: upstream response metadata keys kept off the HTTP response (see
# "Upstream controls"). Every other application key is forwarded as a header.
response_headers:
  deny: ["x-debug-trace"]

# Optional: how the client's address is resolved and what the upstream
# receives of it (see "Client address"). Defaults: no trusted proxy, the right
# setting for a proxy facing clients; a verified X-Forwarded-For.
client_address:
  # Proxies trusted to report the client's address: CIDR ranges or addresses.
  trusted_proxies: ["10.0.0.0/8"]
  # The header they report it in: x_forwarded_for (default) or x_real_ip.
  header: x_forwarded_for
  # Refuse a request whose address does not resolve. Default: false.
  required: false
  forward:
    # X-Forwarded-For upstream: verified (default), resolved, append,
    # preserve or remove.
    x_forwarded_for: verified
    # Header carrying the resolved address; null for none.
    client_header: x-real-ip
    # Header carrying X-Forwarded-For exactly as it arrived, for logs.
    # Default: off.
    audit_header: null

# Rate limiting (Shield)
#
# Every decision is made locally with a GCRA shaper (no blocking latency).
# Named profiles define tiers as data; rules bind a path glob to a key and a
# limit. Rules keyed by a JWT claim run after auth (so the claim is verified);
# the rest run before auth so anonymous floods are shed cheaply.
shield:
  enabled: true
  # Which traffic the rules apply to. Default: [transcoded, endpoints].
  # scope: { traffic: [transcoded, endpoints, grpc] }
  # IP rules key by the client address of `client_address:` below.
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
  # Which traffic needs a token. Default: [transcoded, endpoints]; the
  # forward-auth endpoint is never behind it. `auth.authz` takes a `scope` too
  # (default: [transcoded]).
  # scope: { traffic: [transcoded, grpc] }
  jwt:
    jwks_uri: "https://idp.example.com/.well-known/jwks.json"
    # OR a static key: public_key_pem_file: "/etc/proxy/idp-ed25519.pub.pem"
    jwks_max_age_secs: 300 # refetch the keys after this age (default 300, at least 60)
    issuer: "https://idp.example.com"
    audience: "my-api"
    roles_claim: "roles" # array-of-strings claim used for required_roles
    claims_headers: # forward claims to the upstream as headers
      sub: "x-user-id"
    # Verified tokens are reused until the earlier of their `exp` and
    # max_ttl_secs (see "JWT verification"). Defaults shown.
    cache:
      enabled: true
      max_entries: 10000
      max_ttl_secs: 60
      max_token_bytes: 4096
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

## Request mapping

The gRPC request message is built from the path, the query string and the
body, as the route's `google.api.http` rule says:

- **Precedence:** a path parameter wins over the body, and the body over the
  query string. A query parameter only fills a field the body did not send;
  a field sent at its default still counts as sent (`{"count": 0}` beats
  `?count=5`), and a body key in the JSON name (`displayName`) and a query key
  in the proto name (`display_name`) are the same field.
- **JSON body:** the ProtoJSON of the input message (`body: "*"`) or of the
  field `body` names. An unknown key is an error.
- **Path, query and form values** (`application/x-www-form-urlencoded`
  bodies) are strings, converted to each field's type the way ProtoJSON reads
  them: numbers, `true`/`false`, enum names, base64 bytes, and the string form
  of `Timestamp`, `Duration`, `FieldMask` and the wrapper types. A key names a
  field by its proto or JSON name, a repeated key fills a repeated field, `a.b`
  reaches a nested field, and an unknown key is dropped. A well-known type can
  also be set field by field (`at.seconds=5&at.nanos=7`, `note.value=x`, or a
  form body bound to it); the result must be a value its JSON form could hold,
  so `at.nanos=2000000000` is rejected.

A value that is not valid for its field, or two members of one `oneof`, is
answered with `INVALID_ARGUMENT` (400) before the upstream is called.

A variable bound to a multi-segment template (`{name=shelves/*/books/*}`,
AIP-127) takes only a value of that shape: its literals, one segment per `*`,
any number for `**`. `**` must be the last part of the path: a template that
uses it before the last segment, or puts another segment after it, is left
out with an error in the log. Of the bindings of one router path, those such
a template or an escaped literal constrains are tried before the open ones. The value of such a variable, and of `{name=**}`, is
percent-decoded except for `%2F`, which reaches the field as received, so an
encoded slash stays distinct from a segment boundary; a single-segment
variable decodes it. A literal of such a template that holds a percent-escape
matches whatever the case of its hex digits, so to the router it is a
variable: like any variable, it cannot share its position with a `**` of
another binding, and the later of the two is left out with an error.

**Custom verbs.** A path template may end in a verb, as AIP-136 custom methods
do (`post: "/v1/{name=operations/*}:cancel"`):

- A request's verb is its last segment from the first unencoded colon: a
  client percent-encodes the reserved characters of a variable's value, and a
  verb writes its own reserved characters encoded too
  (`:run%3Anow`), so neither holds a raw `:`. A percent-encoded colon (`%3A`)
  in a request is part of a value, never the verb's delimiter.
- A verb some binding of the request's path binds owns that URL: only the
  bindings of that verb answer it, each reaching its own RPC. A verb no
  binding binds stays part of the last variable (`/v1/items/a:b` is the item
  `a:b`), as Envoy's transcoder and grpc-gateway treat an unbound verb.
- A template ending in a literal matches its URL exactly and wins over a
  variable with the same verb: `get: "/v1/jobs/special:cancel"` answers that
  URL ahead of `post: "/v1/jobs/{name}:cancel"`, as a static route does.
- `**` before a verb may match no segment: `/v1/{name=**}:purge` answers
  `/v1/:purge` with an empty `name`.
- A path with a verb after its variable answers every method, so an extra
  route of yours on the same path stops the proxy at startup.
- A URL that bindings answer, but none with the request's method, is `405`,
  with their methods in `Allow`; a path that no binding answers is `404`.

A template the router cannot match, such as text around a variable within one
segment (`/v1/a{name}b`), is left out with an error in the log; the other
routes still serve.

## Client address

The proxy works out who the client is once per request, before any guard
runs, and every consumer reads that one answer: the rate limits, the auth
decider and extra routes, your fallback and an upstream in process (as the
`ClientAddress` request extension), and a remote upstream (as headers).

**Resolution.** The connection's peer is the client, unless it is listed in
`client_address.trusted_proxies`. Only then does the proxy read the header the
trusted proxy reports the address in, because forwarding information is not
trustworthy by itself (RFC 7239 §8.1):

- `x_forwarded_for` (default): every `X-Forwarded-For` field line, in order, as
  one list (RFC 9110 §5.3). The proxy walks it from the right through the
  trusted proxies and stops at the first address outside them; what lies left
  of that address is the client's own claim and is never read. When every hop
  is trusted, the leftmost is the client. Empty elements are skipped
  (RFC 9110 §5.6.1). An element may be an IPv4 or IPv6 address, bracketed
  IPv6, either with a port; an IPv4-mapped IPv6 address counts as IPv4, for
  the peer too.
- `x_real_ip`: one `X-Real-IP` value, the trusted proxy's own peer.

The proxy does not fall back from one header to the other. A trusted peer that
sends neither is the client itself (an internal service calling directly).
The walk reads at most 32 elements of at most 128 bytes each before the
client, so a long header costs nothing past that, and no lookup leaves the
process.

**When nothing resolves.** The proxy never makes an address up:

| Case | `Resolution` | The request |
|------|--------------|-------------|
| The server recorded no connection (a Unix socket, a server of your own without `for_connection`) | `Unavailable` | goes on without an address, or with `required: true` is refused with `INTERNAL` (500) |
| A trusted proxy reported something unreadable where the client should be (not an address, a repeated `X-Real-IP`, more than 32 hops) | `Invalid` | goes on without an address, or with `required: true` is refused with `INVALID_ARGUMENT` (400) |

Such a request is never credited to the trusted proxy's own address. Its rate
limits key into one shared bucket per case, so it cannot escape a limit. A
refusal reaches a gRPC or gRPC-Web client as a status in its own protocol, like
any guard's (see [Guards and scopes](#guards-and-scopes)). Malformed data left
of an address already resolved cannot cause either case.

**What the upstream receives.** Resolution decides who the client is; the
`forward` policy decides what the upstream is told, independently. The rate
limits and the hooks always use the resolved address, whatever is forwarded.

| `forward.x_forwarded_for` | `X-Forwarded-For` upstream | Its first element |
|---|---|---|
| `verified` (default) | the client, the trusted proxies after it, this proxy's peer: `203.0.113.7, 10.0.0.2, 10.0.0.1` | the client |
| `resolved` | the client alone | the client |
| `append` | the list as it arrived, then this proxy's peer | whatever the client wrote |
| `preserve` | the list as it arrived; `X-Real-IP` and `Forwarded` too | whatever the client wrote |
| `remove` | nothing | none |

With `verified`, whatever the client wrote left of its own address is dropped,
so an upstream reading the first element and one walking the list from the
right reach the same client. In every mode but `preserve`, `X-Real-IP` and
`Forwarded` (RFC 7239) from the request are removed, since they would
contradict the list. On top of the list:

- `forward.client_header` (`x-real-ip` by default, `null` for none) carries
  the resolved address alone, whatever the request sent under that name, and
  is absent when nothing resolved.
- `forward.audit_header` (off by default) carries the request's
  `X-Forwarded-For` field lines exactly as they arrived, before any change.
  Nothing in it is verified: it is for logs and audits, never for decisions.

The same headers reach native gRPC, gRPC-Web passed through or translated,
transcoded unary and streaming calls, and the fallback; remote and in process
alike. Listing them in `forwarded_headers` changes nothing. They are the
proxy's own: a JWT `claims_headers` entry naming one stops the proxy at
startup, and an ext_authz server's or the auth decider's copies are ignored
with a warning in the log. An upstream in process also gets the
`ClientAddress` extension, while `Request::remote_addr` and
`Request::peer_certs` keep describing the real connection.

**Coming from another proxy.** Each one's habit is one setting away:

| Behind | `forward` |
|---|---|
| nginx with `$proxy_add_x_forwarded_for` and `X-Real-IP $remote_addr` | `x_forwarded_for: append`, `client_header: x-real-ip` |
| nginx without `proxy_set_header` | `x_forwarded_for: preserve`, `client_header: null` |
| Envoy with `use_remote_address` | `append`, `client_header: x-envoy-external-address` |
| HAProxy with `option forwardfor` | `append` |
| AWS ALB `append` / `preserve` / `remove` | the mode of the same name |
| Cloudflare | `append`, `client_header: cf-connecting-ip` |
| Akamai | `client_header: true-client-ip` |
| Traefik, Caddy | `verified` (stricter: a prefix forged before a trusted balancer does not get through), or `append` |

With `append` and `preserve`, the first element of `X-Forwarded-For` is
whatever the client chose to write. An upstream behind them should read the
client header, or walk the list from the right with this proxy as its only
trusted hop.

**At the edge**, facing clients directly, leave `trusted_proxies` empty: the
peer is the client, and what it sends in forwarding headers never counts.

**Behind a load balancer**, trust exactly the addresses it connects from, and
have it append the peer it sees to `X-Forwarded-For` (nginx
`proxy_add_x_forwarded_for`, most cloud load balancers), or set `X-Real-IP` and
choose `header: x_real_ip`:

```yaml
client_address:
  trusted_proxies: ["10.0.0.0/8"]   # the load balancer's subnet
  header: x_forwarded_for
  required: true                    # every request must name its client
  forward:
    audit_header: x-original-forwarded-for   # what arrived, for the access log
```

**The upstream's side.** The proxy is the upstream's only reporter: the
upstream should trust forwarding headers from the proxy's address alone and
read the client header, or the first element of a `verified` list, rather than
judge the chain on its own (Keycloak, for instance: `proxy-headers=xforwarded`
with `proxy-trusted-addresses` set to the proxy). This holds only while
nothing else can reach the upstream: keep it off any network the clients
reach, by network policy or by running it in process, or a client could talk
to it directly and send its own `X-Forwarded-For`.

**In code**, `ProxyServer::with_client_address` takes the same section, and a
tonic handler behind the proxy reads the result:

```rust
use structured_proxy::client_address::Resolution;
use structured_proxy::config::{ClientAddressConfig, ForwardingHeader, XForwardedFor};
use structured_proxy::{ClientAddress, ProxyServer};

# fn build(grpc: tonic::service::Routes) -> anyhow::Result<()> {
let mut client_address = ClientAddressConfig::default();
client_address.trusted_proxies = vec!["10.0.0.0/8".into()];
client_address.header = ForwardingHeader::XForwardedFor;
// As nginx forwards with `$proxy_add_x_forwarded_for`, plus the audit copy.
client_address.forward.x_forwarded_for = XForwardedFor::Append;
client_address.forward.audit_header = Some("x-original-forwarded-for".into());
let service = ProxyServer::new()
    .with_client_address(client_address)
    .service(grpc)?;
# let _ = service;
# Ok(())
# }

// In a tonic handler, transcoded call or native gRPC alike.
fn caller(request: &tonic::Request<()>) -> String {
    match request.extensions().get::<ClientAddress>().map(ClientAddress::resolution) {
        Some(Resolution::Peer(ip) | Resolution::Forwarded(ip)) => ip.to_string(),
        _ => "unknown".to_string(),
    }
}
# let _ = caller;
```

**Moving from `shield.trusted_proxies`.** The list moved to
`client_address.trusted_proxies` and now applies to every consumer, with or
without rate limits; a config that still sets the old key fails to load with a
message saying so. Shield used to fall back to `X-Real-IP` when
`X-Forwarded-For` was missing or broken: a load balancer that sends only
`X-Real-IP` now needs `header: x_real_ip`. Code that mounts the Shield
middleware in a router of its own puts
`client_address::ClientAddressLayer::new(&config)` in front of it, which
resolves the address the same way the proxy does. The hooks' `RequestParts::peer` and
`RouteRequest::peer` became `client`, a `ClientAddress` whose `peer()` is the
connection's peer, absent when the server recorded none instead of
`0.0.0.0:0`.

## Rate limiting

Shield decides every request in the proxy's own process with GCRA, so a limit
never waits on the network. GCRA lets a client burst up to `burst` requests
and then holds it to `rate`, without the spikes a fixed window allows at its
edges.

**Keys and when they run.** A rule keys on the client IP, a header (an API
key) or a verified JWT claim, and the key decides when the rule runs:

- IP and header rules run before auth, so a flood is shed before any token
  signature is checked.
- `jwt_claim` rules run after auth, on the verified claim.

A request that lacks the key's value (no header, no token) is keyed by its IP,
so leaving the header out does not escape the limit. That fallback happens in
the rule's own phase: an anonymous request under a `jwt_claim` rule is limited
by IP only after auth. To shed anonymous floods early, add an IP rule for the
same paths; a path matches at most one rule in each phase, and both apply.

**Which limit applies.** A key's rate and burst come from, in order: the token
(a `ratelimit_tier` claim naming a profile, or `ratelimit_rpm` /
`ratelimit_burst` claims), the external limit service (cached and refreshed in
the background), the rule's profile, the default profile. Limits from the
token apply to `jwt_claim` rules only, the only ones that see verified claims.
A tier name in the token lets you retune the numbers in config without
reissuing tokens.

**Response headers.** Every limited response carries the
[draft-ietf-httpapi-ratelimit-headers](https://datatracker.ietf.org/doc/draft-ietf-httpapi-ratelimit-headers/)
fields: `RateLimit-Limit` (the quota per window), `RateLimit-Remaining`
(requests allowed right now) and `RateLimit-Reset` (seconds until the budget
refills). A rejected request gets `429` with `Retry-After`, the seconds to wait
before retrying. CORS exposes all of them to browser scripts.

**Deployment modes.**

- **Local (default).** Each instance enforces the limit on its own, so `N`
  instances admit roughly `N × rate` together. Set per-instance limits with
  that in mind.
- **Shared (`sync`, with the `redis` feature).** Instances push their counts
  to Redis in the background and read the fleet's total on an interval, so
  `rate` becomes the budget of the whole fleet, approximately. A request never
  waits on Redis; while Redis is down, each instance limits locally.

**How far the fleet can overshoot.** The shared total is up to one
`sync.interval_ms` old. Within that time every other instance can still admit
its own `burst` plus the share of `rate` that falls in the interval, so the
fleet can exceed its budget by about
`(N - 1) × (burst + rate × interval / window)` requests. With `burst = 100`,
`rate = 1000/min`, a 500 ms interval and 4 instances that is
`3 × (100 + 1000 × 0.5 / 60) ≈ 325` requests. A smaller `burst` and a shorter
interval shrink it.

See the `shield:` block under [Configuration](#configuration) for the full
schema.

## Guards and scopes

A guard is a check that may turn a request away: maintenance mode, the
concurrency limit, the rate limits, JWT auth, ext_authz and the auth decider.
Each one covers the traffic its `scope` names, and nothing else:

| Traffic | What it is |
|---------|------------|
| `transcoded` | REST calls the proxy transcodes to gRPC |
| `endpoints` | the proxy's own endpoints: health, metrics, OpenAPI, OIDC, extra routes, forward-auth |
| `grpc` | native gRPC and gRPC-Web calls passed through to the upstream |
| `fallback` | requests no route answers, handed to `ProxyService::with_fallback` |
| `all` | every class above |

```yaml
scope:
  traffic: [transcoded, grpc]
  paths: ["/v1/orders/**", "/acme.v1.Orders/*"]   # optional, globs
  methods: ["POST"]                                 # optional
```

`paths` and `methods` narrow the guard within its traffic; `*` stays within a
path segment and `**` spans segments. A native gRPC call's path is
`/<package>.<Service>/<Method>`. A method is a standard one or one a route
answers (a `custom` rule, an extra route); a scope covering `fallback` takes
any method. A scope whose `traffic` is empty, a relative or invalid glob, `*`
as a method (leave `methods` out to cover every method) or a method no route
answers stops the proxy at startup.

| Guard | Configured by | Default traffic |
|-------|---------------|-----------------|
| maintenance | `maintenance.scope` | `transcoded`, `endpoints` |
| concurrency limit | `concurrency.scope` | `transcoded`, `grpc` |
| rate limits | `shield.scope` | `transcoded`, `endpoints` |
| JWT | `auth.scope` | `transcoded`, `endpoints` |
| ext_authz | `auth.authz.scope` | `transcoded` |
| auth decider | `ProxyServer::with_auth_decider_scope` | `transcoded` |

The forward-auth endpoint answers for JWT, ext_authz and the decider, so it is
never behind them, whatever their scope. A request runs the guards of its own
class only, in this order: a required client address
(`client_address.required`, every class, see [Client address](#client-address)),
maintenance, concurrency, rate limits keyed before auth, JWT, rate limits keyed
by verified claims, ext_authz, the decider. A guard outside the request's class
costs it nothing.

**Rejections in the request's protocol.** A REST client gets the
`google.rpc.Status` JSON body of [Error responses](#error-responses) with the
mapped HTTP status and an empty `details`:

```json
{ "error": "RESOURCE_EXHAUSTED", "code": 8, "message": "rate limit exceeded", "details": [] }
```

A gRPC or gRPC-Web client gets a trailers-only response with the same code
(`UNAUTHENTICATED`, `PERMISSION_DENIED`, `RESOURCE_EXHAUSTED`, `UNAVAILABLE`)
and message, and the guard's headers (`Retry-After`, `RateLimit-*`,
`WWW-Authenticate`, `Location`) as metadata. A gRPC-Web rejection keeps the
proxy's CORS policy. An ext_authz denial carries the Check's own status code;
a decider's `Deny` maps its HTTP status back to a code by the `google.rpc.Code`
table, and its `Redirect` reaches a gRPC client as `UNAUTHENTICATED` with
`Location` in the metadata, since a gRPC client cannot follow it.

## Error responses

A failed gRPC call becomes a JSON body with the status of the gRPC → HTTP
mapping (`INVALID_ARGUMENT` → 400, `NOT_FOUND` → 404, ...):

```json
{
  "error": "INVALID_ARGUMENT",
  "code": 3,
  "message": "invalid email",
  "details": [
    {
      "@type": "type.googleapis.com/google.rpc.ErrorInfo",
      "reason": "EMAIL_TAKEN",
      "domain": "identity.example.com",
      "metadata": { "email": "a@b.c" }
    },
    {
      "@type": "type.googleapis.com/google.rpc.BadRequest",
      "fieldViolations": [{ "field": "email", "description": "already registered" }]
    }
  ]
}
```

- `code`, `message` and `details` follow `google.rpc.Status`; `error` is the
  code's name. A client that parses the body as `google.rpc.Status` with a
  strict ProtoJSON parser must let it ignore unknown fields.
- `details` is the upstream's `grpc-status-details-bin` trailer, one entry per
  `Any`, in [ProtoJSON](https://protobuf.dev/programming-guides/json/#any)
  form: `@type` plus the message fields, or `@type` plus `value` for a
  well-known type with a special JSON representation (`google.protobuf.Duration`
  as `"1.500s"`). Types resolve from the service's descriptors first, then from
  the canonical `google/rpc/status.proto` and `error_details.proto`, which are
  always available. An upstream that sends no trailer yields `"details": []`.
- `google.rpc.DebugInfo` is never forwarded: it carries stack traces and server
  internals meant for the service's operators. It is removed wherever the
  proxy knows the schema; a detail whose type is in neither descriptor set
  cannot be checked, so it is withheld too unless the opaque-detail extension
  below is switched on.
- Details are on for every route. They can be switched off globally or per
  route (see below); on such a route the `details` and `opaqueDetails` keys are
  absent and the body is `{"error", "code", "message"}`.
- Errors the proxy raises itself on a transcoded route use the same body: a
  request that cannot be mapped onto the RPC (`INVALID_ARGUMENT`, 400), an
  upstream that is not reachable (`UNAVAILABLE`, 503), a response that cannot
  be serialized (`INTERNAL`, 500). Their `details` is empty.
- A malformed upstream error is replaced as a whole, never passed on in part
  or guessed at. The client gets
  `{"error": "INTERNAL", "code": 13, "message": "upstream returned a malformed error status", "details": []}`
  (500, or the terminal frame of a started stream), and the proxy logs the
  cause. Malformed means: a details trailer that is not a `google.rpc.Status`
  or contradicts `grpc-status` / `grpc-message`, a type URL that is not
  `…/<protobuf full name>`, or a detail of a known type that does not decode
  or has no JSON form (a `Duration` out of range). Routes with details
  switched off never read the trailer.

**Opaque-detail extension.** ProtoJSON cannot represent an `Any` whose type is
unknown to the writer, so a detail whose type is in neither descriptor set has
no place in `details`. By default such a detail is withheld: its bytes cannot
be inspected, and a `DebugInfo` in one of its fields would otherwise reach the
client. When switched on (`opaque: true`, globally or in a route rule, or
`ErrorDetailsPolicy::with_opaque_details` / `opaque_route`), structured-proxy
keeps it in a separate `opaqueDetails` array instead. Switch it on only for
upstreams trusted not to nest a `DebugInfo` in types the proxy has no
descriptor for. The array is structured-proxy's own extension and **not** part
of ProtoJSON or `google.rpc.Status`:

```json
{
  "error": "FAILED_PRECONDITION",
  "code": 9,
  "message": "quota exhausted",
  "details": [
    { "@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "QUOTA", "domain": "acme.example.com" }
  ],
  "opaqueDetails": [
    { "index": 1, "typeUrl": "type.googleapis.com/acme.v1.QuotaTicket", "bytes": "CgNULTE=" }
  ]
}
```

- `typeUrl` is the original type URL and `bytes` the standard base64 of the
  original bytes. An entry has no `@type` and never appears in `details`, so
  `details` stays an array of ProtoJSON `Any` and nothing in the extension can
  be taken for a message of the named type.
- `index` is the entry's position among the forwarded details: merging
  `details` and `opaqueDetails` by position restores the upstream's order.
- `opaqueDetails` appears only when at least one detail went there. A client
  that knows the type base64-decodes `bytes` and parses the protobuf itself; a
  client that does not handle the extension ignores the key.
- Only an unknown type goes there. A detail of a known type that fails to
  decode is a broken upstream status (see above), never an opaque entry.

**Errors in server-streaming responses.** If the upstream rejects the call
outright, the client gets the mapped HTTP status and the body above. Once the
upstream accepts the call, the proxy answers `200` and starts the stream at
once, without waiting for the first message. A failure after that, or a
message the proxy cannot serialize, ends the stream with one terminal frame
carrying that body:

- **NDJSON**: the last line, the error body with
  `"@type": "type.googleapis.com/google.rpc.Status"` added. An RPC that streams
  `google.protobuf.Any`, `Struct`, `Value` or `ListValue` can send data lines
  that look the same; for those set `streaming.ndjson_envelope: true` (or
  `ProxyServer::with_ndjson_envelope(true)`), and every data line becomes
  `{"result": <message>}` and the error `{"error": <error body>}`, the
  grpc-gateway shape. It is off by default because it changes the data lines
  too.
- **SSE**: an event of type `stream-error` (listen with
  `addEventListener("stream-error", ...)`) whose data is the error body. It is
  not `EventSource.onerror`, which fires on transport failures.

This is the HTTP/JSON transcoding format. It is not the Connect protocol's error
format, and it is not an OAuth 2.0 token endpoint error body (RFC 6749 §5.2):
an upstream that needs one answers successfully with that body instead (see
[Upstream controls](#upstream-controls)).

**Switching details off.** `error_details:` in the config file (see
[Configuration](#configuration)) is read by the binary and by
`ProxyServer::from_yaml_str` / `ProxyServer::from_file`. It is not part of
`ProxyConfig`, so `ProxyConfig::from_yaml_str` alone ignores it. Both warn at
startup about a top-level or `streaming:` key they do not know, so a typo such
as `error_detail:` does not silently keep the default. In code, use
`ProxyServer::with_error_details`.

Route rules are checked in order: for each switch (`enabled`, `opaque`), the
first rule that matches the route and sets that switch decides; with none, the
global value holds. `*` matches within one path segment (a path parameter
counts as one), `**` across segments. A config rule that sets neither switch
is an error:

```rust
use structured_proxy::transcode::error::ErrorDetailsPolicy;
use structured_proxy::{config::ProxyConfig, ProxyServer};

# fn build(config: ProxyConfig) -> Result<ProxyServer, String> {
// Details everywhere except the internal admin surface.
let policy = ErrorDetailsPolicy::default().route("/v1/admin/**", false)?;
// Or: off everywhere except a public sub-route.
// let policy = ErrorDetailsPolicy::disabled().route("/v1/public/**", true)?;
// Unknown detail types as `opaqueDetails` for one trusted partner surface.
let policy = policy.opaque_route("/v1/partner/**", true)?;
Ok(ProxyServer::from_config(config).with_error_details(policy))
# }
```

## Upstream controls

HTTP protocols served as gRPC (an OAuth 2.0 / OpenID Connect provider, a
forward-auth endpoint, a file download) need more than a JSON body with `200`:
a status of their choosing, response headers, bodies that are not JSON, and
methods other than the five standard ones. The upstream RPC decides all of
these; the proxy only carries them, as Envoy's `grpc_json_transcoder` and
grpc-gateway do, so the same service works behind any of them.

**Request headers → request metadata.** Each header listed in
`forwarded_headers` reaches the upstream as metadata:

- byte for byte, every value, in the client's order, so a check that counts
  headers (RFC 9449 §4.3 rejects two `DPoP` headers) sees the request as sent;
- a `-bin` header keeps its base64, one metadata value per comma-separated
  part;
- a value gRPC metadata cannot carry (empty, a character outside visible ASCII
  and space, or bad base64 under a `-bin` key) is refused with
  `INVALID_ARGUMENT` (400) naming the header, since gRPC lets a receiver
  silently drop such a value;
- a listed name that is not a gRPC metadata key (letters, digits, `_`, `-`,
  `.`) stops the proxy at startup.

Trace context goes through whether listed or not: the upstream gets exactly
one valid `traceparent` (the client's first, or a new one when it is missing
or malformed), and `tracestate` only together with the client's own trace.
`X-Forwarded-For`, `X-Real-IP`, `Forwarded` and the headers named in
`client_address.forward` carry what that forwarding policy wrote, listed or
not (see [Client address](#client-address)).

**Response metadata → response headers.** The upstream's response metadata
becomes HTTP response headers: every ASCII entry, in order, repeated values as
repeated headers, a key in both initial metadata and trailers with both
values. That covers a unary call, succeeded or failed (so a `401` carries its
`WWW-Authenticate`), and the initial metadata of a server stream; a stream's
trailers arrive after its headers are sent. Not forwarded:

- gRPC's own keys: `grpc-*`, binary `-bin` keys and `content-type` (the proxy
  sets it for the body it writes);
- hop-by-hop and framing fields, which describe the upstream connection:
  `connection`, `keep-alive`, `proxy-connection`, `te`, `trailer`,
  `transfer-encoding`, `upgrade`, `content-length`;
- `x-http-code` (below);
- anything the operator denies: `response_headers.deny` in the config file or
  `ProxyServer::with_denied_response_headers`, e.g. to keep internal debugging
  headers off a public edge. There is no allow-list: a header the upstream sets
  is meant for its HTTP clients.

A header the proxy writes for the body itself wins over the same upstream key
(an SSE stream stays `Cache-Control: no-cache`). The metadata of an error whose
details are malformed is dropped along with it (see
[Error responses](#error-responses)). Browsers read only
[CORS-safelisted](https://fetch.spec.whatwg.org/#cors-safelisted-response-header-name)
response headers plus the exposed ones, so a browser client that must read a
forwarded header needs it listed in `cors.expose_headers`.

**Status from `x-http-code`.** On a successful unary call, the response
metadata `x-http-code` (grpc-gateway's convention) sets the HTTP status, one
integer from 200 to 599. A value that is not three digits, is out of range or
comes twice turns the whole answer into
`{"error": "INTERNAL", "code": 13, "message": "upstream returned a malformed response", "details": []}`
(500). `204`, `205` and `304` go out without a body or `Content-Type`
(RFC 9110 §15.3.5, §15.3.6, §15.4.5). Failed calls keep the `google.rpc.Code`
mapping, so a protocol's own error body is sent as a successful call with
`x-http-code` and that body. Server-streaming calls ignore the key.

**Raw bodies with `google.api.HttpBody`.**

- An RPC that returns `google.api.HttpBody` (or whose `response_body` names a
  field of that type) answers with `data` as the body and `content_type` as
  `Content-Type` (none when empty; a value that is not a valid header is a
  malformed response, 500).
- An RPC that takes `HttpBody` with `body: "*"` (or whose `body` names a field
  of that type) receives the raw request body and its full `Content-Type`.
  With a named field, the other fields still come from the path and query; a
  query key naming the body field is ignored. With `body: "*"` every field
  comes from the body, so the query binds nothing.
- A server-streaming `HttpBody` writes each message's `data` as it arrives,
  with `Content-Type` from the first message. A raw body has no way to carry
  an error, so a failure after the first message aborts the transfer, and the
  client does not take a partial body for a complete one.

An RFC 6749 token endpoint, for example:

```proto
rpc Token(TokenRequest) returns (google.api.HttpBody) {
  option (google.api.http) = { post: "/oauth2/token" body: "*" };
}
```

answers a bad grant with `x-http-code: 400`, `cache-control: no-store` and an
`HttpBody` of `application/json` holding `{"error": "invalid_grant"}`; the
client gets exactly that `400`. An authorization endpoint answers
`x-http-code: 302` with `location` and an empty `HttpBody`; a JWKS endpoint
returns `application/jwk-set+json` (RFC 7517 §8.5).

**`custom` rules.** `HttpRule.custom` (`{kind, path}`) binds any method:
`kind: "HEAD"`, `kind: "OPTIONS"`, an extension method such as `PROPFIND`
(case-sensitive, RFC 9110 §9.1), or `kind: "*"` for every method, as
`google/api/http.proto` defines; in `additional_bindings` too.

- A `*` rule suits a forward-auth sub-request (nginx `auth_request`, Traefik
  `forwardAuth`), which arrives with the original request's method.
- A `*` rule owns its path for every method, so another binding on the same
  path is an error at startup.
- OpenAPI lists a `*` rule under every operation and leaves extension methods
  out.
- Only a real CORS preflight (`OPTIONS` with both `Origin` and
  `Access-Control-Request-Method`) is answered by CORS; any other `OPTIONS`
  request reaches its route.

## Library Usage

`cargo add structured-proxy` adds the library; the binary and its
command-line dependencies come with the `cli` feature. The library runs on
your tokio runtime and logs through `tracing` to the subscriber you set up.

```rust,no_run
use std::path::Path;
use structured_proxy::ProxyServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Reads the whole config file, including `error_details`,
    // `streaming.ndjson_envelope` and `response_headers`, which live outside
    // `ProxyConfig`.
    let server = ProxyServer::from_file(Path::new("my-service.yaml"))?;

    // Run the proxy on the configured listen address until Ctrl-C, then
    // drain (see "Shutting down").
    server
        .serve_with_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
        })
        .await?;
    Ok(())
}
```

`serve` answers HTTP/1.1 and HTTP/2 on one port: REST requests go to the
proxy's routes, and requests with a gRPC or gRPC-Web content type go to the
upstream as they arrived, so native gRPC clients can use the same address.

### Your own gRPC services as the upstream

A gRPC service that embeds the proxy to add REST hands the proxy its own
services instead of an address. Transcoded calls then reach them in process,
through the service's whole tonic stack (interceptors, layers), like a native
gRPC call. `Request::remote_addr` in a handler gives the address of the
connection, and the `ClientAddress` extension the client's address as the
proxy resolved it (see [Client address](#client-address)).

```rust
use structured_proxy::ProxyServer;

# async fn run() -> anyhow::Result<()> {
// Your services, exactly as you would give them to tonic's server.
let grpc = tonic::service::Routes::default(); // .add_service(MyServer::new(...))

// No `upstream:` in the config: the upstream is `grpc`.
let proxy = ProxyServer::from_file(std::path::Path::new("my-service.yaml"))?
    .service(grpc)?;

// REST and native gRPC on one port.
let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
structured_proxy::serve(listener, proxy).await?;
# Ok(())
# }
```

A transcoded call also carries the HTTP request it was made from as a
`ReceivedRequest` extension: the method and the path and query as the client
sent them, and the gRPC path of the RPC the binding selected. One RPC bound to
several paths (`additional_bindings`, aliases) is told apart by that path, and
a check that names the received request, such as a DPoP proof's `htm` and
`htu` (RFC 9449 §4.3), compares against it. The path is recorded before a
router the proxy is nested in strips its prefix, and no header the client
sends changes it. The proxy only records it; a remote upstream never sees
request extensions.

```rust
use structured_proxy::ReceivedRequest;

fn request_line(request: &tonic::Request<()>) -> Option<(String, String)> {
    let received = request.extensions().get::<ReceivedRequest>()?;
    Some((received.method().to_string(), received.path_and_query().to_string()))
}
# let _ = request_line;
```

`ProxyServer::service` takes any gRPC tower service
(`structured_proxy::upstream::Upstream`): `tonic::service::Routes`, a remote
`tonic::transport::Channel` (what `ProxyServer::upstream` builds from the
config), or anything else that speaks gRPC over `http` types. The result is a
tower service, so it can also run on a server of your own.

### Building the proxy in code

`ProxyServer::new()` starts with every capability off: native gRPC goes to the
upstream, every other request to your fallback. Turn on only what you need;
each method sets the config section of the same name, so a proxy built in code
and one read from YAML behave the same:

```rust
use structured_proxy::config::{self, ConcurrencyConfig, ScopeConfig, Traffic};
use structured_proxy::ProxyServer;

# fn build(pool: prost_reflect::DescriptorPool, grpc: tonic::service::Routes) -> anyhow::Result<()> {
let service = ProxyServer::new()
    // REST for two RPCs of your API.
    .with_descriptors(pool)
    .with_transcoded_rpcs(["acme.v1.Orders/GetOrder", "acme.v1.Orders/ListOrders"])
    // At most 1000 native gRPC calls in flight.
    .with_concurrency_limit(
        ConcurrencyConfig::new(1000).with_scope(ScopeConfig::traffic([Traffic::Grpc])),
    )
    // Sections with many options come from YAML, the file's own syntax.
    .with_rate_limits(config::from_yaml(
        "enabled: true\nprofiles:\n  anon: { rate: \"600/min\" }\nrules:\n  - pattern: \"/**\"\n    key: { type: ip }\n    profile: anon\n",
    )?)
    .service(grpc)?;
# let _ = service;
# Ok(())
# }
```

The methods are `with_upstream_address`, `with_listen`, `with_descriptors`,
`with_transcoded_rpcs`, `with_aliases`, `with_forwarded_headers`,
`with_health`, `with_metrics`, `with_openapi`, `with_oidc_discovery`,
`with_cors`, `with_grpc_web_translation`, `with_streaming`,
`with_maintenance`, `with_concurrency_limit`, `with_client_address`,
`with_rate_limits` and `with_auth`, next to the hooks below.

The config types, and the request views the hooks receive, are
`#[non_exhaustive]`, so a new setting or field is not a breaking change. Build
one from its `Default` and set the fields you need, or with its constructor
when a field has no default (`UpstreamConfig::new`, `ConcurrencyConfig::new`,
`ListenTlsConfig::new`, `AliasConfig::new`, `RequestParts::new`,
`RouteRequest::new`).

### TLS and connection limits

`listen.tls` and `listen.max_connections` configure the listener of
`ProxyServer::serve`. An embedder with a listener of its own gets the same
from `ProxyServer::serve_options`, or builds `ServeOptions` in code, and runs
`structured_proxy::serve_with`:

```rust
use structured_proxy::{ProxyServer, ServeOptions};

# async fn run(tls: rustls::ServerConfig, grpc: tonic::service::Routes) -> anyhow::Result<()> {
let proxy = ProxyServer::from_file(std::path::Path::new("my-service.yaml"))?.service(grpc)?;
let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
// Any rustls config: your own certificate resolver, client verifier, ...
let options = ServeOptions::new().tls(tls).max_connections(10_000);
structured_proxy::serve_with(listener, proxy, options).await?;
# Ok(())
# }
```

Every connection takes a `max_connections` slot from the moment it is
accepted until its socket closes; past the limit, new connections wait in the
listen backlog. Three timeouts keep slots from being held for nothing:

- the TLS handshake runs in the connection's own task, so it never stalls the
  accept loop, and must finish within `listen.tls.handshake_timeout_secs`;
- an HTTP/1.1 request's headers must arrive within
  `listen.header_read_timeout_secs`;
- a connection with no request in flight for `listen.idle_timeout_secs` is
  closed (HTTP/2 gets a GOAWAY, and a gRPC client reconnects when it next
  calls).

A connection a fallback upgrades (a WebSocket) leaves HTTP and these
timeouts, and keeps its slot until it closes. In code the same settings are
`ServeOptions::idle_timeout`, `header_read_timeout` and
`tls_handshake_timeout`. A client certificate the
listener verified reaches a tonic handler in process as `Request::peer_certs`.
TLS needs a rustls crypto provider: the one a crypto backend feature brings,
or the one your process installed (see [TLS crypto](#tls-crypto)).

### Shutting down

`serve` and `serve_with` run until their future is dropped, which closes every
connection at once. For a graceful stop, hand `serve_with_shutdown` (or
`ProxyServer::serve_with_shutdown`) a future that completes when the process
should stop:

```rust
use std::time::Duration;
use structured_proxy::{ProxyServer, ServeOptions};

# async fn run(grpc: tonic::service::Routes) -> anyhow::Result<()> {
let proxy = ProxyServer::from_file(std::path::Path::new("my-service.yaml"))?.service(grpc)?;
let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
let options = ServeOptions::new().drain_timeout(Some(Duration::from_secs(20)));
let stop = async {
    tokio::signal::ctrl_c().await.ok();
};
structured_proxy::serve_with_shutdown(listener, proxy, options, stop).await?;
# Ok(())
# }
```

Once the future completes:

- the listening socket closes, so new connections are refused, and a
  connection still in its TLS handshake or waiting for a `max_connections`
  slot is dropped;
- HTTP/2 connections get a GOAWAY, so their clients open no new calls, and
  HTTP/1.1 connections close after the response in progress;
- calls and streams in flight run to their end, and `serve_with_shutdown`
  returns once every connection has closed;
- after `drain_timeout` (`listen.drain_timeout_secs`; `None` or 0 waits
  without a bound) the connections still open are closed.

Past its grace period an orchestrator kills the process along with its calls,
so keep the drain below it. The default of 25 s fits the 30 s Kubernetes gives
a pod after SIGTERM; with a longer `terminationGracePeriodSeconds` the drain
can grow with it. A connection a fallback upgraded (a
WebSocket) belongs to the fallback's task and closes when that task lets it
go.

### Behind your own TLS

For a server of your own (another TLS stack, a Unix socket), run the service
on your own acceptor: one
`ProxyService::for_connection` call per accepted connection tells the proxy
who is on the other end, so its middleware sees the client's address and a
tonic handler in process reads it with `Request::remote_addr`, and the client
certificate with `Request::peer_certs` (mTLS), for native and transcoded calls
alike. Advertise `h2` next to `http/1.1` in ALPN so gRPC clients get HTTP/2.

```rust
use std::sync::Arc;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use structured_proxy::{ConnectionInfo, ProxyServer};
use tonic::transport::server::Connected;

# async fn run(mut tls: rustls::ServerConfig, grpc: tonic::service::Routes) -> anyhow::Result<()> {
let proxy = ProxyServer::from_file(std::path::Path::new("my-service.yaml"))?.service(grpc)?;
tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
let listener = tokio::net::TcpListener::bind("0.0.0.0:8443").await?;
loop {
    let (tcp, _) = listener.accept().await?;
    let (acceptor, proxy) = (acceptor.clone(), proxy.clone());
    tokio::spawn(async move {
        // The handshake runs in the connection's task, so a slow client
        // does not hold up the others.
        let Ok(stream) = acceptor.accept(tcp).await else { return };
        let service = proxy.for_connection(ConnectionInfo::tls(stream.connect_info()));
        let served = Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
            .await;
        if let Err(error) = served {
            tracing::debug!(%error, "connection ended");
        }
    });
}
# }
```

A plain TCP connection passes `stream.connect_info()` directly
(`ConnectionInfo` converts from tonic's `TcpConnectInfo`).

### What passes through

A request no route matches gets `404`, or goes to your own service with
`ProxyService::with_fallback(my_axum_app)`. Native gRPC calls and the fallback
pass only the guards whose scope names `grpc` or `fallback` (see
[Guards and scopes](#guards-and-scopes)); by default none does. The fallback
keeps its own CORS and tracing.

gRPC-Web calls pass through as they are (but for the forwarding headers, see
[Client address](#client-address)), so the upstream answers them: wrap
your services in tonic-web's layer
(`tower::ServiceBuilder::new().layer(tonic_web::GrpcWebLayer::new()).service(grpc)`)
for binary and text gRPC-Web alike. For an upstream that speaks only gRPC,
set `grpc_web.translate: true` and the proxy converts gRPC-Web calls to gRPC
and the answers back; that needs `cors.grpc_web`, since such an upstream
cannot answer a browser's preflight.

- Browsers get the proxy's CORS policy on these calls, the same one their
  preflight got (`cors.grpc_web`, on by default). `grpc-status`,
  `grpc-message` and `grpc-status-details-bin` are always exposed to them.
- A preflight for a gRPC-Web call (one announcing `x-grpc-web`) goes where
  the call goes: the proxy answers it, the fallback never sees it. With
  `cors.grpc_web: false` it reaches the upstream, whose own CORS policy then
  covers the preflight and the call.
- When the upstream cannot take a call at all, the proxy answers in the
  request's own protocol.

**Deadlines.** A call waits at most five seconds for the upstream's response
headers, or less when the client's `grpc-timeout` says so; then the client
gets `504` `DEADLINE_EXCEEDED`, with an upstream in process or remote. The
client's `grpc-timeout` travels to the upstream; the five-second default does
not, so an upstream that applies `grpc-timeout` to the whole call does not cut
a long server stream short.

### Merging into an axum application

`ProxyServer::router` returns the proxy's HTTP routes in front of the
configured upstream address, to serve or to merge into your own axum `Router`:

```rust,no_run
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

Hooks plug your own stateless logic into the proxy. Their traits use `http`,
`bytes` and `serde_json` types and `#[async_trait]`, so your crate implements
them without depending on axum itself.

```rust
use std::sync::Arc;
use structured_proxy::{config::ProxyConfig, ProxyServer};
use structured_proxy::hooks::{AuthDecider, Decision, RequestParts};

struct MyPdp; // your forward-auth / policy decision

#[async_trait::async_trait]
impl AuthDecider for MyPdp {
    async fn decide(&self, req: &RequestParts<'_>) -> Decision {
        // method / path / headers / client address in, a decision out (no axum types)
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

- **`with_auth_decider`**: an in-process forward-auth / PDP decision, run inline
  on transcoded requests (other traffic with `with_auth_decider_scope`, see
  [Guards and scopes](#guards-and-scopes)) and exposed at `/verify` (path
  configurable via `with_verify_path`).
- **`with_token_verifier`**: replaces the built-in JWT signature check
  (see [JWT verification](#jwt-verification)) while keeping the route policies,
  the roles claim, and the claim→header forwarding.
- **`with_oidc_backend`**: backs the stateless OIDC surface (discovery, JWKS,
  userinfo) with your key/client metadata; supersedes the config-driven static
  discovery.
- **`with_extra_routes`**: registers extra stateless routes through a
  framework-agnostic adapter (request parts in, response parts out).
- **`with_error_details`**: chooses which transcoded routes return the
  upstream's `google.rpc.Status` details (see [Error responses](#error-responses)).
- **`with_denied_response_headers`**: keeps upstream response metadata keys
  off the HTTP responses (see [Upstream controls](#upstream-controls)).

## JWT verification

The bearer-token check sits behind the `TokenVerifier` hook. A build gets one of
two implementations.

**The built-in verifier** is what a plain config-driven deployment uses: keys
from `auth.jwt` (an Ed25519 PEM file or a JWKS endpoint), verified with
`jsonwebtoken`. Its crypto backend is a Cargo feature:

| Feature | Backend | Notes |
|---------|---------|-------|
| `rust_crypto` (default) | RustCrypto | Pure Rust. Uses `rsa`, which carries [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071); the Marvin attack targets private-key timing, and this path only verifies with public keys (see `deny.toml`). |
| `aws_lc_rs` | aws-lc | Constant-time / FIPS-capable, advisory-free, links aws-lc through C FFI. |

Both can be linked at once, as with any pair of Cargo features. `jsonwebtoken`
cannot infer a provider then, so `ProxyServer::from_config` installs `aws_lc_rs`
for the process: it is constant-time and carries no advisory. A build that wants
RustCrypto regardless drops the `aws_lc_rs` feature.

If another crate in your process uses `jsonwebtoken` too, it may reach it before
any proxy server is built, and would hit the same ambiguity. It can also turn on
the other backend for `jsonwebtoken` directly, which leaves this crate looking
single-backend while `jsonwebtoken` sees two. Settle it once at the top of
`main`:

```rust
# fn main() {
# #[cfg(feature = "builtin_jwt")]
structured_proxy::install_default_crypto_provider();
# }
```

The call is idempotent, and installs the backend this crate was built with. It
exists wherever the built-in verifier does, so a `default-features = false`
build with an injected verifier neither has it nor needs it.

**Verified-token cache.** A client sends the same token on every request until
it expires, so the built-in verifier keeps the claims of each token it accepted
(`auth.jwt.cache`, on by default) and skips the signature check on the next
request with it; on an EdDSA token that turns ~41 µs into ~2 µs per request
(`cargo bench --bench jwt_verify`). Route policies, the roles check and claim
headers still run every time.

- An entry is used until the earlier of the token's `exp` and `max_ttl_secs`
  (default 60) after verification, timed on the monotonic clock, so setting
  the system clock back cannot stretch it. A token not yet valid (`nbf` in the
  future) is not cached.
- A token whose signing key leaves the JWKS stops passing within
  `jwks_max_age_secs + max_ttl_secs` (default 360 s): the keys are refetched
  once older than `jwks_max_age_secs` (at least 60 s, since refreshes are at
  least a minute apart), and a cached verification is reused for at most
  `max_ttl_secs`. While the JWKS endpoint is unreachable the keys
  already known stay in use, so the bound starts once it answers again.
- Rejected tokens are never cached. The cache is keyed by the SHA-256 of the
  token, so no bearer token is kept in memory.
- It holds at most `max_entries` (default 10000) tokens; once full of live
  entries, a new token is verified but not stored. No background task runs:
  expired entries go when looked up, and an insert that finds the cache full
  sweeps them at most once per second, so a full cache may pass a new token
  through uncached until the next sweep frees room.
  A token longer than `max_token_bytes` (default 4096) is verified every time
  and never stored, so the memory the cache holds stays bounded.
- It is per process and only skips repeated work, so replicas decide the same
  way with or without it. Switch it off with `enabled: false`.
- An injected verifier is not cached: it owns its policy (introspection,
  revocation) and sees every request.

**An injected verifier** is what you supply when neither of those is the right
answer for your binary: a validated / FIPS crypto module, an HSM, or a verifier
your service already owns.

```rust
use std::sync::Arc;
use structured_proxy::hooks::TokenVerifier;
use structured_proxy::{config::ProxyConfig, ProxyServer};

struct MyVerifier; // your signature + claim check

#[async_trait::async_trait]
impl TokenVerifier for MyVerifier {
    async fn verify(&self, token: &str) -> Option<serde_json::Value> {
        // claims out, or None to reject the request with 401
        # let _ = token;
        None
    }
}

# async fn run(config: ProxyConfig) -> anyhow::Result<()> {
ProxyServer::from_config(config)
    .with_token_verifier(Arc::new(MyVerifier))
    .serve()
    .await
# }
```

Injection also gets around Cargo feature unification. Features apply to the
whole dependency graph, so when two crates in one workspace ask for different
backends, both are enabled and the tie-break above picks `aws_lc_rs` for
everyone. A crate that injects its own verifier takes no backend at all:

```toml
[dependencies]
structured-proxy = { version = "6", default-features = false }
# What the verifier above is written with: the trait is `#[async_trait]`, and
# claims cross it as `serde_json::Value`. Neither is re-exported.
async-trait = "0.1"
serde_json = "1"
```

and brings its own crypto (see [TLS crypto](#tls-crypto)). With neither an
injected verifier nor a backend feature, an `auth.mode: "jwt"` config fails at
startup with a message saying so.

## TLS crypto

All of the proxy's TLS is rustls: the listener (`listen.tls`, see
[TLS and connection limits](#tls-and-connection-limits)) and its own outbound
HTTP calls (JWKS fetches, the rate-limit service). Outbound calls trust
Mozilla's root store bundled from `webpki-roots`, so no system CA bundle is
needed. The rustls crypto provider is, in order:

1. the one your process installed with
   `rustls::crypto::CryptoProvider::install_default`, if any: an explicit
   choice wins;
2. aws-lc, with the `aws_lc_rs` feature;
3. the pure-Rust RustCrypto provider (`rustls-rustcrypto`), with `rust_crypto`.

The default build is pure Rust; aws-lc (C) comes with `aws_lc_rs`. A
`default-features = false` build brings no provider, so a crate that only
transcodes stays free of crypto dependencies. Such a build that terminates TLS,
or configures a JWKS endpoint or the rate-limit service, installs a provider
before building the proxy (the outbound client needs one even for an
`http://` endpoint); otherwise startup fails with an error that says so.

The RustCrypto provider verifies RSA server signatures with `rsa`, under the same
RUSTSEC-2023-0071 note as the `rust_crypto` JWT backend: only public-key
verification runs. Its current release still names `rustls-webpki` 0.102, whose
CRL and name-constraint advisories are listed in `deny.toml` with why they do not
apply: the provider reads only algorithm identifiers from it, and rustls
verifies certificates with its own patched `rustls-webpki`.

## How it works

At startup the proxy reads your proto descriptors and turns every
`google.api.http` rule into a REST route. Each request is then sorted once:

```text
     REST, gRPC and gRPC-Web clients (HTTP/1.1, HTTP/2, optional TLS)
                                  │
                   ┌──────────────▼──────────────┐
                   │ listener                    │  TLS / mTLS, connection limit
                   └──────────────┬──────────────┘
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
   a REST route             gRPC / gRPC-Web          no route matches
   (transcoded call or      content type
    own endpoint)
         │                        │                        │
   CORS, guards             guards in scope          guards in scope
         │                        │                        │
   transcoder               passed through           your fallback
   JSON ↔ protobuf          unchanged                (or 404)
         │                        │
         └───────────┬────────────┘
                     ▼
   upstream: a remote gRPC server, or your tonic services in process
```

The client address is resolved before every guard. Guards run in this order:
a required client address, maintenance, concurrency limit, rate limits keyed
before auth, JWT, rate limits keyed by claims, ext_authz, the auth decider.

<div align="center">

## Support the Project

<img src="./assets/usdt-qr.svg" alt="USDT TRC-20 Donation QR Code" width="200">

USDT (TRC-20): `TFDsezHa1cBkoeZT5q2T49Wp66K8t2DmdA`

</div>

## License

Apache-2.0

Contributions are accepted under the [Structured World Contributor License Agreement](https://sw.foundation/cla); see [CONTRIBUTING.md](CONTRIBUTING.md).
