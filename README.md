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
- **Full request mapping**: path params, query parameters (typed + repeated + nested), and a JSON or form `body` (`*` / named field / none), decoded straight into the request message (see [Request mapping](#request-mapping))
- **`response_body`** to return a single response subfield, and **`additional_bindings`** for multiple routes per RPC
- **`custom` rules**: any HTTP method (`HEAD`, `OPTIONS`, extension methods), or `kind: "*"` for every method
- **Upstream-controlled HTTP answers**: response metadata becomes response headers, `x-http-code` sets the status, and `google.api.HttpBody` carries a raw body and content type in either direction, so OAuth 2.0 / OIDC endpoints, redirects and file downloads work as gRPC (see [Upstream controls](#upstream-controls))
- **Auto-generated OpenAPI** documentation from proto messages, served at `/openapi.json`
- **Server-streaming** RPC → NDJSON by default, or Server-Sent Events via `Accept: text/event-stream` negotiation
- **gRPC → HTTP status mapping** following the standard `google.rpc.Code` table
- **Typed error details**: the upstream's `google.rpc.Status` details (`ErrorInfo`, `BadRequest`, `RetryInfo`, ...) reach the HTTP client as ProtoJSON, switchable globally and per route (see [Error responses](#error-responses))
- **Header forwarding** from HTTP requests to gRPC metadata (configurable allow-list)
- **Context propagation**: W3C trace-context (`traceparent` forwarded or synthesized) and client deadlines (`grpc-timeout`) carried across the REST↔gRPC boundary
- **Path aliasing** for route remapping (e.g. `/oauth2/*` → `/v1/oauth2/*`)
- **Maintenance mode** returning 503 with a configurable exempt-path list
- **Health endpoints** `/health/live`, `/health/ready` (upstream gRPC health probe), `/health/startup`
- **Prometheus metrics** at `/metrics`
- **CORS** with a configurable origin allow-list
- **Rate limiting (Shield)**: local GCRA shaper (no blocking latency) keyed by client IP, header, or validated JWT claim; named limit tiers as config data; optional async cross-instance reconciliation for an approximate fleet-wide limit (requires both the `redis` feature and a configured `sync` block)
- **JWT auth**: validate `Bearer` tokens via an Ed25519 PEM key or JWKS auto-discovery, enforce per-route `require_auth` / `required_roles`, and forward claims as headers — or hand the signature check to your own verifier (a validated / FIPS module, an HSM) without changing anything else
- **OIDC discovery**: serve `/.well-known/openid-configuration` and a JWKS endpoint (Ed25519) built from config, to front an identity provider
- **Forward-auth**: a verification endpoint (`/auth/verify`) for a fronting proxy (nginx `auth_request`, Traefik `forwardAuth`) to delegate auth, returning the verified identity as headers
- **External AuthZ**: gate proxied requests through an Envoy ext_authz gRPC server (`envoy.service.auth.v3.Authorization/Check`), interoperating with OPA and any ext_authz server, with fail-open/closed control
- **Zero code changes** between services: same binary, different config

## Non-goals

- **Session / BFF management** (cookie-based login, server-side token storage, refresh flows) and **stateful OIDC** (`authorize` / `token` with auth codes / PKCE state). The **default build** is a stateless transcoding data plane with stateless auth primitives; session lifecycle is a separate, stateful concern. Put a dedicated BFF (e.g. `oauth2-proxy`, Pomerium) in front, or drive auth through the stateless forward-auth / external-authz hooks below. (A stateful surface behind an opt-in, default-off `bff` Cargo feature is planned; it does not affect the default data-plane build.)

## Quick Start

```bash
# Install the binary (it sits behind the `cli` feature)
cargo install structured-proxy --features cli

# Run with your service config
structured-proxy --config my-service.yaml
```

Prebuilt static Linux binaries and deb/rpm packages are attached to each GitHub
release. To embed the proxy in your own service instead, add the library with
`cargo add structured-proxy` (see [Library Usage](#library-usage)).

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

The gRPC request message is built from the three sources `google.api.http`
names, in one pass and without an intermediate JSON tree:

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
verified claims available; setting `jwt_limits` has no effect on an IP/header
rule, which runs pre-auth (use a `jwt_claim` key if you want the token's tier to
drive the limit). Tier-name indirection lets you retune the numbers in config
without re-issuing tokens or changing the service.

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
`sync.interval_ms`. Within that lag each of the other instances can admit its
local `burst` plus a `rate` fraction of the window before the estimate catches
up (the fleet gate caps sustained fleet volume at `rate`, but `burst` is a
per-instance allowance the gate does not pre-reserve). With the interval in the
same time unit as the window, the worst-case fleet overshoot is about
`(N - 1) × (burst + rate × (interval / window))` requests. For example,
`burst = 100`, `rate = 1000/min`, `interval = 500 ms`, `N = 4` gives
`3 × (100 + 1000 × (0.5 / 60)) ≈ 325` extra requests. Smaller `burst` and shorter
intervals tighten the bound. The global view uses a sliding-window counter, so
there is no boundary burst on top of this lag.

See the `shield:` block under [Configuration](#configuration) for the full
schema.

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
- A broken upstream error status is never passed on in part or reinterpreted:
  a trailer that is not a `google.rpc.Status` or disagrees with `grpc-status` /
  `grpc-message`, a type URL without a `/` or whose last segment is not a
  protobuf full name, or a detail of a known type whose bytes do not decode or
  whose value has no valid JSON form (a `Duration` beyond its range), turns the
  whole error into
  `{"error": "INTERNAL", "code": 13, "message": "upstream returned a malformed error status", "details": []}`
  (500, or the terminal frame of a started stream). The cause is logged by the
  proxy and not sent to the client. With details switched off for a route the
  trailer is not read, so this does not apply there.

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

**Errors in server-streaming responses.** An upstream that rejects the call
outright (a gRPC trailers-only response, with no response headers or messages)
gets the mapped HTTP status and the body above. Once the upstream has accepted
the call, the proxy answers `200` and starts the stream right away, so that
headers and SSE keep-alives are not held back waiting for the first message.
Any later failure, including one that arrives before the first message, is then
delivered as a terminal frame whose payload is exactly that body, after which
the stream ends and no further data follows:

- **NDJSON**: the last line, framed by an extra
  `"@type": "type.googleapis.com/google.rpc.Status"` next to the error body. A
  data line is the ProtoJSON of a response message, which has a top-level
  `@type` only when the RPC streams `google.protobuf.Any`, while `Struct`,
  `Value` and `ListValue` messages can carry any key at all. For those RPCs no
  in-band marker is collision-free: set `streaming.ndjson_envelope: true` (or
  `ProxyServer::with_ndjson_envelope(true)`) and every line is wrapped instead,
  `{"result": <message>}` for data and `{"error": <error body>}` for the
  terminal error, the grpc-gateway stream shape. The envelope changes data
  lines too, so it is off by default.
- **SSE**: one event with type `stream-error` (listen with
  `addEventListener("stream-error", ...)`), distinct from the `EventSource`
  `onerror` that fires on transport failures. The event type is the framing,
  so the event data is exactly the error body, without the NDJSON marker.

The same applies to a message the proxy cannot serialize mid-stream: the
stream ends with an `INTERNAL` terminal frame.

This is the HTTP/JSON transcoding format. It is not the Connect protocol's error
format, and it is not an OAuth 2.0 token endpoint error body (RFC 6749 §5.2):
an upstream that needs one answers successfully with that body instead (see
[Upstream controls](#upstream-controls)).

**Switching details off.** In the config file, `error_details:` (see
[Configuration](#configuration)) is read by the standalone binary and by
`ProxyServer::from_yaml_str` / `ProxyServer::from_file`; it is not part of
`ProxyConfig`, so `ProxyConfig::from_yaml_str` alone ignores it. Both log a
warning for a top-level or `streaming:` key no setting reads, so a misspelled
`error_detail:` or `ndjson_envelop:` shows up at startup instead of silently
leaving the default in force. An embedding
service can choose in code with `ProxyServer::with_error_details`. Overrides are
checked in the order they are added; for each switch (`enabled`, `opaque`) the
first rule whose pattern matches the mounted route and that sets the switch
decides, otherwise the global value; `*` stays within one path segment (a path
parameter counts as one) and `**` spans segments. A config rule that sets
neither switch is rejected:

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

**Request headers → request metadata.** Each header named in
`forwarded_headers` reaches the upstream as request metadata byte for byte,
every value in the order the client sent it, so a check that depends on how
often a header was sent (RFC 9449 §4.3 rejects a request with two `DPoP`
headers) sees the same request behind the proxy. A `-bin` header keeps the
base64 it arrived with, one metadata value per comma-separated part. A value
gRPC metadata cannot carry (empty, or outside visible ASCII and space, such as
a tab or obs-text, or not canonical base64 under a `-bin` key) is refused with
`INVALID_ARGUMENT` (400) naming the header: gRPC lets a receiver drop such a
value, which would change what the upstream counts. A `forwarded_headers` name
must be a gRPC metadata key (letters, digits, `_`, `-`, `.`), or the proxy
does not start. W3C trace-context is the exception, listed or
not: the upstream always gets exactly one valid `traceparent` (the client's
first, or a fresh one when it is missing or malformed), and every `tracestate`
line only with the client's own trace.

**Response metadata → response headers.** The upstream's response metadata is
its HTTP response headers. Every ASCII entry becomes a header, in order, with
repeated values as repeated fields; a key sent in both the initial metadata and
the trailers keeps both values. This covers a successful unary call (initial
metadata and trailers), a failed call (its trailers-only metadata, or the
response headers and trailers of a call that failed after sending headers, so a
`401` carries its `WWW-Authenticate`), and the initial metadata of a server-streaming
call (its trailers arrive after the headers are sent and are not forwarded).
Never forwarded:

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
forwarded header needs a CORS setup that exposes it.

**Status from `x-http-code`.** On a successful unary call, the response
metadata `x-http-code` (grpc-gateway's convention) sets the HTTP status: one
integer from 200 to 599. Anything else (a value that is not three digits, out
of range, or given twice) turns the answer into
`{"error": "INTERNAL", "code": 13, "message": "upstream returned a malformed response", "details": []}`
(500), with nothing else of the upstream's answer. `204`, `205` and `304` are
sent without a body or `Content-Type` (RFC 9110 §15.3.5, §15.3.6, §15.4.5).
Errors keep the
`google.rpc.Code` mapping: a protocol-specific error body is a successful
answer with `x-http-code` and that body. Server-streaming calls ignore the key.

**Raw bodies with `google.api.HttpBody`.** An RPC whose response type is
`google.api.HttpBody`, or whose `response_body` names a field of that type,
answers with `content_type` as `Content-Type` (none when empty) and `data` as
the raw body. An RPC whose request type is `HttpBody` with `body: "*"`, or
whose `body` names a field of that type, receives the raw request body and its
full `Content-Type` value there. With a named field, the other fields still
come from the path and query (a query key naming the body field is ignored);
with `body: "*"`, the query binds nothing, since every field comes from the
body. A server-streaming `HttpBody` writes each message's `data` as it
arrives, with `Content-Type` from the first message; as a raw body has no
in-band error frame, a failure after the first message aborts the transfer so
the client does not take a partial body for a complete one. An `HttpBody`
content type that is not a valid header value is a malformed response (500).
`google/api/httpbody.proto` is always resolvable for error details, like the
`google/rpc` types.

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

**`custom` rules.** `HttpRule.custom` (`{kind, path}`) binds any method token:
`kind: "HEAD"`, `kind: "OPTIONS"`, an extension method such as `PROPFIND`
(case-sensitive, RFC 9110 §9.1), or `kind: "*"` for every method, as
`google/api/http.proto` defines. A forward-auth sub-request (nginx
`auth_request`, Traefik `forwardAuth`) arrives with the original request's
method, so a `*` rule answers it whatever that method is. `custom` works in
`additional_bindings` too. A `*` rule takes its path for every method, so
another binding on that path is rejected at startup. OpenAPI lists a `*` rule
under every operation, and cannot describe an extension method. Only a real
CORS preflight (an `OPTIONS` request with both `Origin` and
`Access-Control-Request-Method`) is
answered by the CORS layer; any other `OPTIONS` request reaches its route.

## Library Usage

`cargo add structured-proxy` adds the library alone: the binary and its
command-line dependencies (`clap`, `tracing-subscriber`) sit behind the `cli`
feature, which is off by default, so a service that embeds the proxy compiles
none of them. The library starts no runtime and installs no logger of its own;
it runs on the
embedder's tokio runtime and logs through `tracing` to whatever subscriber the
embedder sets up.

```rust
use std::path::Path;
use structured_proxy::ProxyServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Reads the whole config file, including `error_details`,
    // `streaming.ndjson_envelope` and `response_headers`, which live outside
    // `ProxyConfig`.
    let server = ProxyServer::from_file(Path::new("my-service.yaml"))?;

    // Run the proxy on the configured listen address.
    server.serve().await?;
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
- **`with_token_verifier`** — replaces the built-in JWT signature check
  (see [JWT verification](#jwt-verification)) while keeping the route policies,
  the roles claim, and the claim→header forwarding.
- **`with_oidc_backend`** — backs the stateless OIDC surface (discovery, JWKS,
  userinfo) with your key/client metadata; supersedes the config-driven static
  discovery.
- **`with_extra_routes`** — registers extra stateless routes through a
  framework-agnostic adapter (request parts in, response parts out).
- **`with_error_details`** — chooses which transcoded routes return the
  upstream's `google.rpc.Status` details (see [Error responses](#error-responses)).
- **`with_denied_response_headers`** — keeps upstream response metadata keys
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

Injection also resolves a problem the features cannot: Cargo unifies features
across the whole dependency graph, so `rust_crypto` / `aws_lc_rs` is a property
of the *resolution*, not of a binary. Two crates in one workspace that link this
one and want different backends cannot both get their way: the resolution enables
both features, and the tie-break above picks `aws_lc_rs` for everyone. A consumer
that injects its own verifier is not in that argument at all: it takes

```toml
[dependencies]
structured-proxy = { version = "4", default-features = false }
# What the verifier above is written with: the trait is `#[async_trait]`, and
# claims cross it as `serde_json::Value`. Neither is re-exported.
async-trait = "0.1"
serde_json = "1"
```

which links no JWT crypto, and supplies the backend from its own binary. With no
verifier injected and no backend feature, an `auth.mode: "jwt"` config is
rejected at startup with that instruction, rather than silently accepting
tokens.

## Outbound TLS

The proxy's own HTTPS calls (JWKS fetches, the rate-limit service) use rustls
with the pure-Rust RustCrypto provider (`rustls-rustcrypto`) and Mozilla's root
store bundled from `webpki-roots`, so no system CA bundle is needed. Neither
`ring` nor aws-lc is linked: the default build and the
`default-features = false` build contain no C crypto, which CI checks. Only the
opt-in `aws_lc_rs` JWT backend brings aws-lc in.

The provider verifies RSA server signatures with `rsa`, so every build links
that crate, under the same RUSTSEC-2023-0071 note as the `rust_crypto` backend:
only public-key verification runs. The current provider release still names
`rustls-webpki` 0.102, whose CRL and name-constraint advisories are listed in
`deny.toml` with why they do not apply: the provider reads only algorithm
identifiers from it, and rustls verifies certificates with its own patched
`rustls-webpki`.

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
