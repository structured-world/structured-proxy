# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.2](https://github.com/structured-world/structured-proxy/compare/v3.0.1...v3.0.2) - 2026-09-05

### Other

- name the copyright holder in the licence appendix ([#80](https://github.com/structured-world/structured-proxy/pull/80))
- *(deps)* update jsonwebtoken requirement from 10 to 11 ([#75](https://github.com/structured-world/structured-proxy/pull/75))

## [3.0.1](https://github.com/structured-world/structured-proxy/compare/v3.0.0...v3.0.1) - 2026-09-05

### Other

- name the maintainer in package metadata
- *(deps)* update base64 requirement from 0.22 to 0.23

## [3.0.0](https://github.com/structured-world/structured-proxy/compare/v2.2.2...v3.0.0) - 2026-07-22

### Added

- *(shield)* [**breaking**] GCRA rate limiting with pluggable keys and limits
- [**breaking**] embedding hooks + configurable edge routes

### Fixed

- *(shield)* skip idle zero-delta keys in fleet reconciliation
- *(shield)* reject unknown and mismatched fields in rule keys
- *(shield)* reject rule patterns without a leading slash
- *(shield)* widen Retry-After when the outer budget wins a header tie
- *(shield)* report fleet-derived reset when the fleet budget binds
- *(shield)* enforce limit-service cache cap at insertion
- *(shield)* throttle high-water GCRA sweeps to bound CPU
- *(shield)* break RateLimit-Reset ties toward the longer-binding phase
- *(shield)* fail closed on unknown client IP and unstarted fleet gate
- *(shield)* bound rate-limit state under key-cardinality floods
- *(shield)* normalize header key names before fingerprinting
- *(shield)* require an http/https limit-service endpoint
- *(shield)* auto-reconnect the shared store; note window-reset is not client-driven
- *(shield)* report tightest phase budget and a decaying global Retry-After
- *(shield)* throttle limit-service retries for stale keys during an outage
- *(shield)* reject invalid header key names at startup
- *(shield)* degrade on stale estimate, gate on carryover, no epoch collapse
- *(shield)* validate limit-service endpoint and honor unknown-tier numbers
- *(shield)* drop unpushable deltas instead of restoring (never double)
- *(shield)* reject dynamic zero rates and bound fetch storms
- *(shield)* fail closed on empty rules and report fleet remaining
- *(shield)* race-free reconcile via claim model, refresh, and eviction
- *(shield)* carry unpushed deltas across an epoch roll
- *(shield)* preserve inner limiter's rate-limit headers
- *(shield)* make delta push atomic and guard stale estimate writes
- *(shield)* evict limit cache by last access, not last fetch
- *(shield)* store GCRA theoretical arrival times in nanoseconds
- *(shield)* bound the limit-service resolution cache
- *(proxy)* apply CORS outside the auth and rate-limit layers
- *(shield)* reject non-positive profile rate and burst
- *(shield)* round Retry-After / RateLimit-Reset up from nanoseconds
- *(shield)* de-identify store keys and namespace by rule fingerprint
- *(shield)* correct cross-instance counter accounting
- *(shield)* cap GCRA admissible count at bucket capacity
- normalize route shape for collisions; unify transcode route enumeration
- key route-collision detection on (method, path), not path alone
- validate every mounted path shape, not just verify
- guard and exempt the verify path that is actually mounted
- reject duplicate edge routes before building the router
- make verify-path collision guard cover all mounted routes
- cover all built-in routes in verify guard; order authz before decider
- short-circuit userinfo without token; guard forward-auth path collision
- *(config)* dedupe edge paths, keep relocated paths exempt and collision-free
- *(embed)* harden extra-route body read, userinfo challenge, bearer scheme

### Other

- *(shield)* add regression test for idle fleet-key refresh
- *(shield)* extract claim_plans from reconcile_at
- *(shield)* add regression test for unknown fields in rule keys
- *(shield)* add regression test for relative rule patterns
- *(shield)* add regression test for Retry-After on tie-break overwrite
- *(deps)* bump EmbarkStudios/cargo-deny-action from 2.0.20 to 2.1.1
- *(shield)* note reconciliation needs the redis feature and a sync block
- *(shield)* add regression test for fleet-bound RateLimit-Reset
- *(shield)* extract reconciled_headers helper
- *(shield)* add regression test for reset tie-break on equal remaining
- *(shield)* document burst>limit behaviour under fleet reconciliation
- *(shield)* reject unknown config fields and assert outer budget headers
- *(shield)* add regression test for carryover epoch collapse
- *(shield)* match phase on borrowed key
- *(shield)* clarify JWT-limit scope and the fleet gate approximation
- *(shield)* add regression test for evicting an active stale limit entry
- *(shield)* explain TAT reuse across a resolved-tier change
- *(shield)* clarify phase-local fallback, header contract, and overshoot
- *(shield)* add regression test for sub-second Retry-After rounding
- *(shield)* add regression test for GCRA idle-key remaining cap
- *(deps)* update ed25519-dalek requirement from 2 to 3
- *(readme)* note async-trait is required for embedding hooks

## [2.2.2](https://github.com/structured-world/structured-proxy/compare/v2.2.1...v2.2.2) - 2026-06-27

### Fixed

- *(auth)* pin self-contained rustls TLS for the JWKS client

### Other

- *(deps)* bump reqwest to 0.13, refresh dependencies
- Merge branch 'main' into dependabot/cargo/redis-1.2
- Merge branch 'main' into dependabot/github_actions/actions/download-artifact-8
- Merge branch 'main' into dependabot/github_actions/softprops/action-gh-release-3
- Merge branch 'main' into dependabot/github_actions/actions/create-github-app-token-3
- Merge branch 'main' into dependabot/github_actions/actions/checkout-7
- *(deps)* bump actions/upload-artifact from 4 to 7

## [2.2.1](https://github.com/structured-world/structured-proxy/compare/v2.2.0...v2.2.1) - 2026-06-21

### Fixed

- *(packaging)* check out the released tag in package jobs
- *(packaging)* declare both published Fedora arches in manifest
- *(packaging)* do not mask config ownership failures in postinst
- *(packaging)* compile the redis feature into release binaries

### Other

- *(packaging)* note sandbox-readable paths for configured files
- *(packaging)* add RPM/DEB packaging and release workflow

## [2.2.0](https://github.com/structured-world/structured-proxy/compare/v2.1.0...v2.2.0) - 2026-06-21

### Added

- *(streaming)* expose server-streaming RPCs as SSE

### Fixed

- *(streaming)* make error frames terminal and rename SSE error event
- *(config)* reject zero SSE keep-alive interval
- *(streaming)* let hyper choose NDJSON body framing
- *(streaming)* parse all Accept headers and quality factors for SSE

### Other

- *(readme)* trim streaming feature bullet to a headline
- *(streaming)* cover terminal error frames and SSE event name
- *(streaming)* add regression tests for Accept negotiation

## [2.1.0](https://github.com/structured-world/structured-proxy/compare/v2.0.1...v2.1.0) - 2026-06-20

### Added

- *(auth)* guard mutually-exclusive jwt backends at compile time

### Other

- add cargo-deny advisories security job
- *(security)* ignore RUSTSEC-2023-0071 advisory

## [2.0.1](https://github.com/structured-world/structured-proxy/compare/v2.0.0...v2.0.1) - 2026-06-20

### Fixed

- *(config)* keep embedded-constructed structs constructible

### Other

- *(test)* clarify forwarded_headers in the embedded test

## [2.0.0](https://github.com/structured-world/structured-proxy/compare/v1.1.0...v2.0.0) - 2026-06-20

### Added

- *(authz)* external authorization via Envoy ext_authz gRPC
- *(auth)* add forward-auth verification endpoint
- *(transcode)* propagate W3C trace-context and request deadlines
- *(oidc)* serve OpenID discovery document and JWKS endpoint
- *(auth)* enforce JWT validation with JWKS and route policies
- *(shield)* enforce rate limiting via pluggable store

### Fixed

- *(config)* [**breaking**] mark config structs non_exhaustive
- *(authz)* default authz endpoint and preserve duplicate headers
- *(transcode)* accept future W3C traceparent versions
- *(transcode)* validate trace-context and bound deadline parsing
- *(oidc)* validate Ed25519 SPKI, always serve JWKS, set media type
- *(auth)* harden claim headers, alg mapping, JWKS fetch, 401 vs 403
- *(shield)* use rightmost untrusted X-Forwarded-For hop
- *(shield)* close identifier bypass, harden store and IP trust

### Other

- center the Support the Project section
- Merge branch 'main' into docs/#39-donation-badge
- *(transcode)* remove per-request route allocations on the hot path
- drop unimplemented BFF session config
- *(config)* add regression test for disabled authz without endpoint
- *(authz)* log authz call failures and assert parsed authz config
- *(auth)* simplify forward-auth query strip and cover invalid token
- *(transcode)* add regression test for versioned traceparent
- *(transcode)* add regression tests for deadline and trace validation
- *(oidc)* add regression tests for SPKI validation and empty JWKS
- *(auth)* add regression tests for header spoof and 401/403
- *(shield)* add regression test for spoofable XFF first hop
- *(shield)* add regression test for identifier-limit bypass

## [1.1.0](https://github.com/structured-world/structured-proxy/compare/v1.0.3...v1.1.0) - 2026-06-19

### Added

- *(transcode)* complete google.api.http request/response mapping

### Fixed

- *(transcode)* tighten query coercion and surface mapping errors
- correct CORS example and guard release job concurrency

### Other

- *(transcode)* add regression test for unsigned 32-bit query coercion
- narrow trusted googleapis scope to release-please
- pin only third-party actions, encode the policy for reviewers
- pin actions to commit SHAs and scope app-token permissions
- migrate release automation from semantic-release to release-plz
- *(readme)* add crates.io badges and correct stale content
## [1.0.3](https://github.com/structured-world/structured-proxy/compare/v1.0.2...v1.0.3) (2026-06-19)

### Bug Fixes

* **transcode:** degrade non-terminal catch-all captures ([10e038b](https://github.com/structured-world/structured-proxy/commit/10e038be3d0b16e0a91c7a8634741838ac7f03c9)), closes [#17](https://github.com/structured-world/structured-proxy/issues/17)
* **transcode:** emit axum 0.8 path syntax in proto_path_to_axum ([b7c0338](https://github.com/structured-world/structured-proxy/commit/b7c0338e35c4b0a35aeb3dc691bb58cc85dc29fb)), closes [#17](https://github.com/structured-world/structured-proxy/issues/17)
* **transcode:** parse brace spans before splitting path on slashes ([ee657e8](https://github.com/structured-world/structured-proxy/commit/ee657e8d09c9047708b4619dc49be8f83393f4dc)), closes [#17](https://github.com/structured-world/structured-proxy/issues/17)

## [1.0.2](https://github.com/structured-world/structured-proxy/compare/v1.0.1...v1.0.2) (2026-06-18)

### Bug Fixes

* **deps:** publish refreshed dependencies (tower-http 0.7) ([75e5c4a](https://github.com/structured-world/structured-proxy/commit/75e5c4a4e4709d8831ac572e754ee4fba47a9ab6))

## [1.0.1](https://github.com/structured-world/structured-proxy/compare/v1.0.0...v1.0.1) (2026-03-14)

### Bug Fixes

* **ci:** use rust-lang/crates-io-auth-action for trusted publishing ([2652a50](https://github.com/structured-world/structured-proxy/commit/2652a50d9bc7bd05bf60a5168a59539265e8e85b))

## 1.0.0 (2026-03-14)

### Features

* initial release — universal gRPC→REST transcoding proxy ([6268f25](https://github.com/structured-world/structured-proxy/commit/6268f2582d5f6100591e194952bdb5e3dde93f09))
