# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
