# Contributing to structured-proxy

Bug reports, fixes, documentation and new capabilities are welcome.

## Development setup

```bash
git clone https://github.com/structured-world/structured-proxy.git
cd structured-proxy
cargo build --features cli
```

Tests run under [cargo-nextest](https://nexte.st/), which is not part of the
Rust toolchain:

```bash
cargo install cargo-nextest --locked
```

Before opening a pull request, run what CI runs. The crate builds with each
crypto backend, without one and with both, and the code differs between them:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --features cli -- -D warnings
cargo clippy --all-targets --no-default-features --features cli -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --features cli
cargo nextest run --no-default-features --features cli
cargo nextest run --all-features
cargo test --doc --all-features
```

CI runs these on every pull request, and three more checks that need a
particular toolchain or host. To run them yourself:

```bash
# The minimum supported Rust version, `rust-version` in Cargo.toml.
rustup toolchain install 1.99
cargo +1.99 check --all-targets --all-features
cargo +1.99 check --all-targets --no-default-features --features cli

# The static musl build the release ships (Linux, with musl-tools installed).
rustup target add x86_64-unknown-linux-musl
cargo nextest run --target x86_64-unknown-linux-musl --features cli

# The advisory check of the dependencies.
cargo install cargo-deny --locked
cargo deny check advisories
```

The rate-limit reconciliation test runs against Redis when
`SHIELD_REDIS_TEST_URL` names one (`redis://127.0.0.1:6379/`).

## Pull requests

1. Create a branch from `main`.
2. Make the change, with tests. A bug fix comes with a test that fails without
   it.
3. Write commit messages and the pull request title in the
   [Conventional Commits](https://www.conventionalcommits.org/) form; pull
   requests are squash-merged, so the title becomes the commit on `main`.
4. A change to what the proxy serves or how it is configured updates the
   README in the same pull request.

## Contributor License Agreement (CLA)

Before a first pull request can be merged, you sign the Structured World
Contributor License Agreement once, at <https://sw.foundation/cla>. It covers
every repository of the organisation and takes a minute: sign in with GitHub,
confirm your e-mail address, sign. The `CLA` status on your pull request then
turns green by itself.

You keep the copyright in your contribution. If you contribute as part of your
job, your employer may also need to sign the corporate agreement; the page
above explains when.

## Security

Do not report vulnerabilities in public issues; see [SECURITY.md](SECURITY.md).
