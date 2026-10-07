# Security policy

structured-proxy faces untrusted clients: a way past a guard (auth, rate
limits, maintenance), a request that reaches the upstream in a form it should
not, a crash, a hang or unbounded memory on any request is a security issue.

## Reporting a vulnerability

Report it privately through
[GitHub private vulnerability reporting](https://github.com/structured-world/structured-proxy/security/advisories/new),
not in a public issue. Include the request or configuration that triggers it,
the version or commit, the features enabled, and what you observed.

You will get an answer within a few days. A confirmed issue is fixed in a new
release, and the advisory is published with credit to you unless you prefer
otherwise.

## Supported versions

Fixes go into the latest release only.
