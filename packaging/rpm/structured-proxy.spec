# structured-proxy RPM spec.
#
# Build expects a pre-compiled musl-static `structured-proxy` binary in SOURCES/.
# The CI release pipeline runs `cargo build --release --target $TARGET-unknown-linux-musl --bin structured-proxy`,
# strips the result, copies it (and the packaging assets) into the rpmbuild
# tree, then invokes `rpmbuild -bb`.

%global _hardened_build 1
%global debug_package %{nil}

Name:           structured-proxy
Version:        %{?version}%{!?version:0.0.0}
Release:        1%{?dist}
Summary:        Universal gRPC to REST transcoding proxy

License:        Apache-2.0
URL:            https://github.com/structured-world/structured-proxy

Source0:        structured-proxy
Source1:        structured-proxy.service
Source2:        config.yaml
Source3:        structured-proxy.sysusers
Source4:        LICENSE
Source5:        README.md

BuildRequires:  systemd-rpm-macros
%{?systemd_requires}

Requires(pre):  shadow-utils
Requires:       systemd

# Match the architectures we publish.
ExclusiveArch:  x86_64 aarch64

%description
structured-proxy is a universal, config-driven gRPC to REST transcoding proxy.
One binary serves any gRPC service from a proto descriptor set and a YAML
config — no code generation, no custom handlers.

The service ships disabled: provide an upstream address and proto descriptors
in /etc/structured-proxy/config.yaml, then `systemctl enable --now`.

# ── Build phases ────────────────────────────────────────────────────
# No %prep / %build: Source0 is already the final binary produced by
# the CI musl toolchain. We only stage it into the buildroot.

%install
install -D -m 0755 %{SOURCE0}                              %{buildroot}%{_bindir}/structured-proxy
install -D -m 0644 %{SOURCE1}                              %{buildroot}%{_unitdir}/structured-proxy.service
install -D -m 0640 %{SOURCE2}                              %{buildroot}%{_sysconfdir}/structured-proxy/config.yaml
install -D -m 0644 %{SOURCE3}                              %{buildroot}%{_sysusersdir}/structured-proxy.conf
install -D -m 0644 %{SOURCE4}                              %{buildroot}%{_licensedir}/%{name}/LICENSE
install -D -m 0644 %{SOURCE5}                              %{buildroot}%{_docdir}/%{name}/README.md

# ── Scriptlets ──────────────────────────────────────────────────────

%pre
# Materialise the system user from the sysusers.d snippet so the %files
# ownership directive on the config resolves on first install. Idempotent.
%sysusers_create_compat %{SOURCE3}

%post
# Register the unit with systemd (preset state, daemon-reload). The unit is
# NOT auto-enabled/started: the shipped config is a template and the proxy
# needs real descriptors + upstream before it can serve.
%systemd_post structured-proxy.service

%preun
%systemd_preun structured-proxy.service

%postun
%systemd_postun_with_restart structured-proxy.service

# ── Payload ─────────────────────────────────────────────────────────
%files
%license %{_licensedir}/%{name}/LICENSE
%doc %{_docdir}/%{name}/README.md
%{_bindir}/structured-proxy
%{_unitdir}/structured-proxy.service
%{_sysusersdir}/structured-proxy.conf
%dir %{_sysconfdir}/structured-proxy
%attr(0640,root,structured-proxy) %config(noreplace) %{_sysconfdir}/structured-proxy/config.yaml

%changelog
* %(date "+%a %b %d %Y") Release Bot <oss@sw.foundation> - %{version}-1
- Automated release; see CHANGELOG.md for details.
