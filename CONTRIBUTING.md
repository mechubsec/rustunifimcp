# Contributing to rustunifimcp

Thanks for considering a contribution. `rustunifimcp` is the UniFi Network member of the [mechub](https://github.com/mechubsec) family of open-source, self-hosted network-security automation tooling. It is built **mecmcp-native**: authentication, transport, audit, policy, inventory, and change control all come from [`mecmcp`](https://github.com/mechubsec/mecmcp); this repo contributes the UniFi resource model, tool surface, and workflows. See [README.md](README.md) for what the server does and [CLAUDE.md](CLAUDE.md) for operational detail on the reference deployment.

## Before you start

- Check open issues and PRs first — someone may already be working on it.
- For anything larger than a small fix, open an issue to discuss the approach before writing code. It saves everyone a rewrite.
- This project follows one hard rule across the whole mechub fleet: **deterministic code decides, a model may explain, a human approves.** Nothing you contribute should let an LLM or other model output directly decide or fire a write against a UniFi controller (a config push, a device action, a change-set approval). Models may draft, summarize, or explain; deterministic code decides.

## Workspace layout

This is a Cargo workspace with two members:

- `rustunifimcp` — the binary: CLI, MCP server wiring, and the `mecmcp-*` integration
- `rustunifimcp-core` — the UniFi client, resource model, and MCP tool surface

The `mecmcp-*` crates (`mecmcp-audit`, `mecmcp-auth`, `mecmcp-changeset`, `mecmcp-http`, `mecmcp-inventory`, `mecmcp-openapi`, `mecmcp-runtime`, `mecmcp-secret`, `mecmcp-server`, `mecmcp-transport`) are consumed read-only, pinned to an exact git tag, from [`mechubsec/mecmcp`](https://github.com/mechubsec/mecmcp) (see `deny.toml`'s `allow-git` exception and the comment in `Cargo.toml` — don't relax the pin from this repo). If a change belongs in shared behavior rather than the UniFi-specific parts of this repo, it likely belongs in that repo instead.

## Build and test

```sh
cargo build --workspace --locked
cargo test --workspace --locked
```

Lint and format, both required to pass in CI (`.github/workflows/ci.yml`):

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
```

CI pins the toolchain to `1.100.0`; the workspace's declared MSRV floor (`rust-version` in `Cargo.toml`) is `1.89`.

If you touch the `Dockerfile` or the container entrypoint, `ci.yml`'s `container-guard` job also builds the image and asserts that config/state file paths (`/etc/unifimcp/controllers.json`, `/var/lib/unifimcp/tokens.json`, `/var/lib/unifimcp/changesets.json`) survive an operator overriding `--host` at the CMD layer. You can reproduce the build locally with:

```sh
docker build -t rustunifimcp:ci .
```

### Supply-chain and secret-scanning checks

Required to pass in CI (`.github/workflows/security.yml`):

```sh
cargo audit
cargo deny check bans sources
```

`security.yml` also runs a `gitleaks` secret scan and a `trivy` filesystem scan (`vuln,misconfig,secret`) over the whole tree. Both are config-driven (`.gitleaks.toml`, `trivy.yaml`, `.trivyignore.yaml`) and don't usually need a separate local run for an ordinary change.

### Fixtures and test data

Never commit real controller data — hostnames, site names, MAC/serial numbers, GPS coordinates, tokens, or credentials. Use synthetic fixtures only, following the existing set under `rustunifimcp-core/tests/fixtures/`.

This is enforced by an automated gate, not just a guideline: `scripts/verify-fixtures-scrubbed.sh` scans fixture files for credential-shaped fields, high-entropy values outside known structural-ID fields, public (non-documentation) IPv4/IPv6 addresses, non-zero GPS coordinates, and real-looking MAC addresses. It runs as part of the fixture test suite (`rustunifimcp-core/tests/fixture_scrub_gate.rs`, which also covers the committed synthetic set on every run). If you add or change a fixture, run the gate against it before opening a PR:

```sh
scripts/verify-fixtures-scrubbed.sh rustunifimcp-core/tests/fixtures/<version>
```

If you find real data already committed anywhere in this repo, don't add to it — report it privately instead (see [SECURITY.md](SECURITY.md)).

## Commit and PR conventions

- Match the existing commit style: `type(scope): summary` (`fix(read):`, `chore(deps):`, `chore(release):`, etc.) — see `git log` for examples.
- Keep PRs focused on one change. A bug fix doesn't need a drive-by refactor riding along.
- Fill out the PR template, including the exact commands you ran to verify the change.
- This repo does not require a Developer Certificate of Origin sign-off. By opening a pull request, you're agreeing your contribution is licensed under this repository's [MIT license](LICENSE).
- All contributions land as a pull request against `main` for review — there is no direct-push path, including for maintainers.

## Review process

Every pull request goes through a security review and a code review, then an independent test run, before a maintainer merges. Only a maintainer merges — contributors, including anyone with write access, should not merge their own PR. CI (build, test, clippy, fmt, `cargo audit`, `cargo deny`, gitleaks, trivy) must be green first.

## Reporting a vulnerability

Please don't open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) for how to report one privately.
