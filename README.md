<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustunifimcp</h1>

<p align="center"><strong>Enterprise MCP server for UniFi Network — curated tools, scoped access, audited change control</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project and does not claim affiliation with or endorsement by Ubiquiti Inc. Product names and trademarks are used only to identify the systems with which the software interoperates.

---

`rustunifimcp` is the UniFi Network member of the mechub MCP server family. It
does for UniFi what [`rustjunosmcp`](https://github.com/mechubsec/rustjunosmcp)
does for Junos and [`rustpanosmcp`](https://github.com/mechubsec/rustpanosmcp)
does for PAN-OS: a curated, scoped, audited MCP surface over one vendor's
management API.

It is built **mecmcp-native** — no local authentication, transport, audit,
policy, inventory, or change-control code at all. All of that comes from
[`mecmcp`](https://github.com/mechubsec/mecmcp), the shared Rust foundation.
What is written here is the UniFi resource model, the tool surface, and the
workflows. Nothing else.

UniFi is the first vendor in the family with **no candidate configuration at
all** — no staging area, no commit, no on-box validation. Junos and PAN-OS have
candidate/commit; Proxmox and Security Director have server-side task semantics
to bind an approval to. UniFi has immediate REST writes against live
configuration and nothing else, which makes it the real test of whether
`mecmcp-changeset` generalises beyond the two vendors that produced it.

## Status

**In production. The dependency on the legacy server is retired.**

`rustunifimcp` v0.5.0 serves the full surface — reads, workflows, operational
actions, and change control — from LXC 981 over TLS, under two-person control.
The `unifi-mcp-legacy` registration is gone; nothing routes to the Python
server any more.

**LXC 980 itself is untouched and still running.** It is tagged
`notmechub;protected` and was never ours to modify: retiring the *dependency*
never meant acting on the guest. It remains as a rollback path — re-adding its
registration restores the old surface — and stopping or destroying it is a
separate decision for its owner.

| Guest | Role | Endpoint |
|---|---|---|
| 981 `prod-unifimcp` | production, two-person, TLS | `https://prod-unifimcp.example.org:30033/mcp` |
| 622 `test-twoperson-unifi` | rig, two-person | `http://test-twoperson-unifi.example.org:30033/mcp` |
| 623 `test-labmode-unifi` | rig, `--lab-mode` | `http://test-labmode-unifi.example.org:30033/mcp` |

Parity against the legacy surface is recorded in
[`docs/PARITY-AUDIT.md`](docs/PARITY-AUDIT.md): of 33 legacy tools in the usage
window, 31 are covered and verified against the live controller, one is
built but unverified (`execute_port_action`, reachable as
`unifi_device_action action=port_action` — PoE power-cycle only, behind
`--allow-direct-commit`, and not exercised live because it would disrupt a
switch port in use), and one is an accepted gap (`set_device_port_overrides`
— no verified write route on 10.5.67).

| Document | What it is |
|---|---|
| [`PLAN.md`](PLAN.md) | The phase sequence and its two cutovers, at a glance |
| [`docs/HOW-TO-SETUP-LXC.md`](docs/HOW-TO-SETUP-LXC.md) | How to build a `rustunifimcp` Proxmox LXC from scratch |
| [`docs/HOW-TO-SETUP-DOCKER.md`](docs/HOW-TO-SETUP-DOCKER.md) | How to run `rustunifimcp` in Docker, two-person and lab mode |
| [`docs/superpowers/specs/2026-08-26-rustunifimcp-cutover-design.md`](docs/superpowers/specs/2026-08-26-rustunifimcp-cutover-design.md) | Build and cutover design: deployment topology, controller trust, phase detail, risks |
| [`docs/superpowers/specs/2026-07-24-rustunifimcp-design.md`](docs/superpowers/specs/2026-07-24-rustunifimcp-design.md) | The original design — still authoritative for tool surface, API tagging, and the change-control adaptation |

## Minimum supported controller version

**Minimum supported version: UniFi Network Application 10.5.67 / UniFi OS Server 5.1.37**

This server requires a UniFi Network controller running at least version 10.5.67 (Network Application) or 5.1.37 (UniFi OS Server). These versions include the 2026 CVSS 10 security fixes (SAB-062, SAB-064, SAB-066/067) that this project depends on for secure API access.

The minimum version is verified against the `rustunifimcp` test rigs and fixture sets. Running against an older controller version may result in missing endpoints or unhandled API drift.

## What it replaces

The homelab runs `enuno/unifi-mcp-server` (Python / FastMCP). It is a capable
API client with two problems this project exists to fix.

**Tool sprawl.** Its registry auto-registers every public async function in
`src/tools/` by reflection — 205 functions across 37 modules become roughly
**270 MCP tools**. Nobody chose that number. `rustunifimcp` targets **22**:
typed read primitives over a resource enum, a change-control lifecycle, scoped
operational actions, and four workflows that earn their names. Every one of
the 22 does real work end to end — none is advertised and then refuses or
returns an empty result on every call.

**No MCP-layer security.** It listens on plain HTTP with no bearer token, no
scopes, no audit trail, and no rate limiting. Anything that can reach the port
has unrestricted write access to the controller. `rustunifimcp` inherits the
full `mecmcp` security layer instead.

## Tool catalog

The read primitives, the collapsed surface behind `unifi_list_resources` and
`unifi_get_resource`. Every `kind` is projected through the allowlist or scan
documented in `rustunifimcp-core::redact` before it reaches the model — see
[Design highlights](#design-highlights) below.

| Tool | Notes |
|---|---|
| `unifi_list_resources` | `kind` = `station \| device \| network \| wlan \| port_profile \| dhcp_reservation \| firewall_policy \| firewall_zone \| firewall_group \| firewall_rule \| port_forward \| static_route \| traffic_route \| radius_profile` |
| `unifi_get_resource` | `kind`, `id` |
| `unifi_query_stats` | `subject` = `site \| device \| station \| wlan \| flow \| event`, plus a time window |
| `unifi_search` | Free-text across stations, devices, and sites |
| `unifi_list_sites` | |

`firewall_rule`, `port_forward`, and `static_route` (MEC-509) are the legacy
(non-zone-based) ruleset, port forwarding rules, and static routes —
read-only for now; no write route exists for them through
`unifi_stage_change`. `subject=event` reaches the controller's event log.

`unifi_backup_action` (MEC-516) wires `list` and `trigger`: `list` returns
the controller's retained backups, capped at 100 entries with a `truncated`
marker like every other list-shaped tool; `trigger` starts a new backup.
`download` and `validate` are not offered at all (MEC-505: removed from the
action enum rather than advertised and refused) — both would need to move a
raw `.unf` file rather than JSON, which this server does not yet support.
`restore` is refused permanently; restoring a backup overwrites the entire
configuration, so it goes through the change-set lifecycle instead.

## Run with Docker (stdio)

The catalog-friendly stdio invocation replaces the image's HTTP `CMD` with
`--transport stdio`. Put `controllers.json` (shape:
[`packaging/examples/controllers.example.json`](packaging/examples/controllers.example.json))
and the controller API key file in `etc/`, and give the container a writable
`state/` directory for change sets and the audit HMAC key. Both must be owned
by the image's UID/GID `65532:65532`, files at mode `0600`:

```bash
mkdir -p etc state
# etc/controllers.json  -> "api_key_file": "/etc/unifimcp/api.key"
# etc/api.key           -> the controller API key
sudo chown -R 65532:65532 etc state
sudo chmod 0700 etc state
sudo chmod 0600 etc/controllers.json etc/api.key

docker run --rm -i \
  -v "$PWD/etc:/etc/unifimcp:ro" \
  -v "$PWD/state:/var/lib/unifimcp" \
  ghcr.io/mechubsec/rustunifimcp:latest \
  --transport stdio
```

stdio carries no caller identity, so change-set approval and the direct-commit
tools are refused; use the streamable-HTTP setup in
[`docs/HOW-TO-SETUP-DOCKER.md`](docs/HOW-TO-SETUP-DOCKER.md) for two-person
change control.

## Design highlights

**Three API surfaces, each labelled.** UniFi's supported Integration API is far
narrower than what the controller can actually do, so the private `/api/s/` and
`/v2/api/` routes stay in — but every endpoint carries its tag in code, and the
private ones are gated behind an explicit per-controller `allow_private_api`
flag in `controllers.json`, not a token scope. A supported-only deployment is
a real, runnable configuration that a controller upgrade cannot silently break.

**Change control adapted honestly.** UniFi has no candidate configuration and no
commit. The change-set lifecycle is implemented with client-side pre-image
capture, local validation, sequential apply, and best-effort rollback — and the
tool descriptions say so. An operator approving a UniFi change set is not
getting commit-confirmed semantics, and the server does not pretend otherwise.
`unifi_approve_change_set` requires a human approver: the server passes the
caller's token `actor_type` through to mecmcp, which refuses any approval
from an `agent` or unattributed (stdio) caller — only `actor_type: human`
can approve. Mint the approver's token with `rustunifimcp token add ...
--actor-type human`. `actor_type` is a claim the operator makes at mint
time, not something the server proves; a token tagged `human` but handed to
an LLM agent defeats the gate.

**Multi-controller.** Controllers live in an inventory registry rather than
environment variables, so one instance can front several and a token can be
scoped to a subset.

**HTTP defaults are metered, not open.** Per-IP and per-token request rates,
concurrent session counts, and body-size limits are all enforced by default
(`LimitsConfig::default()`); every limit is also a CLI flag (see
`rustunifimcp --help`), so an operator can tune them without a fork. An
unauthenticated `/healthz` (process up) and `/readyz` (no dependency checks
configured, so "ready" tracks "up") are always mounted. `/metrics` is off by
default (`--enable-metrics`) and, when enabled, restricted to loopback
callers.

## License

Licensed under [MIT](LICENSE).
