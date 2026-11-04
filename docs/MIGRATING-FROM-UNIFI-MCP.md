# Migrating from the third-party `unifi-mcp`

For operators moving off the third-party server (LXC 980, tagged
`notmechub;protected`) to `rustunifimcp`.

Retirement here means **ceasing to depend on 980**, not acting on the guest.
It is not ours to modify.

## The behavioural difference that matters

The third-party server **writes configuration on a single call**. This one makes
configuration changes a governed change set:

```
unifi_stage_change → unifi_diff_change_set → unifi_validate_change_set →
unifi_approve_change_set → unifi_apply_change_set
```

The stage renders a server-generated preview and records the operation; the
approval binds the **plan digest**, which covers `(controller, owner, expected
fingerprint, actions)`; and applying re-checks the controller's fingerprint.

`--lab-mode` waives the second principal for a single-operator lab, and
`--waivers-file` carries time-boxed operator waivers — both originate outside
the tool call, because an override a caller can pass is not an override.

**The change-set lifecycle ships in Phase 6**, which occurs **after Cutover #1**
(Phases 1-3). This means Cutover #1 knowingly leaves the most-used legacy
capability on LXC 980: **`create_network`** (12 calls, the single most-invoked
legacy tool). Six configuration writes remain a dependency on the legacy server
until Phase 6 completes: `create_network`, `update_dhcp_reservation`,
`set_device_port_overrides`, `create_port_profile`, `create_dhcp_reservation`,
`update_port_profile`.

The cutover bar for Phase 3 is **all read operations and device actions** — 28
of the 34 actually-invoked legacy tools, covering 108 of 114 total calls. The
six writes (6 calls) stay on 980 as an accepted trade-off to ship the read
surface early and develop the change-set lifecycle correctly rather than
quickly.

That is the reason to migrate. Everything below is the mechanics.

## Tool mapping

### Same name, same meaning

None. Every legacy tool is reached through a new primitive, workflow, or is a
named gap.

### Reached through read primitives and workflows instead of directly

The 22-tool surface collapses ~130 legacy tools. **5 read primitives** take a
`kind` enum; **4 workflows** return aggregated data; the rest are admin,
operational, and change-set tools.

| Legacy tool | Reachable via |
|---|---|
| `search_clients` | `unifi_search` |
| `list_vlans` | `unifi_list_resources kind=network` |
| `list_devices_by_type` | `unifi_list_resources kind=device` |
| `list_sites` | `unifi_list_sites` |
| `get_device_port_overrides` | `unifi_get_resource kind=device` |
| `list_dhcp_reservations` | `unifi_list_resources kind=dhcp_reservation` |
| `health_check` | `unifi_site_health_report` |
| `get_client_details` | `unifi_get_resource kind=station` |
| `get_dhcp_reservation` | `unifi_get_resource kind=dhcp_reservation` |
| `search_devices` | `unifi_search` |
| `list_port_profiles` | `unifi_list_resources kind=port_profile` |
| `get_device_details` | `unifi_get_resource kind=device` |
| `execute_port_action` | `unifi_device_action action=port_action` — PoE power-cycle only, behind `--allow-direct-commit`; port enable/disable is a configuration change and goes through the change-set lifecycle |
| `list_firewall_zones_v2` | `unifi_list_resources kind=firewall_zone` |
| `get_device_by_mac` | `unifi_search` or `unifi_get_resource kind=device` |
| `get_port_profile` | `unifi_get_resource kind=port_profile` |
| `list_active_clients` | `unifi_list_resources kind=station` |
| `get_port_mappings` | `unifi_get_resource kind=device` |
| `list_firewall_policies` | `unifi_list_resources kind=firewall_policy` |
| `get_site_health_summary` | `unifi_site_health_report` |
| `get_flow_risks` | `unifi_traffic_flow_report` |
| `get_network_details` | `unifi_get_resource kind=network` |
| `list_traffic_routes` | `unifi_list_resources kind=traffic_route` |
| `get_site_inventory` | `unifi_list_resources kind=device` |
| `list_wlans` | `unifi_list_resources kind=wlan` |
| `list_firewall_zones` | `unifi_list_resources kind=firewall_zone` |
| `list_wan_connections` | `unifi_list_resources kind=network` |
| `list_wan_dns` | `unifi_get_resource kind=network` |

Configuration writes (6 tools, 6 calls) are **gap (accepted)** until Phase 6:

| Legacy tool | Calls | Reachable via |
|---|---|---|
| `create_network` | 12 | `unifi_stage_change` (Phase 6) |
| `update_dhcp_reservation` | 6 | `unifi_stage_change` (Phase 6) |
| `set_device_port_overrides` | 4 | `unifi_stage_change` (Phase 6) |
| `create_port_profile` | 4 | `unifi_stage_change` (Phase 6) |
| `create_dhcp_reservation` | 3 | `unifi_stage_change` (Phase 6) |
| `update_port_profile` | 1 | `unifi_stage_change` (Phase 6) |

### No equivalent, by decision

| Legacy tool | Why |
|---|---|
| `restore` action in the legacy backup tool | **None.** Overwrites the entire controller configuration, so it is governed by the change-set lifecycle from Phase 6, not an operational action. |
| `unifi_add_controller` | **Returns a hand-edit instruction.** `/etc/unifimcp` is read-only to the service under `ProtectSystem=strict`, and the fleet prefers a narrow sandbox over a working `add_*` tool. |
| `authorize`, `limit_bandwidth` client actions | **Not in the advertised catalog.** The controller returns `{"meta":{"rc":"ok"}}` for commands that do not exist (verified live — it validates the client but not the command), so a guessed spelling would look like success. `unifi_client_action`'s action enum only admits `block`, `unblock`, `reconnect`; the rest stay out until confirmed rather than shipping as a silent no-op. |
| Backup download/validate | **Not offered.** `unifi_backup_action` admits only `list` and `trigger`; `download` and `validate` would move a raw `.unf` file rather than JSON, which this server does not support, and no `validate` command is confirmed on the controller at all. |
| Speed test | **No tool at all.** `unifi_run_speed_test` shipped briefly but always returned an error — no endpoint spelling has been verified from a live controller. Removed rather than left advertised and non-functional; see `docs/PARITY-AUDIT.md` for what would need to be confirmed before it is reintroduced. |

### Here but not there

`unifi_list_sites` · `unifi_list_resources` · `unifi_get_resource` ·
`unifi_query_stats` · `unifi_search` · `unifi_site_health_report` ·
`unifi_topology_report` · `unifi_traffic_flow_report` ·
`unifi_client_troubleshoot` · `unifi_device_action` · `unifi_client_action` ·
`unifi_backup_action` · `unifi_add_controller` · `unifi_list_controllers` · `unifimcp_status` ·
plus the eight-tool change-set lifecycle (Phase 6).

## Before you cut over

1. **Name every tool in the token scope.** `tools: ["*"]` deliberately
   **excludes mutating tools**, so a wildcard token reaches only 11 of the
   23-tool surface: the 5 read primitives, 2 admin tools (`unifi_list_controllers`,
   `unifimcp_status` — `unifi_add_controller` is a write), and 4 workflows.
   **The three operational tools (`unifi_device_action`, `unifi_client_action`,
   `unifi_backup_action`) and every change-set tool require explicit grants.**
   Use `token set-scopes --name N --tools ...` — it changes scopes without
   reissuing the secret.
2. **Grant the action tiers you need.** `read`, `low`, `destructive`. A grant
   carrying only `read` cannot call `unifi_device_action` however its tool
   scope reads.
3. **Pass `--state-file`.** Without it, change sets live in memory and every
   approval is lost on restart. The packaged unit passes
   `${STATE_DIRECTORY}/changeset-state.json`.
4. **Endpoint:** `https://prod-unifimcp.mechub.org:30033/mcp` (LXC 981, Debian
   13), bearer token required, TLS verified. LXC 980 remains running and
   unmodified.
5. **Controllers are named in config, not environment.** The legacy server
   handled one controller from `UNIFI_*` variables. Here every tool takes a
   `controller` naming an entry in `controllers.json`.

## Arguments the new tools take differently

| Legacy call | What changes |
|---|---|
| ~130 `list_x` / `get_x` pairs | Collapsed into `unifi_list_resources` / `unifi_get_resource` with a `kind` enum. `kind=station` **not** `client` — `client.rs` is the HTTP client and the collision would land in every import. |
| Every tool | Takes a `controller` parameter naming an entry in `controllers.json`. The legacy server had no multi-controller concept. |
| Any tool with filter arguments | Every args struct uses `deny_unknown_fields`, so a **misspelled filter is an error**, not silently-unfiltered results. This is deliberate. |
| `list_wan_connections` | Becomes `unifi_list_resources kind=network` with filter `purpose=wan`. A UniFi WAN *is* a network — `networkconf` entries carry `purpose: "wan"`. |
| `list_wan_dns` | Becomes `unifi_get_resource kind=network` reading `wan_dns1` / `wan_dns2` fields. |

## Options the same-named tool no longer takes

There are no same-named tools. Every legacy tool is reached through a new
primitive or workflow.

## Two behaviours that will surprise a 980 caller

- **TLS verification cannot be disabled.** The legacy server ran with
  `UNIFI_LOCAL_VERIFY_SSL=false`. `mecmcp-http` offers no bypass and none was
  added; a controller with a self-signed certificate must be given a real one
  or a PEM trust anchor in `controllers.json`. The homelab controller was given
  a Let's Encrypt certificate for exactly this reason.

- **A wildcard token is read-only.** `tools: ["*"]` grants no mutating tool.
  Verified live: a wildcard token sees 11 of 23 tools, cannot see
  `unifi_device_action` in `tools/list`, and its invocation does not flash an
  AP's locate LED — while an explicitly-scoped operator token does. The legacy
  server has no equivalent: anything that can reach its port has unrestricted
  write access.
