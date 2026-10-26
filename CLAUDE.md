# CLAUDE.md

Guidance for Claude Code working in this repository.

## Deployment: two production instances, one per mode

There are two production instances, both on pve2 and both tagged `protected`. Each
runs a different approval mode on purpose. Work out which one you are on before
reading `lab_mode` as a fault.

| Guest | MCP registration | Mode | `unifimcp_status.lab_mode` | Drop-in in `rustunifimcp.service.d/` |
|---|---|---|---|---|
| LXC 981 `prod-unifimcp` | `prod-labmode-unifi` | lab mode | `true` | `labmode.conf` |
| LXC 982 `prod-unifi2mcp` | `prod-unifi2mcp` | two-person control | `false` | `twoperson.conf` |
| LXC 622 `test-twoperson-unifi` | none | two-person, test rig | `false` | `override.conf` |
| LXC 623 `test-labmode-unifi` | none | lab mode, test rig | `true` | `override.conf` |

The trap: 981's guest name says `unifimcp`, but its MCP registration says `labmode`.
The test rigs are tagged `disposable`, are normally stopped, and serve plain HTTP, not
TLS.

- **Two-person control (982):** the token that stages a change set cannot approve
  it. Approval needs a second, distinct `actor_type: human` token.
- **Lab mode (981):** `--lab-mode` waives the second principal for a single
  operator. Each approval it records has `approver: null` and
  `approval_waiver: "lab-mode"`, so a waived approval can still be told apart from a
  reviewed one.

**Do not move either production instance to the other's mode.** Both values of
`lab_mode` are correct where they are. A mismatch with the table is the fault:

- 981 reporting `false` means `labmode.conf` was lost or overridden.
- 982 reporting `true` means lab mode leaked into `twoperson.conf`. Its approval gate
  is then silently waived, and `tool_count`/`write_tool_count` do not change to
  show it.

Both drop-ins live in `/etc/systemd/system/rustunifimcp.service.d/`. Each one starts
with a blank `ExecStart=` to clear the shipped line, then re-declares the full
`ExecStart`. Keeping the mode in a drop-in means an `install.sh` unit rewrite cannot
drop it.

- `labmode.conf` appends `--lab-mode` and sets `Environment=UNIFIMCP_LAB_MODE_MARKER=1`
  as a greppable marker.
- `twoperson.conf` is generated from 981's `labmode.conf`, with `--lab-mode` and the
  marker removed. A change to the server's command line, such as a new flag, must be
  made in both files.

**Upgrades:** do the test rigs first, then 982, then 981. Snapshot each production
guest first as `pre-X-Y-Z`. When `packaging/` is unchanged since the last release,
swap only `/usr/local/bin/rustunifimcp`, which leaves the units alone.

**After changing a drop-in, restart the service and confirm with the `unifimcp_status`
tool that `lab_mode` matches the table above.** Two things that will mislead you if
you skip that:

- The shipped unit sets `ProtectSystem=strict`, so verify the service actually came
  back rather than assuming the drop-in parsed.
- MCP negotiates its tool list at connect time. Enabling or disabling lab mode does
  **not** change what an already-connected client sees — the client must reconnect.
  A session that skips this will draw the wrong conclusion about whether the flag
  took effect.

## Verifying entitlement quickly

`unifimcp_status` returns `tool_count` and `write_tool_count` regardless of mode.
`tool_count: 22, write_tool_count: 11, lab_mode: false` means the writes exist and are
gated behind two-person approval, not missing — that distinction is the fastest way
to tell a config problem from a capability gap. Whether `lab_mode` should be `true`
depends on the instance: check the table above.

## Upgrading past the change-set store swap

The change-set state file changed shape when this server adopted
`mecmcp-changeset`'s coordinator. The server writes `/var/lib/unifimcp/changesets.json`,
and a binary from before the swap wrote a bare `{"<id>": {...}}` map; the coordinator
writes `{"version": n, "state": {...}}`.

**The new binary refuses to start on the old file** and names the change sets in it.
That is deliberate — not a bug to work around. Move the file aside and re-plan. The
approvals cannot come across: an approval now binds to the digest of the preview its
approver read, and the old records have no preview, so synthesising one would mint an
approval over text nobody saw.

Two things that will look like unrelated faults:

- The coordinator reads the file through the workspace's hardened reader, so a group- or
  world-readable file is a startup failure. The message carries the `chmod`. The old
  store wrote 0600 but never required it, so a file touched by hand may not be.
- Change-set ids are now 64 hex characters. A saved `cs-<uuid>` from before the swap is
  refused by the id validator, not merely "not found".

## Related

Packaging and the installer live in `packaging/`. TLS is terminated by the server
itself (`--tls-cert` / `--tls-key` from `/etc/unifimcp/tls/`), not by a proxy, so a
certbot renewal has to land inside the container.

## `--tools "*"` means READ-ONLY, not "all tools"

This is the single most misleading thing about deploying this server, and it cost a
session on 2026-08-30.

`rustunifimcp token add --tools` documents `*` as *"or '*' for read-only tools only"*.
A token minted with `--tools "*"` is granted the 11 read tools and **none of the 11
writes**, even though `token list` displays its TOOLS column as `*`, which reads as
fully permissive. The server then advertises 11 tools over `tools/list` and a caller
sees a read-only server with no error explaining the gap.

**To grant write tools, name every one explicitly** in a comma-separated list. There is
no wildcard that includes them.

Do not mistake this for a lab-mode problem. `--lab-mode` does **not** gate tool
exposure: in `server/mod.rs` it only decides the `approver` / `approval_waiver` fields
recorded on a change set, and the `write_tool_count` in `unifimcp_status` is a static
`WRITE_TOOLS.len()`, not a count of what is exposed. Both flags are needed on a
single-operator deployment, for different reasons — the token scope decides what is
*advertised*, lab mode decides whether an approval can proceed without a second person.
Two-person control is also enforced on the token itself (MEC-503): a token combining
`unifi_stage_change` and `unifi_approve_change_set` is refused at issuance unless minted
with `--allow-self-approval`, and refused at call time unless the server runs with
`--lab-mode`. A single-operator lab deployment needs both: the flag at issuance and
`--lab-mode` on the server.

Diagnosing it: probe `tools/list` directly rather than trusting the client. A client
caches its tool list at connect time, so a `/mcp` reconnect that still shows 11 tools is
ambiguous between a stale client and a real server-side gate; the wire answer is not.
