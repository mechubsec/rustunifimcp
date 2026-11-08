# UniFi Controller Fixtures

Two kinds of fixture live under this directory.

## Synthetic Fixtures

The **synthetic** set (`synthetic/`) is hand-written, committed, and present in
every checkout. It is what the parser, workflow, and changeset tests read. The
fixtures carry documentation-range addresses (192.0.2.x, 198.51.100.x,
203.0.113.x, 2001:db8::/32), locally administered MACs (02:00:00:xx:xx:xx),
zeroed coordinates, and 24-character lowercase hex structural IDs.

The synthetic set exists because the recorded sets cannot be published:
seventeen tests used to skip on a fresh clone, and CI reported `ok` while
never running them. The scrub gate (`scripts/verify-fixtures-scrubbed.sh`)
enforces that the synthetic set contains no sensitive data, and
`tests/fixture_scrub_gate.rs` verifies the gate passes on the committed set.

`policies.json` carries a controller-predefined BLOCK policy
(`000000000000000000000202`, `predefined: true`, `create_allow_respond: true`).
Real controllers ship such policies, and the respond-traffic staging check must
not refuse them; CI has no recorded set, so without this entry nothing would
catch a regression there. It also carries UniFi Network 11.0's `report_flow`
and `report_flow_supported`, which every 11.0 policy has.

## Recorded Fixtures

The **recorded** sets are captured per controller version by
`scripts/capture-fixtures.sh`, carry real network data (scrubbed), and are
gitignored. Each subdirectory is named by controller version (e.g., `10.5.67/`),
containing JSON responses from the capture endpoints.

Recorded sets are what `tests/version_matrix.rs` reads, because only a real
capture is evidence about what a real controller version serves. A hand-written
fixture proves nothing about drift, which is why the matrix skips the synthetic
set rather than counting it as a version.

## Capturing a New Controller Version

Run `scripts/capture-fixtures.sh` with environment variables:

```sh
UNIFI_API_KEY="..." CONTROLLER="https://..." ./scripts/capture-fixtures.sh
```

The script captures all endpoints into `tests/fixtures/<version>/` and
**automatically verifies the output is scrubbed** before completing.

## Scrubbing Requirements

Fixture files **must not contain**:

1. **Credential-shaped values** — fields matching `pass`, `psk`, `secret`,
   `token`, `key`, `cred`, `auth`, `hash`, `salt`, `priv`, or `cert` (case-
   insensitive) must hold only accepted placeholders: values containing
   `REDACT`, `EXAMPLE`, matching `^[A0]+=?$`, or starting with `SHA256:0000`.

2. **High-entropy values** — any base64-like string 32+ characters
   (`[A-Za-z0-9+/]{32,}={0,2}`) that is not a structural UniFi identifier
   (`_id`, `site_id`, `device_id`, etc.) or an accepted placeholder.

3. **Public IP addresses** — IPv4 and IPv6 addresses that are globally
   routable, except:
   - Documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
     `2001:db8::/32`
   - Well-known public resolvers: Cloudflare (`1.1.1.1`, `1.0.0.1`, `1.0.0.2`,
     `2606:4700::/32`), Google (`8.8.8.8`, `8.8.4.4`), Quad9 (`9.9.9.9`)
   - Any IP address inside `policies.json` (contains legitimate firewall rules
     for public CDN/DNS ranges)

4. **Non-zero geographic coordinates** — `lat`, `latitude`, `lng`, or
   `longitude` fields with values other than `0.0`.

5. **Denied identifiers** — any substring match (case-insensitive) against
   entries in `scripts/fixture-denylist.txt`. **This file is local-only and not
   committed** because it necessarily contains the identifiers it exists to
   protect. Copy `scripts/fixture-denylist.example.txt` to
   `scripts/fixture-denylist.txt` and add your own identifiers **before
   capturing a new controller version**.

## Verification Gate

`scripts/verify-fixtures-scrubbed.sh <fixture-dir>` scans all JSON files in the
directory and exits non-zero if it finds any of the above violations.

The gate reports:
- File path and field path for each violation
- Redacted locators (field name, value length, never the value itself)
- Summary on success: files scanned, values checked, violations found

An empty fixture directory is an error — the gate must scan actual files to
report success.

## Adding a New Controller Version Safely

1. **Update the denylist first** — if `scripts/fixture-denylist.txt` does not
   yet exist, copy it from `scripts/fixture-denylist.example.txt` first. Then
   append any personal or site-specific identifiers (SSID names, surnames, site
   names) to `scripts/fixture-denylist.txt`.

2. **Run the capture** — `scripts/capture-fixtures.sh` will invoke the
   verification gate automatically at the end.

3. **If the gate fails** — the script exits non-zero and prints each violation.
   Scrub the offending fields manually and re-run the gate until it passes.

4. **Update the version matrix** — add a row to `endpoint_available()` in
   `rustunifimcp-core/src/version.rs` for the new version. Every row must be
   justified by a fixture or an `.absent` marker — never guess. If any
   endpoint returned HTTP 404, create a `.absent` marker file (e.g.,
   `10.5.67/policies.absent`) in the version directory. The capture also writes
   `manifest.txt` (`<name> <http_code>` per attempted endpoint, published only
   when the whole capture succeeds); a kind with neither fixture nor marker is
   skipped only if the manifest shows it was never attempted, and fails
   otherwise (unexpected status or a deleted file). A recording with no
   manifest must be recaptured, or given one by hand. The matrix test
   (`tests/version_matrix.rs`) will fail if the matrix and fixtures disagree.

5. **Keep at least two versions** — Phase 1's exit criterion (10.5.67 and
   11.0.97). `at_least_two_controller_versions_are_recorded()` in
   `tests/version_matrix.rs` fails on a checkout holding exactly one recording,
   and skips on one holding none, as CI does.

6. **Commit only after the gate passes** — a passing gate is not proof the
   fixtures are safe (the denylist could be incomplete), but a failing gate is
   proof they are not.

## Manual Scrubbing

If you need to scrub fixtures manually:

1. Replace credential values with `"REDACTED"` or `"AAAA"`.
2. Replace public IPs with documentation range addresses.
3. Set geographic coordinates to `0.0`.
4. Replace personal identifiers with generic placeholders like `"home"`,
   `"user1"`, `"device-a"`.

Then re-run the gate to verify:

```sh
./scripts/verify-fixtures-scrubbed.sh rustunifimcp-core/tests/fixtures/10.5.67
```

## Why This Matters

Fixture scrubbing failures discovered across four fix rounds:

- **Round 1**: MACs, `x_passphrase`
- **Round 2**: Real SSIDs, surname, WAN IPv4 hidden in CIDR notation
- **Round 3**: Owner's Comcast IPv6 prefix (201 occurrences), family names (43),
  **home GPS coordinates**
- **Round 4**: **Live cryptographic material** — WireGuard private key,
  RADIUS shared secret, device inform keys, guest tokens (58 values, 5 files)

The root cause was checking only hand-picked field names rather than
enumerating what was actually present. This gate makes the check mechanical.
