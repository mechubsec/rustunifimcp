# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- LXC packages record provenance for the packed binary, including when that
  binary is supplied prebuilt (`UNIFIMCP_PACKAGE_SKIP_BUILD=1`). The installer
  refuses a package whose record is missing or does not match the binary.
- The LXC setup guide extracts that package under its top-level directory and
  runs the installer from inside it.

## [0.5.0] - 2026-10-06

### Security

- **Hardens authorization and path-handling checks in the direct-commit ops
  tools** (MEC-503, #54).
- **Container and LXC/systemd installs now provision a keyed audit HMAC key
  automatically on first run** (MEC-978, #87, #97). Both deployment paths
  now provision and wire the key the same way.
- **The shared CLI security options for approval digests and telemetry are
  now honoured end to end** (#88): unusable configuration fails startup
  instead of being silently accepted.

### Changed

- **Bumped the pinned `mecmcp` to v0.26.1** (MEC-1459). No call-site changes
  were needed: this release's redaction fix is Junos-XML-specific and does
  not touch any crate or call site this server uses.
- **Bumped the pinned `mecmcp` to v0.26.0** (MEC-1235). No call-site changes
  were needed: `mecmcp-redact` gained `Profile` extension hooks and vendor
  JSON/XML profiles for other servers in this release, but this server's
  own allowlist-and-denylist redaction (`crate::redact`) already covers
  every tool-output path and does not need those hooks.
- **Bumped the pinned `mecmcp` to v0.25.0** and adapted to its API changes:
  - `mecmcp-server::tool_result` now takes an `OutputRedaction` argument;
    every call site here passes `OutputRedaction::Apply` (this server's
    output already touches device data, so nothing changes in practice —
    see `crate::redact`, which already ran the same redaction directly).
  - `mecmcp-audit::AuditConfig` gained an `otel` field. Set to `None`: this
    server does not wire OTel through to mecmcp, so the pin bump does not
    turn telemetry on as a side effect.
  - `mecmcp-transport::LimitsConfig` gained `trusted_proxies`. Set to an
    empty `Vec`, matching the prior behavior of trusting no proxy for
    `X-Forwarded-For` (no flag exposes this yet).
  - `mecmcp_http::HttpError` gained `RetryRequiresGet`; `UnifiError`'s error
    classifier now matches it exhaustively (unreachable today — this crate
    never calls the retry-with-backoff path that produces it).
  - `UnifiClient` now builds requests with `HttpRequest::from_absolute_url`
    (the new `absolute-url` feature) instead of the removed
    `HttpRequest::new`, since this client appends a percent-encoded query
    string after the path for offset/limit pagination, which
    `with_base_and_path`'s path-only `ExpandedPath` has no way to carry.
  - `mecmcp-changeset`'s coordinator now freezes a change set's owner,
    device, and plan digest at creation (MEC-525): restaging under an
    existing `change_set_id` with a changed plan is refused up front
    instead of being caught later at approval time. The one test that
    exercised the old, two-step "restage then approve a stale digest"
    sequence (`approving_a_digest_the_plan_has_moved_past_is_refused`) is
    replaced with `restaging_an_existing_change_set_with_a_different_plan_is_refused`,
    which pins the new, earlier refusal directly.
  - `tool_error` now redacts unconditionally, and mecmcp-redact's key
    denylist matches `token` as a substring; a denylisted-key match blanks
    the rest of the line, not just the value. `SiteNotInScope`'s message
    and the two-person-control refusal both said "token" next to
    non-secret identifiers (a token name, the scope list), which would have
    silently lost everything after it. Both are reworded to say "caller"
    instead, so the identifiers survive redaction intact.
- **Test: a missing `tokens.json` fails startup loudly, naming the path**
  (MEC-988, mecmcp#356). `rustunifimcp` shipped `/var/lib/unifimcp/tokens.json`
  from its first release and never had an `/etc` token store to migrate away
  from, so it doesn't need the canonical/legacy resolver its five sibling
  mecmcp servers carry. What it does need, and lacked a regression test for,
  is confirmation that `mecmcp_auth::TokenStoreFile::load` refuses a missing
  file outright — no silent empty store, no unauthenticated fallback — and
  names the exact path in its error, so a bad drop-in restore is diagnosable
  at startup rather than mid-incident. See `docs/FILESYSTEM-LAYOUT.md` in
  `mecmcp` for the full six-server standard this closes out.
- **Removed unwired stub tools and sub-actions** (MEC-505): `unifi_run_speed_test`
  and `unifi_firewall_audit` are gone from the tool catalog, `unifi_client_action`
  no longer admits `authorize` or `limit_bandwidth`, and `unifi_backup_action` no
  longer admits `download` or `validate` — each was advertised but only ever
  returned an error or an empty result. The catalog is now 22 tools (11 write).
  `adopt`, `upgrade`, `port_action`, and backup `list`/`trigger`, wired for real
  in #80/#81, are kept. README/CLAUDE.md contradictions on `--lab-mode` and
  stale tool counts across the docs are corrected.
- **Wired `unifi_backup_action list` and `trigger`** (MEC-516): `list` calls
  the controller's `cmd/backup` `list-backups` command and returns the
  result capped at 100 entries with a `truncated`/`shown`/`total` marker,
  the same shape `mecmcp-server::truncate_items` (MEC-513, mecmcp#443) will
  give once `rustunifimcp` adopts a tagged `mecmcp-server` release that
  carries it — the local helper is a deliberate placeholder, not a
  reimplementation to keep. `trigger` calls `cmd/backup` `backup`. `download`
  and `validate` still refuse: both would move a raw `.unf` file rather than
  JSON, which `UnifiClient` does not support today.
- **Added read coverage for legacy firewall rules, port forwards, static
  routes, and the controller event log** (MEC-509). `unifi_list_resources`
  and `unifi_get_resource` gain three new `kind`s: `firewall_rule` (the
  pre-zone-based ruleset, `rest/firewallrule`), `port_forward`
  (`rest/portforward`), and `static_route` (`rest/routing`) — all read-only
  for now, projected through their own field allowlists like every other
  kind. `unifi_query_stats` gains `subject=event` for the controller's event
  log (`stat/event`), projected through a typed model rather than the
  shared crate's denylist-and-shape scan: an event's type discriminator is
  carried in a field literally named `key`, which that scan treats as an
  exact-match secret-shaped name, so it is renamed to `event_type` on the
  way out instead.
- **Release supply chain hardening** (MEC-507): the `Release image` workflow now
  publishes a CycloneDX SBOM per workspace crate as a release artifact,
  cosign-signs the pushed image keylessly (GitHub OIDC, no key material),
  attaches a SLSA build provenance attestation, and builds/publishes
  `linux/arm64` alongside `linux/amd64` in one multi-arch manifest.
  `cargo deny check` in CI now covers `advisories` and `licenses` as well as
  `bans` and `sources`; that surfaced a yanked `chacha20 0.10.1` (bumped to
  0.10.2) and an unallowed `CDLA-Permissive-2.0` license on
  `webpki-root-certs`/`webpki-roots` (added to `deny.toml`'s allow list —
  covers embedded Mozilla root cert data, not code, same allowance as
  mecmcp/rustjunosmcp/rustproxmoxmcp). See
  [docs/HOW-TO-SETUP-DOCKER.md](docs/HOW-TO-SETUP-DOCKER.md) for the
  `cosign verify` / `gh attestation verify` recipes.
- **Re-pinned the `mecmcp-*` crates from `v0.23.1` to `v0.24.1`** (MEC-504).
  Brings in mecmcp#390 (the human-approver gate: `ChangesetCoordinator::approve_change_set`
  now takes an `approver_actor_type: mecmcp_audit::ActorType` and refuses
  anything but `Human`), mecmcp#377 (`/healthz` and `/readyz`, unauthenticated
  and always mounted), mecmcp#387 (`mecmcp-http`'s configured private CA now
  replaces the public root store instead of adding to it, and
  `mecmcp-transport`'s `test_harness`/`test_client` moved behind a `test-util`
  feature), and MEC-347 (`LimitsConfig::default()` now rate-limits by default:
  50 requests/second and a burst of 100 per IP, 20/s and a burst of 40 per
  token).
- **`unifi_approve_change_set` now passes the caller's server-verified actor
  type through to mecmcp's `ChangesetCoordinator::approve_change_set`.** A
  change set cannot be approved by a caller whose token declares
  `actor_type: agent`, or by an unattributed (stdio) caller — only a
  distinct `actor_type: human` principal can approve.
  **Upgrading:** every token minted before this release has `actor_type:
  unknown` and can no longer approve change sets. Re-mint each approver's
  token with `rustunifimcp token add ... --actor-type human`; other tokens
  are unaffected. See [README § Change control](README.md#change-control).
- **Per-IP and per-token rate limiting is now on by default over HTTP**, and
  every `LimitsConfig` field is exposed as a CLI flag (`--max-requests-per-second-per-ip`
  and friends — see `rustunifimcp --help`) instead of being hardcoded to
  `LimitsConfig::default()`.
- **Added `--enable-metrics`** to expose a Prometheus `/metrics` endpoint
  (streamable-http only, off by default). As of `mecmcp-transport` 0.24.0,
  `/metrics` is additionally restricted to loopback callers regardless of
  this flag.
- **`/healthz` and `/readyz`** are now served unauthenticated on every HTTP
  deployment, mounted by `mecmcp-transport`'s router assembly. This server
  wires in no readiness checks of its own, so `/readyz` reports ready
  whenever the process is up.
- Raised MSRV to 1.89
- **`unifi_stage_change` now enforces a per-kind writable-field allowlist** (M11) —
  a staged `create`/`update` body may only set the fields this server's read model
  recognises for that kind, and a controller-managed `_id` is never writable for
  any kind. This is a behavioural restriction: a body naming an unrecognised field,
  or a non-object body, is now refused at staging (and again at apply, for a plan
  that reached `Approved` before this check existed). The visible effect for
  `traffic_route` is the most restrictive: this server's read model for that kind
  carries only `name`, so a `traffic_route` write is now name-only — any other
  field in the body is refused.
- **Container images now publish to `ghcr.io/mechubsec/rustunifimcp`** —
  the repo moved to the mechubsec organization, and images are renamed to
  match. Older tags were copied from the previous name.

## [0.4.0] - 2026-09-16

### Security

- **rustls 0.23.45, closing RUSTSEC-2026-0285** (#35) — TLS 1.3 handshake messages 
  accepted across encryption-level boundaries, CVSS 5.3. The advisory describes a 
  server vulnerability where incoming TLS 1.3 handshake messages could be accepted 
  and processed in the wrong encryption state, potentially exposing the server to 
  state confusion attacks. This is the primary reason for this release. The fix 
  was backported to the 0.23 series in rustls 0.23.45, which this server now pins.

### Changed

- **`unifi_list_resources` now honours `limit` and `offset`** (#39, closes #36) — 
  previously the documented bound was ignored on the PrivateV1 and PrivateV2 surfaces, 
  so `limit=1` returned all 230 firewall policies (226 KB) instead of 1. This is an 
  observable change in tool behaviour and the reason for the minor version bump. The 
  paging is applied per surface: the Integration API already honoured both parameters 
  and still does, so its responses are unchanged. Only calls to the Private API with 
  a `limit` parameter will see different results.

- **Listener arguments are now validated before any file is read** (#38) — this server 
  never called the shared validator that checks bind-address safety and TLS 
  configuration coherence, so an unsafe bind was refused with 
  `Fatal: failed to serve HTTP router` and the actual error discarded. It now names 
  the offending flag. This also changes error ordering: an argument mistake is no 
  longer masked by a config-file mistake — the CLI is validated first and the server 
  exits early if the bind configuration would fail.

### Updated dependencies

- **rmcp 3.4.0** (#37) — the `ServerInfo` type was renamed to `ServerConfig`, which 
  better describes its purpose as configuration rather than runtime information. This 
  server's `rmcp::Server<RustUnifiMcp, ServerConfig>` initialization is updated 
  accordingly. No wire-format or behavioural change.

- **distroless/cc-debian13 base image digest bumps** (#32) — the container image's 
  runtime base was updated from digest `9b615ff` to `4594d59`. This brings in 
  Debian security updates for the distroless-packaged libc and system libraries. 
  No application-level changes.

- **rust build image digest bump** (#30) — the build stage's base image was updated 
  from digest `17d1ba8` to `bce1476`. This brings in Rust toolchain and system 
  library updates from the upstream `rust:latest` image.

- **uuid 1.26.0 → 1.26.1** (#34) — patch version bump for the uuid crate.

- **rustls 0.23.43 → 0.23.44** (#31) — an intermediate rustls version bump before 
  the 0.23.45 security fix. This was a non-security patch release in the 0.23 series.

- **rmcp 3.1.4 → 3.2.0** (#28) — a minor version bump in the rmcp framework with no 
  breaking changes to this server's integration surface.

- **tokio-rustls 0.26.4 → 0.26.5** (#27) — patch version bump for the tokio-rustls 
  TLS adapter.

### Added

- **Docker ecosystem is now tracked by dependabot** (#29) — the `.github/dependabot.yml` 
  configuration now includes Dockerfile base-image updates alongside Cargo.toml and 
  GitHub Actions. Digest-pinned images in the Dockerfile will now receive automated 
  update PRs when their upstreams publish new versions.

### Fixed

- **LXC setup documentation now includes the missing `--allowed-origin` flag** (#26) — 
  the systemd service drop-in example in `docs/HOW-TO-SETUP-LXC.md` was missing this 
  required argument, which would cause the server to reject cross-origin requests from 
  Claude Code clients. The drop-in now correctly documents the flag.

### Documentation

- **New LXC setup guide** (#25) — `docs/HOW-TO-SETUP-LXC.md` was added, providing a 
  complete walkthrough for building and deploying a rustunifimcp LXC container from 
  scratch. This complements the existing Docker setup guide and is the deployment 
  method used in the mechub homelab's production LXC 981.



## [0.3.2] - 2026-09-06

### Fixed

- **Systemd unit now sets `SystemCallErrorNumber=EPERM`** so a denied syscall
  returns an error instead of killing the server with SIGSYS. The shipped unit had
  `SystemCallFilter=~@privileged` but no `SystemCallErrorNumber`, so systemd's
  default applied and a denied syscall raised SIGSYS. On 2026-09-05 that killed
  rustunifimcp mid-request on LXC 623 during a change-set approval write: the
  client saw `curl: (52) Empty reply from server`, the journal recorded
  `Main process exited, code=killed, status=31/SYS`, systemd restarted the service,
  and the approval never landed. Kernel audit named it: `sig=31 ... syscall=92`
  (chown). mecmcp#351 fixed the chown call in v0.23.1, but the unit is the other
  half: `SystemCallErrorNumber=EPERM` makes denials return EPERM instead of
  killing the server. An EPERM denial is silent at the systemd layer — the only
  place it can become visible is the application, which must not discard the errno.
  This is mecmcp#354's seccomp standard, now applied to all shipped units.

## [0.3.1] - 2026-09-05

### Fixed

- **Change-set state writes no longer kill the server under systemd's
  `SystemCallFilter=~@privileged`** (#351 upstream). With 0.3.0's write path on
  the mecmcp coordinator, a change-set state write made a `chown` syscall that
  this server's own systemd unit denies via `SystemCallFilter=~@privileged`.
  Because seccomp answers a denied syscall with SIGSYS rather than EPERM, the
  process was killed mid-write and systemd restarted it. The client saw an empty
  reply and the write never landed. The trigger was the second state write, so
  `stage` succeeded and `approve` died. Fixed upstream in mecmcp v0.23.1, which
  only calls `chown` when the replacement file's ownership actually differs from
  the destination's. Re-pinned every `mecmcp-*` dependency from `v0.23.0` to
  `v0.23.1`.

## [0.3.0] - 2026-09-05

### Added

- **A committed synthetic fixture set** at `rustunifimcp-core/tests/fixtures/synthetic/`
  (#13). Seventeen of 143 tests needed fixtures captured from a live controller, which
  are deliberately gitignored, so on a fresh clone they printed "SKIPPED: no fixtures"
  and returned early — and CI reported `ok`. Among them were the change-set `diff`,
  `preimage` and `validate` tests, so every green run overstated what had been checked
  on the write path specifically. The synthetic set is hand-written with
  documentation-range addresses, locally administered MACs and zeroed coordinates, and
  is held to the same `scripts/verify-fixtures-scrubbed.sh` gate the recorded sets must
  pass — `gate_passes_on_the_committed_synthetic_fixtures` runs it on every test run.

- **SSDF evidence is wired** (#16). `mecmcp-audit` was a declared dependency imported
  nowhere and the `--ssdf-audit-*` flags were already on the CLI via
  `mecmcp_runtime::cli::Cli`, so they parsed and did nothing — this server emitted none
  of the fleet's change records. With `--ssdf-audit-endpoint` configured all four now
  land: the coordinator emits the approval records itself, and the server emits the
  proposal on first stage and the apply-intent and result-receipt around the writes.
  The apply is **refused** if the intent cannot be made durable, because an intent that
  survives only in memory proves nothing about a crash; the receipt cannot fail closed,
  since the controller has already acted. The pipeline is flushed with `shutdown()` at
  exit — dropping it stops the worker but deliberately does not spool, so a proposal or
  approval not followed by an apply would otherwise be lost. Off by default.

### Changed

- **`DEFAULT_FIXTURE_VERSION` is now the synthetic set**, and the fixture-gated tests
  no longer skip: the guards are gone, so a missing fixture is a failure rather than a
  silent pass. `fixtures_available()` is replaced by `recorded_fixtures_available()`,
  which only the version matrix and the scrub gate's live check consult — a hand-written
  fixture is evidence about the parsers and nothing at all about controller drift, so
  `tests/version_matrix.rs` excludes it from the recorded versions.
- **`every_resource_kind_has_a_parser_wired` now runs over every fixture set present**,
  so a developer holding a live capture still exercises the parsers against real data
  while CI exercises them against the synthetic set. A recorded version with an
  `.absent` marker for a kind is skipped for that kind — recording a 404 is how the
  matrix asserts drift, and it must not break the parser test — while the synthetic
  set is required to carry every kind.
- Two assertions pinned to the 10.5.67 capture's exact DHCP-reservation count are now
  stated as relationships — strictly fewer than the total, and not zero. The count made
  the committed set carry 46 reservations to satisfy a test that is about the filter
  being active.

- **The change-set store is now `mecmcp-changeset`'s coordinator** (#16). It was a
  persisted `HashMap` with `insert` / `get` / `remove` and no state machine, so three
  protections the rest of the fleet spent three mecmcp minors acquiring were absent
  here: claim-before-apply (two concurrent applies could both observe `Approved` and
  both proceed), the transition policy (any field could be written over any other), and
  preview-bound approval (an approval referenced no preview at all). None of that is
  reimplemented — `insert_change_set`, `approve_change_set` / `waive_approval`,
  `claim_change_set_for_apply` and `update_change_set_from` replace the map, and
  `--approval-timeout-secs` now configures the coordinator's approval TTL, which is
  what actually expires an approval.
- **`unifi_get_change_set` reports the lifecycle's state** rather than a string inferred
  from which fields happen to be populated. `approved` and `pending` used to be derived
  from whether an approver was set, which cannot distinguish an expired approval or a
  cancelled set from a pending one. It also returns the plan digest, the pre-image
  fingerprint, the approval expiry and the preview.
- **A change set can no longer be staged into after approval.** Staging rewrites the
  plan and the digest an approval binds to, so allowing it would let a reviewed plan be
  swapped for an unreviewed one with the approval still attached.
- **`unifi_apply_change_set` records `Applied` only when every write landed** (and for
  an apply that landed but could not be re-read to confirm it, which did apply). A
  partial apply is `Failed`: a record claiming a change landed when only some of it did
  is worse than one an operator has to go and read.
- **The per-mutation apply breakdown is now an audit event**
  (`event = unifi_change_set_applied`) rather than a field on the stored change set. It
  has no home on `ChangeSetRecord`, which is `deny_unknown_fields`, and the shared
  crate's `OperationRecord` was the wrong container: its non-terminal states make every
  later operation on the device refuse as unreconciled, which is right for a vendor
  whose commit either lands or does not and would wedge this one, where a partial apply
  is routine and no tool exists to clear it. The state file holds state; what happened
  is an event.
- Change-set ids are now 64 hex characters, which is what the shared lifecycle validates
  against. The old `cs-<uuid>` form is refused by it.
- **`unifi_approve_change_set` takes an optional `expected_digest`.** Supplying the plan
  digest the approver read is what makes the approval attest to a specific plan: without
  it the lifecycle's digest check compares the stored value with itself, and the approval
  covers whatever the record holds when the call lands.

- **`kind=firewall_policy` now returns the whole policy** from `unifi_get_resource`
  and `unifi_list_resources` (#11). The projection kept six summary fields and dropped
  `source`, `destination`, `protocol`, ports, `schedule` and `connection_state_type` —
  everything that makes a policy mean anything — so an existing policy could not be
  read and adapted into a new one. `FirewallPolicy` now carries the remaining fields
  verbatim and round-trips losslessly.

### Removed

- `mecmcp-job` and `mecmcp-policy` from `[workspace.dependencies]`. Declared, imported
  nowhere, and no plausible use here. `mecmcp-audit` moves from the core crate, which
  never imported it, to the binary, which is where the recorder is built.

### Fixed

- **`unifi_validate_change_set` no longer refuses every zone-based firewall policy**
  (#10). The reference check read its zone list from the change set's pre-image and
  looked for a resource with `_id == "_all_"`, which no controller returns. A create
  records no pre-image at all, so the zone index was empty for exactly the mutations
  that needed checking and every `firewall_policy` create was rejected as referencing
  a zone that did not exist. Validate now fetches the controller's live zone list, and
  only when a staged body names a zone. Three further changes to the same check:
  `destination.zone_id` is checked as well as `source.zone_id`; a zone named by its
  `external_id` reports the `_id` to use instead of claiming the zone is absent; and a
  zone list that cannot be read is a distinct error from a zone that is not there —
  the new `UnifiError::ReferenceNotFound` renders without the "unexpected response
  shape" prefix that made a lookup miss read like a parse failure. A policy naming a
  zone the same change set deletes is now refused too — apply runs the staged writes
  in order, so the live list still has a zone that will be gone by the time the policy
  lands. That check follows staging order and runs against the *effective* policy, not
  the staged fragment: a Private v2 update is a partial write the client overlays on
  the live resource, so a fragment touching only `enabled` still applies a policy
  carrying the live zones, a second fragment lands on the result of the first, and a
  non-object body changes nothing at all. Both failing orderings are reported with the
  ordering named as the fix.
- **Change-set tools now refuse a controller that does not own the change set.** Every
  one of the seven took a `controller` argument and used it to pick the client without
  ever comparing it to the controller the set was created against, so a set planned
  against one controller could be validated — and applied — against another.

### Upgrading

**The change-set state file is not carried forward.** LXC 981 `prod-unifimcp` writes
`/var/lib/unifimcp/changesets.json`; the new binary refuses to start on a file written by
the old store and names the change sets in it. Move the file aside and re-plan them.

They are deliberately not converted: an approval is now bound to the digest of the
preview its approver read, and the old records have no preview, so carrying one across
would mint an approval over text nobody saw — exactly what preview binding exists to
prevent. Re-planning also re-reads the controller rather than trusting a pre-image of
unknown age.

Two behaviour changes that are easier to read here than to discover:

- **`--approval-timeout-secs` now runs from staging, not from approval.** It configures
  the coordinator's approval TTL, and the deadline is stamped when the change set is
  written — the first `unifi_stage_change`. Apply checks it through `change_set_status`,
  and then against the deadline on the record the claim returns. Neither upstream gate
  covers it: `claim_change_set_for_apply` checks the state and not the clock, and
  `change_set_status` applies the approval TTL only to a `Planned` record — so an
  ordinary two-person approval granted inside the window and applied long after it
  would otherwise still reach the controller. The check is after the claim because the
  claim is what serialises; a pre-claim check alone is a check-then-act race. The packaged default of 300 seconds therefore bounds the whole
  plan-review-apply round. That also bounds the age of the pre-image the plan was built
  against, which is the point, but it is a shorter window than the old code enforced.
- **One pending change set per principal per controller.** A second
  `unifi_create_change_set` on the same controller by the same token is refused until
  the first reaches an outcome or is cancelled.
- **`unifi_create_change_set` returns a draft, not a stored change set.** The
  coordinator's persistence layer refuses to load a state file containing a change set
  with no actions, so writing an empty plan would make the whole store unloadable at the
  next restart — a fault no test run can see, because nothing in one restarts. The
  change set is created on the first `unifi_stage_change`. A draft is held in memory,
  reports `state: "draft"` from `unifi_get_change_set`, lapses with the approval window,
  and is lost on restart along with nothing.
- **`unifi_create_change_set` refuses a description too large for the preview**, which
  would otherwise mint an id that could never become a change set: the description is
  stored inside the preview, so every first stage would rebuild it and be refused after
  the controller reads.
- **A plan is checked against the configured ceilings at stage.** Neither
  `insert_change_set` nor `update_change_set` consults them — only `create_change_set`
  does, which this server cannot use — while the load path enforces a structural cap of
  64 actions. Staging past the limit would persist and then refuse to reload.

Two smaller things about the state file. The coordinator reads it through the workspace's
hardened reader, so a group- or world-readable file is a startup failure with a `chmod`
in the message; the old store wrote 0600 but did not require it. And a **blank** file is
now discarded rather than refused, because the coordinator cannot parse one and an
interrupted first write produces one.

## [0.2.0] - 2026-09-01

This is a **minor version** because it adds the reproducible release path (Dockerfile
and GitHub Actions workflow) that v0.1.0 lacked. The binary running on LXC 981 at
v0.1.0's tag date was built and installed by hand, predating the GitHub release artifact
by fifteen hours. v0.2.0 closes that gap.

### Added

- **Dockerfile** for reproducible multi-stage builds, producing a distroless runtime
  image with no shell, no package manager, and only the server binary and libc.
  Builder and runtime both pinned to Debian 13 (trixie) to ensure glibc compatibility
  with LXC 981.
- **GitHub Actions `release-image.yml` workflow** to build and push container images
  to `ghcr.io/fastrevmd-lab/rustunifimcp` on version tags.
- **CI workflow** with format, clippy, build, and test steps.
- **Security workflow** with gitleaks, cargo-audit, and cargo-deny checks.
- **Dependabot** configuration for cargo and github-actions ecosystems, with
  mecmcp-* and dtolnay/rust-toolchain ignores.
- **`deny.toml`** for supply-chain checks.
- **`CLAUDE.md`** documenting that LXC 981 `prod-unifimcp` must run with
  `--lab-mode` to expose write tools in the single-operator homelab deployment.
- **gitleaks allowlist** (`.gitleaks.toml`) for the fixture-scrub gate's two
  synthetic credentials in `rustunifimcp-core/tests/fixture_scrub_gate.rs`.

### Changed

- Re-pinned the `mecmcp-*` crates from `v0.20.0` to `v0.23.0`. 0.23.0 binds a
  change set's preview digest into its approval digest, so an approval now
  vouches for the exact preview a reviewer saw.
- **`Atomicity` is now re-exported from `mecmcp-changeset`** instead of being
  defined locally. A local duplicate would be a distinct type that shared code
  could not accept, defeating the point of declaring the guarantee.
  `UnifiTransaction::atomicity()` returns `Atomicity::live_writes()`.
- Updated `rcgen` from 0.14.9 to 0.14.10.

### Fixed

- **Three changeset tests now guard on `fixtures_available()`** instead of
  calling `fixture()` directly. The tests pass on a developer machine but
  failed on a fresh clone because `rustunifimcp-core/tests/fixtures/*/` is
  gitignored. A missing fixture is now an un-run test, not a failing one.
- **`a_top_level_api_key_is_rejected_at_load_time` is no longer ignored.**
  It covers a security invariant — an `api_key` at the inventory envelope level
  must not be silently accepted — and was the only test for it. Enabled because
  `CanonicalEnvelope` in mecmcp 0.23.0 now carries `#[serde(deny_unknown_fields)]`.

[unreleased]: https://github.com/mechubsec/rustunifimcp/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/mechubsec/rustunifimcp/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/mechubsec/rustunifimcp/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/mechubsec/rustunifimcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/mechubsec/rustunifimcp/releases/tag/v0.2.0
