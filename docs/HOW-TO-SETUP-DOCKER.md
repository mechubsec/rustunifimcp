# How to run rustunifimcp in Docker

Runs the server as a container in either **lab mode** or **two-person** mode.
Written from a working setup built on 2026-09-07: every command here was run,
and both returned HTTP 401 to an unauthenticated POST, which is the success
case — serving and enforcing auth.

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation, recorded as `approval_waiver=lab-mode` | ordinary tool work, reads, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

The server announces lab mode at startup, as a `WARN`:

```
lab mode enabled: change sets are approved on creation with no second principal.
Records carry approval_waiver=lab-mode. Do not run this against production controllers.
```

If you see that line and did not intend it, stop and fix the flag.

## Minimum controller version

`rustunifimcp` requires UniFi Network Application 10.5.67 or UniFi OS Server 5.1.37
(or later). These versions include the 2026 CVSS 10 security fixes (SAB-062, SAB-064,
SAB-066/067) that this project depends on for secure API access.

## What the image supplies (and what it does not)

The image runs as numeric UID/GID `65532:65532` and has `ENTRYPOINT
["/usr/local/bin/rustunifimcp"]` with **no `CMD`**. Nothing is preset, so
nothing can be silently lost when you pass your own arguments — unlike two
sibling servers where config or audit flags live in `CMD` and disappear the
moment a caller overrides anything (see mechubsec/mecmcp#357). The cost is
that **you must supply every argument yourself**. The examples below are long
because the image provides only the binary.

## 1. Prepare host paths

```bash
mkdir -p unifi-docker/etc unifi-docker/state
cd unifi-docker
```

`controllers.json` — this follows the shape in
`packaging/examples/controllers.example.json`. The controller API key is **not**
in the controllers file; it is referenced by `api_key_file`:

```json
{
    "version": 1,
    "devices": {
        "unifi-demo": {
            "endpoint": "https://192.0.2.10:8443",
            "site": "default",
            "api_key_file": "/etc/unifimcp/api.key",
            "allow_private_api": true
        }
    }
}
```

The flat `{"<name>": {"url": ...}}` shape and `skip_tls_verify` are no longer
accepted: the server exits with `inventory parse failed`. For a controller with
a self-signed certificate, point `ca_pem_path` at its CA certificate instead.

**`api_key_file` must be the in-container path**, not the host path. The file
lives at `etc/api.key` on the host and is mounted to `/etc/unifimcp`.

Place the controller API key in a separate file:

```bash
echo 'your-api-key-here' > etc/api.key
```

Mint a bearer token. The binary can do this on the host — no container needed:

```bash
rustunifimcp token add --tokens-file ./state/tokens.json \
    --name my-client --devices '*' --tools '*'
```

The secret prints **once** and is stored hashed. `--tools '*'` resolves to
**read-only tools only**; write tools must be named explicitly, so a wildcard
token calling a change-set tool gets `insufficient_scope`. That is deliberate.

If this token will call `unifi_approve_change_set`, add `--actor-type
human`: the server refuses approvals from any token whose actor type is
`agent` or unset.

Two-person control is enforced on tokens: a token combining
`unifi_stage_change` and `unifi_approve_change_set` is refused at issuance and
at call time, so issue separate staging and approving tokens. Only a lab-mode
single operator may combine them: mint it with `--allow-self-approval` and run
the server with `--lab-mode` (section 5); the self-approval is recorded as
`approval_waiver=lab-mode`.

Then lock the modes down:

```bash
chmod 0600 etc/controllers.json etc/api.key state/tokens.json
```

## 2. Ownership: two options

The container process is UID 65532 and must read the config and write the state
directory.

**For a real deployment**, give it ownership:

```bash
sudo chown -R 65532:65532 etc state
sudo chmod 0700 etc state
```

**For local testing without root**, run the container as yourself instead. The
files stay owned by you and nothing needs `sudo`:

```bash
--user "$(id -u):$(id -g)"
```

Both are shown below. The second is what the examples here were verified with.

## 3. Pin the image by digest

Pull first if not already present, then capture the resolved digest (RepoDigests
is empty if the image has not been pulled):

```bash
docker pull ghcr.io/mechubsec/rustunifimcp:0.4.0
image=$(docker inspect ghcr.io/mechubsec/rustunifimcp:0.4.0 \
    --format '{{index .RepoDigests 0}}')
```

Record the digest value wherever the deployment is tracked — it identifies the
exact bytes.

**Verify the signature and provenance before running it.** Every image pushed
by the `Release image` workflow is signed keylessly with
[cosign](https://github.com/sigstore/cosign) via GitHub Actions OIDC — no key
pair exists anywhere. Verification pins the signing identity to that exact
workflow, so a signature from anywhere else (a fork, a different repo, a local
build) fails:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/mechubsec/rustunifimcp/\.github/workflows/release-image\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$image"
```

The same workflow also attaches a
[SLSA build provenance attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds),
checkable with the GitHub CLI instead of cosign:

```bash
gh attestation verify "oci://$image" --repo mechubsec/rustunifimcp
```

The workflow also attaches a signed CycloneDX SBOM to the same digest,
checkable the same way:

```bash
gh attestation verify "oci://$image" --repo mechubsec/rustunifimcp \
  --predicate-type https://cyclonedx.org/bom
```

A failure in any of these checks means do not run it, not "probably fine."

**Multi-arch:** the published manifest covers both `linux/amd64` and
`linux/arm64` — `docker pull`/`docker run` resolve the matching platform
automatically. `cosign verify` and `gh attestation verify` above check the
manifest-list digest once; that one signature and one attestation cover both
platform images underneath it.

## 4. Run it — two-person mode

```bash
docker run -d --name unifi-twoperson \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30035:30033 \
  -v "$PWD/etc/controllers.json:/etc/unifimcp/controllers.json:ro" \
  -v "$PWD/etc/api.key:/etc/unifimcp/api.key:ro" \
  -v "$PWD/state/tokens.json:/var/lib/unifimcp/tokens.json:ro" \
  "$image" \
  --controllers-file /etc/unifimcp/controllers.json \
  --tokens-file /var/lib/unifimcp/tokens.json \
  --transport streamable-http --host 0.0.0.0 --port 30033 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30035 --allowed-host localhost:30035 \
  --allowed-origin http://127.0.0.1:30035 --allowed-origin http://localhost:30035
```

The loopback publish (`-p 127.0.0.1:...`) binds only to localhost. Reaching the
server from another host requires BOTH a non-loopback publish (e.g., `-p 30035:30033`)
AND TLS (with the allow-lists updated to the externally dialled authority), or a
TLS-terminating reverse proxy in front of the loopback endpoint.

**Note:** A browser-based MCP client served from a different port sends its own
origin (e.g., `http://localhost:6274`), not the server's address. Add that
client's origin to `--allowed-origin` if you encounter 403.

Configuration and keys are mounted read-only. UniFi has no candidate
configuration and no server-side staging directory to manage, so only the token
file is writable.

## 5. Run it — lab mode

Identical but for `--lab-mode`, and a different published port so both can run
side by side:

```bash
docker run -d --name unifi-labmode \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30045:30033 \
  -v "$PWD/etc/controllers.json:/etc/unifimcp/controllers.json:ro" \
  -v "$PWD/etc/api.key:/etc/unifimcp/api.key:ro" \
  -v "$PWD/state/tokens.json:/var/lib/unifimcp/tokens.json:ro" \
  "$image" \
  --controllers-file /etc/unifimcp/controllers.json \
  --tokens-file /var/lib/unifimcp/tokens.json \
  --transport streamable-http --host 0.0.0.0 --port 30033 \
  --allow-insecure-bind \
  --allowed-host 127.0.0.1:30045 --allowed-host localhost:30045 \
  --allowed-origin http://127.0.0.1:30045 --allowed-origin http://localhost:30045 \
  --lab-mode
```

**Note the port asymmetry, because it catches people.** The server always
listens on `30033` *inside* the container; `-p 30045:30033` publishes it as
30045 on the host. But `--allowed-host` and `--allowed-origin` are matched
against the `Host` and `Origin` headers the **client** sends, and the client is
talking to 30045. So those flags carry the *published* port, not the internal
one. Get this wrong and the server starts cleanly and then refuses every request
with `421`.

## 6. Verify

```bash
docker ps --filter name=unifi- --format '{{.Names}} {{.Status}}'

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30035/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30045/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
```

**`401` is the success case**: the transport is up and authentication is being
enforced. `000` means nothing is listening — check `docker logs`. A `421` means
the allow-lists do not match the address the client used.

Confirm the mode is what you intended:

```bash
docker logs unifi-labmode 2>&1 | grep -i 'lab mode'
```

## 7. Stop

```bash
docker stop unifi-twoperson unifi-labmode
docker rm unifi-twoperson unifi-labmode
```

`docker stop` sends SIGTERM and waits, which lets the server finish in-flight
work and flush its state. Avoid `docker kill` for anything holding change-set
state: a process killed mid-write leaves an operation non-terminal. This server
persists change-set state, and a SIGSYS that killed it on 2026-09-05 lost an
approval mid-write — exactly the failure this rule is meant to prevent.

## Contrast with the LXC deployment

See [`HOW-TO-SETUP-LXC.md`](HOW-TO-SETUP-LXC.md) for running `rustunifimcp` in a
Proxmox LXC container. The **LXC** unit shipped by `install.sh` is a template
containing `@UNIFIMCP_BIND_HOST@`-style placeholders that the installer
substitutes, and it defaults to **TLS**. The Docker image takes none of that —
you pass plain flags, and the examples above run plain HTTP with
`--allow-insecure-bind`. Do not copy an `ExecStart` line from the LXC drop-in
into a `docker run` command; the shapes are different.

## Troubleshooting

**`Fatal: failed to serve HTTP router`** — the actual cause is usually a missing
`--allowed-origin` on an off-loopback listener (`--host 0.0.0.0` or a LAN
address). Binding anything other than loopback demands an explicit origin
allow-list. The unhelpful error message is a known gap (mechubsec/mecmcp#358).
`--allowed-origin` lists the origins of browser applications that call this
server; clients sending no Origin header (curl, non-browser MCP clients) are
never matched against it. Note that this server validates its inventory before
its arguments, so a config error will mask an argument error.

**Container exits immediately with no log output** — check `docker logs` on the
stopped container: `docker ps -a --filter name=unifi-`. Startup validation
failures print and exit before the transport is up, so the container is gone by
the time you look for it with plain `docker ps`.

**Permission denied reading the inventory or writing state** — the container
process is UID 65532 and does not own your files. Either `chown -R 65532:65532`
them, or run with `--user "$(id -u):$(id -g)"` as shown above.

**`421 Misdirected Request`** — the `Host` header the client sent does not match
any entry in the `--allowed-host` list. Verify that `--allowed-host` carries the
**published** port (the left-hand number in `-p 30045:30033`), not the internal
one.

**`403 Forbidden` with `"Origin '<origin>' is not allowed"`** — the calling
browser page's origin is not in the `--allowed-origin` list. Add the origin of
the browser application making the call. Non-browser clients (curl, CLI) send no
Origin header and are unaffected.
