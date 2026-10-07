#!/usr/bin/env bash
# Build a release tarball for LXC / Debian deployment.
# Output: dist/rustunifimcp_<version>_<arch>.tar.gz
#
# UNIFIMCP_PACKAGE_SKIP_BUILD=1 packages target/release/rustunifimcp without
# compiling it. That path must not claim a toolchain that did not produce the
# binary: BUILD-INFO then records rustc=unknown (...).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION="${UNIFIMCP_PACKAGE_VERSION:-$(
    sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' Cargo.toml | head -n 1
)}"
if [[ -z "$VERSION" ]]; then
    echo ">> could not read the package version from Cargo.toml" >&2
    exit 1
fi

case "$(uname -m)" in
    x86_64) DEFAULT_ARCH=amd64 ;;
    aarch64) DEFAULT_ARCH=arm64 ;;
    *) DEFAULT_ARCH="$(uname -m)" ;;
esac
ARCH="${UNIFIMCP_PACKAGE_ARCH:-$DEFAULT_ARCH}"
OUTPUT_DIR="${UNIFIMCP_PACKAGE_OUTPUT_DIR:-dist}"

if [[ "${UNIFIMCP_PACKAGE_SKIP_BUILD:-0}" != "1" ]]; then
    echo ">> Building release binary..."
    cargo build --release --locked -p rustunifimcp --bin rustunifimcp
fi

if [[ ! -x target/release/rustunifimcp ]]; then
    echo ">> Missing executable target/release/rustunifimcp" >&2
    exit 1
fi

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

PKG="rustunifimcp_${VERSION}_${ARCH}"
PKGROOT="$STAGING/$PKG"

mkdir -p \
    "$PKGROOT/packaging/systemd" \
    "$PKGROOT/packaging/examples" \
    "$PKGROOT/packaging/lxc"

install -m 0755 target/release/rustunifimcp "$PKGROOT/rustunifimcp"
install -m 0644 packaging/systemd/rustunifimcp.service "$PKGROOT/packaging/systemd/rustunifimcp.service"
install -m 0644 packaging/systemd/rustunifimcp.sysusers "$PKGROOT/packaging/systemd/rustunifimcp.sysusers"
install -m 0644 packaging/systemd/rustunifimcp.tmpfiles "$PKGROOT/packaging/systemd/rustunifimcp.tmpfiles"
install -m 0644 packaging/examples/controllers.example.json "$PKGROOT/packaging/examples/controllers.example.json"
install -m 0755 packaging/lxc/install.sh "$PKGROOT/packaging/lxc/install.sh"

# Provenance for the bytes actually in the archive. Skip-build must not name a
# local rustc that did not compile the binary (mecmcp packaging R3).
binary_sha256=$(sha256sum "$PKGROOT/rustunifimcp" | cut -d' ' -f1)
git_commit=$(git rev-parse HEAD)
if [[ "${UNIFIMCP_PACKAGE_SKIP_BUILD:-0}" == "1" ]]; then
    rustc_metadata="unknown (binary supplied prebuilt via UNIFIMCP_PACKAGE_SKIP_BUILD; not compiled by this script)"
else
    rustc_metadata=$(rustc -vV | tr '\n' ' ' | sed 's/[[:space:]]*$//')
fi
cat >"$PKGROOT/BUILD-INFO" <<EOF
version=$VERSION
git_commit=$git_commit
rustc=$rustc_metadata
binary_sha256=$binary_sha256
EOF

mkdir -p "$OUTPUT_DIR"
DIST_DIR="$(cd "$OUTPUT_DIR" && pwd)"
TARBALL="$DIST_DIR/$PKG.tar.gz"

tar -czf "$TARBALL" -C "$STAGING" "$PKG"
( cd "$DIST_DIR" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256" )

echo ">> Wrote $TARBALL"
echo ">> Wrote $TARBALL.sha256"
