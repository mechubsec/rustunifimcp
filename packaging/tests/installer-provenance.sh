#!/usr/bin/env bash
# The LXC installer must refuse a package whose BUILD-INFO is missing or does
# not describe the binary, and accept a record that does. Uses the installer's
# provenance-only hook so the check runs without root, apt, or Debian 13.
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
install_sh="$repo_root/packaging/lxc/install.sh"

work=""
cleanup() {
    [[ -z "$work" ]] || rm -rf -- "$work"
}
trap cleanup EXIT
work=$(mktemp -d)

write_binary() {
    printf '%s\n' '#!/bin/sh' 'exit 0' > "$1/rustunifimcp"
    chmod 0755 "$1/rustunifimcp"
}

sha_of() {
    sha256sum "$1" | cut -d' ' -f1
}

run_check() {
    (
        cd "$1"
        set +e
        UNIFIMCP_INSTALL_CHECK_PROVENANCE_ONLY=1 sh "$install_sh" >"$2" 2>"$3"
        printf '%s' "$?"
    )
}

# Missing record.
missing="$work/missing"
mkdir -p "$missing"
write_binary "$missing"
status=$(run_check "$missing" "$work/missing.out" "$work/missing.err")
[[ "$status" -ne 0 ]] || {
    printf '%s\n' 'installer accepted a package with no BUILD-INFO' >&2
    exit 1
}
grep -q 'BUILD-INFO' "$work/missing.err" || {
    printf '%s\n' "refusal did not name BUILD-INFO: $(cat "$work/missing.err")" >&2
    exit 1
}

# Hash does not match the binary.
mismatch="$work/mismatch"
mkdir -p "$mismatch"
write_binary "$mismatch"
cat >"$mismatch/BUILD-INFO" <<EOF
version=test
git_commit=000000000000
rustc=unknown (test fixture; binary was not compiled by the packager)
binary_sha256=$(printf '%064d' 0)
EOF
status=$(run_check "$mismatch" "$work/mismatch.out" "$work/mismatch.err")
[[ "$status" -ne 0 ]] || {
    printf '%s\n' 'installer accepted a BUILD-INFO hash that does not match the binary' >&2
    exit 1
}
grep -q 'does not match' "$work/mismatch.err" || {
    printf '%s\n' "hash refusal was not specific: $(cat "$work/mismatch.err")" >&2
    exit 1
}

# Unrecognised rustc field.
bad_rustc="$work/bad-rustc"
mkdir -p "$bad_rustc"
write_binary "$bad_rustc"
cat >"$bad_rustc/BUILD-INFO" <<EOF
version=test
git_commit=000000000000
rustc=workstation
binary_sha256=$(sha_of "$bad_rustc/rustunifimcp")
EOF
status=$(run_check "$bad_rustc" "$work/bad-rustc.out" "$work/bad-rustc.err")
[[ "$status" -ne 0 ]] || {
    printf '%s\n' 'installer accepted a BUILD-INFO rustc field that names neither a toolchain nor unknown' >&2
    exit 1
}
grep -q 'rustc metadata is invalid' "$work/bad-rustc.err" || {
    printf '%s\n' "rustc refusal was not specific: $(cat "$work/bad-rustc.err")" >&2
    exit 1
}

# Honest prebuilt record.
honest="$work/honest"
mkdir -p "$honest"
write_binary "$honest"
cat >"$honest/BUILD-INFO" <<EOF
version=test
git_commit=000000000000
rustc=unknown (test fixture; binary was not compiled by the packager)
binary_sha256=$(sha_of "$honest/rustunifimcp")
EOF
status=$(run_check "$honest" "$work/honest.out" "$work/honest.err")
[[ "$status" -eq 0 ]] || {
    printf '%s\n' "installer rejected an honest BUILD-INFO: $(cat "$work/honest.err")" >&2
    exit 1
}
grep -q 'provenance ok' "$work/honest.out" || {
    printf '%s\n' "honest package did not confirm provenance: $(cat "$work/honest.out")" >&2
    exit 1
}

printf '%s\n' 'installer provenance checks passed'
