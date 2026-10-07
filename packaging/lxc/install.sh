#!/bin/sh
# POSIX shell installer for rustunifimcp on Debian 13 LXC.
set -eu

die() {
    printf 'rustunifimcp installer: %s\n' "$*" >&2
    exit 1
}

# Refuse a package whose provenance record is missing or does not describe the
# binary about to be installed. A compile-path record names its toolchain
# (`rustc ...`). A binary this package script did not compile must say
# `unknown (...)` instead of naming a workstation toolchain.
verify_package_provenance() {
    if [ ! -f BUILD-INFO ] || [ ! -s BUILD-INFO ]; then
        die "package payload is missing BUILD-INFO"
    fi
    if [ ! -f rustunifimcp ] || [ ! -s rustunifimcp ] || [ ! -x rustunifimcp ]; then
        die "package binary is missing or not executable"
    fi
    rustc_field=$(sed -n 's/^rustc=//p' BUILD-INFO | head -n 1)
    case "$rustc_field" in
        "rustc "*|"unknown ("*) ;;
        *) die "BUILD-INFO rustc metadata is invalid" ;;
    esac
    recorded_sha=$(sed -n 's/^binary_sha256=//p' BUILD-INFO | head -n 1)
    if ! printf '%s\n' "$recorded_sha" | grep -Eq '^[0-9a-f]{64}$'; then
        die "BUILD-INFO binary_sha256 is invalid"
    fi
    actual_sha=$(sha256sum rustunifimcp | awk 'NR==1 { print $1; exit }')
    if [ "$recorded_sha" != "$actual_sha" ]; then
        die "BUILD-INFO binary_sha256 does not match the shipped binary"
    fi
}

# Test hook. The check still runs; the installer then stops before it mutates
# the host (users, packages, units).
if [ "${UNIFIMCP_INSTALL_CHECK_PROVENANCE_ONLY:-0}" = 1 ]; then
    verify_package_provenance
    printf '%s\n' "provenance ok"
    exit 0
fi

# Prove whether systemd's IPAddress* filters actually attach here, rather than
# assuming the unit's declaration means anything. systemd implements them with
# cgroup eBPF and FAILS OPEN when it cannot load the program -- typical in an
# unprivileged LXC without host delegation -- so the unit can declare a full
# egress policy while enforcing none of it. `systemd-analyze security` reads the
# declaration and cannot tell the difference.
#
# Informational by default: a runtime that withholds BPF is a legitimate
# deployment, and the operator needs to know rather than be blocked. Set
# UNIFIMCP_REQUIRE_EGRESS_FILTER=1 to make a non-enforcing host fatal.
egress_probe_unknown() {
    require=$1
    reason=$2
    printf '%s\n' "egress filter: UNKNOWN ($reason)" >&2
    # Strict mode must not accept what it could not measure. An unmeasurable
    # host is exactly as unguaranteed as a non-enforcing one.
    if [ "$require" = 1 ]; then
        die 'UNIFIMCP_REQUIRE_EGRESS_FILTER=1 and egress enforcement could not be determined'
    fi
    return 0
}

report_egress_enforcement() {
    require=${UNIFIMCP_REQUIRE_EGRESS_FILTER:-0}
    probe_unit="rustunifimcp-egress-probe-$$"
    unit_path="/etc/systemd/system/rustunifimcp.service"

    if ! command -v systemd-run >/dev/null; then
        egress_probe_unknown "$require" 'systemd-run unavailable; cannot probe'
        return $?
    fi

    # Two independent conditions have to hold, and conflating them is how the
    # previous version overstated its result:
    #   1. the host can attach the cgroup BPF program at all, and
    #   2. the *installed* unit actually declares an egress policy.
    # A transient probe only establishes (1). If the installer preserved a
    # customized unit with no IPAddressDeny, (1) alone would still have printed
    # ENFORCED and satisfied the strict flag over a service filtering nothing.
    counters=''
    if systemd-run --quiet --collect --unit="$probe_unit" \
        --property=IPAccounting=yes --property=RemainAfterExit=yes \
        /bin/true >/dev/null 2>&1
    then
        counters=$(systemctl show "$probe_unit.service" -p IPEgressBytes --value 2>/dev/null || printf '')
        systemctl stop "$probe_unit.service" >/dev/null 2>&1 || true
        systemctl reset-failed "$probe_unit.service" >/dev/null 2>&1 || true
    else
        egress_probe_unknown "$require" 'probe unit would not start; run as root to determine'
        return $?
    fi

    if [ -z "$counters" ] || [ "$counters" = '[no data]' ]; then
        printf '%s\n' \
            'egress filter: NOT ENFORCED' \
            '  systemd cannot attach its cgroup BPF program here, so the IPAddressAllow/' \
            '  IPAddressDeny lines in rustunifimcp.service have no effect. This is normal in' \
            '  an unprivileged LXC. The unit still applies every other sandbox directive.' \
            '  Move the control outward to whatever layer sees this workload'"'"'s packets --' \
            '  guest firewall, host nftables, NetworkPolicy, or cloud security group -- and' \
            '  deny 169.254.0.0/16 plus the local subnet except your resolver, allow 443 out.' \
            '  README.md, "Enforcing it where systemd cannot", has the per-runtime' \
            '  mechanism and a verification command.' >&2
        if [ "$require" = 1 ]; then
            die 'UNIFIMCP_REQUIRE_EGRESS_FILTER=1 and systemd IP filtering is not enforced here'
        fi
        return 0
    fi

    # (1) holds. Now (2): does the unit that was actually installed carry a
    # policy for the kernel to enforce?
    if ! grep -Eq '^[[:space:]]*IPAddressDeny[[:space:]]*=[[:space:]]*[^[:space:]]' "$unit_path"; then
        printf '%s\n' \
            'egress filter: NO POLICY' \
            "  This host can enforce systemd IP filtering, but $unit_path declares no" \
            '  IPAddressDeny. A preserved customized unit overrides the packaged policy;' \
            '  re-install or add the directives by hand.' >&2
        if [ "$require" = 1 ]; then
            die 'UNIFIMCP_REQUIRE_EGRESS_FILTER=1 and the installed unit declares no egress policy'
        fi
        return 0
    fi

    printf '%s\n' 'egress filter: ENFORCED'
    return 0
}

# Refuse if not root
if [ "$(id -u)" -ne 0 ]; then
    echo "error: this installer must run as root" >&2
    exit 1
fi

# Refuse if not Debian 13
if [ ! -f /etc/os-release ]; then
    echo "error: /etc/os-release not found; cannot verify OS" >&2
    exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release

if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
    echo "error: this installer requires Debian 13 (detected: ${ID:-unknown} ${VERSION_ID:-unknown})" >&2
    exit 1
fi

# Before apt, users, or unit installation. A package we will not install
# must leave the host alone.
verify_package_provenance

echo "==> Installing rustunifimcp"

# Install runtime dependencies
echo "    Installing runtime dependencies..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates
apt-get clean
rm -rf /var/lib/apt/lists/*

# Create service user and directories via systemd
if [ ! -f packaging/systemd/rustunifimcp.sysusers ]; then
    echo "error: packaging/systemd/rustunifimcp.sysusers not found" >&2
    exit 1
fi
if [ ! -f packaging/systemd/rustunifimcp.tmpfiles ]; then
    echo "error: packaging/systemd/rustunifimcp.tmpfiles not found" >&2
    exit 1
fi

echo "    Creating unifimcp system user..."
systemd-sysusers packaging/systemd/rustunifimcp.sysusers

echo "    Creating directories..."
systemd-tmpfiles --create packaging/systemd/rustunifimcp.tmpfiles

# Install the binary
if [ ! -f rustunifimcp ]; then
    echo "error: rustunifimcp binary not found in current directory" >&2
    exit 1
fi
echo "    Installing binary to /usr/local/bin/rustunifimcp..."
install -m 0755 -o root -g root rustunifimcp /usr/local/bin/rustunifimcp

# /etc/unifimcp already created by tmpfiles

# Install example config files only if absent
if [ ! -f /etc/unifimcp/controllers.json ]; then
    echo "    Installing example controllers.json..."
    if [ -f packaging/examples/controllers.example.json ]; then
        # mecmcp-inventory requires mode 0600 AND ownership by the service user.
        # Mode 0600 owned by root is unreadable by the unifimcp service.
        install -m 0600 -o unifimcp -g unifimcp packaging/examples/controllers.example.json /etc/unifimcp/controllers.json
        echo "    NOTE: The example points at /etc/unifimcp/api.key and cannot be used for a"
        echo "          local smoke test without creating that key file first."
    else
        echo "    warning: packaging/examples/controllers.example.json not found; skipping" >&2
    fi
else
    echo "    /etc/unifimcp/controllers.json exists; not overwriting"
fi

# tokens.json under /var/lib, never /etc — /etc/unifimcp is read-only to the
# service under ProtectSystem=strict. This is the most repeated defect in the
# fleet's backlog (junos#333, sdc#92, mist#42, proxmox#22).
#
# Provision only if absent; install with a fixed owner and mode.
tokens_file=/var/lib/unifimcp/tokens.json
if [ -L "$tokens_file" ] || { [ -e "$tokens_file" ] && [ ! -f "$tokens_file" ]; }; then
    die "$tokens_file is not a regular file; refusing"
fi
if [ ! -e "$tokens_file" ]; then
    tokens_tmp=$(mktemp)
    printf '{"version":1,"tokens":[]}\n' > "$tokens_tmp"
    install -m 0600 -o unifimcp -g unifimcp "$tokens_tmp" "$tokens_file"
    rm -f "$tokens_tmp"
else
    echo "    /var/lib/unifimcp/tokens.json exists; not overwriting"
fi

# Generate the audit HMAC key if it does not exist. Do NOT regenerate on
# upgrade -- a new key breaks verification of every prior record, the same
# reasoning as rust-junosmcp's install.sh. This LXC path previously shipped
# unkeyed audit by default, same as the five container images (mecmcp#376 /
# MEC-978).
#
# Provision only if absent; install with a fixed owner and mode.
audit_key=/var/lib/unifimcp/audit-hmac.key
if [ -L "$audit_key" ] || { [ -e "$audit_key" ] && [ ! -f "$audit_key" ]; }; then
    die "$audit_key is not a regular file; refusing"
fi
if [ ! -e "$audit_key" ]; then
    audit_key_tmp=$(mktemp)
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32 > "$audit_key_tmp"
    elif command -v head >/dev/null 2>&1 && [ -e /dev/urandom ]; then
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$audit_key_tmp"
    else
        echo "    WARNING: cannot generate audit-hmac.key (no openssl or /dev/urandom)" >&2
        echo "    WARNING: the server will generate it on first start" >&2
    fi
    if [ -s "$audit_key_tmp" ]; then
        install -m 0600 -o unifimcp -g unifimcp "$audit_key_tmp" "$audit_key"
    fi
    rm -f "$audit_key_tmp"
fi

# Install systemd unit
if [ -f packaging/systemd/rustunifimcp.service ]; then
    echo "    Installing systemd unit..."

    # Determine hostname and IP for substitution.
    # The service must bind an address clients can reach and allowlist the
    # Host/Origin headers those clients will send. Defaulting --host to 0.0.0.0
    # without an allowed-host check would accept any Host header, which is unsafe.
    unifimcp_hostname="${UNIFIMCP_HOSTNAME:-}"
    if [ -z "$unifimcp_hostname" ]; then
        unifimcp_hostname=$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf '')
    fi
    if [ -z "$unifimcp_hostname" ]; then
        die 'cannot determine hostname; set UNIFIMCP_HOSTNAME or fix hostname -f'
    fi

    # Determine the primary IP address.
    unifimcp_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || printf '')
    if [ -z "$unifimcp_ip" ]; then
        die 'cannot determine IP address; set UNIFIMCP_BIND_HOST manually'
    fi

    # Substitute placeholders in the unit file.
    # Bind to 0.0.0.0 so clients on other hosts can reach the server, and
    # allowlist both the FQDN and IP so clients dialing either are accepted.
    sed -e "s|@UNIFIMCP_BIND_HOST@|0.0.0.0|g" \
        -e "s|@UNIFIMCP_ALLOWED_HOST@|$unifimcp_hostname $unifimcp_ip|g" \
        -e "s|@UNIFIMCP_ALLOWED_ORIGIN@|https://$unifimcp_hostname https://$unifimcp_ip|g" \
        packaging/systemd/rustunifimcp.service > /etc/systemd/system/rustunifimcp.service

    chmod 0644 /etc/systemd/system/rustunifimcp.service
    chown root:root /etc/systemd/system/rustunifimcp.service

    # Verify that no placeholders remain.
    if grep -q '@UNIFIMCP_' /etc/systemd/system/rustunifimcp.service; then
        die 'unit file installation failed: placeholders remain unsubstituted'
    fi

    systemctl daemon-reload
    report_egress_enforcement
else
    echo "    warning: packaging/systemd/rustunifimcp.service not found; skipping unit install" >&2
fi

echo ""
echo "==> Installation complete"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/unifimcp/controllers.json with your UniFi controller details"
echo "  2. Write the API key to /etc/unifimcp/api.key (mode 0600, owned by unifimcp:unifimcp)"
echo "  3. Mint a token, e.g.:"
echo "       rustunifimcp token add --tokens-file /var/lib/unifimcp/tokens.json \\"
echo "           --name readonly --devices '*' --tools '*'"
echo "     A wildcard token grants the read tools only. That is enforced against"
echo "     the server's write-tool registry, not a consequence of there being no"
echo "     write tools -- there are twelve. To grant a write tool, name it."
echo "     For a token that will call unifi_approve_change_set, add --actor-type human;"
echo "     agent and unattributed callers are refused."
echo "  4. (Optional) Configure TLS certificates at /etc/unifimcp/tls/{fullchain,privkey}.pem"
echo "  5. Start the service: systemctl start rustunifimcp"
echo "     The unit runs two-person change control. For a lab deployment where"
echo "     one principal approves their own change sets, add --lab-mode to"
echo "     ExecStart; it records an explicit waiver on every approval."
echo "  6. Enable on boot: systemctl enable rustunifimcp"
echo ""
echo "IMPORTANT: Before upgrading, snapshot this container in Proxmox."
echo "           A failed upgrade can be reverted by rolling back to the snapshot."
echo ""
