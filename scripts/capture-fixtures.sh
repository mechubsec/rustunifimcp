#!/bin/sh
# scripts/capture-fixtures.sh
# Record controller JSON per endpoint into tests/fixtures/<version>/.
#
# Requires UNIFI_API_KEY in the environment and a controller reachable over
# verified TLS -- no -k, because the server it feeds cannot use -k either.
set -eu

: "${UNIFI_API_KEY:?set UNIFI_API_KEY}"
CONTROLLER="${CONTROLLER:-https://unifi.mechub.org}"
SITE="${SITE:-default}"

VERSION=$(curl -sS -H "X-API-KEY: $UNIFI_API_KEY" \
    "$CONTROLLER/proxy/network/integration/v1/info" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["applicationVersion"])')

# The two surface families identify a site DIFFERENTLY, and mixing them up is
# not a visible failure -- it is a 400 that the capture below would otherwise
# record as "endpoint absent", feeding a false absence into the version matrix.
#   Integration API : site UUID   (the name `default` returns 400)
#   Private v1 / v2 : site NAME   (`default`)
SITE_UUID=$(curl -sS -H "X-API-KEY: $UNIFI_API_KEY" \
    "$CONTROLLER/proxy/network/integration/v1/sites" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["id"])')
printf 'site name=%s uuid=%s\n' "$SITE" "$SITE_UUID"

OUT="rustunifimcp-core/tests/fixtures/$VERSION"
mkdir -p "$OUT"
rm -f "$OUT/manifest.txt"
: > "$OUT/manifest.partial"
printf 'capturing controller %s into %s\n' "$VERSION" "$OUT"

# Only a 404 means "this endpoint is not on this controller version". Anything
# else -- 400 from a malformed path, 401 from a bad key, 5xx from a sick
# controller -- is OUR bug, and recording it as absent would put a false row in
# the version matrix. So the status code is inspected rather than just success
# vs failure.
capture() {
    name=$1; path=$2
    code=$(curl -sS -o "$OUT/$name.raw" -w '%{http_code}' \
        -H "X-API-KEY: $UNIFI_API_KEY" "$CONTROLLER$path")
    # Every attempt is listed, so an endpoint that left no file is distinguishable
    # from one this capture never fetched.
    printf '%s %s\n' "$name" "$code" >> "$OUT/manifest.partial"
    case "$code" in
        200)
            python3 -m json.tool < "$OUT/$name.raw" > "$OUT/$name.json"
            rm -f "$OUT/$name.raw"
            printf '  %-22s 200  %s\n' "$name" "$path"
            ;;
        404)
            printf '404\n' > "$OUT/$name.absent"
            rm -f "$OUT/$name.raw" "$OUT/$name.json"
            printf '  %-22s 404  absent on %s\n' "$name" "$VERSION"
            ;;
        *)
            rm -f "$OUT/$name.raw"
            printf '  %-22s %s  *** UNEXPECTED -- not recorded as absent ***\n' "$name" "$code" >&2
            printf '      %s\n' "$path" >&2
            FAILED=1
            ;;
    esac
}
FAILED=0

# Supported surface
capture info               "/proxy/network/integration/v1/info"
capture sites              "/proxy/network/integration/v1/sites"
capture devices            "/proxy/network/integration/v1/sites/$SITE_UUID/devices"
capture clients            "/proxy/network/integration/v1/sites/$SITE_UUID/clients"

# PrivateV1
capture networkconf        "/proxy/network/api/s/$SITE/rest/networkconf"
capture wlanconf           "/proxy/network/api/s/$SITE/rest/wlanconf"
capture portconf           "/proxy/network/api/s/$SITE/rest/portconf"
capture firewallgroup      "/proxy/network/api/s/$SITE/rest/firewallgroup"
capture firewallrule       "/proxy/network/api/s/$SITE/rest/firewallrule"
capture portforward      "/proxy/network/api/s/$SITE/rest/portforward"
capture routing            "/proxy/network/api/s/$SITE/rest/routing"
capture user               "/proxy/network/api/s/$SITE/rest/user"
capture radiusprofile      "/proxy/network/api/s/$SITE/rest/radiusprofile"
capture stat_device        "/proxy/network/api/s/$SITE/stat/device"
capture stat_sta           "/proxy/network/api/s/$SITE/stat/sta"
capture health             "/proxy/network/api/s/$SITE/stat/health"

# PrivateV2 -- the drift-prone surface, and the reason the tags exist
capture zones              "/proxy/network/v2/api/site/$SITE/firewall/zone"
capture policies           "/proxy/network/v2/api/site/$SITE/firewall-policies"
capture traffic_routes     "/proxy/network/v2/api/site/$SITE/trafficroutes"
capture topology           "/proxy/network/v2/api/site/$SITE/topology"

if [ "$FAILED" -ne 0 ]; then
    printf '\nSTOP: at least one endpoint returned an unexpected status. Fix the\n' >&2
    printf 'request before trusting this capture -- an unexplained non-200 is a\n' >&2
    printf 'bug in the path, not evidence the endpoint is gone.\n' >&2
    exit 1
fi

# Published only now: an aborted or failed capture leaves no manifest, so the
# matrix cannot mistake the endpoints it never reached for ones it predates.
mv "$OUT/manifest.partial" "$OUT/manifest.txt"

printf 'done: %s\n' "$OUT"
ls -1 "$OUT"

# Verify captured fixtures contain no sensitive data
printf '\nVerifying fixtures are scrubbed...\n'
"$(dirname "$0")/verify-fixtures-scrubbed.sh" "$OUT"
