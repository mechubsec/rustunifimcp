//! MEC-700: every read-only tool, driven end to end against a mock UniFi
//! controller whose synthetic fixtures carry secret-shaped fields, must never
//! hand one of those secrets to the model.
//!
//! This is deliberately a real round trip rather than a call into
//! `crate::redact` directly: a real TLS listener stands in for the
//! controller, a real `UnifiServer` (the same type `main.rs` builds) answers
//! MCP tool calls over an in-process transport, and the assertion is against
//! the bytes an MCP client would actually receive. That is the only way a
//! tool that bypasses the allowlist projection by fetching data some other
//! way still gets caught here -- asserting on a constructed `Value` would
//! prove the projection function works, not that every tool calls it.
//!
//! The read-only tool list is not hand-maintained: it is
//! `rustunifimcp_core::tools::TOOL_NAMES` minus `WRITE_TOOLS`, the same two
//! registries `tests/write_tool_registry.rs` holds the write side to. A tool
//! added to `TOOL_NAMES` without a matching entry in this file's argument
//! table fails the coverage assertion in `read_only_tool_calls` below.

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Json};
use axum::routing::get;
use rmcp::ServiceExt;
use rmcp::model::CallToolRequestParams;
use rustunifimcp::changeset_state::build_coordinator;
use rustunifimcp::server::UnifiServer;
use rustunifimcp_core::inventory::ControllerRegistry;
use rustunifimcp_core::model::ResourceKind;
use rustunifimcp_core::testing::{DEFAULT_FIXTURE_VERSION, fixture};
use rustunifimcp_core::tools::{TOOL_NAMES, WRITE_TOOLS};
use std::collections::HashSet;
use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

const CONTROLLER: &str = "sweep";
const SITE_UUID: &str = "11111111-2222-3333-4444-555555555555";
const CLIENT_MAC: &str = "02:00:00:02:01:01";

/// Every fake secret this sweep's fixtures carry, across every resource kind
/// the MEC-6 review named: WLAN passphrase and inter-AP roaming key, VPN
/// shared secret, PPPoE password, WireGuard private key, IPsec PSK, RADIUS
/// auth/acct shared secrets, a firewall policy's custom secret field, and an
/// 802.1X client password. `FAKE`/`EXAMPLE`-prefixed, RFC 5737 addressed,
/// `example.net` -- none of it is real device data (see the scrub gate these
/// same fixtures also pass, `tests/fixture_scrub_gate.rs`).
const FIXTURE_SECRETS: &[&str] = &[
    "EXAMPLE-wifi-passphrase-fake1",
    "EXAMPLE-iapp-key-fake1",
    "EXAMPLE-vpn-shared-secret-fake1",
    "EXAMPLE-pppoe-password-fake1",
    "EXAMPLE-wireguard-private-key-fake1",
    "EXAMPLE-ipsec-preshared-key-fake1",
    "EXAMPLE-radius-auth-secret-fake1",
    "EXAMPLE-radius-acct-secret-fake1",
    "EXAMPLE-policy-shared-secret-fake1",
    "EXAMPLE-802-1x-password-fake1",
    "EXAMPLE-event-secret-fake1-AQ==",
    // GHSA-7fmh-fgch-xwqf: `stat/device` keys joined into the health report.
    "EXAMPLE-device-authkey-fake1",
    "EXAMPLE-inform-authkey-fake1",
    "EXAMPLE-syslog-key-fake1",
    "EXAMPLE-guest-token-fake1",
    "EXAMPLE-ssh-hostkey-fake1",
    "EXAMPLE-ssh-session-fake1",
];

fn secure(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Self-signed `localhost` cert/key as PEM: used both as the outbound
/// client's trust anchor (`ca_pem_path`) and the mock controller's own TLS
/// material, so the two always agree.
fn tls_material() -> (String, String) {
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("self-signed cert");
    (cert.pem(), key_pair.serialize_pem())
}

/// One JSON body served verbatim for an exact request path.
struct Route {
    path: String,
    body: serde_json::Value,
}

/// Build the mock controller's routes from the synthetic fixture set -- the
/// same fixtures the crate's unit tests read, now carrying the secrets
/// above. Every path here is a real endpoint this crate's `read.rs` /
/// `workflow.rs` construct; see the comment on each for which tool reaches
/// it.
fn routes() -> Vec<Route> {
    let f = |name: &str| fixture(DEFAULT_FIXTURE_VERSION, name);
    let route = |path: String, body: serde_json::Value| Route { path, body };

    vec![
        // unifi_list_sites, unifi_search (sites leg is `/self`, not this --
        // this is also how `default_site_for(Supported)` resolves the site
        // UUID every Integration API call needs).
        route("/proxy/network/integration/v1/sites".to_owned(), f("sites")),
        route(
            "/proxy/network/integration/v1/info".to_owned(),
            serde_json::json!({"applicationVersion": "9.0.0"}),
        ),
        // unifi_list_resources/get_resource(kind=station), unifi_search
        // (stations leg), workflow joins.
        route(
            format!("/proxy/network/integration/v1/sites/{SITE_UUID}/clients"),
            f("clients"),
        ),
        // unifi_list_resources/get_resource(kind=device), unifi_search
        // (devices leg), site_health_report, topology_report,
        // client_troubleshoot.
        route(
            format!("/proxy/network/integration/v1/sites/{SITE_UUID}/devices"),
            f("devices"),
        ),
        // kind=network; topology_report's networks leg. Carries every WAN /
        // VPN secret this sweep exists to catch.
        route(
            "/proxy/network/api/s/default/rest/networkconf".to_owned(),
            f("networkconf"),
        ),
        // kind=wlan. Carries the WLAN passphrase and iAPP key.
        route(
            "/proxy/network/api/s/default/rest/wlanconf".to_owned(),
            f("wlanconf"),
        ),
        // kind=port_profile.
        route(
            "/proxy/network/api/s/default/rest/portconf".to_owned(),
            f("portconf"),
        ),
        // kind=dhcp_reservation. Carries an 802.1X client password.
        route(
            "/proxy/network/api/s/default/rest/user".to_owned(),
            f("user"),
        ),
        // kind=firewall_group.
        route(
            "/proxy/network/api/s/default/rest/firewallgroup".to_owned(),
            f("firewallgroup"),
        ),
        // kind=radius_profile. Carries the RADIUS auth/acct shared secrets.
        route(
            "/proxy/network/api/s/default/rest/radiusprofile".to_owned(),
            f("radiusprofile"),
        ),
        // kind=firewall_policy; client_troubleshoot. Carries
        // a custom secret-named field on an otherwise-open shape.
        route(
            "/proxy/network/v2/api/site/default/firewall-policies".to_owned(),
            f("policies"),
        ),
        // kind=firewall_zone; client_troubleshoot.
        route(
            "/proxy/network/v2/api/site/default/firewall/zone".to_owned(),
            f("zones"),
        ),
        // kind=traffic_route.
        route(
            "/proxy/network/v2/api/site/default/trafficroutes".to_owned(),
            f("traffic_routes"),
        ),
        // topology_report's edges leg.
        route(
            "/proxy/network/v2/api/site/default/topology".to_owned(),
            f("topology"),
        ),
        // kind=firewall_rule (legacy, non-zone-based ruleset).
        route(
            "/proxy/network/api/s/default/rest/firewallrule".to_owned(),
            f("firewallrule"),
        ),
        // kind=port_forward.
        route(
            "/proxy/network/api/s/default/rest/portforward".to_owned(),
            f("portforward"),
        ),
        // kind=static_route.
        route(
            "/proxy/network/api/s/default/rest/routing".to_owned(),
            f("routing"),
        ),
        // unifi_query_stats(subject=event).
        route(
            "/proxy/network/api/s/default/stat/event".to_owned(),
            f("stat_event"),
        ),
        // unifi_query_stats(subject=device); site_health_report.
        route(
            "/proxy/network/api/s/default/stat/device".to_owned(),
            f("stat_device"),
        ),
        // unifi_query_stats(subject=station); traffic_flow_report,
        // client_troubleshoot.
        route(
            "/proxy/network/api/s/default/stat/sta".to_owned(),
            f("stat_sta"),
        ),
        // unifi_query_stats(subject=site). No dedicated fixture -- `Site`
        // has no typed model (see `read.rs::project_stats`), so this leg is
        // the defensive denylist-and-shape scan, not an allowlist. Reusing
        // `sites` here is enough to prove the endpoint round-trips; the scan
        // itself is proven against a secret-bearing payload by the `wlan`
        // and `flow` legs below.
        route(
            "/proxy/network/api/s/default/stat/sites".to_owned(),
            f("sites"),
        ),
        // unifi_query_stats(subject=wlan). Reuses `wlanconf`'s secret so the
        // *defensive* scan this leg uses (no typed model for `stat/wlan`) is
        // proven against a real secret, not just the allowlist path.
        route(
            "/proxy/network/api/s/default/stat/wlan".to_owned(),
            f("wlanconf"),
        ),
        // unifi_query_stats(subject=flow). Same reasoning, reusing
        // `networkconf`'s secrets.
        route(
            "/proxy/network/api/s/default/stat/flow".to_owned(),
            f("networkconf"),
        ),
        // site_health_report's health leg.
        route(
            "/proxy/network/api/s/default/stat/health".to_owned(),
            f("health"),
        ),
        // unifi_search's sites leg (Private v1 `/self`, distinct from the
        // Integration API `/sites` list above).
        route("/proxy/network/api/s/default/self".to_owned(), f("sites")),
    ]
}

async fn route_handler(
    State(routes): State<Arc<Vec<Route>>>,
    uri: Uri,
) -> axum::response::Response {
    let path = uri.path();
    if let Some(route) = routes.iter().find(|r| r.path == path) {
        return Json(route.body.clone()).into_response();
    }
    // A get_resource(kind, id) call: `<list path>/<id>`. The list route's
    // body is a reasonable stand-in for what a real controller returns for a
    // single lookup here -- `parse_single_resource` tolerates an unreduced
    // array (see `read.rs::get_resource`'s doc comment), and this sweep only
    // needs the secret-bearing fields to be present and then dropped, not a
    // byte-exact single-object response.
    if let Some(route) = routes
        .iter()
        .find(|r| path.starts_with(r.path.as_str()) && path[r.path.len()..].starts_with('/'))
    {
        return Json(route.body.clone()).into_response();
    }
    (StatusCode::NOT_FOUND, "no route").into_response()
}

/// Start the mock controller on an ephemeral loopback TLS port, using
/// `cert_pem`/`key_pem` as its own certificate. Returns the port; the server
/// task runs for the lifetime of the test process (`cargo test` tears down
/// the whole binary, so nothing leaks past the run).
async fn serve_mock_controller(cert_pem: String, key_pem: String, routes: Vec<Route>) -> u16 {
    ensure_crypto_provider();
    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.into_bytes(),
        key_pem.into_bytes(),
    )
    .await
    .expect("tls config");

    let make_service = Router::new()
        .fallback(get(route_handler))
        .with_state(Arc::new(routes))
        .into_make_service();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    listener.set_nonblocking(true).expect("nonblocking");

    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls_config)
            .expect("rustls acceptor")
            .serve(make_service)
            .await;
    });

    port
}

/// Write `contents` to a fresh 0600 temp file and leak the guard so the path
/// outlives the test (`ControllerRegistry::load` and `UnifiClient` both hold
/// only the path, not the guard).
fn write_temp(contents: &[u8]) -> std::path::PathBuf {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(contents).expect("write");
    file.flush().expect("flush");
    secure(file.path());
    file.into_temp_path().keep().expect("persist")
}

fn build_server(endpoint: &str, ca_pem_path: &std::path::Path) -> UnifiServer {
    ensure_crypto_provider();

    let api_key_path = write_temp(b"sweep-test-key\n");

    let controllers_body = serde_json::json!({
        "version": 1,
        "devices": {
            CONTROLLER: {
                "endpoint": endpoint,
                "site": "default",
                "api_key_file": api_key_path,
                "ca_pem_path": ca_pem_path,
                "allow_private_api": true,
            }
        }
    });
    let controllers_path = write_temp(controllers_body.to_string().as_bytes());

    let registry = Arc::new(ControllerRegistry::load(&controllers_path).expect("load inventory"));
    let coordinator =
        build_coordinator(None, Duration::from_secs(300), true, None, None).expect("coordinator");
    UnifiServer::new(
        registry,
        true,
        coordinator,
        None,
        mecmcp_audit::DirectCommitPolicy::new(false),
    )
    .expect("build server")
}

/// The read-only tool surface, computed from the crate's own registries
/// rather than hand-picked, with the minimal valid arguments each needs
/// against the `CONTROLLER`/`default` site this test wires up.
fn read_only_tool_calls() -> Vec<(&'static str, serde_json::Value)> {
    let mut calls: Vec<(&'static str, serde_json::Value)> = vec![
        (
            "unifi_list_resources",
            serde_json::json!({"controller": CONTROLLER, "kind": "network"}),
        ),
        (
            "unifi_get_resource",
            serde_json::json!({
                "controller": CONTROLLER,
                "kind": "wlan",
                "id": "000000000000000000000501"
            }),
        ),
        (
            "unifi_query_stats",
            serde_json::json!({"controller": CONTROLLER, "subject": "wlan"}),
        ),
        (
            "unifi_search",
            serde_json::json!({"controller": CONTROLLER, "query": "test"}),
        ),
        (
            "unifi_list_sites",
            serde_json::json!({"controller": CONTROLLER}),
        ),
        ("unifi_list_controllers", serde_json::json!({})),
        ("unifimcp_status", serde_json::json!({})),
        (
            "unifi_site_health_report",
            serde_json::json!({"controller": CONTROLLER}),
        ),
        (
            "unifi_topology_report",
            serde_json::json!({"controller": CONTROLLER}),
        ),
        (
            "unifi_traffic_flow_report",
            serde_json::json!({"controller": CONTROLLER}),
        ),
        (
            "unifi_client_troubleshoot",
            serde_json::json!({"controller": CONTROLLER, "mac": CLIENT_MAC}),
        ),
    ];

    // Every stats subject and every list_resources kind, in addition to the
    // hand-picked calls above, so a per-kind allowlist gap is at least
    // reachable here even for kinds the table above does not name.
    for subject in ["site", "device", "station", "wlan", "flow", "event"] {
        calls.push((
            "unifi_query_stats",
            serde_json::json!({"controller": CONTROLLER, "subject": subject}),
        ));
    }
    for kind in ResourceKind::ALL {
        let kind_str = serde_json::to_value(kind)
            .expect("kind serializes")
            .as_str()
            .expect("kind is a string")
            .to_owned();
        calls.push((
            "unifi_list_resources",
            serde_json::json!({"controller": CONTROLLER, "kind": kind_str}),
        ));
    }

    let write_tools: HashSet<&str> = WRITE_TOOLS.iter().copied().collect();
    let covered: HashSet<&str> = calls.iter().map(|(name, _)| *name).collect();
    for name in TOOL_NAMES {
        assert!(
            write_tools.contains(name) || covered.contains(name),
            "{name} is neither a registered write tool nor covered by this sweep's argument \
             table -- add it to one"
        );
    }

    calls
}

/// Every fixture secret must be absent from every read-only tool's output,
/// success or error, over one reused MCP session against a controller that
/// actually serves the secret-bearing fixtures.
///
/// Fails loudly (never skips) on a transport error: a prior sibling server's
/// sweep silently skipped most calls on a rate-limit response and counted
/// that as passing. This test never goes through `mecmcp-transport`'s HTTP
/// rate limiter -- the MCP session runs over an in-process duplex, the same
/// transport `tests/writable_fields_gate.rs` uses -- so any `Err` here is a
/// real defect in the sweep or the tool, not a transient condition to
/// tolerate.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_read_only_tool_leaks_a_fixture_secret() {
    let (server_cert_pem, server_key_pem) = tls_material();
    let ca_pem_path = write_temp(server_cert_pem.as_bytes());

    let port = serve_mock_controller(server_cert_pem, server_key_pem, routes()).await;
    let endpoint = format!("https://localhost:{port}");
    let handler = build_server(&endpoint, &ca_pem_path);

    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client init");

    let calls = read_only_tool_calls();
    let mut checked = 0usize;
    for (tool, args) in &calls {
        let result = client
            .call_tool(
                CallToolRequestParams::new((*tool).to_owned())
                    .with_arguments(serde_json::from_value(args.clone()).expect("args")),
            )
            .await
            .unwrap_or_else(|error| {
                panic!("{tool}({args}) transport/protocol error, not tolerated: {error}")
            });

        // An error result carries no resource data, so it would "pass" the
        // leak check without proving anything (MEC-737 F3).
        assert!(
            !result.is_error.unwrap_or(false),
            "{tool}({args}) returned a tool error, so its output was never checked for leaks"
        );
        let mut rendered = String::new();
        for content in &result.content {
            if let Some(text) = content.as_text() {
                rendered.push_str(&text.text);
            }
        }

        for secret in FIXTURE_SECRETS {
            // Message intentionally omits `secret` and `rendered`: both can
            // hold the fixture's fake credential, and CodeQL's
            // rust/cleartext-logging query flags any format argument shaped
            // like a secret landing in a panic message (which the test
            // harness writes to its output log on failure).
            assert!(
                !rendered.contains(secret),
                "{tool}({args}) leaked a fixture secret"
            );
        }
        checked += 1;
    }

    client.cancel().await.expect("client shutdown");
    server_task.abort();

    assert_eq!(checked, calls.len());
    assert!(
        checked >= TOOL_NAMES.len() - WRITE_TOOLS.len(),
        "swept fewer tools than the read-only registry holds"
    );
}

/// MEC-737 F1: the pre-image must stay raw internally -- drift detection
/// compares it with the live object -- while every copy that reaches the model
/// (the diff's `before`) is projected. Drives the real `UnifiClient` against
/// the sweep's mock controller, whose WLAN carries fixture `x_*` secrets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preimage_is_raw_for_drift_but_diff_output_is_projected() {
    use rustunifimcp_core::changeset::apply::ControllerOps as _;
    use rustunifimcp_core::changeset::{Preimage, StagedMutation, diff_against_preimage};
    use rustunifimcp_core::client::UnifiClient;

    let (server_cert_pem, server_key_pem) = tls_material();
    let ca_pem_path = write_temp(server_cert_pem.as_bytes());
    let port = serve_mock_controller(server_cert_pem, server_key_pem, routes()).await;
    ensure_crypto_provider();
    let api_key_path = write_temp(b"sweep-test-key\n");
    let controllers_body = serde_json::json!({
        "version": 1,
        "devices": {
            CONTROLLER: {
                "endpoint": format!("https://localhost:{port}"),
                "site": "default",
                "api_key_file": api_key_path,
                "ca_pem_path": ca_pem_path,
                "allow_private_api": true,
            }
        }
    });
    let controllers_path = write_temp(controllers_body.to_string().as_bytes());
    let registry = ControllerRegistry::load(&controllers_path).expect("load inventory");
    let client = UnifiClient::new(registry.get(CONTROLLER).expect("controller")).expect("client");

    let wlan = "000000000000000000000501";
    for mutation in [
        StagedMutation::Update {
            kind: "wlan".to_owned(),
            id: wlan.to_owned(),
            body: serde_json::json!({"name": "renamed"}),
        },
        StagedMutation::Delete {
            kind: "wlan".to_owned(),
            id: wlan.to_owned(),
        },
    ] {
        let mutations = vec![mutation];
        let preimage = Preimage::capture_preimage(&client, &mutations)
            .await
            .expect("capture pre-image");
        assert!(
            client
                .preimage_matches(&preimage, &mutations)
                .await
                .expect("drift check"),
            "an unchanged resource with x_* fields must not read as stale"
        );
        let diff = diff_against_preimage(&preimage, &mutations).expect("diff");
        let rendered = serde_json::to_string(&diff.changes).expect("render diff");
        assert!(
            rendered.contains(wlan),
            "the diff must still describe the resource"
        );
        for secret in FIXTURE_SECRETS {
            assert!(
                !rendered.contains(secret),
                "the diff leaked a fixture secret"
            );
        }
    }
}
