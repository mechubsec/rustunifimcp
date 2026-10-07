//! Administration tools — inventory listing, server status, and add-controller.

use crate::client::UnifiClient;
use crate::error::UnifiError;
use crate::inventory::{Controller, ControllerRegistry};
use crate::tools::{TOOL_NAMES, WRITE_TOOLS};
use serde_json::{Value, json};

/// The pinned mecmcp version this binary was built against.
///
/// Reported by `unifimcp_status`. Must track the `tag = "vX.Y.Z"` on every
/// `mecmcp-*` dependency in the workspace `Cargo.toml` — the regression test
/// `mecmcp_version_tracks_the_workspace_pin` enforces this.
const MECMCP_VERSION: &str = "0.27.0";

/// Build a redacted view of one controller for list_controllers.
///
/// The view names the endpoint, site, and surface posture, but never discloses
/// where the credential lives. Naming `api_key_file`'s path tells a caller
/// exactly which file to attack.
fn redacted_controller_view(name: &str, controller: &Controller) -> Value {
    json!({
        "name": name,
        "endpoint": controller.endpoint,
        "site": controller.site,
        "allow_private_api": controller.allow_private_api,
        "allow_cloud": controller.allow_cloud,
        "reachable": "unknown"
    })
}

/// List all controllers without disclosing credential locations.
///
/// Returns name, endpoint, site, and surface posture for each controller.
/// Deliberately excludes `api_key_file` and `api_key_env` to avoid telling a
/// caller where to look for credentials.
///
/// # Errors
///
/// Returns [`UnifiError::Inventory`] if the registry cannot be accessed.
pub async fn unifi_list_controllers(registry: &ControllerRegistry) -> Result<Value, UnifiError> {
    let names = registry.names();
    let mut controllers = Vec::new();

    for name in &names {
        let controller = registry.get(name)?;
        controllers.push(redacted_controller_view(name, &controller));
    }

    Ok(json!({
        "controllers": controllers,
        "count": controllers.len()
    }))
}

/// Report server status and per-controller reachability.
///
/// This is the tool an operator calls first, so it answers "is this working and
/// what is it talking to" in one response: server version, the pinned `mecmcp`
/// version, transport, whether lab mode is on, tool count, and per-controller
/// reachability with the controller version each reports.
///
/// A controller that is unreachable shows as unreachable with the reason, not
/// silently omitted.
///
/// Takes the server's own client map rather than building one per controller.
/// `UnifiClient::new` reads the credential from disk and stands up a whole
/// connection pool, so status -- the tool an operator polls most often --
/// was paying that cost, for every controller, on every call, instead of
/// reusing the pool the server already holds.
///
/// # Errors
///
/// Never returns an error: an individual controller's failure is reported as
/// `reachable: false`, not propagated.
pub async fn unifimcp_status(
    clients: &std::collections::BTreeMap<String, UnifiClient>,
    lab_mode: bool,
) -> Result<Value, UnifiError> {
    let mut controller_status = Vec::new();

    for (name, client) in clients {
        match client.controller_version().await {
            Ok(version) => {
                controller_status.push(json!({
                    "name": name,
                    "reachable": true,
                    "controller_version": version
                }));
            }
            Err(e) => {
                controller_status.push(json!({
                    "name": name,
                    "reachable": false,
                    "error": e.to_string()
                }));
            }
        }
    }

    Ok(json!({
        "server_version": env!("CARGO_PKG_VERSION"),
        "mecmcp_version": MECMCP_VERSION,
        "lab_mode": lab_mode,
        "tool_count": TOOL_NAMES.len(),
        "write_tool_count": WRITE_TOOLS.len(),
        "controllers": controller_status,
        "controller_count": clients.len()
    }))
}

/// Attempt to add a controller to the inventory.
///
/// This tool deliberately fails under the production systemd unit, which runs
/// with `ProtectSystem=strict` and `/etc/unifimcp` read-only to the service.
/// The fleet's documented preference is a narrow sandbox over a working
/// `add_*` tool.
///
/// # Errors
///
/// Always returns [`UnifiError::Malformed`] naming the hand-edit path:
/// edit `/etc/unifimcp/controllers.json` as root, then
/// `systemctl kill -s HUP rustunifimcp.service`.
pub async fn unifi_add_controller(
    _name: &str,
    _endpoint: &str,
    _site: &str,
    _api_key_env: Option<&str>,
    _api_key_file: Option<&str>,
) -> Result<Value, UnifiError> {
    Err(UnifiError::Malformed(
        "add_controller is not supported; the service runs with a read-only /etc/unifimcp. \
         Edit /etc/unifimcp/controllers.json as root, then \
         systemctl kill -s HUP rustunifimcp.service"
            .to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::{MECMCP_VERSION, redacted_controller_view};
    use crate::inventory::Controller;
    use serde_json::json;

    /// list_controllers must not disclose credential locations. Naming the file
    /// path tells a caller exactly which file to attack.
    #[test]
    fn the_controller_view_hides_credential_locations() {
        let controller: Controller = serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_file": "/etc/unifimcp/api.key"
            }"#,
        )
        .expect("parses");

        let view = redacted_controller_view("home", &controller);
        let rendered = serde_json::to_string(&view).expect("serializes");

        assert!(!rendered.contains("/etc/unifimcp/api.key"), "{rendered}");
        assert!(!rendered.contains("api_key_file"), "{rendered}");
        assert!(rendered.contains("unifi.example.org"), "{rendered}");
    }

    /// `unifimcp_status` must read whatever client map it is handed rather
    /// than needing a registry to build one -- the whole point of the fix is
    /// that it can no longer construct a client of its own. Taking a
    /// `&ControllerRegistry` here again would fail to compile against the
    /// server's call site, which now builds and holds the map once.
    #[tokio::test]
    async fn unifimcp_status_reports_from_the_map_it_is_given_not_a_registry() {
        let clients = std::collections::BTreeMap::new();
        let status = super::unifimcp_status(&clients, true)
            .await
            .expect("status never errors, even with nothing to report on");

        assert_eq!(status["controller_count"], json!(0));
        assert_eq!(status["controllers"].as_array().expect("array").len(), 0);
        assert_eq!(status["lab_mode"], json!(true));
    }

    /// The view must say whether private surfaces are reachable, because that
    /// is what a caller needs to know before choosing a resource kind.
    #[test]
    fn the_controller_view_states_its_surface_posture() {
        let controller: Controller = serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_env": "K",
                "allow_private_api": true
            }"#,
        )
        .expect("parses");

        let view = redacted_controller_view("home", &controller);
        let rendered = serde_json::to_string(&view).expect("serializes");
        assert!(rendered.contains("allow_private_api"), "{rendered}");
    }

    /// `MECMCP_VERSION` must track the workspace manifest's `mecmcp-*` pins — all of them.
    ///
    /// Checking only the first pin would pass a half-finished re-pin: a bump that moves
    /// `mecmcp-audit` and this const while leaving, say, `mecmcp-http` on the previous tag
    /// builds a binary carrying two mecmcp versions, and `unifimcp_status` would report the
    /// one that happened to be listed first. So every pin is collected and they must agree
    /// with each other as well as with the const.
    ///
    /// When a mecmcp bump lands, this fails until `MECMCP_VERSION` at the top of admin.rs
    /// matches the new `tag = "vX.Y.Z"`.
    #[test]
    fn mecmcp_version_tracks_every_workspace_pin() {
        let manifest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml");
        let manifest_content =
            std::fs::read_to_string(manifest_path).expect("workspace Cargo.toml must be readable");

        let mut pins: Vec<(String, String)> = Vec::new();
        for line in manifest_content.lines() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("mecmcp-") {
                continue;
            }
            let name = trimmed
                .split_whitespace()
                .next()
                .expect("a non-empty line has a first token")
                .to_owned();

            // `mecmcp-redact` has not shipped in a tagged mecmcp release (see the
            // comment above its line in the workspace manifest), so it is pinned by
            // `rev` and carries no `tag = "vX.Y.Z"`. It still declares `version =
            // "X.Y.Z"` alongside the `rev`, which is what is checked against
            // `MECMCP_VERSION` here instead.
            let (needle, needle_len) = if name == "mecmcp-redact" {
                ("version = \"", "version = \"".len())
            } else {
                ("tag = \"v", "tag = \"v".len())
            };

            // A mecmcp dependency without the expected pin marker is the failure this
            // guard exists to catch: the pin comment above these lines says the tag
            // (or, for mecmcp-redact, the version) is what holds the version.
            let marker_start = trimmed.find(needle).unwrap_or_else(|| {
                panic!(
                    "workspace Cargo.toml dependency `{name}` has no {needle}X.Y.Z\"; \
                     every mecmcp-* dependency must be pinned by tag (or, for \
                     mecmcp-redact, by version alongside its rev)"
                )
            });
            let value_start = marker_start + needle_len;
            let value_len = trimmed[value_start..]
                .find('"')
                .expect("pin value must be closed with a quote");
            pins.push((
                name,
                trimmed[value_start..value_start + value_len].to_owned(),
            ));
        }

        assert!(
            !pins.is_empty(),
            "workspace manifest must pin at least one mecmcp-* dependency by tag"
        );

        let mismatched: Vec<&(String, String)> =
            pins.iter().filter(|(_, v)| v != MECMCP_VERSION).collect();
        assert!(
            mismatched.is_empty(),
            "MECMCP_VERSION in rustunifimcp-core/src/tools/admin.rs is \"{MECMCP_VERSION}\", but \
             these workspace Cargo.toml pins disagree: {mismatched:?}. Every mecmcp-* dependency \
             must carry the same tag, and the const must match it — unifimcp_status reports this \
             value, so a stale const tells an operator the wrong mecmcp is running. Update the \
             const and any lagging pin together."
        );
    }
}
