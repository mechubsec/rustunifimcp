//! Operational actions.
//!
//! These are commands, not configuration, so they do not go through change
//! control. Each is individually scoped and audited, and all three are in
//! [`crate::tools::WRITE_TOOLS`] -- a wildcard token reaches none of them.
//!
//! `device_action`'s `restart`, `adopt`, `upgrade`, and `port_action`, and
//! `client_action`'s `block`, `unblock`, and `reconnect` mutate a device or
//! client in a single model call, with no independent second-principal
//! review -- there is no change set to route an immediate command like
//! "restart this device" through. The dispatch layer
//! (`server::UnifiServer::gate_direct_commit`) refuses those specific actions
//! unless the server was started with `--allow-direct-commit`, and audits the
//! outcome either way via `mecmcp_audit::AuditScope`. `locate` is exempt: it
//! is self-reverting and carries no lasting effect.
//!
//! Only actions that do real work are advertised. `client_action`'s
//! `authorize` and `limit_bandwidth`, `backup_action`'s `download` and
//! `validate`, and the speed test are deliberately absent (MEC-505): they
//! were reachable through `tools/list` but only ever returned an error, and
//! the controller returns `{"meta":{"rc":"ok"}}` for commands that do not
//! exist (it validates the device or client, not the command), so a guessed
//! spelling would look like success. See `docs/PARITY-AUDIT.md` for what
//! would need to be confirmed before any of them could come back.
//!
//! `adopt`, `upgrade`, and `port_action` additionally confirm live controller
//! state for the target device -- via the private `stat/device` surface --
//! before dispatching a command, rather than trusting a caller-supplied MAC
//! blind: `adopt` refuses a device the controller does not report as pending
//! (`state != 2`) or whose reported `model` (and, if given, `serial`) does not
//! match the caller-supplied `expected_model`/`expected_serial`; `upgrade`
//! refuses a device that is not adopted, is not marked upgradable, is already
//! at the requested firmware version, or whose controller-queued
//! `upgrade_to_firmware` does not match the requested `firmware_version` (so
//! the call never installs a build the caller did not name); and
//! `port_action` refuses a device that is not adopted or whose `port_table`
//! does not report the requested `port_index` as PoE-capable. This is on top
//! of, not instead of, the direct-commit gate.
//!
//! `unifi_backup_action` deliberately does not carry `restore`. Restoring a
//! controller backup overwrites the entire configuration, which is a larger
//! blast radius than any change set this server will ever carry, so it is a
//! change-set operation instead. See `tools::changeset`.

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, de};

/// Explanation for why `restore` is not an operational backup action.
///
/// This text appears both in the tool description and in the runtime error when
/// a caller attempts `action: "restore"`, so it cannot drift.
pub const RESTORE_NOT_OPERATIONAL: &str = "\
`restore` is not an operational action. Restoring a controller backup overwrites \
the entire configuration, so it is governed by the change-set lifecycle: \
`unifi_create_change_set` -> `unifi_stage_change` -> `unifi_approve_change_set` -> \
`unifi_apply_change_set`. Valid actions here are: trigger, list.";

/// What to do to an adopted device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeviceAction {
    /// Reboot the device.
    Restart,
    /// Flash the locate LED. This is self-reverting — the LED will turn off
    /// automatically after a short time.
    Locate,
    /// Adopt a pending device into the site.
    Adopt,
    /// Start a firmware upgrade.
    Upgrade,
    /// Power-cycle PoE on a single switch port; requires `port_index`.
    ///
    /// This is the one port action with a verified command spelling
    /// (`power-cycle`). Enabling or disabling a port is a device
    /// configuration change (it edits the port's `port_overrides` entry, not
    /// an ephemeral command), so — like `unifi_backup_action`'s `restore` —
    /// it belongs to the change-set lifecycle, not here, and is not wired by
    /// this action.
    PortAction,
}

impl DeviceAction {
    /// Whether this action mutates a device in one call with no independent
    /// change-set approval, and so must pass
    /// `server::UnifiServer::gate_direct_commit` before it runs.
    ///
    /// `#[non_exhaustive]` only stops other crates from matching
    /// exhaustively; it has no effect inside this crate, so this match has no
    /// wildcard arm. Adding a variant is a compile error here until this
    /// function says explicitly whether it is gated -- the server's dispatch
    /// match relies on that, rather than defaulting a new, unreviewed
    /// variant to ungated.
    #[must_use]
    pub fn requires_direct_commit(self) -> bool {
        match self {
            Self::Restart | Self::Adopt | Self::Upgrade | Self::PortAction => true,
            // Self-reverting: the LED turns off on its own, so it carries no
            // lasting effect worth gating.
            Self::Locate => false,
        }
    }
}

/// Arguments to `unifi_device_action`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceActionArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Device MAC address.
    pub device: String,
    /// What to do.
    pub action: DeviceAction,
    /// Which port, for `port_action`.
    #[serde(default)]
    pub port_index: Option<u16>,
    /// Target firmware version, required for `upgrade`.
    ///
    /// Naming the version the caller expects to land on -- rather than
    /// letting `upgrade` mean "whatever the controller currently has queued"
    /// -- is what [`device_action`] checks against the device's live
    /// `stat/device` state before dispatching, so a stale or mistaken
    /// upgrade call is refused instead of silently upgrading to the wrong
    /// build.
    #[serde(default)]
    pub firmware_version: Option<String>,
    /// Model the caller expects the pending device to report, required for
    /// `adopt`.
    ///
    /// A pending device's MAC and model are self-reported in its inform to
    /// the controller, so `adopt_command` checking `stat/device` alone is
    /// not an identity check -- any host that can reach the inform endpoint
    /// can present as a pending device. Naming the expected model here, for a
    /// human to have confirmed out of band, is what [`device_action`] checks
    /// the live `stat/device` entry against before adopting.
    #[serde(default)]
    pub expected_model: Option<String>,
    /// Serial the caller expects the pending device to report, checked
    /// against `stat/device` in addition to `expected_model` when given.
    ///
    /// Optional because not every deployment tracks serials ahead of
    /// adoption, but strictly stronger than `expected_model` alone when
    /// available: two pending devices of the same model would otherwise both
    /// satisfy the model check.
    #[serde(default)]
    pub expected_serial: Option<String>,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Characters permitted in a caller-supplied site identifier.
///
/// UniFi site ids are opaque slugs (`default`, or a short generated id) with
/// no meaningful characters outside this set. `device_action` and
/// `client_action` build their request path with this value, so this check
/// is a second, independent layer of defence in front of
/// `mecmcp_openapi::expand_path`'s traversal check at the HTTP layer: a
/// caller cannot steer either request onto a different path or site even if
/// a future refactor ever drops the `expand_path` routing.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `site` is `Some` and
/// contains anything other than ASCII alphanumerics, `-`, or `_`, or is
/// empty or longer than 64 bytes.
fn validate_site(site: &Option<String>) -> Result<(), crate::error::UnifiError> {
    if let Some(site) = site {
        let is_valid = !site.is_empty()
            && site.len() <= 64
            && site
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !is_valid {
            return Err(crate::error::UnifiError::Malformed(format!(
                "site {site:?} is not a valid site identifier"
            )));
        }
    }
    Ok(())
}

/// Whether `mac` is a well-formed IEEE 802 MAC address: six colon-separated
/// hex octets.
///
/// `device_action` and `client_action` interpolate this value directly into
/// the `cmd/devmgr` and `cmd/stamgr` request bodies, and the controller does
/// not itself validate the `mac` field -- a malformed value reaches the
/// device management API unrejected. This is the only check standing between
/// a garbage or malicious caller-supplied string and the wire.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `mac` is not six
/// colon-separated two-digit hex octets.
fn validate_mac(mac: &str) -> Result<(), crate::error::UnifiError> {
    let octets: Vec<&str> = mac.split(':').collect();
    let is_valid = octets.len() == 6
        && octets
            .iter()
            .all(|octet| octet.len() == 2 && octet.bytes().all(|b| b.is_ascii_hexdigit()));
    if is_valid {
        Ok(())
    } else {
        Err(crate::error::UnifiError::Malformed(format!(
            "{mac:?} is not a valid MAC address (expected six colon-separated hex octets, e.g. aa:bb:cc:dd:ee:ff)"
        )))
    }
}

/// Characters permitted in a caller-supplied firmware version string.
///
/// UniFi firmware versions are dotted numeric strings, occasionally with a
/// build suffix (e.g. `7.1.66.15380`, `6.6.65.15303`). `device_action`
/// compares this value against the device's live `stat/device` state and
/// interpolates it into audit records, so it is closed to the same
/// conservative set `validate_mac` uses rather than accepting arbitrary text.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `version` is empty,
/// longer than 64 bytes, or contains anything other than ASCII
/// alphanumerics, `.`, `-`, or `_`.
fn validate_firmware_version(version: &str) -> Result<(), crate::error::UnifiError> {
    let is_valid = !version.is_empty()
        && version.len() <= 64
        && version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if is_valid {
        Ok(())
    } else {
        Err(crate::error::UnifiError::Malformed(format!(
            "{version:?} is not a valid firmware version (expected dotted alphanumerics, e.g. 7.1.66.15380)"
        )))
    }
}

/// Characters permitted in a caller-supplied device identity token
/// (`expected_model`, `expected_serial`).
///
/// UniFi model names and serials are short alphanumeric tokens, occasionally
/// with a `-` (e.g. `U6-LR`, `USW-24-PoE`). `adopt_command` compares these
/// values against the device's live `stat/device` state, so this is closed to
/// the same conservative set `validate_firmware_version` uses.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `value` is empty,
/// longer than 64 bytes, or contains anything other than ASCII
/// alphanumerics, `.`, `-`, or `_`.
fn validate_identity_token(label: &str, value: &str) -> Result<(), crate::error::UnifiError> {
    let is_valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if is_valid {
        Ok(())
    } else {
        Err(crate::error::UnifiError::Malformed(format!(
            "{label} {value:?} is not valid (expected alphanumerics, '.', '-', or '_', max 64 \
             bytes)"
        )))
    }
}

impl DeviceActionArgs {
    /// Check the cross-field invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::UnifiError::Malformed`] if `port_action` was
    /// requested without a `port_index`, if `upgrade` was requested without a
    /// well-formed `firmware_version`, if `adopt` was requested without a
    /// well-formed `expected_model` (or an ill-formed `expected_serial`), if
    /// `site` is not a valid site identifier, or if `device` is not a valid
    /// MAC address.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        validate_site(&self.site)?;
        validate_mac(&self.device)?;
        if self.action == DeviceAction::PortAction && self.port_index.is_none() {
            return Err(crate::error::UnifiError::Malformed(
                "action `port_action` requires `port_index`".to_owned(),
            ));
        }
        if self.action == DeviceAction::Upgrade {
            match &self.firmware_version {
                Some(version) => validate_firmware_version(version)?,
                None => {
                    return Err(crate::error::UnifiError::Malformed(
                        "action `upgrade` requires `firmware_version`, naming the version the \
                         caller expects to land on, so a blind upgrade cannot proceed"
                            .to_owned(),
                    ));
                }
            }
        }
        if self.action == DeviceAction::Adopt {
            match &self.expected_model {
                Some(model) => validate_identity_token("expected_model", model)?,
                None => {
                    return Err(crate::error::UnifiError::Malformed(
                        "action `adopt` requires `expected_model`, naming the model a human has \
                         confirmed the pending device should report, so adoption cannot proceed \
                         against an unexpected device"
                            .to_owned(),
                    ));
                }
            }
            if let Some(serial) = &self.expected_serial {
                validate_identity_token("expected_serial", serial)?;
            }
        }
        Ok(())
    }
}

/// What to do to a connected client/station.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ClientAction {
    /// Block the client from the network.
    Block,
    /// Unblock a previously blocked client.
    Unblock,
    /// Disconnect and force the client to reconnect.
    Reconnect,
}

impl ClientAction {
    /// Whether this action mutates a client in one call with no independent
    /// change-set approval, and so must pass
    /// `server::UnifiServer::gate_direct_commit` before it runs.
    ///
    /// See [`DeviceAction::requires_direct_commit`] for why this match has no
    /// wildcard arm.
    #[must_use]
    pub fn requires_direct_commit(self) -> bool {
        match self {
            Self::Block | Self::Unblock | Self::Reconnect => true,
        }
    }
}

/// Arguments to `unifi_client_action`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientActionArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Client MAC address.
    pub client: String,
    /// What to do.
    pub action: ClientAction,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

impl ClientActionArgs {
    /// Check the cross-field invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::UnifiError::Malformed`] if `site` is not a
    /// valid site identifier, or if `client` is not a valid MAC address.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        validate_site(&self.site)?;
        validate_mac(&self.client)
    }
}

/// What to do with controller backups.
///
/// `restore` is not available here. Restoring a controller backup overwrites
/// the entire configuration, which is a larger blast radius than any change set
/// this server will ever carry, so it goes through the change-set lifecycle:
/// `unifi_create_change_set` -> `unifi_stage_change` -> `unifi_approve_change_set`
/// -> `unifi_apply_change_set`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackupAction {
    /// Trigger a new backup.
    Trigger,
    /// List available backups.
    List,
}

impl<'de> Deserialize<'de> for BackupAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "restore" => Err(de::Error::custom(RESTORE_NOT_OPERATIONAL)),
            "trigger" => Ok(Self::Trigger),
            "list" => Ok(Self::List),
            other => Err(de::Error::unknown_variant(other, &["trigger", "list"])),
        }
    }
}

impl JsonSchema for BackupAction {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "BackupAction".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // Build the schema as JSON and convert to Schema via serde.
        // This ensures the enum values match what the custom deserializer accepts.
        let schema_json = serde_json::json!({
            "type": "string",
            "enum": ["trigger", "list"]
        });

        serde_json::from_value(schema_json).expect("static schema JSON must deserialize to Schema")
    }
}

/// Arguments to `unifi_backup_action`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupActionArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// What to do.
    pub action: BackupAction,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

impl BackupActionArgs {
    /// Check the cross-field invariants `serde` cannot express.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::UnifiError::Malformed`] if `site` is not a
    /// valid site identifier.
    pub fn validate(&self) -> Result<(), crate::error::UnifiError> {
        validate_site(&self.site)
    }
}

/// Largest number of backup entries returned by `unifi_backup_action
/// action=list` before truncation.
///
/// A real controller's retained backup count is small (typically a handful,
/// bounded by its own retention setting), so this is generous headroom
/// rather than a tight limit.
const MAX_BACKUP_ITEMS: usize = 100;

/// A capped list, reporting how many were shown of how many there were.
///
/// Local equivalent of `mecmcp_server::truncate_items` (MEC-513, mecmcp#443).
/// `rustunifimcp` does not yet depend on the commit that introduced it:
/// pinning to it would also pull in roughly thirty unrelated upstream
/// commits since the last tagged `mecmcp-server` release (OpenTelemetry
/// audit export, SBOM/cosign release workflows, credential lifetime
/// tracking, changeset file locking, redact denylist changes), which is a
/// larger dependency-surface change than this backups feature should carry.
/// Shaped identically to the upstream type so adopting it later, once it is
/// tagged, is a mechanical swap rather than a rewrite.
struct TruncatedBackups<T> {
    /// At most `MAX_BACKUP_ITEMS` elements, in original order.
    items: Vec<T>,
    /// Whether any elements were omitted.
    truncated: bool,
    /// `items.len()` — how many are in this result.
    shown: usize,
    /// How many elements were in the input before truncation.
    total: usize,
}

impl<T> TruncatedBackups<T> {
    /// A caller-facing marker, e.g. `"truncated: 10 of 42 shown"`.
    fn marker(&self) -> Option<String> {
        self.truncated
            .then(|| format!("truncated: {} of {} shown", self.shown, self.total))
    }
}

/// Cap `items` at [`MAX_BACKUP_ITEMS`] elements.
fn truncate_backups<T>(mut items: Vec<T>) -> TruncatedBackups<T> {
    let total = items.len();
    if total <= MAX_BACKUP_ITEMS {
        return TruncatedBackups {
            items,
            truncated: false,
            shown: total,
            total,
        };
    }
    items.truncate(MAX_BACKUP_ITEMS);
    let shown = items.len();
    TruncatedBackups {
        items,
        truncated: true,
        shown,
        total,
    }
}

/// Fetch the private `stat/device` entry for `mac` on `site`, case-insensitively.
///
/// `stat/device` is the one private surface that reports devices the
/// Integration API omits -- most notably a device awaiting adoption, which
/// never appears in `/integration/v1/sites/{site}/devices` because that
/// collection only lists devices already under management. `adopt`,
/// `upgrade`, and `port_action` call this before dispatching a command so
/// they act on what the controller currently reports, not on a caller's
/// unverified claim about a MAC address.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::ReferenceNotFound`] if no entry in the
/// response matches `mac`, and otherwise whatever [`crate::client::UnifiClient::get`]
/// returns.
async fn find_private_device(
    client: &crate::client::UnifiClient,
    site: &str,
    mac: &str,
) -> Result<serde_json::Value, crate::error::UnifiError> {
    let raw = client
        .get(
            crate::ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/device",
            &[("site", site)],
            &[],
        )
        .await?;

    let data = crate::model::unwrap_enveloped_data(&raw)?;
    data.iter()
        .find(|item| {
            item.get("mac")
                .and_then(|m| m.as_str())
                .is_some_and(|m| m.eq_ignore_ascii_case(mac))
        })
        .cloned()
        .ok_or_else(|| {
            crate::error::UnifiError::ReferenceNotFound(format!(
                "no device with MAC {mac} is known to controller site {site:?}; refusing to \
                 act on a device the controller has not reported"
            ))
        })
}

/// The `stat/device` `state` value UniFi controllers use for a device
/// awaiting adoption.
const DEVICE_STATE_PENDING: i64 = 2;

/// Decide the `adopt` command, or refuse, from a device's live `stat/device` state.
///
/// Kept separate from [`device_action`] so the decision -- as opposed to the
/// network fetch that feeds it -- is unit-testable against a canned device
/// entry, without a live controller.
///
/// A pending device's MAC and model are self-reported in its inform to the
/// controller, so `adopted: false` alone is not an identity check -- any host
/// that can reach the inform endpoint can present as a pending device with
/// any MAC and model. This additionally requires the controller-reported
/// `state` to be the pending-adoption state, and the reported `model` (and,
/// when the caller gave one, `serial`) to match `expected_model` /
/// `expected_serial` -- values a human is expected to have confirmed out of
/// band before calling `adopt`.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::WriteRefused`] if `device` is already
/// adopted, is not reported in the pending-adoption state, or its reported
/// model or serial does not match `expected_model` / `expected_serial`.
/// Returns [`crate::error::UnifiError::Malformed`] if `device` carries no
/// `adopted` or `state` field at all.
fn adopt_command(
    device: &serde_json::Value,
    mac: &str,
    expected_model: &str,
    expected_serial: Option<&str>,
) -> Result<&'static str, crate::error::UnifiError> {
    match device.get("adopted").and_then(serde_json::Value::as_bool) {
        Some(false) => {}
        Some(true) => {
            return Err(crate::error::UnifiError::WriteRefused(format!(
                "device {mac} is already adopted; `adopt` is only valid for a device pending \
                 adoption"
            )));
        }
        None => {
            return Err(crate::error::UnifiError::Malformed(format!(
                "controller did not report an adoption state for device {mac}; refusing to \
                 adopt without confirming it is pending"
            )));
        }
    }

    match device.get("state").and_then(serde_json::Value::as_i64) {
        Some(DEVICE_STATE_PENDING) => {}
        Some(other) => {
            return Err(crate::error::UnifiError::WriteRefused(format!(
                "device {mac} is reported in state {other}, not the pending-adoption state \
                 ({DEVICE_STATE_PENDING}); refusing to adopt"
            )));
        }
        None => {
            return Err(crate::error::UnifiError::Malformed(format!(
                "controller did not report a state for device {mac}; refusing to adopt without \
                 confirming it is pending"
            )));
        }
    }

    let reported_model = device.get("model").and_then(|v| v.as_str());
    if reported_model != Some(expected_model) {
        return Err(crate::error::UnifiError::WriteRefused(format!(
            "device {mac} reports model {reported_model:?}, not the expected \
             {expected_model:?}; refusing to adopt a device that does not match the caller's \
             expectation"
        )));
    }

    if let Some(expected_serial) = expected_serial {
        let reported_serial = device.get("serial").and_then(|v| v.as_str());
        if reported_serial != Some(expected_serial) {
            return Err(crate::error::UnifiError::WriteRefused(format!(
                "device {mac} reports serial {reported_serial:?}, not the expected \
                 {expected_serial:?}; refusing to adopt a device that does not match the \
                 caller's expectation"
            )));
        }
    }

    Ok("adopt")
}

/// Decide the `upgrade` command, or refuse, from a device's live `stat/device` state.
///
/// Refuses a device that is not adopted, one already at `firmware_version`
/// (a no-op that still carries mutation risk), one the controller does not
/// itself report as upgradable, and -- critically -- one whose
/// controller-queued `upgrade_to_firmware` does not match `firmware_version`.
/// The `cmd/devmgr` `upgrade` command carries no firmware version of its own;
/// it installs whatever the controller currently has queued for the device.
/// Without this last check, a caller naming a version that merely differs
/// from the one currently running would pass every other check while the
/// controller silently installed a different build than the one requested --
/// so an upgrade only ever proceeds when the queued build is the one the
/// caller named, never a caller's unverified claim about what will land.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::WriteRefused`] if `device` is not
/// adopted, already runs `firmware_version`, is not reported upgradable, or
/// the controller's queued `upgrade_to_firmware` does not match
/// `firmware_version`. Returns [`crate::error::UnifiError::Malformed`] if
/// `device` carries no current `version` field or no `upgrade_to_firmware`
/// field.
fn upgrade_command(
    device: &serde_json::Value,
    mac: &str,
    firmware_version: &str,
) -> Result<&'static str, crate::error::UnifiError> {
    match device.get("adopted").and_then(serde_json::Value::as_bool) {
        Some(true) => {}
        Some(false) | None => {
            return Err(crate::error::UnifiError::WriteRefused(format!(
                "device {mac} is not adopted; cannot upgrade firmware on a device not under \
                 management"
            )));
        }
    }
    match device.get("version").and_then(|v| v.as_str()) {
        Some(current) if current == firmware_version => {
            return Err(crate::error::UnifiError::WriteRefused(format!(
                "device {mac} already runs firmware {firmware_version}; refusing a no-op \
                 upgrade"
            )));
        }
        Some(_) => {}
        None => {
            return Err(crate::error::UnifiError::Malformed(format!(
                "controller did not report a current firmware version for device {mac}; \
                 refusing a blind upgrade"
            )));
        }
    }
    match device
        .get("upgradable")
        .and_then(serde_json::Value::as_bool)
    {
        Some(true) => {}
        Some(false) | None => {
            return Err(crate::error::UnifiError::WriteRefused(format!(
                "controller does not report device {mac} as upgradable to a new firmware version"
            )));
        }
    }
    match device.get("upgrade_to_firmware").and_then(|v| v.as_str()) {
        Some(queued) if queued == firmware_version => Ok("upgrade"),
        Some(queued) => Err(crate::error::UnifiError::WriteRefused(format!(
            "controller would install firmware {queued} on device {mac}, not the requested \
             {firmware_version}; the `upgrade` command carries no version of its own and \
             installs whatever the controller has queued, so refusing rather than upgrading to \
             the wrong build"
        ))),
        None => Err(crate::error::UnifiError::Malformed(format!(
            "controller did not report a queued firmware version (upgrade_to_firmware) for \
             device {mac}; refusing a blind upgrade"
        ))),
    }
}

/// Decide the `port_action` command, or refuse, from a device's live `stat/device` state.
///
/// The controller answers `rc: "ok"` to a `power-cycle` naming a port that
/// does not exist or carries no PoE, so this confirms `device`'s reported
/// `port_table` has an entry at `port_index` with `port_poe: true` before
/// dispatching -- otherwise the call would be audited as a success while
/// nothing on the device actually changed.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::WriteRefused`] if `device` is not
/// adopted, or its `port_table` has no PoE-capable entry at `port_index`.
fn port_action_command(
    device: &serde_json::Value,
    mac: &str,
    port_index: u16,
) -> Result<&'static str, crate::error::UnifiError> {
    match device.get("adopted").and_then(serde_json::Value::as_bool) {
        Some(true) => {}
        Some(false) | None => {
            return Err(crate::error::UnifiError::WriteRefused(format!(
                "device {mac} is not adopted; cannot act on a port of a device not under \
                 management"
            )));
        }
    }

    let port = device
        .get("port_table")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .find(|entry| {
            entry
                .get("port_idx")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|idx| idx == u64::from(port_index))
        });
    match port {
        Some(entry) if entry.get("port_poe").and_then(serde_json::Value::as_bool) == Some(true) => {
            Ok("power-cycle")
        }
        Some(_) => Err(crate::error::UnifiError::WriteRefused(format!(
            "device {mac} port {port_index} is not reported as PoE-capable; refusing a \
             power-cycle the controller would silently no-op"
        ))),
        None => Err(crate::error::UnifiError::WriteRefused(format!(
            "device {mac} does not report a port at index {port_index}; refusing a power-cycle \
             the controller would silently no-op"
        ))),
    }
}

/// Execute an operational action on a device.
///
/// Wired actions: `restart`, `locate`, `adopt`, `upgrade`, `port_action`. The
/// controller validates devices but not commands — a misspelled command
/// returns `rc: "ok"`, so command strings are closed and validated here.
///
/// `adopt`, `upgrade`, and `port_action` additionally confirm the device's
/// live `stat/device` state via `find_private_device` before dispatching --
/// see `adopt_command`, `upgrade_command`, and `port_action_command` for
/// what each one checks -- per the module documentation.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `port_action` is
/// requested without a `port_index` or `upgrade` without a `firmware_version`.
/// Returns [`crate::error::UnifiError::ReferenceNotFound`] if the controller
/// does not report a device with the given MAC. Returns
/// [`crate::error::UnifiError::WriteRefused`] if `adopt` targets an
/// already-adopted device, or if `upgrade`/`port_action` target a device that
/// is not adopted, or if `upgrade` targets a device already at the requested
/// firmware version or not marked upgradable.
pub async fn device_action(
    args: DeviceActionArgs,
    client: &crate::client::UnifiClient,
) -> Result<serde_json::Value, crate::error::UnifiError> {
    args.validate()?;

    let site = args
        .site
        .as_deref()
        .unwrap_or_else(|| client.default_site());

    // Map enum to controller command string. Command spellings are closed —
    // the controller returns `rc: "ok"` for garbage commands, so validation
    // happens here.
    let cmd = match args.action {
        DeviceAction::Restart => "restart",
        DeviceAction::Locate => "set-locate",
        DeviceAction::Adopt => {
            // `validate` already refused a missing `expected_model`.
            let expected_model = args
                .expected_model
                .as_deref()
                .expect("adopt requires expected_model, enforced by validate()");
            let device = find_private_device(client, site, &args.device).await?;
            adopt_command(
                &device,
                &args.device,
                expected_model,
                args.expected_serial.as_deref(),
            )?
        }
        DeviceAction::Upgrade => {
            // `validate` already refused a missing `firmware_version`.
            let firmware_version = args
                .firmware_version
                .as_deref()
                .expect("upgrade requires firmware_version, enforced by validate()");
            let device = find_private_device(client, site, &args.device).await?;
            upgrade_command(&device, &args.device, firmware_version)?
        }
        DeviceAction::PortAction => {
            // `validate` already refused a missing `port_index`.
            let port_index = args
                .port_index
                .expect("port_action requires port_index, enforced by validate()");
            let device = find_private_device(client, site, &args.device).await?;
            port_action_command(&device, &args.device, port_index)?
        }
    };

    let mut body = serde_json::json!({
        "cmd": cmd,
        "mac": args.device
    });
    if args.action == DeviceAction::PortAction {
        // `validate` already refused a missing `port_index`.
        let port_index = args
            .port_index
            .expect("port_action requires port_index, enforced by validate()");
        body["port_idx"] = serde_json::json!(port_index);
    }

    client
        .post(
            crate::ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/cmd/devmgr",
            &[("site", site)],
            &[],
            &body,
        )
        .await
}

/// Execute an operational action on a client/station.
///
/// Wired actions: `block`, `unblock`, `reconnect`. The controller validates
/// clients but not commands, so command strings are closed and validated here.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if the arguments fail
/// validation, and otherwise whatever the controller call returns.
pub async fn client_action(
    args: ClientActionArgs,
    client: &crate::client::UnifiClient,
) -> Result<serde_json::Value, crate::error::UnifiError> {
    args.validate()?;

    let site = args
        .site
        .as_deref()
        .unwrap_or_else(|| client.default_site());

    // Map enum to controller command string. Closed: only actions with a
    // confirmed command spelling exist in `ClientAction` at all.
    let cmd = match args.action {
        ClientAction::Block => "block-sta",
        ClientAction::Unblock => "unblock-sta",
        ClientAction::Reconnect => "kick-sta",
    };

    let body = serde_json::json!({
        "cmd": cmd,
        "mac": args.client
    });

    client
        .post(
            crate::ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/cmd/stamgr",
            &[("site", site)],
            &[],
            &body,
        )
        .await
}

/// Execute a backup action on the controller.
///
/// Wired actions: `list` (`cmd/backup` `list-backups`, capped at
/// `MAX_BACKUP_ITEMS` and reporting a truncation marker like every other
/// list-shaped tool) and `trigger` (`cmd/backup` `backup`, requesting `days:
/// 0` so the controller builds a config-only backup rather than the largest,
/// slowest full-history one). `trigger` is not idempotent: it starts an
/// asynchronous job on the controller, and a request that times out on the
/// client side does not mean the job stopped. Retrying after a timeout can
/// leave multiple backup files behind; callers must not retry `trigger`
/// automatically. `download` and `validate` are not offered (MEC-505): both
/// would need to move a raw `.unf` file rather than JSON, which `UnifiClient`
/// does not support today, and there is no independent evidence for a
/// `validate` command on the controller at all. `restore` is not available here —
/// restoring a controller backup overwrites the entire configuration, so it
/// goes through change control in Phase 6.
///
/// # Errors
///
/// Returns [`crate::error::UnifiError::Malformed`] if `site` is not a valid
/// site identifier, and otherwise whatever the controller call returns.
pub async fn backup_action(
    args: BackupActionArgs,
    client: &crate::client::UnifiClient,
) -> Result<serde_json::Value, crate::error::UnifiError> {
    args.validate()?;

    let site = args
        .site
        .as_deref()
        .unwrap_or_else(|| client.default_site());

    match args.action {
        BackupAction::List => {
            let raw = client
                .post(
                    crate::ApiSurface::PrivateV1,
                    "/proxy/network/api/s/{site}/cmd/backup",
                    &[("site", site)],
                    &[],
                    &serde_json::json!({"cmd": "list-backups"}),
                )
                .await?;

            let backups = crate::model::backup::parse_backups(&raw)?;
            let page = truncate_backups(backups);

            Ok(serde_json::json!({
                "backups": page.items,
                "shown": page.shown,
                "total": page.total,
                "truncated": page.truncated,
                "marker": page.marker(),
            }))
        }
        BackupAction::Trigger => {
            client
                .post(
                    crate::ApiSurface::PrivateV1,
                    "/proxy/network/api/s/{site}/cmd/backup",
                    &[("site", site)],
                    &[],
                    &serde_json::json!({"cmd": "backup", "days": 0}),
                )
                .await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientAction, DeviceAction, DeviceActionArgs};

    #[test]
    fn device_actions_parse_from_their_documented_spellings() {
        for (raw, expected) in [
            ("restart", DeviceAction::Restart),
            ("locate", DeviceAction::Locate),
            ("adopt", DeviceAction::Adopt),
            ("upgrade", DeviceAction::Upgrade),
            ("port_action", DeviceAction::PortAction),
        ] {
            let json = format!(r#""{raw}""#);
            let parsed: DeviceAction =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    /// An action the server does not implement must be a parse error, not a
    /// request that reaches the controller as an unrecognised command.
    #[test]
    fn an_unknown_device_action_is_refused() {
        let parsed: Result<DeviceAction, _> = serde_json::from_str(r#""factory_reset""#);
        assert!(parsed.is_err());
    }

    /// Pins which `DeviceAction` variants the direct-commit gate covers, so a
    /// future variant added to the match in [`DeviceAction::requires_direct_commit`]
    /// is a deliberate, reviewed decision rather than a silent default.
    #[test]
    fn device_action_direct_commit_gating_matches_documented_actions() {
        assert!(DeviceAction::Restart.requires_direct_commit());
        assert!(DeviceAction::Adopt.requires_direct_commit());
        assert!(DeviceAction::Upgrade.requires_direct_commit());
        assert!(DeviceAction::PortAction.requires_direct_commit());
        assert!(
            !DeviceAction::Locate.requires_direct_commit(),
            "locate is self-reverting and must stay ungated"
        );
    }

    /// Same pin for `ClientAction`: only the three wired mutating actions are
    /// gated.
    #[test]
    fn client_action_direct_commit_gating_matches_documented_actions() {
        assert!(ClientAction::Block.requires_direct_commit());
        assert!(ClientAction::Unblock.requires_direct_commit());
        assert!(ClientAction::Reconnect.requires_direct_commit());
    }

    #[test]
    fn a_port_action_requires_a_port_index() {
        let raw = r#"{"controller":"home","device":"aa:bb:cc:dd:ee:ff","action":"port_action"}"#;
        let args: DeviceActionArgs = serde_json::from_str(raw).expect("parses");
        assert!(
            args.validate().is_err(),
            "port_action without a port index must be refused before dispatch"
        );
    }

    #[test]
    fn client_actions_parse_from_their_documented_spellings() {
        for raw in ["block", "unblock", "reconnect"] {
            let json = format!(r#""{raw}""#);
            let parsed: Result<ClientAction, _> = serde_json::from_str(&json);
            assert!(parsed.is_ok(), "{raw} must parse");
        }
    }

    /// The removed unwired sub-actions (MEC-505) must not parse at all, so a
    /// caller gets a schema error rather than a silent no-op.
    #[test]
    fn removed_client_and_backup_actions_do_not_parse() {
        use super::BackupAction;
        for raw in ["authorize", "limit_bandwidth"] {
            let json = format!(r#""{raw}""#);
            assert!(
                serde_json::from_str::<ClientAction>(&json).is_err(),
                "{raw} must not parse as a client action"
            );
        }
        for raw in ["download", "validate"] {
            let json = format!(r#""{raw}""#);
            assert!(
                serde_json::from_str::<BackupAction>(&json).is_err(),
                "{raw} must not parse as a backup action"
            );
        }
    }

    #[test]
    fn backup_actions_parse_from_their_documented_spellings() {
        use super::BackupAction;
        for (raw, expected) in [
            ("trigger", BackupAction::Trigger),
            ("list", BackupAction::List),
        ] {
            let json = format!(r#""{raw}""#);
            let parsed: BackupAction =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(parsed, expected);
        }
    }

    /// `restore` must be a parse error with a message naming the change-set path,
    /// not a runtime refusal. Restoring a controller backup overwrites the entire
    /// configuration, so it goes through approval in Phase 6.
    #[test]
    fn backup_restore_is_refused_at_parse_time() {
        use super::BackupAction;
        let parsed: Result<BackupAction, _> = serde_json::from_str(r#""restore""#);
        assert!(
            parsed.is_err(),
            "restore must be a parse error, not a runtime refusal"
        );
    }

    /// The restore refusal error message must explain the reason and name the
    /// change-set path, so it cannot regress to a bare serde message.
    #[test]
    fn backup_restore_error_explains_the_governed_path() {
        use super::BackupAction;
        let parsed: Result<BackupAction, _> = serde_json::from_str(r#""restore""#);
        let err_msg = parsed
            .expect_err("restore must be refused at parse time")
            .to_string();
        assert!(
            err_msg.contains("change-set lifecycle") || err_msg.contains("change_set"),
            "error must explain why restore is refused, got: {err_msg}"
        );
        assert!(
            err_msg.contains("unifi_create_change_set"),
            "error must name at least one change-set tool, got: {err_msg}"
        );
    }

    /// `device_action` and `client_action` used to build their request path
    /// with a raw `format!`, bypassing the traversal check every other
    /// request path gets from `mecmcp_openapi::expand_path` (see
    /// `client.rs`'s `a_traversing_site_id_is_rejected_not_sanitised`). A
    /// `site` such as `../../v2/api/site/default` would have reached the
    /// controller unvalidated, redirecting the call onto a different
    /// site/API path than the one it was authorized against.
    ///
    /// The request path is now built from the same `{site}` template and
    /// `expand_path` as every other request, but that alone is not what this
    /// test proves: calling `expand_path` on a copied template literal, as an
    /// earlier version of this test did, still passes even if `device_action`
    /// or `client_action` reverts to a raw `format!`, because the copy and
    /// the production code can drift apart silently. This test instead
    /// drives the real entry point every caller of these tools goes through
    /// -- `DeviceActionArgs::validate` / `ClientActionArgs::validate`, called
    /// before either function touches the client -- so it fails the moment
    /// that path-rejection is missing, regardless of how the request path
    /// happens to be built downstream.
    #[test]
    fn a_traversing_site_is_rejected_by_device_and_client_action_validation() {
        use super::ClientActionArgs;

        let device_args = DeviceActionArgs {
            controller: "home".to_owned(),
            device: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: DeviceAction::Restart,
            port_index: None,
            firmware_version: None,
            expected_model: None,
            expected_serial: None,
            site: Some("../../v2/api/site/default".to_owned()),
        };
        assert!(
            device_args.validate().is_err(),
            "a traversing site must be rejected by DeviceActionArgs::validate"
        );

        let client_args = ClientActionArgs {
            controller: "home".to_owned(),
            client: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: ClientAction::Block,
            site: Some("../../v2/api/site/default".to_owned()),
        };
        assert!(
            client_args.validate().is_err(),
            "a traversing site must be rejected by ClientActionArgs::validate"
        );
    }

    /// A site with extra path segments -- not a `../` traversal, but still an
    /// attempt to steer the request onto a different path than the template
    /// names -- must be rejected the same way, again through the real
    /// `validate()` entry point (see the comment above).
    #[test]
    fn a_site_with_extra_path_segments_is_rejected_by_device_and_client_action_validation() {
        use super::ClientActionArgs;

        let device_args = DeviceActionArgs {
            controller: "home".to_owned(),
            device: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: DeviceAction::Restart,
            port_index: None,
            firmware_version: None,
            expected_model: None,
            expected_serial: None,
            site: Some("default/extra".to_owned()),
        };
        assert!(
            device_args.validate().is_err(),
            "extra path segments in site must be rejected by DeviceActionArgs::validate"
        );

        let client_args = ClientActionArgs {
            controller: "home".to_owned(),
            client: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: ClientAction::Block,
            site: Some("default/extra".to_owned()),
        };
        assert!(
            client_args.validate().is_err(),
            "extra path segments in site must be rejected by ClientActionArgs::validate"
        );
    }

    /// A well-formed site must still be accepted -- the new validation must
    /// not be so strict that it refuses ordinary UniFi site identifiers.
    #[test]
    fn an_ordinary_site_is_accepted_by_device_and_client_action_validation() {
        use super::ClientActionArgs;

        let device_args = DeviceActionArgs {
            controller: "home".to_owned(),
            device: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: DeviceAction::Restart,
            port_index: None,
            firmware_version: None,
            expected_model: None,
            expected_serial: None,
            site: Some("default".to_owned()),
        };
        assert!(device_args.validate().is_ok());

        let client_args = ClientActionArgs {
            controller: "home".to_owned(),
            client: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: ClientAction::Block,
            site: Some("my-site_01".to_owned()),
        };
        assert!(client_args.validate().is_ok());
    }

    #[test]
    fn an_invalid_mac_is_rejected_by_device_and_client_action_validation() {
        use super::ClientActionArgs;

        for device in [
            "not-a-mac",
            "aa:bb:cc:dd:ee",
            "aa:bb:cc:dd:ee:ff:00",
            "aa:bb:cc:dd:ee:gg",
            "",
            "aabbccddeeff",
        ] {
            let device_args = DeviceActionArgs {
                controller: "home".to_owned(),
                device: device.to_owned(),
                action: DeviceAction::Restart,
                port_index: None,
                firmware_version: None,
                expected_model: None,
                expected_serial: None,
                site: None,
            };
            assert!(
                device_args.validate().is_err(),
                "{device:?} must be rejected as a device MAC"
            );

            let client_args = ClientActionArgs {
                controller: "home".to_owned(),
                client: device.to_owned(),
                action: ClientAction::Block,
                site: None,
            };
            assert!(
                client_args.validate().is_err(),
                "{device:?} must be rejected as a client MAC"
            );
        }
    }

    #[test]
    fn a_well_formed_mac_is_accepted_by_device_and_client_action_validation() {
        use super::ClientActionArgs;

        let device_args = DeviceActionArgs {
            controller: "home".to_owned(),
            device: "aa:bb:cc:dd:ee:ff".to_owned(),
            action: DeviceAction::Restart,
            port_index: None,
            firmware_version: None,
            expected_model: None,
            expected_serial: None,
            site: None,
        };
        assert!(device_args.validate().is_ok());

        let client_args = ClientActionArgs {
            controller: "home".to_owned(),
            client: "AA:BB:CC:DD:EE:FF".to_owned(),
            action: ClientAction::Block,
            site: None,
        };
        assert!(client_args.validate().is_ok());
    }

    /// `backup_action` now dispatches `list`/`trigger` with `args.site` in the
    /// request path, so `BackupActionArgs::validate` needs the same
    /// traversal defence `DeviceActionArgs`/`ClientActionArgs` already carry
    /// (see `a_traversing_site_is_rejected_by_device_and_client_action_validation`
    /// above).
    #[test]
    fn a_traversing_site_is_rejected_by_backup_action_validation() {
        use super::{BackupAction, BackupActionArgs};

        let args = BackupActionArgs {
            controller: "home".to_owned(),
            action: BackupAction::List,
            site: Some("../../v2/api/site/default".to_owned()),
        };
        assert!(
            args.validate().is_err(),
            "a traversing site must be rejected by BackupActionArgs::validate"
        );
    }

    /// A well-formed site must still be accepted for backup actions.
    #[test]
    fn an_ordinary_site_is_accepted_by_backup_action_validation() {
        use super::{BackupAction, BackupActionArgs};

        let args = BackupActionArgs {
            controller: "home".to_owned(),
            action: BackupAction::List,
            site: Some("default".to_owned()),
        };
        assert!(args.validate().is_ok());
    }

    #[test]
    fn truncate_backups_reports_everything_shown_under_the_cap() {
        use super::truncate_backups;

        let page = truncate_backups(vec![1, 2, 3]);
        assert_eq!(page.items, vec![1, 2, 3]);
        assert!(!page.truncated);
        assert_eq!(page.shown, 3);
        assert_eq!(page.total, 3);
        assert_eq!(page.marker(), None);
    }

    #[test]
    fn truncate_backups_caps_and_reports_a_marker_over_the_cap() {
        use super::{MAX_BACKUP_ITEMS, truncate_backups};

        let items: Vec<usize> = (0..MAX_BACKUP_ITEMS + 5).collect();
        let page = truncate_backups(items);
        assert!(page.truncated);
        assert_eq!(page.shown, MAX_BACKUP_ITEMS);
        assert_eq!(page.total, MAX_BACKUP_ITEMS + 5);
        assert_eq!(
            page.marker().as_deref(),
            Some(
                format!(
                    "truncated: {MAX_BACKUP_ITEMS} of {} shown",
                    MAX_BACKUP_ITEMS + 5
                )
                .as_str()
            )
        );
    }

    #[test]
    fn trigger_and_list_pass_validation() {
        use super::{BackupAction, BackupActionArgs};
        for action in [BackupAction::Trigger, BackupAction::List] {
            let args = BackupActionArgs {
                controller: "home".to_owned(),
                action,
                site: None,
            };
            assert!(args.validate().is_ok(), "{:?} must pass validation", action);
        }
    }

    /// The generated JSON schema for BackupAction must match the strings the
    /// custom deserializer accepts. Schema-driven callers break when they
    /// disagree.
    #[test]
    fn backup_action_schema_agrees_with_deserializer() {
        use schemars::JsonSchema;

        let schema = super::BackupAction::json_schema(&mut schemars::SchemaGenerator::default());
        let schema_value = serde_json::to_value(schema).expect("schema must serialize to JSON");

        let enum_values = schema_value
            .get("enum")
            .expect("BackupAction schema must have enum field")
            .as_array()
            .expect("enum must be array");

        let expected: Vec<String> = vec!["trigger".to_owned(), "list".to_owned()];

        let actual: Vec<String> = enum_values
            .iter()
            .map(|v| v.as_str().expect("enum value must be string").to_owned())
            .collect();

        assert_eq!(
            actual, expected,
            "schema enum values must match deserializer accepted spellings"
        );

        // Verify deserializer accepts each schema-advertised value
        for spelling in &expected {
            let json = format!(r#""{spelling}""#);
            let parsed: Result<super::BackupAction, _> = serde_json::from_str(&json);
            assert!(
                parsed.is_ok(),
                "deserializer must accept schema-advertised spelling: {spelling}"
            );
        }
    }

    /// `adopt` and `port_action` need no `firmware_version` and pass
    /// validation without one; `upgrade` is checked separately below because
    /// it has its own required field.
    #[test]
    fn adopt_and_port_action_pass_validation_without_a_firmware_version() {
        use super::{DeviceAction, DeviceActionArgs};

        for (action, port_index, expected_model) in [
            (DeviceAction::Adopt, None, Some("U6-LR".to_owned())),
            (DeviceAction::PortAction, Some(1), None),
        ] {
            let args = DeviceActionArgs {
                controller: "test".to_owned(),
                device: "02:00:00:00:00:01".to_owned(),
                action,
                port_index,
                firmware_version: None,
                expected_model,
                expected_serial: None,
                site: None,
            };
            assert!(args.validate().is_ok(), "{action:?} must pass validation");
        }
    }

    /// `adopt` without `expected_model` must be refused before dispatch --
    /// naming the expected model is what stands between this action and
    /// adopting whatever pending device the controller reports.
    #[test]
    fn adopt_requires_an_expected_model() {
        use super::{DeviceAction, DeviceActionArgs};

        let args = DeviceActionArgs {
            controller: "test".to_owned(),
            device: "02:00:00:00:00:01".to_owned(),
            action: DeviceAction::Adopt,
            port_index: None,
            firmware_version: None,
            expected_model: None,
            expected_serial: None,
            site: None,
        };
        assert!(
            args.validate().is_err(),
            "adopt without expected_model must be refused before dispatch"
        );
    }

    /// A well-formed `expected_model`/`expected_serial` is accepted; a
    /// malformed one is refused before dispatch, the same way a malformed
    /// firmware version is.
    #[test]
    fn adopt_identity_tokens_are_validated() {
        use super::{DeviceAction, DeviceActionArgs};

        for (model, serial, should_pass) in [
            (Some("U6-LR"), None, true),
            (Some("USW-24-PoE"), Some("ABC123"), true),
            (Some(""), None, false),
            (Some("bad; rm -rf /"), None, false),
            (Some("U6-LR"), Some("bad serial"), false),
            (None, None, false),
        ] {
            let args = DeviceActionArgs {
                controller: "test".to_owned(),
                device: "02:00:00:00:00:01".to_owned(),
                action: DeviceAction::Adopt,
                port_index: None,
                firmware_version: None,
                expected_model: model.map(str::to_owned),
                expected_serial: serial.map(str::to_owned),
                site: None,
            };
            assert_eq!(
                args.validate().is_ok(),
                should_pass,
                "model {model:?} / serial {serial:?} validation must be {should_pass}"
            );
        }
    }

    /// `upgrade` without `firmware_version` must be refused before dispatch —
    /// naming *some* target version is what stands between this action and a
    /// blind upgrade to whatever the controller has queued.
    #[test]
    fn upgrade_requires_a_firmware_version() {
        use super::{DeviceAction, DeviceActionArgs};

        let args = DeviceActionArgs {
            controller: "test".to_owned(),
            device: "02:00:00:00:00:01".to_owned(),
            action: DeviceAction::Upgrade,
            port_index: None,
            firmware_version: None,
            expected_model: None,
            expected_serial: None,
            site: None,
        };
        assert!(
            args.validate().is_err(),
            "upgrade without firmware_version must be refused before dispatch"
        );
    }

    /// A well-formed `firmware_version` is accepted; a malformed one is
    /// refused before dispatch, the same way a malformed MAC is.
    #[test]
    fn upgrade_firmware_version_is_validated() {
        use super::{DeviceAction, DeviceActionArgs};

        for (version, should_pass) in [
            ("7.1.66.15380", true),
            ("6.6.65", true),
            ("", false),
            ("7.1; rm -rf /", false),
            (&"9".repeat(65), false),
        ] {
            let args = DeviceActionArgs {
                controller: "test".to_owned(),
                device: "02:00:00:00:00:01".to_owned(),
                action: DeviceAction::Upgrade,
                port_index: None,
                firmware_version: Some(version.to_owned()),
                expected_model: None,
                expected_serial: None,
                site: None,
            };
            assert_eq!(
                args.validate().is_ok(),
                should_pass,
                "{version:?} validation must be {should_pass}"
            );
        }
    }

    /// `adopt_command` must refuse a device already adopted, refuse one with
    /// no reported adoption state, refuse one not in the pending-adoption
    /// `state`, refuse one whose reported model or serial does not match the
    /// caller's expectation, and only allow the command against a device the
    /// controller reports as pending with a matching identity.
    #[test]
    fn adopt_command_only_allows_a_pending_device_matching_the_expected_identity() {
        use super::adopt_command;

        let pending = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": false,
            "state": 2,
            "model": "U6-LR",
            "serial": "ABC123",
        });
        assert_eq!(
            adopt_command(&pending, "aa:bb:cc:dd:ee:ff", "U6-LR", None).expect("pending device"),
            "adopt"
        );
        assert_eq!(
            adopt_command(&pending, "aa:bb:cc:dd:ee:ff", "U6-LR", Some("ABC123"))
                .expect("pending device matching serial too"),
            "adopt"
        );

        let already_adopted = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": true,
            "state": 1,
            "model": "U6-LR",
        });
        assert!(
            adopt_command(&already_adopted, "aa:bb:cc:dd:ee:ff", "U6-LR", None).is_err(),
            "an already-adopted device must be refused"
        );

        let unknown_state = serde_json::json!({"mac": "aa:bb:cc:dd:ee:ff", "model": "U6-LR"});
        assert!(
            adopt_command(&unknown_state, "aa:bb:cc:dd:ee:ff", "U6-LR", None).is_err(),
            "a device with no reported adoption state must be refused, not assumed pending"
        );

        let not_pending_state = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": false,
            "state": 4,
            "model": "U6-LR",
        });
        assert!(
            adopt_command(&not_pending_state, "aa:bb:cc:dd:ee:ff", "U6-LR", None).is_err(),
            "a device reported `adopted: false` but not in the pending state must be refused"
        );

        let wrong_model = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": false,
            "state": 2,
            "model": "USW-24-PoE",
        });
        assert!(
            adopt_command(&wrong_model, "aa:bb:cc:dd:ee:ff", "U6-LR", None).is_err(),
            "a device reporting a different model than expected must be refused"
        );

        let wrong_serial = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": false,
            "state": 2,
            "model": "U6-LR",
            "serial": "XYZ999",
        });
        assert!(
            adopt_command(&wrong_serial, "aa:bb:cc:dd:ee:ff", "U6-LR", Some("ABC123")).is_err(),
            "a device reporting a different serial than expected must be refused"
        );
    }

    /// `upgrade_command` must refuse a device that is not adopted, refuse a
    /// no-op upgrade to the firmware already running, refuse a device the
    /// controller does not mark upgradable, refuse a device whose
    /// controller-queued firmware does not match what the caller asked for,
    /// and only allow the command when every check passes.
    #[test]
    fn upgrade_command_validates_adoption_version_upgradability_and_queued_firmware() {
        use super::upgrade_command;

        let ready = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": true,
            "version": "6.6.65.15303",
            "upgradable": true,
            "upgrade_to_firmware": "7.1.66.15380",
        });
        assert_eq!(
            upgrade_command(&ready, "aa:bb:cc:dd:ee:ff", "7.1.66.15380").expect("ready device"),
            "upgrade"
        );

        let not_adopted = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": false,
            "version": "6.6.65.15303",
            "upgradable": true,
            "upgrade_to_firmware": "7.1.66.15380",
        });
        assert!(
            upgrade_command(&not_adopted, "aa:bb:cc:dd:ee:ff", "7.1.66.15380").is_err(),
            "a device that is not adopted must be refused"
        );

        let already_at_target = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": true,
            "version": "7.1.66.15380",
            "upgradable": true,
            "upgrade_to_firmware": "7.1.66.15380",
        });
        assert!(
            upgrade_command(&already_at_target, "aa:bb:cc:dd:ee:ff", "7.1.66.15380").is_err(),
            "a no-op upgrade to the currently running firmware must be refused"
        );

        let not_upgradable = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": true,
            "version": "6.6.65.15303",
            "upgradable": false,
            "upgrade_to_firmware": "7.1.66.15380",
        });
        assert!(
            upgrade_command(&not_upgradable, "aa:bb:cc:dd:ee:ff", "7.1.66.15380").is_err(),
            "a device the controller does not mark upgradable must be refused"
        );

        let no_version_reported = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": true,
            "upgradable": true,
            "upgrade_to_firmware": "7.1.66.15380",
        });
        assert!(
            upgrade_command(&no_version_reported, "aa:bb:cc:dd:ee:ff", "7.1.66.15380").is_err(),
            "a device with no reported current firmware must be refused, not blindly upgraded"
        );

        let queued_mismatch = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": true,
            "version": "6.6.65.15303",
            "upgradable": true,
            "upgrade_to_firmware": "7.2.0.0",
        });
        assert!(
            upgrade_command(&queued_mismatch, "aa:bb:cc:dd:ee:ff", "7.1.66.15380").is_err(),
            "a controller queuing a different firmware than requested must be refused, not \
             installed blind"
        );

        let no_queued_firmware = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": true,
            "version": "6.6.65.15303",
            "upgradable": true,
        });
        assert!(
            upgrade_command(&no_queued_firmware, "aa:bb:cc:dd:ee:ff", "7.1.66.15380").is_err(),
            "a device with no reported queued firmware must be refused, not blindly upgraded"
        );
    }

    /// `port_action_command` must refuse a device that is not adopted, refuse
    /// a port index the device does not report at all, refuse a reported
    /// port with no PoE, and only allow `power-cycle` against an adopted
    /// device's PoE-capable port.
    #[test]
    fn port_action_command_only_allows_an_adopted_device_with_a_poe_port() {
        use super::port_action_command;

        let adopted = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": true,
            "port_table": [
                {"port_idx": 1, "port_poe": true},
                {"port_idx": 2, "port_poe": false},
            ],
        });
        assert_eq!(
            port_action_command(&adopted, "aa:bb:cc:dd:ee:ff", 1).expect("adopted device"),
            "power-cycle"
        );

        let not_adopted = serde_json::json!({
            "mac": "aa:bb:cc:dd:ee:ff",
            "adopted": false,
            "port_table": [{"port_idx": 1, "port_poe": true}],
        });
        assert!(
            port_action_command(&not_adopted, "aa:bb:cc:dd:ee:ff", 1).is_err(),
            "a device that is not adopted must be refused"
        );

        let unknown_state = serde_json::json!({"mac": "aa:bb:cc:dd:ee:ff"});
        assert!(
            port_action_command(&unknown_state, "aa:bb:cc:dd:ee:ff", 1).is_err(),
            "a device with no reported adoption state must be refused, not assumed adopted"
        );

        assert!(
            port_action_command(&adopted, "aa:bb:cc:dd:ee:ff", 2).is_err(),
            "a reported port with no PoE must be refused, not silently no-opped"
        );

        assert!(
            port_action_command(&adopted, "aa:bb:cc:dd:ee:ff", 99).is_err(),
            "a port index the device does not report must be refused, not silently no-opped"
        );
    }
}
