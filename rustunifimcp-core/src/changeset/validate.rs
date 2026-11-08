//! Client-side validation for staged mutations.
//!
//! UniFi has no server-side dry-run validation, so referential integrity and
//! schema constraints must be checked locally before apply.

use crate::error::UnifiError;
use crate::model::ResourceKind;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use super::preimage::{Preimage, StagedMutation};

/// The top-level body fields a staged create or update may set, by resource
/// kind. `None` means the kind may not be written at all.
///
/// UniFi has no server-side schema check on the private surfaces this server
/// writes to: a staged body reaches [`crate::client::UnifiClient::apply_mutation`]
/// close to verbatim (a Private v1 create or update sends `body` as-is; a
/// Private v2 update overlays it onto the live resource). Without this list,
/// [`check_writable_fields`] is the only thing standing between "the fields
/// this server actually understands for a resource" and "any JSON a caller or
/// a model hallucinated" — including controller-managed fields like `_id`,
/// which is why no entry here includes it.
///
/// Grounded in what this server already recognises: every kind's named
/// fields, taken from its read model in [`crate::model`], appear here. Two
/// exceptions are deliberate:
///
/// - `station` and `device` allow nothing: they are served from the
///   Integration API ([`crate::ApiSurface::Supported`]), which has no verified write
///   route this server can drive (`client.rs` already refused `kind ==
///   "device"` for updates alone; this closes the same gap for creates and
///   deletes, and extends it to `station`). Device and client state changes
///   go through `unifi_device_action` / `unifi_client_action`, not a generic
///   body write.
/// - `firewall_policy` is wider than its named struct fields:
///   [`crate::model::firewall::FirewallPolicy`] deliberately keeps every field
///   the controller returns (`source`, `destination`, `protocol`, `schedule`,
///   ...) because a policy missing them is not a policy any more, and the
///   supported authoring loop is "read a working policy, change one field,
///   stage it back". The extra names below are the ones every policy a real
///   controller returns carries (`create_allow_respond`, `icmp_typename`,
///   `icmp_v6_typename`, `match_ip_sec`, `match_opposite_protocol`,
///   `report_flow` from UniFi Network 11.0, and the optional `description`).
///   Server-managed fields (`_id`, `hits`, `last_hit`, `origin_id`,
///   `origin_type`, and 11.0's `report_flow_supported`) are deliberately not
///   listed.
///
///   `predefined` stays in this list for the same reason, not by omission:
///   it is a named field on [`crate::model::firewall::FirewallPolicy`] (not
///   part of its `rest` flatten), so every policy this server hands back
///   carries it, and the round-trip loop resubmits it verbatim. Dropping it
///   from the allowlist would not just block re-flagging a policy as
///   predefined -- an edit no caller is expected to make -- it would refuse
///   the read-edit-restage loop for every `firewall_policy` update, since the
///   body would always carry a field the allowlist no longer names.
pub(crate) fn writable_fields(kind: ResourceKind) -> Option<&'static [&'static str]> {
    match kind {
        ResourceKind::Station | ResourceKind::Device => None,
        ResourceKind::Network => Some(&[
            "name",
            "purpose",
            "ip_subnet",
            "vlan",
            "dhcpd_enabled",
            "dhcpd_start",
            "dhcpd_stop",
            "wan_dns1",
            "wan_dns2",
            "wan_ipv6_dns1",
            "wan_ipv6_dns2",
            // #143: what a delete-and-recreate must carry to be faithful.
            // `attr_no_delete` and `wan_type` are read but not written: the
            // first is controller-managed, the second reconfigures a WAN.
            "vlan_enabled",
            "enabled",
            "networkgroup",
            "firewall_zone_id",
            "domain_name",
            "igmp_snooping",
            "internet_access_enabled",
            "network_isolation_enabled",
            "dhcpd_leasetime",
            "dhcpd_dns_enabled",
            "dhcpd_dns_1",
            "dhcpd_dns_2",
            "dhcpd_dns_3",
            "dhcpd_dns_4",
        ]),
        ResourceKind::Wlan => Some(&["name", "enabled", "security", "wlan_band", "is_guest"]),
        ResourceKind::PortProfile => Some(&["name", "forward", "native_networkconf_id"]),
        ResourceKind::DhcpReservation => Some(&[
            "mac",
            "last_ip",
            "fixed_ip",
            "hostname",
            "use_fixedip",
            "network_id",
        ]),
        ResourceKind::FirewallGroup => Some(&["name", "group_type", "group_members"]),
        ResourceKind::RadiusProfile => Some(&["name", "external_id"]),
        // #143: the zone endpoint takes only these (plus `_id` on a PUT), on create
        // and update alike; `default_zone` and `external_id` are refused as
        // unrecognized fields. Checked live against UniFi Network 11.0.97.
        ResourceKind::FirewallZone => Some(&["name", "network_ids"]),
        ResourceKind::FirewallPolicy => Some(&[
            "name",
            "action",
            "enabled",
            "index",
            "predefined",
            "source",
            "destination",
            "protocol",
            "schedule",
            "connection_state_type",
            "connection_states",
            "ip_version",
            "logging",
            "description",
            "create_allow_respond",
            "icmp_typename",
            "icmp_v6_typename",
            "match_ip_sec",
            "match_opposite_protocol",
            "report_flow",
        ]),
        ResourceKind::TrafficRoute => Some(&["name"]),
        ResourceKind::PortForward => Some(&[
            "name",
            "enabled",
            "pfwd_interface",
            "src",
            "dst_port",
            "fwd",
            "fwd_port",
            "proto",
            "destination_ip",
            "log",
        ]),
        ResourceKind::StaticRoute => Some(&[
            "name",
            "type",
            "enabled",
            "static-route_type",
            "static-route_network",
            "static-route_nexthop",
            "static-route_distance",
            "static-route_interface",
        ]),
        // Legacy firewall rules are superseded by `firewall_policy`; they stay
        // read-only (MEC-509), same posture as `Station`/`Device` above.
        ResourceKind::FirewallRule => None,
    }
}

/// Refuse a staged mutation naming a kind this server will not write, or
/// setting a body field its kind does not allow.
///
/// Runs on the mutation list alone — no preimage or controller round trip is
/// needed — so it can run at staging time, before a bad mutation ever enters
/// a change set a human might approve. `Delete` and `Restore` carry no body
/// to check fields on; `Delete` is still refused for a read-only kind, and
/// `Restore` addresses the whole controller rather than a kind.
///
/// # Errors
///
/// Returns [`UnifiError::WriteRefused`] naming the kind or field that was
/// refused.
pub fn check_writable_fields(mutations: &[StagedMutation]) -> Result<(), UnifiError> {
    for mutation in mutations {
        let (kind, body) = match mutation {
            StagedMutation::Create { kind, body } | StagedMutation::Update { kind, body, .. } => {
                (kind, Some(body))
            }
            StagedMutation::Delete { kind, .. } => (kind, None),
            StagedMutation::Restore { .. } => continue,
        };

        let resource_kind: ResourceKind = serde_json::from_value(Value::String(kind.clone()))
            .map_err(|e| {
                UnifiError::WriteRefused(format!("invalid resource kind '{kind}': {e}"))
            })?;

        let Some(allowed) = writable_fields(resource_kind) else {
            return Err(UnifiError::WriteRefused(format!(
                "staged {} names kind '{kind}', which this server refuses to write: no \
                 supported write route exists for it through unifi_stage_change. Device and \
                 client state changes go through unifi_device_action or unifi_client_action.",
                mutation.preview()
            )));
        };

        // A reservation is the client's `user` record with `use_fixedip` set,
        // so a DELETE would forget the whole client (name, note, group, local
        // DNS) and its rollback could not restore it. The body is never
        // rewritten at apply time, so refuse rather than turn it into an update.
        if resource_kind == ResourceKind::DhcpReservation
            && matches!(mutation, StagedMutation::Delete { .. })
        {
            return Err(UnifiError::WriteRefused(format!(
                "staged {} is refused: a dhcp_reservation is the client's `user` record, so \
                 deleting it would forget the whole client; to remove only the reservation, \
                 stage an update with {{\"use_fixedip\": false}}",
                mutation.preview()
            )));
        }

        let Some(body) = body else { continue };
        let Some(object) = body.as_object() else {
            return Err(UnifiError::WriteRefused(format!(
                "staged {} for kind '{kind}' has a non-object body ({body}); the body \
                 must be a JSON object naming only writable fields",
                mutation.preview()
            )));
        };

        for field in object.keys() {
            if !allowed.contains(&field.as_str()) {
                return Err(UnifiError::WriteRefused(format!(
                    "staged {} sets field '{field}', which is not writable for kind '{kind}'; \
                     allowed fields are: {}",
                    mutation.preview(),
                    allowed.join(", ")
                )));
            }
        }

        check_dhcp_reservation_fixedip(mutation, resource_kind, object)?;
        // Early hint only; the authoritative check against the pre-image runs at validate
        // (`check_firewall_policy_against_live`).
        check_firewall_policy_respond(mutation, resource_kind, object)?;
    }
    Ok(())
}

/// A DHCP reservation only exists on the controller when `use_fixedip` is
/// true; a body that names a `fixed_ip` without it creates a plain named
/// client. The body is never rewritten at apply time, so the approved plan is
/// exactly what is sent: a create with a non-null `fixed_ip` must say
/// `use_fixedip: true`, and an update may not say `false` alongside one.
fn check_dhcp_reservation_fixedip(
    mutation: &StagedMutation,
    kind: ResourceKind,
    object: &serde_json::Map<String, Value>,
) -> Result<(), UnifiError> {
    if kind != ResourceKind::DhcpReservation || object.get("fixed_ip").is_none_or(Value::is_null) {
        return Ok(());
    }
    let use_fixedip = object.get("use_fixedip");
    let refused = match mutation {
        StagedMutation::Create { .. } => use_fixedip != Some(&Value::Bool(true)),
        _ => use_fixedip == Some(&Value::Bool(false)),
    };
    if refused {
        return Err(UnifiError::WriteRefused(format!(
            "staged {} sets 'fixed_ip' without 'use_fixedip: true', which would not create a \
             DHCP reservation; stage 'use_fixedip': true explicitly",
            mutation.preview()
        )));
    }
    Ok(())
}

/// The controller refuses a zone-based `firewall_policy` whose `action` is not
/// `ALLOW` unless `create_allow_respond` is `false`, and defaults the field to
/// `true` when a create leaves it out. A body that sets such an action without
/// `create_allow_respond: false` is refused here, on create and update alike
/// (checked live on UniFi Network 11.0.97, issue #143 follow-up).
fn check_firewall_policy_respond(
    mutation: &StagedMutation,
    kind: ResourceKind,
    object: &serde_json::Map<String, Value>,
) -> Result<(), UnifiError> {
    if kind != ResourceKind::FirewallPolicy {
        return Ok(());
    }
    let Some(action) = object.get("action").and_then(Value::as_str) else {
        return Ok(());
    };
    if action == "ALLOW" || object.get("create_allow_respond") == Some(&Value::Bool(false)) {
        return Ok(());
    }
    // The controller's own predefined BLOCK policies carry `create_allow_respond: true`
    // (10.5.67), so a re-staged one is left for the controller to judge.
    // The authoritative check reads `predefined` from the pre-image at validate.
    if object.get("predefined") == Some(&Value::Bool(true)) {
        return Ok(());
    }
    Err(respond_traffic_refusal(mutation, action))
}

/// The refusal shared by the staging-time and validate-time respond-traffic checks.
fn respond_traffic_refusal(mutation: &StagedMutation, action: &str) -> UnifiError {
    UnifiError::WriteRefused(format!(
        "staged {} sets action '{action}' without 'create_allow_respond: false'; the \
         controller refuses a BLOCK or REJECT policy that allows respond traffic, and \
         defaults the field to true when it is left out. Stage 'create_allow_respond': \
         false explicitly",
        mutation.preview()
    ))
}

/// The refusal for turning on flow reporting on a policy the controller says cannot report flows.
fn report_flow_refusal(mutation: &StagedMutation) -> UnifiError {
    UnifiError::WriteRefused(format!(
        "staged {} sets 'report_flow: true' on a policy whose live copy has \
         'report_flow_supported: false'; the controller cannot report flows for it",
        mutation.preview()
    ))
}

/// Refuse a `firewall_policy` whose effective state is a BLOCK or REJECT that allows
/// respond traffic, judged against the live policy.
///
/// Authoritative counterpart of the body-only staging check: an update is folded
/// over the pre-image (cumulatively, like apply), so one that sets only
/// `create_allow_respond: true` on a BLOCK policy is caught, and `predefined` is
/// read from the controller's copy, never from a staged body. A create is never
/// predefined.
///
/// It also refuses an update setting `report_flow: true` on a policy whose live copy
/// has `report_flow_supported: false` (UniFi Network 11.0). That capability, too, is
/// read only from the pre-image, and is checked for predefined policies, which are
/// the only ones that lack it.
///
/// # Errors
///
/// Returns [`UnifiError::WriteRefused`] naming the mutation.
pub fn check_firewall_policy_against_live(
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<(), UnifiError> {
    // id -> (live policy is predefined, live policy cannot report flows,
    //        effective policy after the updates so far)
    let mut live: BTreeMap<&str, (bool, bool, Value)> = BTreeMap::new();
    for mutation in mutations {
        let effective = match mutation {
            StagedMutation::Create { kind, body } if kind == POLICY_KIND => body.clone(),
            StagedMutation::Update { kind, id, body } if kind == POLICY_KIND => {
                if !live.contains_key(id.as_str()) {
                    let Some(resource) = preimage.get_resource(id) else {
                        continue;
                    };
                    let predefined = resource.get("predefined") == Some(&Value::Bool(true));
                    let no_flows =
                        resource.get("report_flow_supported") == Some(&Value::Bool(false));
                    live.insert(id.as_str(), (predefined, no_flows, resource));
                }
                let (predefined, no_flows, resource) =
                    live.get_mut(id.as_str()).expect("seeded above");
                if *no_flows && body.get("report_flow") == Some(&Value::Bool(true)) {
                    return Err(report_flow_refusal(mutation));
                }
                overlay(resource, body);
                // The controller's own BLOCK policies carry `create_allow_respond: true`.
                if *predefined {
                    continue;
                }
                resource.clone()
            }
            StagedMutation::Delete { kind, id } if kind == POLICY_KIND => {
                live.remove(id.as_str());
                continue;
            }
            _ => continue,
        };
        let Some(action) = effective.get("action").and_then(Value::as_str) else {
            continue;
        };
        if action != "ALLOW" && effective.get("create_allow_respond") != Some(&Value::Bool(false)) {
            return Err(respond_traffic_refusal(mutation, action));
        }
    }
    Ok(())
}

/// Validate that all staged mutations are covered by the pre-image.
///
/// # Errors
///
/// Returns an error if any mutation references a resource not in the pre-image.
pub fn validate_locally(
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<(), UnifiError> {
    for mutation in mutations {
        if !preimage.covers(mutation) {
            return Err(UnifiError::Malformed(format!(
                "mutation {} references a resource not in the pre-image",
                mutation.preview()
            )));
        }
    }
    Ok(())
}

/// The firewall zones a staged mutation is allowed to reference.
///
/// Built from the controller's live zone list, never from the pre-image. A
/// create records no prior state at all, so a pre-image-derived index is empty
/// for exactly the mutations that need checking, and every zone reference in a
/// `firewall_policy` create was reported missing.
#[derive(Debug, Clone, Default)]
pub struct ZoneIndex {
    /// Zone `_id` to zone name.
    by_id: BTreeMap<String, String>,
    /// Zone `external_id` to the `_id` the controller wants instead.
    by_external_id: BTreeMap<String, String>,
}

/// What a zone identifier in a staged body resolves to.
enum ZoneLookup<'index> {
    /// The identifier is a zone `_id` on this controller.
    Known,
    /// The identifier is a zone's `external_id`; the `_id` is carried along
    /// because naming it is the whole fix.
    ExternalId(&'index str),
    /// The identifier is neither.
    Absent,
}

impl ZoneIndex {
    /// Build the index from the controller's firewall zone list.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::Malformed`] if the response is not an array of
    /// zone objects each carrying an `_id`. Read that as "the zone list could
    /// not be read", which needs a different operator response from "the zone
    /// is not there" — conflating the two is what made this check unusable.
    pub fn from_zone_list(raw: &Value) -> Result<Self, UnifiError> {
        let items = raw.as_array().ok_or_else(|| {
            UnifiError::Malformed("firewall zone list is not an array".to_owned())
        })?;

        let mut by_id = BTreeMap::new();
        let mut by_external_id = BTreeMap::new();

        for (position, item) in items.iter().enumerate() {
            let id = item
                .get("_id")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    UnifiError::Malformed(format!(
                        "firewall zone at position {position} has no `_id`"
                    ))
                })?
                .to_owned();

            if let Some(external) = item.get("external_id").and_then(Value::as_str) {
                by_external_id.insert(external.to_owned(), id.clone());
            }

            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>")
                .to_owned();
            by_id.insert(id, name);
        }

        Ok(Self {
            by_id,
            by_external_id,
        })
    }

    /// How many zones the controller reported.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether the controller reported no zones at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Resolve one identifier taken from a staged body.
    fn resolve(&self, identifier: &str) -> ZoneLookup<'_> {
        if self.by_id.contains_key(identifier) {
            return ZoneLookup::Known;
        }
        if let Some(id) = self.by_external_id.get(identifier) {
            return ZoneLookup::ExternalId(id.as_str());
        }
        ZoneLookup::Absent
    }
}

/// Where a body names a zone: a policy's two sides, and a network's own zone.
const ZONE_REFERENCES: &[(&str, &[&str])] = &[
    ("source.zone_id", &["source", "zone_id"]),
    ("destination.zone_id", &["destination", "zone_id"]),
    ("firewall_zone_id", &["firewall_zone_id"]),
];

/// Each zone a resource names, with the field that names it.
fn zones_named_by(resource: &Value) -> impl Iterator<Item = (&'static str, &str)> {
    ZONE_REFERENCES.iter().filter_map(move |(field, path)| {
        path.iter()
            .try_fold(resource, |value, key| value.get(key))
            .and_then(Value::as_str)
            .map(|zone_id| (*field, zone_id))
    })
}

/// The zone identifiers staged mutations reference, in staging order.
///
/// Empty means no staged body names a zone, so the caller can skip fetching
/// the zone list rather than making a change set that touches no firewall
/// depend on the firewall surface being reachable.
#[must_use]
pub fn referenced_zone_ids(mutations: &[StagedMutation]) -> Vec<String> {
    let mut referenced = Vec::new();

    for mutation in mutations {
        let body = match mutation {
            StagedMutation::Create { body, .. } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } | StagedMutation::Restore { .. } => continue,
        };

        for (_, zone_id) in zones_named_by(body) {
            if !referenced.iter().any(|seen| seen == zone_id) {
                referenced.push(zone_id.to_owned());
            }
        }
    }

    referenced
}

/// The resource kind whose deletion removes a zone a policy could name.
const ZONE_KIND: &str = "firewall_zone";

/// The resource kind the controller's respond-traffic rule applies to.
const POLICY_KIND: &str = "firewall_policy";

/// The zones this change set deletes.
fn zones_deleted_by(mutations: &[StagedMutation]) -> Vec<&str> {
    mutations
        .iter()
        .filter_map(|mutation| match mutation {
            StagedMutation::Delete { kind, id } if kind == ZONE_KIND => Some(id.as_str()),
            _ => None,
        })
        .collect()
}

/// Overlay a staged fragment on a resource the way an update lands.
///
/// Every update is partial: on Private v2,
/// [`crate::client::UnifiClient::apply_mutation`] overlays the staged fields on
/// the fetched resource, and a v1 `rest/` PUT is merged by the controller. A
/// network renamed before its zone is deleted therefore keeps its zone.
///
/// Whole top-level keys are replaced, not deep-merged, and the
/// controller-managed `_id` and `site_id` are never taken from the fragment.
/// A fragment that supplies `source` therefore replaces the live `source`
/// entirely, including when the replacement carries no `zone_id`.
///
/// Both sides must be objects or nothing is merged and the resource is sent
/// unchanged, because that is what apply's own guard does. `MutationSpec`
/// accepts any JSON as a body, and treating a null or a scalar as a
/// replacement here erased the inherited zone references apply would in fact
/// still send.
fn overlay(base: &mut Value, fragment: &Value) {
    let (Some(base_object), Some(fragment_object)) = (base.as_object_mut(), fragment.as_object())
    else {
        return;
    };

    for (key, value) in fragment_object {
        if key != "_id" && key != "site_id" {
            base_object.insert(key.clone(), value.clone());
        }
    }
}

/// Refuse a change set whose zone deletions and policy writes contradict.
///
/// Apply is a sequence of independent REST calls in staging order, with no
/// candidate and no commit, so the check has to follow that order rather than
/// compare start to end. Two orderings fail, and they fail differently:
///
/// - A zone deleted while something the set writes still references it. The
///   controller refuses to remove a zone in use, and by then earlier writes
///   have already landed.
/// - A policy written after the set has deleted the zone it names. That write
///   fails on a zone that no longer exists.
///
/// The state the check walks starts from the pre-image for every resource the
/// set updates or deletes, because a zone delete is refused by what is *live*
/// and not only by what this set has written so far. Updates then fold
/// cumulatively: apply re-fetches before each one, so a second fragment lands
/// on the result of the first, and projecting each from the pre-image
/// independently refused sets that apply cleanly.
///
/// Bounded to the resources the set touches. A live policy the set never
/// writes is not in the pre-image and cannot be projected, so a zone deletion
/// that orphans an untouched policy is left to the controller to refuse.
///
/// Separate from [`check_zone_references`] because it needs no zone list: it
/// compares the set against itself, so it runs even when nothing was fetched.
///
/// # Errors
///
/// Returns [`UnifiError::ReferenceNotFound`] naming both sides of the conflict
/// and, where it is the fix, the ordering.
pub fn check_zone_deletions(
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<(), UnifiError> {
    if zones_deleted_by(mutations).is_empty() {
        return Ok(());
    }

    // Every resource the set addresses by id, seeded with its live state.
    let mut live: BTreeMap<String, (String, Value)> = BTreeMap::new();
    for mutation in mutations {
        let (kind, id) = match mutation {
            StagedMutation::Update { kind, id, .. } | StagedMutation::Delete { kind, id } => {
                (kind, id)
            }
            StagedMutation::Create { .. } | StagedMutation::Restore { .. } => continue,
        };
        if kind == ZONE_KIND {
            continue;
        }
        if let Some(resource) = preimage.get_resource(id) {
            live.insert(id.clone(), (format!("the live {kind} {id}"), resource));
        }
    }

    // Resources this set creates. They have no id until apply, so they cannot
    // be addressed by a later mutation and never need folding.
    let mut created: Vec<(String, Value)> = Vec::new();
    let mut deleted: BTreeSet<&str> = BTreeSet::new();

    for mutation in mutations {
        match mutation {
            StagedMutation::Create { body, .. } => {
                refuse_reference_to_deleted(&mutation.preview(), body, &deleted)?;
                created.push((mutation.preview(), body.clone()));
            }
            StagedMutation::Update { id, body, .. } => {
                let entry = live
                    .entry(id.clone())
                    .or_insert_with(|| (mutation.preview(), Value::Object(serde_json::Map::new())));
                overlay(&mut entry.1, body);
                entry.0 = mutation.preview();
                let (preview, resource) = (entry.0.clone(), entry.1.clone());
                refuse_reference_to_deleted(&preview, &resource, &deleted)?;
            }
            StagedMutation::Delete { kind, id } if kind == ZONE_KIND => {
                for (preview, resource) in live.values().chain(created.iter()) {
                    for (field, zone_id) in zones_named_by(resource) {
                        if zone_id == id {
                            return Err(UnifiError::ReferenceNotFound(format!(
                                "staged delete firewall_zone {id} would remove a zone \
                                 {preview} still names as {field}; stage the \
                                 change that moves it off the zone before the delete"
                            )));
                        }
                    }
                }
                deleted.insert(id.as_str());
            }
            StagedMutation::Delete { id, .. } => {
                live.remove(id);
            }
            StagedMutation::Restore { .. } => {}
        }
    }

    Ok(())
}

/// Refuse a write naming a zone an earlier mutation in the set removed.
fn refuse_reference_to_deleted(
    preview: &str,
    resource: &Value,
    deleted: &BTreeSet<&str>,
) -> Result<(), UnifiError> {
    for (field, zone_id) in zones_named_by(resource) {
        if deleted.contains(zone_id) {
            return Err(UnifiError::ReferenceNotFound(format!(
                "staged {preview} names {field} '{zone_id}', which an earlier \
                 mutation in this change set deletes"
            )));
        }
    }
    Ok(())
}

/// Check that every zone a staged body names exists on the controller.
///
/// Only the staged fragments are checked here: a reference inherited from the
/// live resource is already resolvable by definition, and the case where the
/// set removes it is [`check_zone_deletions`]'s.
///
/// # Errors
///
/// Returns [`UnifiError::ReferenceNotFound`] if a staged body names a zone the
/// controller does not have. That variant renders on its own, without the
/// "unexpected response shape" prefix a parse failure carries, so the two read
/// differently in a tool result.
pub fn check_zone_references(
    zones: &ZoneIndex,
    mutations: &[StagedMutation],
) -> Result<(), UnifiError> {
    for mutation in mutations {
        let body = match mutation {
            StagedMutation::Create { body, .. } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } | StagedMutation::Restore { .. } => continue,
        };

        for (field, zone_id) in zones_named_by(body) {
            match zones.resolve(zone_id) {
                ZoneLookup::Known => {}
                ZoneLookup::ExternalId(id) => {
                    return Err(UnifiError::ReferenceNotFound(format!(
                        "staged {} names {field} '{zone_id}', which is that zone's \
                         external_id; the controller addresses it by `_id` '{id}'",
                        mutation.preview()
                    )));
                }
                ZoneLookup::Absent => {
                    return Err(UnifiError::ReferenceNotFound(format!(
                        "staged {} names {field} '{zone_id}', which is not one of the \
                         {} firewall zones on this controller",
                        mutation.preview(),
                        zones.len()
                    )));
                }
            }
        }
    }

    Ok(())
}

/// The network `_id`s staged `Create`/`Update` bodies carry as `network_id`
/// (a client reservation moving to another network), in staging order.
///
/// Empty means no staged body names a network, so the caller can skip fetching
/// the network list.
#[must_use]
pub fn referenced_network_ids(mutations: &[StagedMutation]) -> Vec<String> {
    let mut referenced = Vec::new();

    for mutation in mutations {
        let body = match mutation {
            StagedMutation::Create { body, .. } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } | StagedMutation::Restore { .. } => continue,
        };

        let Some(network_id) = body.get("network_id").and_then(Value::as_str) else {
            continue;
        };
        if !referenced.iter().any(|seen| seen == network_id) {
            referenced.push(network_id.to_owned());
        }
    }

    referenced
}

/// The resource kind whose deletion removes a network a reservation could name.
const NETWORK_KIND: &str = "network";

/// Check that every `network_id` a staged body names is a live network that
/// this change set does not itself delete.
///
/// `network_list` is the controller's network list as
/// [`crate::tools::read::list_resources`] returns it: an array of objects
/// each carrying an `_id`.
///
/// # Errors
///
/// Returns [`UnifiError::Malformed`] if the list cannot be read, which is a
/// different operator response from "the network is not there", and
/// [`UnifiError::ReferenceNotFound`] if a staged body names an absent network
/// or one the set deletes.
pub fn check_network_references(
    network_list: &Value,
    mutations: &[StagedMutation],
) -> Result<(), UnifiError> {
    let items = network_list
        .as_array()
        .ok_or_else(|| UnifiError::Malformed("network list is not an array".to_owned()))?;

    let mut live_ids = BTreeSet::new();
    for (position, item) in items.iter().enumerate() {
        let id = item.get("_id").and_then(Value::as_str).ok_or_else(|| {
            UnifiError::Malformed(format!("network at position {position} has no `_id`"))
        })?;
        live_ids.insert(id);
    }

    let deleted: BTreeSet<&str> = mutations
        .iter()
        .filter_map(|mutation| match mutation {
            StagedMutation::Delete { kind, id } if kind == NETWORK_KIND => Some(id.as_str()),
            _ => None,
        })
        .collect();

    for mutation in mutations {
        let body = match mutation {
            StagedMutation::Create { body, .. } | StagedMutation::Update { body, .. } => body,
            StagedMutation::Delete { .. } | StagedMutation::Restore { .. } => continue,
        };
        let Some(network_id) = body.get("network_id").and_then(Value::as_str) else {
            continue;
        };

        if !live_ids.contains(network_id) {
            return Err(UnifiError::ReferenceNotFound(format!(
                "staged {} names network_id '{network_id}', which is not one of the \
                 {} networks on this controller",
                mutation.preview(),
                live_ids.len()
            )));
        }
        if deleted.contains(network_id) {
            return Err(UnifiError::ReferenceNotFound(format!(
                "staged {} names network_id '{network_id}', which this change set deletes",
                mutation.preview()
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        ZoneIndex, check_firewall_policy_against_live, check_network_references,
        check_zone_deletions, check_zone_references, referenced_network_ids, referenced_zone_ids,
    };
    use crate::changeset::{Preimage, StagedMutation};
    use serde_json::{Value, json};

    /// A zone list as the Private v2 surface returns it: a bare array.
    fn zone_list() -> serde_json::Value {
        json!([
            {
                "_id": "aaaaaaaaaaaaaaaaaaaaaaaa",
                "name": "Internal",
                "default_zone": true,
                "network_ids": ["bbbbbbbbbbbbbbbbbbbbbbbb"],
                "external_id": "11111111-1111-4111-8111-111111111111"
            },
            {
                "_id": "cccccccccccccccccccccccc",
                "name": "DMZ",
                "default_zone": false,
                "network_ids": [],
                "external_id": "22222222-2222-4222-8222-222222222222"
            }
        ])
    }

    fn policy_between(source: &str, destination: &str) -> StagedMutation {
        StagedMutation::create(
            "firewall_policy",
            json!({
                "name": "probe",
                "action": "ALLOW",
                "source": { "zone_id": source, "matching_target": "ZONE" },
                "destination": { "zone_id": destination, "matching_target": "ZONE" }
            }),
        )
    }

    /// Referential checks are local because no controller-side dry run exists.
    #[test]
    fn a_policy_referencing_an_absent_zone_is_refused() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = policy_between("does-not-exist", "cccccccccccccccccccccccc");
        let error =
            check_zone_references(&zones, &[staged]).expect_err("an absent zone must be caught");
        let rendered = error.to_string();
        assert!(rendered.contains("does-not-exist"), "{rendered}");
        assert!(
            rendered.contains('2'),
            "the count of known zones: {rendered}"
        );
    }

    /// The bug this replaces: a policy naming zones the controller listed
    /// moments earlier was refused, because the check ran against the
    /// pre-image, which is empty for a create.
    #[test]
    fn a_policy_referencing_listed_zones_passes() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "cccccccccccccccccccccccc");
        assert!(
            check_zone_references(&zones, &[staged]).is_ok(),
            "both zones are in the list the controller returned"
        );
    }

    /// A zone list the caller can read hands out two identifiers. Naming the
    /// wrong one has to say so, not report the zone missing.
    #[test]
    fn an_external_id_reference_names_the_id_to_use_instead() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = policy_between(
            "11111111-1111-4111-8111-111111111111",
            "cccccccccccccccccccccccc",
        );
        let error =
            check_zone_references(&zones, &[staged]).expect_err("an external_id is not an _id");
        let rendered = error.to_string();
        assert!(rendered.contains("external_id"), "{rendered}");
        assert!(rendered.contains("aaaaaaaaaaaaaaaaaaaaaaaa"), "{rendered}");
    }

    /// "Could not read the zone list" and "the zone is not there" want
    /// different operator responses, so they must not render alike.
    #[test]
    fn an_unreadable_zone_list_does_not_read_as_a_missing_zone() {
        let error = ZoneIndex::from_zone_list(&serde_json::json!({ "data": [] }))
            .expect_err("an envelope is not the Private v2 shape");
        let rendered = error.to_string();
        assert!(rendered.contains("unexpected response shape"), "{rendered}");
        assert!(
            !rendered.contains("not one of the"),
            "a parse failure must not claim a zone is absent: {rendered}"
        );
    }

    /// A zone entry with no `_id` is drift, not an absent reference.
    #[test]
    fn a_zone_without_an_id_is_a_parse_failure() {
        let error = ZoneIndex::from_zone_list(&serde_json::json!([{ "name": "Internal" }]))
            .expect_err("a zone with no `_id` cannot be indexed");
        assert!(error.to_string().contains("position 0"), "{error}");
    }

    /// Both sides of a policy are checked. Only checking `source` let a
    /// destination naming a deleted zone through to apply.
    #[test]
    fn the_destination_zone_is_checked_too() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let staged = policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "does-not-exist");
        let error =
            check_zone_references(&zones, &[staged]).expect_err("destination must be checked");
        assert!(error.to_string().contains("destination"), "{error}");
    }

    /// A pre-image holding one live policy, so a partial update has something
    /// to inherit from.
    fn preimage_with_live_policy() -> Preimage {
        Preimage::from_fixture(&json!({ "data": [{
            "_id": "dddddddddddddddddddddddd",
            "name": "live policy",
            "action": "ALLOW",
            "enabled": false,
            "source": { "zone_id": "aaaaaaaaaaaaaaaaaaaaaaaa", "matching_target": "ZONE" },
            "destination": { "zone_id": "cccccccccccccccccccccccc", "matching_target": "ZONE" }
        }]}))
    }

    /// Apply runs staged mutations in order against live state, so a zone the
    /// same change set deletes is gone before a later policy write lands. The
    /// live list still has it, which is why the zone index alone is not enough.
    #[test]
    fn a_policy_naming_a_zone_the_same_set_deletes_is_refused() {
        let staged = vec![
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
            policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "cccccccccccccccccccccccc"),
        ];
        let error = check_zone_deletions(&preimage_with_live_policy(), &staged)
            .expect_err("the destination zone is being deleted");
        let rendered = error.to_string();
        assert!(rendered.contains("deletes"), "{rendered}");
        assert!(rendered.contains("cccccccccccccccccccccccc"), "{rendered}");
    }

    /// #143: a network names its zone at the top level, and every zone
    /// check must see it, not only a policy's `source`/`destination`.
    #[test]
    fn a_network_zone_reference_is_checked_like_a_policy_side() {
        let zones = ZoneIndex::from_zone_list(&zone_list()).expect("a well-formed zone list");
        let network = |zone: &str| {
            StagedMutation::create(
                "network",
                json!({ "name": "moved", "firewall_zone_id": zone }),
            )
        };
        assert_eq!(
            referenced_zone_ids(&[network("cccccccccccccccccccccccc")]),
            ["cccccccccccccccccccccccc"]
        );
        assert!(check_zone_references(&zones, &[network("cccccccccccccccccccccccc")]).is_ok());
        let absent = check_zone_references(&zones, &[network("does-not-exist")])
            .expect_err("an absent zone must be caught");
        assert!(absent.to_string().contains("firewall_zone_id"), "{absent}");

        let into_deleted = vec![
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
            network("cccccccccccccccccccccccc"),
        ];
        check_zone_deletions(&preimage_with_live_policy(), &into_deleted)
            .expect_err("the network's zone is deleted first");
        let off_deleted = vec![
            network("cccccccccccccccccccccccc"),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        check_zone_deletions(&preimage_with_live_policy(), &off_deleted)
            .expect_err("the zone is deleted while the new network still names it");

        // A v1 PUT is merged by the controller, so a rename keeps the zone.
        let live_network = Preimage::from_fixture(&json!({ "data": [{
            "_id": "eeeeeeeeeeeeeeeeeeeeeeee",
            "name": "in dmz",
            "firewall_zone_id": "cccccccccccccccccccccccc"
        }]}));
        let rename_then_delete = vec![
            StagedMutation::update(
                "network",
                "eeeeeeeeeeeeeeeeeeeeeeee",
                json!({ "name": "renamed" }),
            ),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        check_zone_deletions(&live_network, &rename_then_delete)
            .expect_err("the renamed network is still in the zone");
    }

    /// Staging order does not rescue it: the policy is checked against the
    /// state the whole set projects, not the prefix before it.
    #[test]
    fn the_delete_is_caught_even_when_staged_after_the_policy() {
        let staged = vec![
            policy_between("cccccccccccccccccccccccc", "aaaaaaaaaaaaaaaaaaaaaaaa"),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        assert!(check_zone_deletions(&preimage_with_live_policy(), &staged).is_err());
    }

    /// Deleting some other resource that happens to share an id must not
    /// invalidate a zone reference.
    #[test]
    fn deleting_a_non_zone_resource_does_not_invalidate_a_zone_reference() {
        let staged = vec![
            StagedMutation::delete("firewall_policy", "cccccccccccccccccccccccc"),
            policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "cccccccccccccccccccccccc"),
        ];
        assert!(check_zone_deletions(&preimage_with_live_policy(), &staged).is_ok());
    }

    /// A Private v2 update is a partial write: the client overlays the staged
    /// fields on the live resource, so a fragment that touches only `enabled`
    /// still applies a policy carrying the live zones. Reading the fragment
    /// alone saw no reference at all and let the set delete a zone the
    /// surviving policy points at.
    #[test]
    fn a_partial_update_inherits_the_zone_it_does_not_mention() {
        let staged = vec![
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "enabled": true }),
            ),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        let error = check_zone_deletions(&preimage_with_live_policy(), &staged)
            .expect_err("the applied policy still names the deleted zone");
        assert!(
            error.to_string().contains("cccccccccccccccccccccccc"),
            "{error}"
        );
    }

    /// The overlay replaces whole top-level keys, so a fragment that supplies
    /// `destination` wins outright -- moving the policy off the doomed zone is
    /// a legitimate way to make the set consistent.
    #[test]
    fn a_partial_update_that_moves_the_zone_is_allowed() {
        let staged = vec![
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "destination": { "zone_id": "aaaaaaaaaaaaaaaaaaaaaaaa" } }),
            ),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        assert!(check_zone_deletions(&preimage_with_live_policy(), &staged).is_ok());
    }

    /// Apply re-fetches before each update, so a second fragment is overlaid
    /// on the result of the first. Projecting each one from the pre-image
    /// independently made this set -- move the policy off Z, toggle another
    /// field, delete Z -- look as though it still referenced the zone it had
    /// just left, and refused a change set that applies cleanly.
    #[test]
    fn a_second_update_is_overlaid_on_the_first_not_on_the_preimage() {
        let staged = vec![
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "destination": { "zone_id": "aaaaaaaaaaaaaaaaaaaaaaaa" } }),
            ),
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "enabled": true }),
            ),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        assert!(
            check_zone_deletions(&preimage_with_live_policy(), &staged).is_ok(),
            "the policy was moved off the deleted zone by the first update"
        );
    }

    /// And the fold does not launder a reference back in: moving the policy
    /// onto the doomed zone in a later update is still refused.
    #[test]
    fn a_later_update_moving_onto_the_deleted_zone_is_refused() {
        let staged = vec![
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "destination": { "zone_id": "aaaaaaaaaaaaaaaaaaaaaaaa" } }),
            ),
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "destination": { "zone_id": "cccccccccccccccccccccccc" } }),
            ),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        assert!(check_zone_deletions(&preimage_with_live_policy(), &staged).is_err());
    }

    /// A policy this set deletes leaves nothing to reference, so deleting it
    /// and its zone together is consistent.
    #[test]
    fn deleting_the_policy_and_its_zone_together_is_allowed() {
        let staged = vec![
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "enabled": true }),
            ),
            StagedMutation::delete("firewall_policy", "dddddddddddddddddddddddd"),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        assert!(check_zone_deletions(&preimage_with_live_policy(), &staged).is_ok());
    }

    /// Comparing start to end is not enough, because apply has no candidate
    /// and no commit: it writes in order. This set puts the policy on the
    /// doomed zone, deletes the zone, then moves the policy off. The end state
    /// is consistent and the zone is in the live list, but the controller
    /// reaches the delete while the policy still references the zone, refuses
    /// it, and the first write has already landed.
    #[test]
    fn a_reference_live_at_the_moment_of_the_delete_is_refused() {
        let staged = vec![
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "destination": { "zone_id": "cccccccccccccccccccccccc" } }),
            ),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "destination": { "zone_id": "aaaaaaaaaaaaaaaaaaaaaaaa" } }),
            ),
        ];
        let error = check_zone_deletions(&preimage_with_live_policy(), &staged)
            .expect_err("the delete is reached while the policy still names the zone");
        assert!(
            error.to_string().contains("before the delete"),
            "the fix is an ordering one and the message should say so: {error}"
        );
    }

    /// The live state is what refuses a zone delete, not only what this set
    /// has written so far. A policy the set deletes *after* the zone still
    /// holds the zone when the zone delete is reached.
    #[test]
    fn a_live_reference_blocks_the_delete_even_before_the_set_touches_it() {
        let staged = vec![
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
            StagedMutation::delete("firewall_policy", "dddddddddddddddddddddddd"),
        ];
        assert!(
            check_zone_deletions(&preimage_with_live_policy(), &staged).is_err(),
            "the live policy still names the zone when the zone delete lands"
        );
    }

    /// `MutationSpec` accepts any JSON as a body. Apply's merge is guarded on
    /// both sides being objects, so a null body sends the resource unchanged --
    /// inherited zone references and all. Treating it as a replacement erased
    /// them and let the zone delete validate.
    #[test]
    fn a_non_object_update_body_leaves_the_resource_as_apply_would() {
        let staged = vec![
            StagedMutation::update("firewall_policy", "dddddddddddddddddddddddd", Value::Null),
            StagedMutation::delete("firewall_zone", "cccccccccccccccccccccccc"),
        ];
        assert!(
            check_zone_deletions(&preimage_with_live_policy(), &staged).is_err(),
            "a null body changes nothing, so the policy still names the deleted zone"
        );
    }

    /// A set that deletes no zone needs no projection at all.
    #[test]
    fn a_set_deleting_no_zone_passes_the_deletion_check() {
        let staged = vec![policy_between(
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            "cccccccccccccccccccccccc",
        )];
        assert!(check_zone_deletions(&preimage_with_live_policy(), &staged).is_ok());
    }

    /// A change set that names no zone must not be made to depend on the
    /// firewall surface being reachable.
    #[test]
    fn a_change_set_naming_no_zone_needs_no_zone_list() {
        let staged = StagedMutation::update("network", "abc123", serde_json::json!({"name": "x"}));
        assert!(referenced_zone_ids(&[staged]).is_empty());
    }

    /// Deletes carry no body, so they contribute no reference to resolve.
    #[test]
    fn deletes_reference_no_zones() {
        let staged = StagedMutation::delete("firewall_policy", "abc123");
        assert!(referenced_zone_ids(&[staged]).is_empty());
    }

    #[test]
    fn both_sides_of_a_policy_are_collected_once_each() {
        let staged = policy_between("aaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(
            referenced_zone_ids(&[staged]),
            vec!["aaaaaaaaaaaaaaaaaaaaaaaa"]
        );
    }

    fn network_list() -> serde_json::Value {
        json!([
            { "_id": "dddddddddddddddddddddddd", "name": "Default" },
            { "_id": "eeeeeeeeeeeeeeeeeeeeeeee", "name": "IoT" }
        ])
    }

    fn reservation_on(network_id: &str) -> StagedMutation {
        StagedMutation::update(
            "dhcp_reservation",
            "ffffffffffffffffffffffff",
            json!({ "network_id": network_id }),
        )
    }

    #[test]
    fn a_reservation_moving_to_a_listed_network_passes() {
        let staged = reservation_on("eeeeeeeeeeeeeeeeeeeeeeee");
        assert!(check_network_references(&network_list(), &[staged]).is_ok());
    }

    #[test]
    fn a_reservation_moving_to_an_absent_network_is_refused() {
        let staged = reservation_on("000000000000000000000000");
        let rendered = check_network_references(&network_list(), &[staged])
            .expect_err("an absent network must be caught")
            .to_string();
        assert!(rendered.contains("network_id"), "{rendered}");
        assert!(rendered.contains("000000000000000000000000"), "{rendered}");
        assert!(rendered.contains("2 networks"), "{rendered}");
    }

    #[test]
    fn a_reservation_moving_to_a_network_the_set_deletes_is_refused() {
        let mutations = [
            reservation_on("eeeeeeeeeeeeeeeeeeeeeeee"),
            StagedMutation::delete("network", "eeeeeeeeeeeeeeeeeeeeeeee"),
        ];
        let rendered = check_network_references(&network_list(), &mutations)
            .expect_err("a deleted network is absent")
            .to_string();
        assert!(rendered.contains("deletes"), "{rendered}");
    }

    #[test]
    fn an_unreadable_network_list_is_a_parse_failure() {
        let error = check_network_references(&json!({ "data": [] }), &[reservation_on("x")])
            .expect_err("an envelope is not an array");
        assert!(error.to_string().contains("not an array"), "{error}");
    }

    #[test]
    fn no_network_id_means_nothing_to_fetch() {
        let staged = StagedMutation::update("dhcp_reservation", "u1", json!({ "hostname": "a" }));
        assert!(referenced_network_ids(&[staged]).is_empty());
        let named = reservation_on("eeeeeeeeeeeeeeeeeeeeeeee");
        assert_eq!(
            referenced_network_ids(&[named]),
            ["eeeeeeeeeeeeeeeeeeeeeeee"]
        );
    }

    fn respond_preimage(action: &str, allow_respond: bool, predefined: bool) -> Preimage {
        Preimage::from_resources(vec![json!({
            "_id": "pol000000000000000000001",
            "action": action,
            "create_allow_respond": allow_respond,
            "predefined": predefined
        })])
    }

    fn update_policy(body: Value) -> StagedMutation {
        StagedMutation::update("firewall_policy", "pol000000000000000000001", body)
    }

    #[test]
    fn respond_true_alone_on_a_live_block_policy_is_refused() {
        let staged = [update_policy(json!({ "create_allow_respond": true }))];
        let result =
            check_firewall_policy_against_live(&respond_preimage("BLOCK", false, false), &staged);
        assert!(result.is_err());
    }

    #[test]
    fn switching_a_live_allow_policy_to_block_needs_respond_false() {
        let preimage = respond_preimage("ALLOW", true, false);
        let bare = [update_policy(json!({ "action": "BLOCK" }))];
        assert!(check_firewall_policy_against_live(&preimage, &bare).is_err());
        let explicit = [update_policy(
            json!({ "action": "BLOCK", "create_allow_respond": false }),
        )];
        assert!(check_firewall_policy_against_live(&preimage, &explicit).is_ok());
    }

    #[test]
    fn updates_to_one_policy_fold() {
        let staged = [
            update_policy(json!({ "action": "BLOCK", "create_allow_respond": false })),
            update_policy(json!({ "create_allow_respond": true })),
        ];
        let result =
            check_firewall_policy_against_live(&respond_preimage("ALLOW", true, false), &staged);
        assert!(result.is_err());
    }

    #[test]
    fn a_create_cannot_claim_predefined() {
        let staged = [StagedMutation::create(
            "firewall_policy",
            json!({ "action": "BLOCK", "create_allow_respond": true, "predefined": true }),
        )];
        let result = check_firewall_policy_against_live(&Preimage::from_resources(vec![]), &staged);
        assert!(result.is_err());
    }

    #[test]
    fn an_update_cannot_claim_predefined() {
        let staged = [update_policy(
            json!({ "action": "BLOCK", "create_allow_respond": true, "predefined": true }),
        )];
        let result =
            check_firewall_policy_against_live(&respond_preimage("ALLOW", true, false), &staged);
        assert!(result.is_err());
    }

    #[test]
    fn a_live_predefined_block_policy_may_be_edited() {
        let staged = [update_policy(json!({ "enabled": false }))];
        let result =
            check_firewall_policy_against_live(&respond_preimage("BLOCK", true, true), &staged);
        assert!(result.is_ok());
    }

    #[test]
    fn other_kinds_are_not_checked_for_respond_traffic() {
        let staged = [StagedMutation::create(
            "network",
            json!({ "action": "BLOCK", "create_allow_respond": true }),
        )];
        let result = check_firewall_policy_against_live(&Preimage::from_resources(vec![]), &staged);
        assert!(result.is_ok());
    }

    fn flow_preimage(supported: bool) -> Preimage {
        Preimage::from_resources(vec![json!({
            "_id": "pol000000000000000000001",
            "action": "ALLOW",
            "predefined": true,
            "report_flow": false,
            "report_flow_supported": supported
        })])
    }

    #[test]
    fn report_flow_on_a_policy_that_cannot_report_flows_is_refused() {
        let staged = [update_policy(json!({ "report_flow": true }))];
        let error = check_firewall_policy_against_live(&flow_preimage(false), &staged)
            .expect_err("the live policy cannot report flows");
        assert!(
            error.to_string().contains("report_flow_supported"),
            "{error}"
        );
        let off = [update_policy(json!({ "report_flow": false }))];
        assert!(check_firewall_policy_against_live(&flow_preimage(false), &off).is_ok());
    }

    #[test]
    fn report_flow_on_a_policy_that_can_report_flows_passes() {
        let staged = [update_policy(json!({ "report_flow": true }))];
        assert!(check_firewall_policy_against_live(&flow_preimage(true), &staged).is_ok());
    }

    #[test]
    fn a_staged_body_cannot_claim_flow_support() {
        let staged = [update_policy(
            json!({ "report_flow_supported": true, "report_flow": true }),
        )];
        assert!(check_firewall_policy_against_live(&flow_preimage(false), &staged).is_err());
    }
}

#[cfg(test)]
mod writable_fields_tests {
    use super::check_writable_fields;
    use crate::changeset::StagedMutation;
    use serde_json::{Value, json};

    /// A field this server does not recognise for the kind must be refused,
    /// not forwarded to the controller.
    /// The zone endpoint refuses `default_zone` and `external_id`, so staging
    /// either is refused here rather than failing at apply with a 400.
    #[test]
    fn a_zone_write_is_refused_a_field_the_zone_endpoint_rejects() {
        for field in ["default_zone", "external_id"] {
            let staged = StagedMutation::update("firewall_zone", "z1", json!({ field: true }));
            let error = check_writable_fields(&[staged]).expect_err("a read-only zone field");
            assert!(error.to_string().contains(field), "{error}");
        }
        let renamed = StagedMutation::update(
            "firewall_zone",
            "z1",
            json!({ "name": "renamed", "network_ids": [] }),
        );
        assert!(check_writable_fields(&[renamed]).is_ok());
    }

    #[test]
    fn a_disallowed_field_is_refused() {
        let staged = StagedMutation::create(
            "network",
            json!({ "name": "corp", "definitely_not_a_real_field": true }),
        );
        let error =
            check_writable_fields(&[staged]).expect_err("an unrecognised field must be refused");
        let rendered = error.to_string();
        assert!(
            rendered.contains("definitely_not_a_real_field"),
            "{rendered}"
        );
        assert!(rendered.contains("network"), "{rendered}");
    }

    /// A reservation create naming a fixed IP must stage `use_fixedip: true`
    /// itself, and an explicit `false` is refused, so what is approved is what
    /// the controller receives.
    #[test]
    fn dhcp_reservation_fixed_ip_requires_use_fixedip() {
        let mac = "aa:bb:cc:dd:ee:ff";
        let missing = StagedMutation::create(
            "dhcp_reservation",
            json!({ "mac": mac, "fixed_ip": "10.0.0.5" }),
        );
        assert!(check_writable_fields(&[missing]).is_err());
        let contradictory = StagedMutation::create(
            "dhcp_reservation",
            json!({ "mac": mac, "fixed_ip": "10.0.0.5", "use_fixedip": false }),
        );
        assert!(check_writable_fields(&[contradictory]).is_err());
        let ok = StagedMutation::create(
            "dhcp_reservation",
            json!({ "mac": mac, "fixed_ip": "10.0.0.5", "use_fixedip": true }),
        );
        assert!(check_writable_fields(&[ok]).is_ok());
        let no_ip = StagedMutation::create("dhcp_reservation", json!({ "mac": mac }));
        assert!(check_writable_fields(&[no_ip]).is_ok());
    }

    /// The controller refuses a BLOCK or REJECT policy unless
    /// `create_allow_respond` is `false`, so staging must say so.
    #[test]
    fn firewall_policy_non_allow_requires_create_allow_respond_false() {
        let refused = [
            StagedMutation::create("firewall_policy", json!({ "name": "p", "action": "BLOCK" })),
            StagedMutation::create(
                "firewall_policy",
                json!({ "action": "REJECT", "create_allow_respond": true }),
            ),
            StagedMutation::update("firewall_policy", "p1", json!({ "action": "BLOCK" })),
        ];
        for staged in refused {
            let error = check_writable_fields(&[staged]).expect_err("respond traffic refused");
            assert!(
                error.to_string().contains("create_allow_respond"),
                "{error}"
            );
        }
        let allowed = [
            StagedMutation::create(
                "firewall_policy",
                json!({ "action": "BLOCK", "create_allow_respond": false }),
            ),
            StagedMutation::create("firewall_policy", json!({ "action": "ALLOW" })),
            StagedMutation::update(
                "firewall_policy",
                "p1",
                json!({ "action": "BLOCK", "create_allow_respond": false }),
            ),
            StagedMutation::update("firewall_policy", "p1", json!({ "name": "x" })),
            StagedMutation::update(
                "firewall_policy",
                "p1",
                json!({ "action": "BLOCK", "create_allow_respond": true, "predefined": true }),
            ),
        ];
        for staged in allowed {
            assert!(check_writable_fields(&[staged]).is_ok());
        }
    }

    /// Deleting a reservation would DELETE the client's whole `user` record;
    /// the refusal must name the update that removes only the reservation.
    #[test]
    fn dhcp_reservation_delete_is_refused() {
        let staged = StagedMutation::delete("dhcp_reservation", "665f1c2e8a3b4d0001aa0001");
        let error = check_writable_fields(&[staged]).expect_err("a reservation delete is refused");
        assert!(error.to_string().contains("use_fixedip"), "{error}");
    }

    /// The supported way to drop a reservation is an update clearing the flag.
    #[test]
    fn dhcp_reservation_update_clearing_use_fixedip_passes() {
        let staged = StagedMutation::update(
            "dhcp_reservation",
            "665f1c2e8a3b4d0001aa0001",
            json!({ "use_fixedip": false }),
        );
        assert!(check_writable_fields(&[staged]).is_ok());
    }

    /// A body naming only allowed fields must pass.
    #[test]
    fn only_allowed_fields_passes() {
        let staged = StagedMutation::create(
            "network",
            json!({ "name": "corp", "vlan": 20, "purpose": "corporate" }),
        );
        assert!(check_writable_fields(&[staged]).is_ok());
    }

    /// #143: a network read back through the MCP restages as a faithful
    /// copy, and a reservation can follow it to the new network.
    #[test]
    fn a_read_network_and_its_reservation_restage_for_a_move() {
        let network = StagedMutation::create(
            "network",
            json!({
                "name": "corp", "purpose": "vlan-only", "vlan_enabled": true, "vlan": 20,
                "enabled": true, "networkgroup": "LAN", "firewall_zone_id": "z1",
                "domain_name": "corp.invalid", "igmp_snooping": false,
                "internet_access_enabled": true, "network_isolation_enabled": false,
                "dhcpd_leasetime": 86400, "dhcpd_dns_enabled": true, "dhcpd_dns_1": "192.0.2.53",
                "dhcpd_dns_2": "", "dhcpd_dns_3": "", "dhcpd_dns_4": ""
            }),
        );
        let reservation =
            StagedMutation::update("dhcp_reservation", "u1", json!({ "network_id": "n2" }));
        assert!(check_writable_fields(&[network, reservation]).is_ok());

        for read_only in ["attr_no_delete", "wan_type"] {
            let staged =
                StagedMutation::create("network", json!({ "name": "corp", read_only: "x" }));
            assert!(
                check_writable_fields(&[staged]).is_err(),
                "{read_only} must stay read-only"
            );
        }
    }

    /// `station` is a read/observability kind served from the Integration
    /// API; there is no verified write route for it. Staging a create must
    /// be refused before it ever reaches a change set.
    #[test]
    fn a_write_to_a_read_only_kind_is_refused() {
        let staged = StagedMutation::create("station", json!({ "name": "someones-laptop" }));
        let error = check_writable_fields(&[staged])
            .expect_err("a write to a read-only kind must be refused");
        assert!(error.to_string().contains("station"), "{error}");
    }

    /// `device` carries the same refusal as `station` — this is the gap
    /// `client.rs` used to close only for updates (`kind == "device"`).
    /// Creates and deletes must be refused the same way, and earlier: at
    /// staging, not at apply.
    #[test]
    fn a_device_update_is_refused() {
        let staged = StagedMutation::update("device", "abc123", json!({ "name": "renamed-ap" }));
        let error =
            check_writable_fields(&[staged]).expect_err("device writes have no verified route");
        assert!(error.to_string().contains("device"), "{error}");
    }

    /// Deletes carry no body, but a read-only kind must still be refused —
    /// deleting is a write too.
    #[test]
    fn a_delete_of_a_read_only_kind_is_refused() {
        let staged = StagedMutation::delete("device", "abc123");
        assert!(check_writable_fields(&[staged]).is_err());
    }

    /// Port forwards and static routes are writable (#143); the legacy
    /// `firewall_rule` kind is not.
    #[test]
    fn port_forward_and_static_route_writes_are_gated_by_field() {
        let forward = StagedMutation::create(
            "port_forward",
            json!({ "name": "ssh", "enabled": true, "pfwd_interface": "wan", "src": "any",
                    "dst_port": "2222", "fwd": "192.0.2.10", "fwd_port": "22",
                    "proto": "tcp", "destination_ip": "203.0.113.10", "log": false }),
        );
        assert!(check_writable_fields(&[forward]).is_ok());
        let route = StagedMutation::update(
            "static_route",
            "abc123",
            json!({ "name": "lab", "type": "static-route", "enabled": true,
                    "static-route_type": "nexthop-route",
                    "static-route_network": "198.51.100.0/24",
                    "static-route_nexthop": "192.0.2.1", "static-route_distance": 1,
                    "static-route_interface": "wan" }),
        );
        assert!(check_writable_fields(&[route]).is_ok());
        for kind in ["port_forward", "static_route"] {
            let bad = StagedMutation::create(kind, json!({ "name": "x", "_id": "y" }));
            let error = check_writable_fields(&[bad]).expect_err("unknown field must be refused");
            assert!(error.to_string().contains("_id"), "{error}");
        }
        let rule = StagedMutation::create("firewall_rule", json!({ "name": "x" }));
        assert!(check_writable_fields(&[rule]).is_err());
    }

    /// A restore addresses the whole controller, not a kind, so it is not
    /// checked here — [`crate::changeset::apply::ControllerOps`] refuses it
    /// unconditionally at apply.
    #[test]
    fn a_restore_is_not_checked() {
        let staged = StagedMutation::restore("backup-1");
        assert!(check_writable_fields(&[staged]).is_ok());
    }

    /// `firewall_policy` deliberately allows the wider set of fields its
    /// round-trip test fixture carries, because the authoring loop is "read a
    /// working policy, change one field, stage it back."
    #[test]
    fn a_firewall_policy_update_keeps_its_full_field_set() {
        let staged = StagedMutation::update(
            "firewall_policy",
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            json!({
                "name": "Phones to DMZ web (https)",
                "action": "ALLOW",
                "enabled": true,
                "index": 10000,
                "predefined": false,
                "protocol": "tcp",
                "ip_version": "BOTH",
                "logging": false,
                "connection_state_type": "ALL",
                "connection_states": [],
                "schedule": { "mode": "ALWAYS" },
                "source": { "zone_id": "b", "matching_target": "ANY" },
                "destination": { "zone_id": "c", "matching_target": "IP" }
            }),
        );
        assert!(check_writable_fields(&[staged]).is_ok());
    }

    /// A policy as a real controller returns it, minus the server-managed
    /// fields, must stage: the read-edit-restage loop has to work for every
    /// policy, not just ones shaped like the synthetic fixture.
    #[test]
    fn a_real_controller_policy_stages_without_its_server_managed_fields() {
        let inline = json!({
            "name": "p", "action": "ALLOW", "enabled": true, "index": 1,
            "predefined": false, "protocol": "all", "ip_version": "BOTH",
            "logging": false, "connection_state_type": "ALL", "connection_states": [],
            "schedule": { "mode": "ALWAYS" }, "source": {}, "destination": {},
            "description": "d", "create_allow_respond": false, "icmp_typename": "ANY",
            "icmp_v6_typename": "ANY", "match_ip_sec": false,
            "match_opposite_protocol": false
        });
        let mut bodies = vec![inline];
        for version in crate::testing::fixture_versions() {
            let recorded = crate::testing::fixture(&version, "policies");
            bodies.extend(recorded.as_array().cloned().unwrap_or_default());
        }
        for mut body in bodies {
            // `x_shared_secret` is the synthetic set's scrub-gate canary, not a controller field.
            for field in [
                "_id",
                "hits",
                "last_hit",
                "origin_id",
                "origin_type",
                "report_flow_supported",
                "x_shared_secret",
            ] {
                body.as_object_mut().expect("object").remove(field);
            }
            let staged = StagedMutation::create("firewall_policy", body);
            assert!(check_writable_fields(&[staged]).is_ok());
        }
    }

    /// Controller-managed identity fields must never be settable through a
    /// staged body, for any kind — a body that names them is trying to
    /// reassign identity, not configure the resource.
    #[test]
    fn no_kind_allows_setting_the_controller_managed_id() {
        let staged = StagedMutation::update(
            "network",
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            json!({ "name": "corp", "_id": "attacker-chosen" }),
        );
        let error = check_writable_fields(&[staged]).expect_err("_id must never be writable");
        assert!(error.to_string().contains("_id"), "{error}");
    }

    /// An unknown kind string is refused with a clear reason rather than a
    /// panic or a silent pass.
    #[test]
    fn an_unknown_kind_is_refused() {
        let staged = StagedMutation::create("not_a_real_kind", json!({}));
        assert!(check_writable_fields(&[staged]).is_err());
    }

    /// `MutationSpec` accepts any JSON as a body, and the field loop used to
    /// `continue` past a non-object body -- an empty allowlist scan finds no
    /// disallowed field in `[]`, `null`, a string, or a number, so all four
    /// passed with no fields checked at all. A non-object body must be
    /// refused outright, the same way an unrecognised field is.
    #[test]
    fn a_null_body_is_refused() {
        let staged = StagedMutation::update("network", "aaaaaaaaaaaaaaaaaaaaaaaa", Value::Null);
        assert!(check_writable_fields(&[staged]).is_err());
    }

    #[test]
    fn an_array_body_is_refused() {
        let staged = StagedMutation::update(
            "network",
            "aaaaaaaaaaaaaaaaaaaaaaaa",
            json!(["not", "a", "map"]),
        );
        assert!(check_writable_fields(&[staged]).is_err());
    }

    #[test]
    fn a_string_body_is_refused() {
        let staged = StagedMutation::create("network", json!("just a string"));
        assert!(check_writable_fields(&[staged]).is_err());
    }

    #[test]
    fn a_number_body_is_refused() {
        let staged = StagedMutation::create("network", json!(42));
        assert!(check_writable_fields(&[staged]).is_err());
    }
}
