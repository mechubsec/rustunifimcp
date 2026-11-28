//! Re-indexing one zone pair's custom firewall policies.
//!
//! UniFi evaluates a zone pair's policies by `index`, first match. Verified on
//! UniFi Network 10.6.109: the controller ignores `index` on create (it assigns
//! the next free value) and ignores a changed `index` on PUT. Only
//! `PUT /v2/api/site/<site>/firewall-policies/batch-reorder` re-indexes, with
//! the body [`batch_body`] builds; it re-indexed the listed policies to
//! 40000, 40001, ...
//!
//! A reorder's pre-image is the pair's order, stored under [`pair_key`] so it
//! travels through the record, the fingerprint and the digest like any other
//! pre-image entry.

use super::preimage::{OrderEntry, Preimage, StagedMutation};
use crate::error::UnifiError;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};

/// The only kind a reorder addresses.
pub const POLICY_KIND: &str = "firewall_policy";

/// The batch-reorder route, on the Private v2 surface.
pub const BATCH_REORDER_PATH: &str =
    "/proxy/network/v2/api/site/{site}/firewall-policies/batch-reorder";

/// The pre-image key for a zone pair's order. Cannot collide with a resource
/// `_id`, which is 24 hex characters.
#[must_use]
pub fn pair_key(source_zone_id: &str, destination_zone_id: &str) -> String {
    format!("zone-pair:{source_zone_id}:{destination_zone_id}")
}

/// The batch-reorder request body, in the shape the controller accepted.
///
/// `before_predefined_ids` is always empty: [`pair_entry`] refuses a pair with
/// a custom policy placed before its predefined ones, so nothing belongs there.
#[must_use]
pub fn batch_body(source_zone_id: &str, destination_zone_id: &str, ids: &[String]) -> Value {
    json!({
        "source_zone_id": source_zone_id,
        "destination_zone_id": destination_zone_id,
        "before_predefined_ids": [],
        "after_predefined_ids": ids,
    })
}

/// Whether a policy's zones are this pair.
fn in_pair(policy: &Value, source_zone_id: &str, destination_zone_id: &str) -> bool {
    policy.pointer("/source/zone_id").and_then(Value::as_str) == Some(source_zone_id)
        && policy
            .pointer("/destination/zone_id")
            .and_then(Value::as_str)
            == Some(destination_zone_id)
}

/// A pair's state as the controller's policy list shows it: the custom policy
/// ids in index order, and the predefined ones, which a reorder never moves.
///
/// # Errors
///
/// [`UnifiError::Malformed`] for a list that is not an array of policies with
/// an `_id` and a numeric `index`. [`UnifiError::WriteRefused`] when a custom
/// policy sits before a predefined one in the pair: the controller's
/// `before_predefined_ids` placement is unverified, and sending the custom
/// policies as `after_predefined_ids` would move that one behind the
/// predefined policies.
pub fn pair_entry(
    policies: &Value,
    source_zone_id: &str,
    destination_zone_id: &str,
) -> Result<Value, UnifiError> {
    let items = policies
        .as_array()
        .ok_or_else(|| UnifiError::Malformed("firewall policy list is not an array".to_owned()))?;

    let mut custom: Vec<(u64, String)> = Vec::new();
    let mut predefined: Vec<(u64, String)> = Vec::new();
    for policy in items
        .iter()
        .filter(|policy| in_pair(policy, source_zone_id, destination_zone_id))
    {
        let id = policy.get("_id").and_then(Value::as_str).ok_or_else(|| {
            UnifiError::Malformed("a firewall policy in the list has no `_id`".to_owned())
        })?;
        let index = policy.get("index").and_then(Value::as_u64).ok_or_else(|| {
            UnifiError::Malformed(format!("firewall policy {id} has no numeric `index`"))
        })?;
        let bucket = if policy.get("predefined") == Some(&Value::Bool(true)) {
            &mut predefined
        } else {
            &mut custom
        };
        bucket.push((index, id.to_owned()));
    }
    custom.sort();
    predefined.sort();

    if let (Some((first_custom, custom_id)), Some((last_predefined, predefined_id))) =
        (custom.first(), predefined.last())
        && first_custom < last_predefined
    {
        return Err(UnifiError::WriteRefused(format!(
            "zone pair {source_zone_id} -> {destination_zone_id}: custom policy {custom_id} \
             (index {first_custom}) sits before predefined policy {predefined_id} (index \
             {last_predefined}); this server only reorders custom policies placed after the \
             predefined ones, so it refuses rather than move it"
        )));
    }

    let ids = |list: Vec<(u64, String)>| list.into_iter().map(|(_, id)| id).collect::<Vec<_>>();
    Ok(json!({
        "_id": pair_key(source_zone_id, destination_zone_id),
        "source_zone_id": source_zone_id,
        "destination_zone_id": destination_zone_id,
        "order": ids(custom),
        "predefined_ids": ids(predefined),
    }))
}

/// The custom policy ids of a pair entry, in order.
#[must_use]
pub fn entry_order(entry: &Value) -> Vec<String> {
    entry
        .get("order")
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The pair's live entry, read from the controller's policy list.
///
/// # Errors
///
/// The list request's error, or as [`pair_entry`].
pub async fn pair_live(
    client: &crate::client::UnifiClient,
    source_zone_id: &str,
    destination_zone_id: &str,
) -> Result<Value, UnifiError> {
    use crate::ApiSurface;
    use crate::model::ResourceKind;

    let site = client.default_site_for(ApiSurface::PrivateV2).await?;
    let policies = client
        .get(
            ApiSurface::PrivateV2,
            ResourceKind::FirewallPolicy.path_template(),
            &[("site", &site)],
            &[],
        )
        .await?;
    pair_entry(&policies, source_zone_id, destination_zone_id)
}

/// Capture a reorder's pre-image, refusing a zone the controller lacks.
///
/// # Errors
///
/// [`UnifiError::ReferenceNotFound`] for an unknown zone; otherwise as
/// [`pair_live`].
pub async fn capture_pair(
    client: &crate::client::UnifiClient,
    source_zone_id: &str,
    destination_zone_id: &str,
) -> Result<Value, UnifiError> {
    use crate::ApiSurface;
    use crate::model::ResourceKind;

    let site = client.default_site_for(ApiSurface::PrivateV2).await?;
    let zones = client
        .get(
            ApiSurface::PrivateV2,
            ResourceKind::FirewallZone.path_template(),
            &[("site", &site)],
            &[],
        )
        .await?;
    let zones = super::ZoneIndex::from_zone_list(&zones)?;
    for zone_id in [source_zone_id, destination_zone_id] {
        if !zones.contains(zone_id) {
            return Err(UnifiError::ReferenceNotFound(format!(
                "staged reorder names zone '{zone_id}', which the controller does not have"
            )));
        }
    }
    pair_live(client, source_zone_id, destination_zone_id).await
}

/// The staged create a `created_name` refers to, as `(position, body)`.
fn creates_named<'a>(mutations: &'a [StagedMutation], name: &str) -> Vec<(usize, &'a Value)> {
    mutations
        .iter()
        .enumerate()
        .filter_map(|(position, mutation)| match mutation {
            StagedMutation::Create { kind, body }
                if kind == POLICY_KIND
                    && body.get("name").and_then(Value::as_str) == Some(name) =>
            {
                Some((position, body))
            }
            _ => None,
        })
        .collect()
}

/// Refuse a staged reorder that is not a permutation of its pair.
///
/// Pure over the plan and its pre-image, so staging, validation, approval and
/// apply all run the same check. Refused: a kind other than
/// `firewall_policy`; a second reorder of one pair; an id that is not one of
/// the pair's custom policies (a predefined or foreign one included); a
/// duplicate; an order that omits a custom policy, or omits a policy this set
/// creates in the pair before the reorder; a `created_name` that names no
/// create, more than one, a later one, or one in another pair; and a delete,
/// or a zone-changing update, of a policy the order places.
///
/// # Errors
///
/// [`UnifiError::WriteRefused`] or [`UnifiError::ReferenceNotFound`] naming
/// the problem.
pub fn check_policy_reorders(
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<(), UnifiError> {
    let mut seen_pairs = BTreeSet::new();

    for (position, mutation) in mutations.iter().enumerate() {
        let StagedMutation::Reorder {
            kind,
            source_zone_id: source,
            destination_zone_id: destination,
            order,
        } = mutation
        else {
            continue;
        };
        let what = mutation.preview();
        let refuse = |reason: String| UnifiError::WriteRefused(format!("staged {what}: {reason}"));

        if kind != POLICY_KIND {
            return Err(refuse(format!(
                "only kind '{POLICY_KIND}' can be reordered"
            )));
        }
        let key = pair_key(source, destination);
        if !seen_pairs.insert(key.clone()) {
            return Err(refuse(
                "a change set may reorder a zone pair once; combine the orders".to_owned(),
            ));
        }
        let Some(entry) = preimage.get_resource(&key) else {
            return Err(refuse(
                "the pre-image does not hold the pair's order".to_owned(),
            ));
        };
        let live: BTreeSet<String> = entry_order(&entry).into_iter().collect();
        let predefined: BTreeSet<String> = entry
            .get("predefined_ids")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        let mut placed_ids = BTreeSet::new();
        let mut placed_names = BTreeSet::new();
        for item in order {
            match item {
                OrderEntry::Id(id) => {
                    if predefined.contains(id) {
                        return Err(refuse(format!(
                            "{id} is a predefined policy; only custom policies are reordered"
                        )));
                    }
                    if !live.contains(id) {
                        return Err(UnifiError::ReferenceNotFound(format!(
                            "staged {what}: {id} is not a custom policy of this zone pair"
                        )));
                    }
                    if !placed_ids.insert(id.clone()) {
                        return Err(refuse(format!("{id} appears twice")));
                    }
                }
                OrderEntry::Created(created) => {
                    let name = &created.created_name;
                    let named = creates_named(mutations, name);
                    let [(created_at, body)] = named.as_slice() else {
                        return Err(refuse(format!(
                            "created_name '{name}' must name exactly one staged {POLICY_KIND} \
                             create; it names {}",
                            named.len()
                        )));
                    };
                    if *created_at > position {
                        return Err(refuse(format!(
                            "'{name}' is created after the reorder; stage its create first"
                        )));
                    }
                    if !in_pair(body, source, destination) {
                        return Err(refuse(format!("'{name}' is created in another zone pair")));
                    }
                    if !placed_names.insert(name.clone()) {
                        return Err(refuse(format!("'{name}' appears twice")));
                    }
                }
            }
        }

        if let Some(missing) = live.difference(&placed_ids).next() {
            return Err(refuse(format!(
                "not a permutation of the pair: custom policy {missing} is missing"
            )));
        }
        for earlier in &mutations[..position] {
            if let StagedMutation::Create { kind, body } = earlier
                && kind == POLICY_KIND
                && in_pair(body, source, destination)
            {
                let name = body.get("name").and_then(Value::as_str).unwrap_or_default();
                if !placed_names.contains(name) {
                    return Err(refuse(format!(
                        "not a permutation of the pair: '{name}' is created in it earlier \
                         in this set and is missing"
                    )));
                }
            }
        }
        for other in mutations {
            match other {
                StagedMutation::Delete { kind, id }
                    if kind == POLICY_KIND && placed_ids.contains(id) =>
                {
                    return Err(refuse(format!("this set also deletes {id}")));
                }
                StagedMutation::Update { kind, id, body }
                    if kind == POLICY_KIND
                        && placed_ids.contains(id)
                        && (body.get("source").is_some() || body.get("destination").is_some()) =>
                {
                    return Err(refuse(format!("this set also moves {id} to another zone")));
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// The mutation at `position` with every `created_name` replaced by the id
/// its create returned. Other mutations come back unchanged.
///
/// # Errors
///
/// [`UnifiError::Malformed`] if a referenced create recorded no id, which
/// [`check_policy_reorders`] and the in-order apply make unreachable.
pub fn resolve_created(
    mutations: &[StagedMutation],
    position: usize,
    created_ids: &HashMap<usize, String>,
) -> Result<StagedMutation, UnifiError> {
    let mut resolved = mutations[position].clone();
    let StagedMutation::Reorder { order, .. } = &mut resolved else {
        return Ok(resolved);
    };
    for item in order.iter_mut() {
        let OrderEntry::Created(created) = item else {
            continue;
        };
        let id = creates_named(&mutations[..position], &created.created_name)
            .first()
            .and_then(|(created_at, _)| created_ids.get(created_at))
            .ok_or_else(|| {
                UnifiError::Malformed(format!(
                    "reorder: no created id for '{}'",
                    created.created_name
                ))
            })?;
        *item = OrderEntry::Id(id.clone());
    }
    Ok(resolved)
}

/// The ids of a resolved order.
///
/// # Errors
///
/// [`UnifiError::Malformed`] if a `created_name` was never resolved.
pub fn resolved_ids(order: &[OrderEntry]) -> Result<Vec<String>, UnifiError> {
    order
        .iter()
        .map(|item| match item {
            OrderEntry::Id(id) => Ok(id.clone()),
            OrderEntry::Created(created) => Err(UnifiError::Malformed(format!(
                "reorder: '{}' was not resolved to an id",
                created.created_name
            ))),
        })
        .collect()
}

/// The order rollback sends: the pre-image order, then every policy the
/// applied order placed that the pre-image did not hold (one this set
/// created). Rollback runs in reverse, so the reorder is undone while that
/// policy still exists and is deleted next; sending it last keeps the body a
/// full permutation, the only shape verified, and if its delete fails it is
/// stranded at the bottom of the pair, behind every policy that was there.
#[must_use]
pub fn rollback_ids(prior_entry: &Value, applied: &[String]) -> Vec<String> {
    let mut ids = entry_order(prior_entry);
    for id in applied {
        if !ids.contains(id) {
            ids.push(id.clone());
        }
    }
    ids
}

/// Whether the live pair holds `applied` in that order. Policies the order
/// did not name (one created later in the set) are ignored.
#[must_use]
pub fn order_took(live_entry: &Value, applied: &[String]) -> bool {
    let live: Vec<String> = entry_order(live_entry)
        .into_iter()
        .filter(|id| applied.contains(id))
        .collect();
    live == applied
}

