//! Mapping a UniFi change set onto `mecmcp-changeset`'s record.
//!
//! The shared crate owns the lifecycle — the transition policy, the
//! claim-before-apply, the preview-bound approval — and it stores a change set
//! as an owner, a device, an expected fingerprint and an ordered list of
//! opaque `actions`. UniFi's change set carries two things that do not map
//! onto a field of their own: the staged mutations, and the pre-image they
//! were planned against.
//!
//! Both go into `actions`, one [`StagedAction`] per mutation.
//! [`mecmcp_changeset::ChangeSetRecord`] is `deny_unknown_fields`, so a
//! side-car field is not available; and folding the pre-image in is the better
//! answer anyway. The plan digest is computed over the actions, and the
//! approval digest binds to the plan digest, so an approval now covers the
//! pre-image the plan was built against — a state file edited to swap a
//! pre-image no longer verifies.

use crate::changeset::{Preimage, StagedMutation};
use crate::error::UnifiError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One entry of a change set's `actions`.
///
/// A mutation and the resource it was planned against, kept together so
/// neither can be swapped for the other's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedAction {
    /// The planned mutation.
    pub mutation: StagedMutation,
    /// The resource as it stood when the mutation was staged.
    ///
    /// Absent for a create, which has no prior state, and for a restore, whose
    /// pre-image would be the whole controller. That absence is what lets
    /// rollback delete a created resource rather than guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<Value>,
}

/// Pair each mutation with its pre-image entry.
///
/// The order is the staging order, which apply follows, so the actions are the
/// plan and not merely a set of it.
#[must_use]
pub fn actions_for(mutations: &[StagedMutation], preimage: &Preimage) -> Vec<StagedAction> {
    mutations
        .iter()
        .map(|mutation| StagedAction {
            mutation: mutation.clone(),
            preimage: mutation
                .preimage_key()
                .and_then(|key| preimage.get_resource(&key)),
        })
        .collect()
}

/// Read the actions back off a stored record.
///
/// # Errors
///
/// Returns [`UnifiError::Malformed`] if an action is not a [`StagedAction`].
/// The state file is the server's own, so this is corruption or a version
/// mismatch rather than caller input, and it must not be read as an empty plan
/// — an empty plan would apply cleanly and change nothing while reporting
/// success.
pub fn actions_of(actions: &[Value]) -> Result<Vec<StagedAction>, UnifiError> {
    actions
        .iter()
        .enumerate()
        .map(|(position, action)| {
            serde_json::from_value(action.clone()).map_err(|error| {
                UnifiError::Malformed(format!(
                    "change set action {position} is not a staged action: {error}"
                ))
            })
        })
        .collect()
}

/// The mutations a stored record plans, in staging order.
///
/// # Errors
///
/// As [`actions_of`].
pub fn mutations_of(actions: &[Value]) -> Result<Vec<StagedMutation>, UnifiError> {
    Ok(actions_of(actions)?
        .into_iter()
        .map(|action| action.mutation)
        .collect())
}

/// The pre-image a stored record was planned against.
///
/// # Errors
///
/// As [`actions_of`].
pub fn preimage_of(actions: &[Value]) -> Result<Preimage, UnifiError> {
    Ok(Preimage::from_resources(
        actions_of(actions)?
            .into_iter()
            .filter_map(|action| action.preimage)
            .collect(),
    ))
}

/// The fingerprint of the controller state a plan was built against.
///
/// UniFi has no candidate configuration, so there is no candidate to
/// fingerprint. What the shared crate needs from
/// `expected_candidate_fingerprint` is a value that changes when the state the
/// plan assumed changes, and for UniFi that is the pre-image. Fingerprinting
/// it gives the lifecycle the staleness check the vendor does not provide.
///
/// An empty plan fingerprints the empty pre-image rather than failing: a
/// change set exists before anything is staged into it.
///
/// # Errors
///
/// Returns [`UnifiError::Malformed`] if the actions cannot be serialized.
pub fn fingerprint_of(actions: &[StagedAction]) -> Result<String, UnifiError> {
    let entries: Vec<&Value> = actions
        .iter()
        .filter_map(|action| action.preimage.as_ref())
        .collect();

    let encoded = serde_json::to_vec(&entries).map_err(|error| {
        UnifiError::Malformed(format!("could not fingerprint the pre-image: {error}"))
    })?;

    Ok(format!(
        "sha256:{}",
        mecmcp_changeset::digest::digest_hex(&encoded)
    ))
}

#[cfg(test)]
mod tests {
    use super::{actions_for, fingerprint_of, mutations_of, preimage_of};
    use crate::changeset::{Preimage, StagedMutation};
    use serde_json::json;

    fn live_policy() -> Preimage {
        Preimage::from_resources(vec![json!({
            "_id": "dddddddddddddddddddddddd",
            "name": "live policy",
            "enabled": false
        })])
    }

    fn plan() -> Vec<StagedMutation> {
        vec![
            StagedMutation::update(
                "firewall_policy",
                "dddddddddddddddddddddddd",
                json!({ "enabled": true }),
            ),
            StagedMutation::create("firewall_policy", json!({ "name": "new policy" })),
        ]
    }

    /// The record is the only place the plan lives, so what goes in has to come
    /// back out -- mutations, order, and the pre-image each was planned
    /// against.
    #[test]
    fn a_plan_round_trips_through_the_actions() {
        let actions = actions_for(&plan(), &live_policy());
        let stored: Vec<serde_json::Value> = actions
            .iter()
            .map(|action| serde_json::to_value(action).expect("serialize"))
            .collect();

        assert_eq!(mutations_of(&stored).expect("read back"), plan());

        let recovered = preimage_of(&stored).expect("read back");
        assert!(
            recovered.get_resource("dddddddddddddddddddddddd").is_some(),
            "the update's pre-image entry was lost"
        );
    }

    /// A create has no prior state. Recording one anyway would make rollback
    /// restore a resource that never existed instead of deleting it.
    #[test]
    fn a_create_carries_no_preimage() {
        let actions = actions_for(&plan(), &live_policy());
        assert!(actions[1].preimage.is_none(), "{:?}", actions[1]);
        assert!(actions[0].preimage.is_some(), "{:?}", actions[0]);
    }

    /// The state file is the server's own. An unreadable action is corruption
    /// or a version mismatch, and reading it as an empty plan would apply
    /// nothing and report success.
    #[test]
    fn an_unreadable_action_is_an_error_not_an_empty_plan() {
        let stored = vec![json!({ "not": "a staged action" })];
        let error = mutations_of(&stored).expect_err("this is not a staged action");
        assert!(error.to_string().contains("action 0"), "{error}");
    }

    /// The fingerprint stands in for a candidate UniFi does not have. It has to
    /// move when the state the plan assumed moves, or the staleness check the
    /// lifecycle performs at apply is vacuous.
    #[test]
    fn the_fingerprint_follows_the_preimage() {
        let before = fingerprint_of(&actions_for(&plan(), &live_policy())).expect("fingerprint");

        let drifted = Preimage::from_resources(vec![json!({
            "_id": "dddddddddddddddddddddddd",
            "name": "live policy",
            "enabled": true
        })]);
        let after = fingerprint_of(&actions_for(&plan(), &drifted)).expect("fingerprint");

        assert_ne!(before, after, "the fingerprint ignored the drift");
    }

    /// And it must satisfy the shared crate's format check, or every insert is
    /// refused.
    #[test]
    fn the_fingerprint_is_in_the_format_the_lifecycle_requires() {
        let fingerprint = fingerprint_of(&actions_for(&plan(), &live_policy())).expect("f");
        mecmcp_changeset::digest::validate_fingerprint(&fingerprint)
            .expect("the lifecycle must accept the fingerprint we mint");
    }

    /// A change set exists before anything is staged into it, so the empty
    /// plan has to fingerprint rather than fail.
    #[test]
    fn an_empty_plan_still_fingerprints() {
        let fingerprint = fingerprint_of(&[]).expect("an empty plan fingerprints");
        mecmcp_changeset::digest::validate_fingerprint(&fingerprint).expect("valid format");
    }
}
