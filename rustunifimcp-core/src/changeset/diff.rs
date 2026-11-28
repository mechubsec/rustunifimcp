//! Client-side diff computation.
//!
//! UniFi has no candidate configuration, so diffs are computed client-side by
//! comparing the pre-image against the desired state from staged mutations.

use crate::error::UnifiError;

use super::preimage::{Preimage, StagedMutation};

/// A computed diff between pre-image and staged mutations.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Diff {
    /// Whether the diff was actually computed.
    ///
    /// An empty diff is distinguishable from one that was never computed.
    /// This project has hit "empty result indistinguishable from no work"
    /// four separate times.
    pub computed: bool,
    /// The changes that would be applied.
    pub changes: Vec<Change>,
}

/// A single change in a diff.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Change {
    /// The mutation that will be applied.
    pub mutation: StagedMutation,
    /// A preview of what this change does.
    pub preview: String,
    /// The value before the change (None for creates).
    pub before: Option<serde_json::Value>,
    /// The value after the change (None for deletes).
    pub after: Option<serde_json::Value>,
}

/// Compute a diff between the pre-image and staged mutations.
///
/// # Errors
///
/// Returns an error if the diff computation fails.
pub fn diff_against_preimage(
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Result<Diff, UnifiError> {
    let changes = mutations
        .iter()
        .map(|mutation| {
            // `before` comes from the pre-image, which is kept raw for drift
            // detection and rollback, so it is projected through the per-kind
            // allowlist here, at output (MEC-737 F1). `after` is the staged mutation's own body --
            // caller-supplied, not fetched from the controller by this
            // function -- but is projected the same way before it reaches
            // the model, so a body built by copying fields forward from an
            // earlier raw read (e.g. an update that merges in unrelated
            // fields from the resource it is patching) cannot carry a
            // secret field the read path would have dropped.
            let (before, after) = match mutation {
                StagedMutation::Create { kind, body } => {
                    (None, Some(crate::redact::project_by_kind_name(kind, body)))
                }
                StagedMutation::Update { kind, id, body } => (
                    preimage
                        .get_resource(id)
                        .map(|before| crate::redact::project_by_kind_name(kind, &before)),
                    Some(crate::redact::project_by_kind_name(kind, body)),
                ),
                StagedMutation::Delete { kind, id } => (
                    preimage
                        .get_resource(id)
                        .map(|before| crate::redact::project_by_kind_name(kind, &before)),
                    None,
                ),
                StagedMutation::Restore { backup_id } => {
                    // Restore overwrites the entire controller, so there's no meaningful
                    // before/after at the resource level. The backup_id is the "after".
                    (None, Some(serde_json::json!({"backup_id": backup_id})))
                }
                // Ids only, so nothing to project: the pair's order before,
                // and the staged order (created policies by name) after.
                StagedMutation::Reorder { order, .. } => (
                    mutation
                        .preimage_key()
                        .and_then(|key| preimage.get_resource(&key)),
                    Some(serde_json::json!({ "order": order })),
                ),
            };

            Change {
                preview: mutation.preview(),
                mutation: mutation.clone(),
                before,
                after,
            }
        })
        .collect();

    Ok(Diff {
        computed: true,
        changes,
    })
}

#[cfg(test)]
mod tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};
    use serde_json::json;

    /// An empty diff is not the same as a diff that was never computed.
    #[test]
    fn a_no_op_change_set_is_distinguishable_from_an_uncomputed_one() {
        let preimage =
            super::Preimage::from_fixture(&fixture(DEFAULT_FIXTURE_VERSION, "networkconf"));
        let diff = super::diff_against_preimage(&preimage, &[]).expect("diffs");
        assert!(diff.computed);
        assert!(diff.changes.is_empty());
    }

    /// The diff must show before and after values from the pre-image and mutations.
    #[test]
    fn diff_shows_before_and_after_values_for_update() {
        use super::{Preimage, StagedMutation};

        let preimage_data = json!({
            "data": [{
                "_id": "id1",
                "name": "before_value"
            }]
        });
        let preimage = Preimage::from_fixture(&preimage_data);

        let mutations = vec![StagedMutation::update(
            "network",
            "id1",
            json!({"name": "after_value"}),
        )];

        let diff = super::diff_against_preimage(&preimage, &mutations).expect("diff");

        assert_eq!(diff.changes.len(), 1);
        let change = &diff.changes[0];

        assert!(
            change.before.is_some(),
            "update should have a before value from pre-image"
        );
        assert_eq!(
            change
                .before
                .as_ref()
                .expect("before value")
                .get("name")
                .and_then(|v| v.as_str()),
            Some("before_value"),
            "before should be the pre-image value"
        );

        assert!(
            change.after.is_some(),
            "update should have an after value from the mutation"
        );
        assert_eq!(
            change
                .after
                .as_ref()
                .expect("after value")
                .get("name")
                .and_then(|v| v.as_str()),
            Some("after_value"),
            "after should be the mutation value"
        );
    }
}
