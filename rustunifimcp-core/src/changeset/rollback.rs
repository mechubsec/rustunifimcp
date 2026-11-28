//! Best-effort rollback to pre-image state.
//!
//! UniFi has no checkpoint to roll back to, so rollback replays the pre-image
//! as a sequence of REST calls. The rollback itself can fail partway through.

use super::apply::ControllerOps;
use super::preimage::{Preimage, StagedMutation};

/// Attempt to roll back to the pre-image state.
///
/// # Errors
///
/// Returns a Vec of failure descriptions if any rollback operations fail.
/// An empty Vec indicates success; a non-empty Vec indicates partial rollback.
pub async fn rollback_to_preimage<C>(
    controller: &C,
    preimage: &Preimage,
    succeeded: &[StagedMutation],
    created_ids: &std::collections::HashMap<usize, String>,
) -> Result<(), Vec<String>>
where
    C: ControllerOps,
{
    let mut failures = Vec::new();

    // Roll back in reverse order - last mutation first
    for (forward_index, mutation) in succeeded.iter().enumerate().rev() {
        // Extract the prior value from the pre-image based on mutation type
        let prior_value = match mutation {
            StagedMutation::Create { .. } => None, // No prior value for creates
            StagedMutation::Update { id, .. } | StagedMutation::Delete { id, .. } => {
                preimage.get_resource(id)
            }
            StagedMutation::Reorder { .. } => mutation
                .preimage_key()
                .and_then(|key| preimage.get_resource(&key)),
            StagedMutation::Restore { .. } => {
                // Restores cannot be rolled back - the entire controller was overwritten
                failures.push(format!(
                    "cannot rollback {} (mutation {forward_index}): restores cannot be undone",
                    mutation.preview(),
                ));
                continue;
            }
        };

        let created_id = created_ids.get(&forward_index).map(String::as_str);

        if let Err(e) = controller
            .rollback_mutation(forward_index, mutation, prior_value.as_ref(), created_id)
            .await
        {
            failures.push(format!(
                "rollback failed for {} (mutation {forward_index}): {e}",
                mutation.preview(),
            ));
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}
