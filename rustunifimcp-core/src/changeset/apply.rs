//! Sequential apply and verification.
//!
//! UniFi has no atomic commit, so apply is a sequence of independent REST calls.
//! Partial failure is a reachable state and must be tracked accurately.

use super::preimage::{Preimage, StagedMutation};
use super::rollback::rollback_to_preimage;

/// The outcome of applying a change set.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Outcome {
    /// The final state after apply.
    pub state: State,
    /// Mutations that succeeded.
    pub succeeded: Vec<StagedMutation>,
    /// All mutations that did not succeed (attempted + never attempted).
    pub failed: Vec<StagedMutation>,
    /// Mutations that were attempted but failed.
    pub attempted_and_failed: Vec<StagedMutation>,
    /// Mutations that were never attempted due to prior failure.
    pub never_attempted: Vec<StagedMutation>,
    /// Rollback operations that failed.
    pub rollback_failures: Vec<String>,
    /// Why verification could not confirm the apply, when it could not.
    ///
    /// Set only alongside [`State::AppliedUnverified`]. `AppliedUnverified`
    /// tells an operator the writes went out but were not confirmed; without
    /// naming which resource failed and why, that is not actionable at the
    /// hour someone is usually reading it.
    pub verification_failure: Option<String>,
    /// Why the mutation that failed did not apply, when one did not.
    ///
    /// Set only when a mutation was attempted and failed, naming its index,
    /// what it was and the controller's error. Without it a failed apply says
    /// which mutation failed but never why.
    pub apply_failure: Option<String>,
}

/// The state of a change set after apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum State {
    /// All mutations succeeded and verification confirmed they landed.
    Applied,
    /// All mutations succeeded but verification could not confirm.
    AppliedUnverified,
    /// Some mutations succeeded, some failed.
    Partial,
    /// Partial apply with failed rollback.
    PartialRollbackFailed,
    /// Apply was refused because the pre-image no longer matches.
    RefusedStale,
}

/// Apply staged mutations sequentially.
///
/// # Errors
///
/// This function does not return an error directly. All failures are captured
/// in the returned [`Outcome`].
pub async fn apply_sequentially<C>(
    controller: &C,
    preimage: &Preimage,
    mutations: &[StagedMutation],
) -> Outcome
where
    C: ControllerOps,
{
    // Refuse if the controller moved under the approval, and refuse equally
    // when the check itself could not be completed.
    if !matches!(
        controller.preimage_matches(preimage, mutations).await,
        Ok(true)
    ) {
        return Outcome {
            state: State::RefusedStale,
            succeeded: Vec::new(),
            failed: mutations.to_vec(),
            attempted_and_failed: Vec::new(),
            never_attempted: mutations.to_vec(),
            rollback_failures: Vec::new(),
            verification_failure: None,
            apply_failure: None,
        };
    }

    let mut succeeded = Vec::new();
    let mut attempted_and_failed = Vec::new();
    let mut never_attempted = Vec::new();
    let mut apply_failure = None;
    let mut created_ids: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();

    // Apply mutations sequentially
    for (index, mutation) in mutations.iter().enumerate() {
        match controller.apply_mutation(index, mutation).await {
            Ok(created_id) => {
                succeeded.push(mutation.clone());
                if let Some(id) = created_id {
                    created_ids.insert(index, id);
                }
            }
            Err(error) => {
                // This mutation failed
                apply_failure = Some(format!(
                    "mutation {index} ({}): {error}",
                    mutation.preview()
                ));
                attempted_and_failed.push(mutation.clone());
                // Everything after this is never attempted
                never_attempted.extend(mutations[index + 1..].iter().cloned());
                break;
            }
        }
    }

    // If all succeeded, verify they landed as expected
    if attempted_and_failed.is_empty() && never_attempted.is_empty() {
        let (state, verification_failure) =
            match controller.verify_applied(mutations, &created_ids).await {
                Ok(()) => (State::Applied, None),
                Err(error) => (State::AppliedUnverified, Some(error.to_string())),
            };
        return Outcome {
            state,
            succeeded,
            failed: Vec::new(),
            attempted_and_failed: Vec::new(),
            never_attempted: Vec::new(),
            rollback_failures: Vec::new(),
            verification_failure,
            apply_failure: None,
        };
    }

    // Partial failure - attempt rollback
    let rollback_result =
        rollback_to_preimage(controller, preimage, &succeeded, &created_ids).await;

    let mut failed = attempted_and_failed.clone();
    failed.extend(never_attempted.clone());

    match rollback_result {
        Ok(()) => Outcome {
            state: State::Partial,
            succeeded,
            failed,
            attempted_and_failed,
            never_attempted,
            rollback_failures: Vec::new(),
            verification_failure: None,
            apply_failure,
        },
        Err(rollback_failures) => Outcome {
            state: State::PartialRollbackFailed,
            succeeded,
            failed,
            attempted_and_failed,
            never_attempted,
            rollback_failures,
            verification_failure: None,
            apply_failure,
        },
    }
}

/// Operations a controller must support for apply and rollback.
///
/// Implemented by both `UnifiClient` and `MockController`.
pub trait ControllerOps {
    /// Apply a single mutation.
    ///
    /// Returns `Ok(Some(id))` for successful creates, where `id` is the controller-assigned
    /// resource ID. Returns `Ok(None)` for successful updates, deletes, and restores.
    fn apply_mutation(
        &self,
        index: usize,
        mutation: &StagedMutation,
    ) -> impl std::future::Future<Output = Result<Option<String>, crate::error::UnifiError>> + Send;

    /// Roll back a single mutation.
    ///
    /// For creates, `prior_value` will be `None` and `created_id` will hold the ID to delete.
    /// For updates, `prior_value` contains the original state to restore.
    /// For deletes, `prior_value` contains the deleted resource to re-create.
    fn rollback_mutation(
        &self,
        index: usize,
        mutation: &StagedMutation,
        prior_value: Option<&serde_json::Value>,
        created_id: Option<&str>,
    ) -> impl std::future::Future<Output = Result<(), crate::error::UnifiError>> + Send;

    /// Whether the resources the change set touches still look as they did
    /// when the pre-image was captured.
    ///
    /// Takes the pre-image and the mutations because the question cannot be
    /// answered without them: an implementation given only `&self` has nothing
    /// to compare against, and the only thing it can return is a constant.
    ///
    /// `Err` means the check could not be completed. Callers must treat that
    /// as stale and refuse -- an approval is a statement about a specific
    /// controller state, and a check that did not run cannot renew it.
    fn preimage_matches(
        &self,
        preimage: &Preimage,
        mutations: &[StagedMutation],
    ) -> impl std::future::Future<Output = Result<bool, crate::error::UnifiError>> + Send;

    /// Fetch a resource for verification.
    ///
    /// Returns `None` if the resource does not exist (expected for deleted resources).
    fn fetch_resource(
        &self,
        kind: &str,
        id: &str,
    ) -> impl std::future::Future<
        Output = Result<Option<serde_json::Value>, crate::error::UnifiError>,
    > + Send;

    /// Verify that mutations were applied as expected.
    ///
    /// Re-fetches each touched resource and compares against the desired state.
    /// For creates, verifies the resource now exists using controller-assigned IDs.
    /// For updates, verifies the resource matches the staged body. For deletes,
    /// verifies the resource is gone.
    fn verify_applied(
        &self,
        mutations: &[StagedMutation],
        created_ids: &std::collections::HashMap<usize, String>,
    ) -> impl std::future::Future<Output = Result<(), crate::error::UnifiError>> + Send;
}

/// Verify that mutations were applied as expected (deprecated - moved to trait method).
///
/// This function remains for backward compatibility but delegates to the trait method.
/// Call `ControllerOps::verify_applied` directly instead.
///
/// # Errors
///
/// Returns an error describing which resources failed verification, or if
/// verification itself could not run (controller unreachable, fetch failed).
/// A mismatch is reported as a verification failure, not as "could not check".
#[deprecated(note = "use ControllerOps::verify_applied instead")]
pub async fn verify_applied<C>(
    controller: &C,
    mutations: &[StagedMutation],
) -> Result<(), crate::error::UnifiError>
where
    C: ControllerOps,
{
    controller
        .verify_applied(mutations, &std::collections::HashMap::new())
        .await
}

/// Verify that mutations were applied as expected.
///
/// This is the implementation moved to client.rs as a ControllerOps method.
/// Left here for reference but will be removed once the impl is complete.
#[allow(dead_code)]
async fn verify_applied_impl<C>(
    controller: &C,
    mutations: &[StagedMutation],
    created_ids: &std::collections::HashMap<usize, String>,
) -> Result<(), crate::error::UnifiError>
where
    C: ControllerOps,
{
    use crate::error::UnifiError;

    let mut failed_verifications = Vec::new();

    for (index, mutation) in mutations.iter().enumerate() {
        match mutation {
            StagedMutation::Create { kind, .. } => {
                // For creates, use the controller-assigned ID from apply
                if let Some(id) = created_ids.get(&index) {
                    match controller.fetch_resource(kind, id).await {
                        Ok(Some(_)) => {
                            // Resource exists as expected
                        }
                        Ok(None) => {
                            failed_verifications.push(format!(
                                "create {} {}: resource does not exist after apply",
                                kind, id
                            ));
                        }
                        Err(e) => {
                            return Err(UnifiError::Malformed(format!(
                                "could not verify create {} {}: {}",
                                kind, id, e
                            )));
                        }
                    }
                }
                // If no created ID recorded, skip verification for this create
            }
            StagedMutation::Update { kind, id, body } => {
                // For updates, verify the resource matches the staged body
                match controller.fetch_resource(kind, id).await {
                    Ok(Some(fetched)) => {
                        // Compare key fields (simplified - full implementation would
                        // need deep comparison logic)
                        if let Some(expected_name) = body.get("name")
                            && fetched.get("name") != Some(expected_name)
                        {
                            failed_verifications.push(format!(
                                "update {} {}: field mismatch after apply",
                                kind, id
                            ));
                        }
                    }
                    Ok(None) => {
                        failed_verifications.push(format!(
                            "update {} {}: resource does not exist after apply",
                            kind, id
                        ));
                    }
                    Err(e) => {
                        return Err(UnifiError::Malformed(format!(
                            "could not verify update {} {}: {}",
                            kind, id, e
                        )));
                    }
                }
            }
            StagedMutation::Delete { kind, id } => {
                // For deletes, verify the resource is gone
                match controller.fetch_resource(kind, id).await {
                    Ok(None) => {
                        // Resource is absent as expected
                    }
                    Ok(Some(_)) => {
                        failed_verifications.push(format!(
                            "delete {} {}: resource still exists after apply",
                            kind, id
                        ));
                    }
                    Err(e) => {
                        return Err(UnifiError::Malformed(format!(
                            "could not verify delete {} {}: {}",
                            kind, id, e
                        )));
                    }
                }
            }
            StagedMutation::Restore { .. } => {
                // Restores cannot be verified in the same way as other mutations
                // since they replace the entire controller state. Skip verification.
                continue;
            }
        }
    }

    if !failed_verifications.is_empty() {
        return Err(UnifiError::Malformed(format!(
            "verification failed for {} mutations: {}",
            failed_verifications.len(),
            failed_verifications.join("; ")
        )));
    }

    Ok(())
}
