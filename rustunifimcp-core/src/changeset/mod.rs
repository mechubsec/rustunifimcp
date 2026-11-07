//! UniFi Network transaction implementation.
//!
//! UniFi has no candidate configuration, no dry-run validation, and no checkpoint
//! to roll back to. Every write is an immediate, independent REST call against
//! live configuration. The [`UnifiTransaction`] type declares this plainly via
//! [`Atomicity`], so shared code that renders approval prompts can say so rather
//! than offering commit-confirmed semantics the vendor cannot deliver.

pub mod apply;
pub mod diff;
pub mod preimage;
pub mod record;
pub mod rollback;
pub mod validate;

pub use apply::{ControllerOps, Outcome, State, apply_sequentially};
pub use diff::{Change, Diff, diff_against_preimage};
pub use preimage::{Preimage, StagedMutation};
pub use record::{
    StagedAction, actions_for, actions_of, fingerprint_of, mutations_of, preimage_of,
};
pub use rollback::rollback_to_preimage;
pub use validate::{
    ZoneIndex, check_firewall_policy_respond_traffic, check_network_references,
    check_writable_fields, check_zone_deletions, check_zone_references, referenced_network_ids,
    referenced_zone_ids, validate_locally,
};

// mecmcp#335 landed in mecmcp-changeset v0.22.0: `Atomicity` and
// `DeviceTransaction::atomicity()` are exported upstream, so this crate
// re-exports the shared type rather than defining an incompatible twin.
// A local copy would not be accepted by shared approval renderers.
pub use mecmcp_changeset::Atomicity;

/// UniFi Network transaction.
///
/// Implements the vendor-agnostic [`mecmcp_changeset::DeviceTransaction`] trait
/// over UniFi's immediate-write REST API. Because UniFi has no candidate
/// configuration, this is a best-effort approximation: staging snapshots the
/// current state as a pre-image; applying is a sequence of independent REST
/// calls; rollback replays the pre-image and can itself fail.
pub struct UnifiTransaction;

impl UnifiTransaction {
    /// What UniFi can guarantee about applying a change set.
    ///
    /// None of the three. This method exists so a future refactor cannot quietly
    /// make the server claim otherwise.
    #[must_use]
    pub const fn atomicity() -> Atomicity {
        Atomicity::live_writes()
    }
}

#[cfg(test)]
mod tests {
    use super::UnifiTransaction;

    /// UniFi promises none of the three. This test exists so that a future
    /// refactor cannot quietly make the server claim otherwise.
    #[test]
    fn unifi_declares_no_atomicity_guarantees() {
        let atomicity = UnifiTransaction::atomicity();
        assert!(!atomicity.atomic_apply);
        assert!(!atomicity.dry_run_validation);
        assert!(!atomicity.guaranteed_rollback);
    }

    /// The design forbids the word outright, because an operator approving a
    /// UniFi change set is not getting commit-confirmed semantics and the model
    /// relaying the request must be able to say so.
    #[test]
    fn no_change_set_tool_description_claims_atomicity() {
        for (name, description) in crate::tools::changeset::DESCRIPTIONS {
            let lowered = description.to_lowercase();
            assert!(
                !lowered.contains("atomic"),
                "{name} description contains 'atomic': {description}"
            );
            assert!(
                !lowered.contains("all-or-nothing"),
                "{name} description implies atomicity: {description}"
            );
        }
    }

    /// And the descriptions must say the true thing, not merely avoid the
    /// false one.
    #[test]
    fn the_apply_description_states_that_partial_failure_is_reachable() {
        let apply = crate::tools::changeset::DESCRIPTIONS
            .iter()
            .find(|(name, _)| *name == "unifi_apply_change_set")
            .expect("apply is registered");
        let lowered = apply.1.to_lowercase();
        assert!(
            lowered.contains("partial"),
            "apply must state that partial failure is a reachable outcome: {}",
            apply.1
        );
    }
}
