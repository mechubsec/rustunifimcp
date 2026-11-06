//! Change-set lifecycle tools.
//!
//! UniFi Network has no candidate configuration, no dry-run validation, and no
//! checkpoint to roll back to. The eight tools below implement the change-control
//! lifecycle over UniFi's immediate-write REST API as a best-effort approximation,
//! with explicit honesty about what cannot be guaranteed.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Tool descriptions for all eight change-set tools.
///
/// Written here so the honesty tests in `changeset/mod.rs` can run before the
/// handlers exist. Task 27 registers handlers against these same names.
pub const DESCRIPTIONS: &[(&str, &str)] = &[
    (
        "unifi_create_change_set",
        "Creates a new change set with a fingerprint snapshot of current running \
         configuration for the touched resources. Returns the change set ID. \
         UniFi has no candidate configuration, so the fingerprint is computed \
         over live state rather than a staged candidate.",
    ),
    (
        "unifi_stage_change",
        "Stages one or more changes into an existing change set. Each change is \
         recorded as a planned mutation against live configuration. Because UniFi \
         writes directly to running state, staging is a planning step only — it \
         snapshots the current state as a pre-image and defers the actual writes \
         until apply.",
    ),
    (
        "unifi_diff_change_set",
        "Returns a diff showing what applying the change set would do, based on \
         the staged changes and the current running state. Because UniFi has no \
         candidate to diff against running, this is a projection of the planned \
         mutations, not a server-generated diff.",
    ),
    (
        "unifi_validate_change_set",
        "Validates the change set as far as possible without applying it. UniFi \
         has no server-side dry-run validation, so this performs client-side \
         checks only: referential integrity, schema constraints, and fingerprint \
         staleness. It cannot detect issues the controller would find on apply.",
    ),
    (
        "unifi_approve_change_set",
        "Approves a change set for apply. Requires approval by a different principal \
         than the one who created the set (two-person control); in lab mode the owner \
         may waive that, and the waiver is recorded as a waiver rather than as an \
         approval. The approval binds to the digest of the plan and of the preview the \
         approver read, so a change set that moves on afterwards cannot spend it. Pass \
         `expected_digest` to bind the approval to the plan you actually read.",
    ),
    (
        "unifi_apply_change_set",
        "Applies the staged changes as a sequence of independent REST calls \
         against live configuration. UniFi has no candidate configuration and no \
         commit, so a partial failure is a reachable outcome and is recorded as \
         `partial`. An apply whose first change the controller refuses (a 4xx) \
         wrote nothing and is recorded as `failed`. Rollback replays a stored \
         pre-image and is best-effort; it can itself fail.",
    ),
    (
        "unifi_get_change_set",
        "Returns the current status and contents of a change set: pending, applied, \
         failed, partial, or rolled back. Includes the fingerprint, staged changes, \
         any apply outcome, and whether rollback is available.",
    ),
    (
        "unifi_cancel_change_set",
        "Cancels a planned, approved or expired change set, so its owner can create \
         another. Only the owner or the approver may cancel. The record is kept as \
         `cancelled`. A set that has started applying, including a failed or partial \
         apply, cannot be cancelled.",
    ),
];

/// Arguments for `unifi_create_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CreateChangeSetArgs {
    /// The controller to target.
    pub controller: String,
    /// A human-readable description of this change set.
    pub description: String,
}

/// Arguments for `unifi_stage_change`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct StageChangeArgs {
    /// The controller to target.
    pub controller: String,
    /// The change set ID to stage into.
    pub change_set_id: String,
    /// The mutations to stage.
    pub mutations: Vec<MutationSpec>,
}

/// A mutation specification for staging.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum MutationSpec {
    /// Create a new resource.
    Create {
        /// The resource kind.
        kind: String,
        /// The resource body.
        body: serde_json::Value,
    },
    /// Update an existing resource.
    Update {
        /// The resource kind.
        kind: String,
        /// The resource ID.
        id: String,
        /// The new resource body.
        body: serde_json::Value,
    },
    /// Delete a resource.
    Delete {
        /// The resource kind.
        kind: String,
        /// The resource ID.
        id: String,
    },
    /// Restore from backup.
    Restore {
        /// The backup ID to restore from.
        backup_id: String,
    },
}

/// Arguments for `unifi_diff_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct DiffChangeSetArgs {
    /// The controller to target.
    pub controller: String,
    /// The change set ID to diff.
    pub change_set_id: String,
}

/// Arguments for `unifi_validate_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ValidateChangeSetArgs {
    /// The controller to target.
    pub controller: String,
    /// The change set ID to validate.
    pub change_set_id: String,
}

/// Arguments for `unifi_approve_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ApproveChangeSetArgs {
    /// The controller to target.
    pub controller: String,
    /// The change set ID to approve.
    pub change_set_id: String,
    /// The plan digest the approver read, as `unifi_get_change_set` reports it.
    ///
    /// Optional, and supplying it is what makes the approval attest to a
    /// specific plan: the approval is refused if the change set has moved on
    /// since it was read. Omitting it approves whatever the record holds when
    /// the call lands.
    #[serde(default)]
    pub expected_digest: Option<String>,
}

/// Arguments for `unifi_apply_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ApplyChangeSetArgs {
    /// The controller to target.
    pub controller: String,
    /// The change set ID to apply.
    pub change_set_id: String,
}

/// Arguments for `unifi_get_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct GetChangeSetArgs {
    /// The controller to target.
    pub controller: String,
    /// The change set ID to retrieve.
    pub change_set_id: String,
}

/// Arguments for `unifi_cancel_change_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CancelChangeSetArgs {
    /// The controller to target.
    pub controller: String,
    /// The change set ID to cancel.
    pub change_set_id: String,
}
