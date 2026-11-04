//! Pre-image capture and staged mutations.
//!
//! UniFi has no candidate configuration, so change sets must snapshot the
//! current state before apply. The pre-image is the only thing standing between
//! a partial apply and an unrecoverable one.

use crate::error::UnifiError;
use serde_json::Value;

/// A snapshot of controller state before staging mutations.
///
/// Captures the current state of all resources a change set will touch, so
/// apply can be refused if the controller drifted since staging.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Preimage {
    resources: Value,
}

impl Preimage {
    /// Construct a pre-image from a recorded fixture for testing.
    #[must_use]
    pub fn from_fixture(fixture: &Value) -> Self {
        Self {
            resources: fixture.clone(),
        }
    }

    /// Construct a pre-image from the resources it snapshots.
    ///
    /// The inverse of reading the entries back out of a stored change set: the
    /// pre-image travels folded into the record's actions, one entry per
    /// mutation, and is reassembled here.
    #[must_use]
    pub fn from_resources(resources: Vec<Value>) -> Self {
        Self {
            resources: serde_json::json!({ "data": resources }),
        }
    }

    /// Capture a pre-image from a live controller.
    ///
    /// Fetches the current state of all resources that will be touched by the
    /// mutations. For creates, no prior state exists (recorded as absence). For
    /// updates and deletes, the resource is fetched and stored.
    ///
    /// # Errors
    ///
    /// Returns an error if any resource fetch fails or if a mutation kind cannot
    /// be parsed.
    pub async fn capture_preimage(
        client: &crate::client::UnifiClient,
        mutations: &[StagedMutation],
    ) -> Result<Self, UnifiError> {
        use crate::ApiSurface;
        use crate::model::{ResourceKind, unwrap_enveloped_data};

        let mut data = Vec::new();

        for mutation in mutations {
            match mutation {
                StagedMutation::Create { .. } => {
                    // Creates have no prior state - absence is recorded by not
                    // adding anything to the data array. This explicit non-presence
                    // is what lets rollback delete a created resource rather than
                    // guessing.
                    continue;
                }
                StagedMutation::Restore { .. } => {
                    // Restores overwrite the entire controller state. The pre-image
                    // would be the whole controller, which is not meaningful to capture.
                    continue;
                }
                StagedMutation::Update { kind, id, .. } | StagedMutation::Delete { kind, id } => {
                    // Parse the kind string to ResourceKind
                    let kind_value = serde_json::Value::String(kind.clone());
                    let resource_kind: ResourceKind =
                        serde_json::from_value(kind_value).map_err(|e| {
                            UnifiError::Malformed(format!(
                                "invalid resource kind '{}': {}",
                                kind, e
                            ))
                        })?;

                    let surface = resource_kind.surface();
                    let site = client.default_site_for(surface).await?;

                    // Fetch the resource
                    let raw = client
                        .get_single_raw(resource_kind, &site, id)
                        .await
                        .map_err(|e| {
                            UnifiError::Malformed(format!(
                                "failed to capture pre-image for {} {}: {}",
                                kind, id, e
                            ))
                        })?;

                    // Extract the resource from the envelope based on surface
                    let resource = match surface {
                        ApiSurface::Supported | ApiSurface::PrivateV1 => {
                            // These surfaces wrap responses in {"data": [...]}
                            let items = unwrap_enveloped_data(&raw)?;
                            if items.is_empty() {
                                return Err(UnifiError::Malformed(format!(
                                    "resource {} {} not found for pre-image capture",
                                    kind, id
                                )));
                            }
                            items[0].clone()
                        }
                        ApiSurface::PrivateV2 => {
                            // Private v2 returns a bare array
                            if let Some(arr) = raw.as_array() {
                                let Some(found) = crate::client::select_by_id(arr, id) else {
                                    return Err(UnifiError::Malformed(format!(
                                        "resource {} {} not found for pre-image capture",
                                        kind, id
                                    )));
                                };
                                found.clone()
                            } else if raw.is_object() {
                                // Sometimes returns a single object
                                raw
                            } else {
                                return Err(UnifiError::Malformed(format!(
                                    "unexpected response format for {} {}",
                                    kind, id
                                )));
                            }
                        }
                        ApiSurface::Cloud => {
                            return Err(UnifiError::Malformed(
                                "cloud surface not supported".to_owned(),
                            ));
                        }
                    };

                    // Kept raw: drift detection (`preimage_matches`) compares
                    // this against the live object and rollback writes it
                    // back, so a projected copy would read every edit as stale
                    // and roll back a stripped object (MEC-737 F1). It never
                    // reaches the model raw -- `diff.rs` projects `before`
                    // through the per-kind allowlist at output.
                    let _ = resource_kind;
                    data.push(resource);
                }
            }
        }

        Ok(Self {
            resources: serde_json::json!({"data": data}),
        })
    }

    /// Check if this pre-image covers a given mutation.
    #[must_use]
    pub fn covers(&self, mutation: &StagedMutation) -> bool {
        match mutation {
            StagedMutation::Update { kind: _, id, .. } => {
                // Check if we have this resource type and ID in the pre-image
                if let Some(data) = self.resources.get("data").and_then(|d| d.as_array()) {
                    data.iter().any(|item| {
                        item.get("_id")
                            .and_then(|v| v.as_str())
                            .is_some_and(|item_id| item_id == id)
                    })
                } else {
                    false
                }
            }
            StagedMutation::Create { .. } => true, // Creates don't need pre-image coverage
            StagedMutation::Delete { .. } => true, // Deletes are checked at validate time
            StagedMutation::Restore { .. } => true, // Restores have no meaningful pre-image
        }
    }

    /// Get the pre-image entry for a resource by ID.
    ///
    /// Returns `None` if the resource does not exist in the pre-image (which is
    /// expected for creates, and an error for updates/deletes).
    #[must_use]
    pub fn get_resource(&self, id: &str) -> Option<Value> {
        if let Some(data) = self.resources.get("data").and_then(|d| d.as_array()) {
            data.iter()
                .find(|item| {
                    item.get("_id")
                        .and_then(|v| v.as_str())
                        .is_some_and(|item_id| item_id == id)
                })
                .cloned()
        } else {
            None
        }
    }
}

/// A planned mutation against live configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StagedMutation {
    /// Create a new resource.
    Create {
        /// The resource kind being created.
        kind: String,
        /// The resource body.
        body: Value,
    },
    /// Update an existing resource.
    Update {
        /// The resource kind being updated.
        kind: String,
        /// The resource ID.
        id: String,
        /// The new resource body.
        body: Value,
    },
    /// Delete a resource.
    Delete {
        /// The resource kind being deleted.
        kind: String,
        /// The resource ID.
        id: String,
    },
    /// Restore entire controller configuration from a backup.
    ///
    /// This overwrites the entire controller state and cannot be undone by
    /// rollback. The pre-image for a restore would be the entire controller,
    /// so no meaningful pre-image is captured.
    Restore {
        /// The backup ID to restore from.
        backup_id: String,
    },
}

impl StagedMutation {
    /// Stage a resource creation.
    #[must_use]
    pub fn create(kind: impl Into<String>, body: Value) -> Self {
        Self::Create {
            kind: kind.into(),
            body,
        }
    }

    /// Stage a resource update.
    #[must_use]
    pub fn update(kind: impl Into<String>, id: impl Into<String>, body: Value) -> Self {
        Self::Update {
            kind: kind.into(),
            id: id.into(),
            body,
        }
    }

    /// Stage a resource deletion.
    #[must_use]
    pub fn delete(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self::Delete {
            kind: kind.into(),
            id: id.into(),
        }
    }

    /// Stage a controller restore from backup.
    ///
    /// This overwrites the entire controller configuration and cannot be undone.
    #[must_use]
    pub fn restore(backup_id: impl Into<String>) -> Self {
        Self::Restore {
            backup_id: backup_id.into(),
        }
    }

    /// The resource this mutation addresses, if it addresses one by id.
    ///
    /// `None` for a create, which has no id until apply, and for a restore,
    /// which addresses the whole controller.
    #[must_use]
    pub fn resource_id(&self) -> Option<&str> {
        match self {
            Self::Update { id, .. } | Self::Delete { id, .. } => Some(id.as_str()),
            Self::Create { .. } | Self::Restore { .. } => None,
        }
    }

    /// Preview this mutation as a human-readable string.
    #[must_use]
    pub fn preview(&self) -> String {
        match self {
            Self::Create { kind, .. } => format!("create {kind}"),
            Self::Update { kind, id, .. } => format!("update {kind} {id}"),
            Self::Delete { kind, id } => format!("delete {kind} {id}"),
            Self::Restore { backup_id } => format!(
                "restore from backup {} (overwrites entire controller configuration, \
                 cannot be undone by rollback)",
                backup_id
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// The pre-image is the only thing standing between a partial apply and an
    /// unrecoverable one. If a staged mutation touches a resource the pre-image
    /// does not cover, the change set must be refused before apply.
    #[test]
    fn a_mutation_outside_the_preimage_is_refused() {
        let preimage =
            super::Preimage::from_fixture(&fixture(DEFAULT_FIXTURE_VERSION, "networkconf"));
        let staged =
            super::StagedMutation::update("firewall_policy", "abc123", serde_json::json!({}));
        assert!(
            super::super::validate::validate_locally(&preimage, &[staged]).is_err(),
            "a mutation with no pre-image coverage must not reach apply"
        );
    }
}

#[cfg(test)]
mod restore_tests {
    use super::StagedMutation;

    /// Restore overwrites the entire controller configuration. It is not an
    /// operational action, and there must be no path to it that skips approval.
    #[test]
    fn restore_is_not_reachable_through_backup_action() {
        let raw = r#"{"controller":"home","action":"restore","backup_id":"x"}"#;
        let parsed: Result<crate::tools::ops::BackupActionArgs, _> = serde_json::from_str(raw);
        assert!(
            parsed.is_err(),
            "restore must not parse as an operational action"
        );
    }

    #[test]
    fn a_staged_restore_declares_its_blast_radius() {
        let staged = StagedMutation::restore("backup-2026-08-26");
        let rendered = staged.preview();
        let lowered = rendered.to_lowercase();
        assert!(lowered.contains("entire"), "{rendered}");
        assert!(
            lowered.contains("cannot be undone by rollback"),
            "{rendered}"
        );
    }
}
