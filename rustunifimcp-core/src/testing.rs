//! Test helpers for loading recorded controller responses.
//!
//! Two kinds of fixture live under `tests/fixtures/`.
//!
//! The **synthetic** set is hand-written, committed, and present in every
//! checkout. It carries documentation-range addresses, locally administered
//! MACs and zeroed coordinates, and it is what the parser, workflow and
//! change-set tests read. It exists because the recorded set cannot be
//! published: seventeen tests used to skip on a fresh clone, and CI reported
//! `ok` while never running them.
//!
//! The **recorded** sets are captured per controller version by
//! `scripts/capture-fixtures.sh`, carry real network data, and are gitignored.
//! They are what `tests/version_matrix.rs` reads, because only a real capture
//! is evidence about what a real controller version serves. A hand-written
//! fixture proves nothing about drift, which is why the matrix skips the
//! synthetic set rather than counting it as a version.

use std::path::PathBuf;

/// The fixture set the unit tests read.
///
/// The committed synthetic set, so these tests run on a fresh clone and in CI.
pub const DEFAULT_FIXTURE_VERSION: &str = SYNTHETIC_FIXTURE_VERSION;

/// The directory name of the committed, hand-written fixture set.
pub const SYNTHETIC_FIXTURE_VERSION: &str = "synthetic";

/// The fixture directory for this crate.
fn fixtures_dir() -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures"]
        .iter()
        .collect()
}

/// Every fixture set present in this checkout: the synthetic one first, then
/// any recorded controller versions.
///
/// Tests that assert a parser accepts what a controller returns should loop
/// over this, so a developer holding a live capture exercises the parsers
/// against real data while CI still exercises them against the synthetic set.
#[must_use]
pub fn fixture_versions() -> Vec<String> {
    let mut versions = vec![SYNTHETIC_FIXTURE_VERSION.to_owned()];
    versions.extend(recorded_versions());
    versions
}

/// The recorded controller versions present in this checkout, if any.
///
/// Excludes the synthetic set: it is not a capture and is not evidence about
/// any controller version.
#[must_use]
pub fn recorded_versions() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(fixtures_dir()) else {
        return Vec::new();
    };

    let mut versions: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name != SYNTHETIC_FIXTURE_VERSION)
        .collect();
    versions.sort();
    versions
}

/// Whether this checkout holds fixtures recorded from a live controller.
///
/// Only the version matrix and the scrub gate's live check need this. A test
/// that merely needs a controller-shaped response should read the synthetic
/// set instead of skipping — a missing fixture is an un-run test, never a
/// passing one, and seventeen of them going un-run is how CI came to overstate
/// what it checked.
#[must_use]
pub fn recorded_fixtures_available() -> bool {
    !recorded_versions().is_empty()
}

/// Load a recorded controller response.
///
/// # Panics
///
/// Panics if the fixture is absent or is not valid JSON. Both are test-authoring
/// errors, and a panic naming the path is the fastest way to fix them.
#[must_use]
pub fn fixture(version: &str, name: &str) -> serde_json::Value {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        version,
        &format!("{name}.json"),
    ]
    .iter()
    .collect();

    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("no fixture at {}: {error}", path.display()));

    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("fixture {} is not JSON: {error}", path.display()))
}

/// Whether a fixture file was recorded for this endpoint on this version.
///
/// False for both a `.absent` marker and a kind the recording predates (an
/// older capture never fetched endpoints added to `capture-fixtures.sh` later).
#[must_use]
pub fn has_fixture(version: &str, name: &str) -> bool {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        version,
        &format!("{name}.json"),
    ]
    .iter()
    .collect();
    path.exists()
}

/// Whether an endpoint was recorded as absent on this controller version.
///
/// `capture-fixtures.sh` writes a `.absent` marker when a route 404s, so the
/// version matrix can assert absence as a fact rather than inferring it from a
/// missing file.
#[must_use]
pub fn is_absent(version: &str, name: &str) -> bool {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "fixtures",
        version,
        &format!("{name}.absent"),
    ]
    .iter()
    .collect();
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::{SYNTHETIC_FIXTURE_VERSION, fixture, fixture_versions, recorded_versions};

    #[test]
    fn loads_a_sites_response() {
        let value = fixture(super::DEFAULT_FIXTURE_VERSION, "sites");
        assert!(value.is_object() || value.is_array());
    }

    /// The synthetic set is committed, so it is present in every checkout.
    /// If this fails the fixtures were deleted or the .gitignore negation was
    /// dropped, and seventeen tests are about to start skipping again.
    #[test]
    fn the_synthetic_set_is_always_present() {
        assert!(
            fixture_versions().contains(&SYNTHETIC_FIXTURE_VERSION.to_owned()),
            "the committed synthetic fixture set is missing from this checkout"
        );
    }

    /// A hand-written fixture is not evidence about a controller version, so
    /// the matrix must never see it as one.
    #[test]
    fn the_synthetic_set_is_not_counted_as_a_recorded_version() {
        assert!(!recorded_versions().contains(&SYNTHETIC_FIXTURE_VERSION.to_owned()));
    }

    #[test]
    #[should_panic(expected = "no fixture")]
    fn a_missing_fixture_panics_with_the_path_it_looked_for() {
        let _ = fixture(super::DEFAULT_FIXTURE_VERSION, "no_such_endpoint");
    }
}
