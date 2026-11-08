//! Controller version matrix.
//!
//! The supported Integration API is stable and always present. The private
//! surfaces are not, so their availability is declared per version and
//! asserted against recorded fixtures in `tests/version_matrix.rs`.
//!
//! Adding a controller version means recording its fixtures and adding a row
//! here. A disagreement between the two is a test failure, deliberately.

use crate::ApiSurface;
use crate::model::ResourceKind;

/// What the recorded fixtures say about an endpoint on a controller version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Availability {
    /// A fixture for this version recorded a 200 for this kind.
    Present,
    /// An `.absent` marker for this version recorded a 404 for this kind.
    Absent,
    /// No fixtures exist for this version, so nothing is known.
    ///
    /// Deliberately distinct from `Present`: the caller may still attempt the
    /// request, but a failure must be attributed as possible drift on an
    /// unrecorded version rather than reported as a broken tool.
    Unrecorded,
}

/// Whether a controller version serves the endpoint behind a resource kind.
///
/// # Arguments
///
/// * `version` - The UniFi controller version (e.g., "10.5.67")
/// * `kind` - The resource kind to check
///
/// # Returns
///
/// Returns the availability status based on recorded fixtures:
/// - `Availability::Present` - Endpoint is known to exist on this version
/// - `Availability::Absent` - Endpoint is known to be absent (404) on this version
/// - `Availability::Unrecorded` - No fixtures exist for this version
///
/// # Examples
///
/// ```
/// use rustunifimcp_core::model::ResourceKind;
/// use rustunifimcp_core::version::{endpoint_availability, Availability};
///
/// // Supported API endpoints are always Present
/// assert_eq!(
///     endpoint_availability("10.5.67", ResourceKind::Station),
///     Availability::Present
/// );
///
/// // Unrecorded versions return Unrecorded for private endpoints
/// assert_eq!(
///     endpoint_availability("99.9.9", ResourceKind::FirewallPolicy),
///     Availability::Unrecorded
/// );
/// ```
#[must_use]
pub fn endpoint_availability(version: &str, kind: ResourceKind) -> Availability {
    // Supported API endpoints are always available across versions
    if kind.surface() == ApiSurface::Supported {
        return Availability::Present;
    }

    // Private API availability matrix. Every row must be justified by a
    // fixture or an .absent marker. Never guess - if a version is not
    // recorded, return Unrecorded.
    match major_minor(version) {
        // Version 10.5.67: All private endpoints present (zero .absent markers)
        (10, 5) => Availability::Present,

        // Version 11.0.97: All private endpoints present (zero .absent markers)
        (11, 0) => Availability::Present,

        // Unrecorded version: caller may attempt the request but must attribute
        // failures as possible drift rather than a broken tool
        _ => Availability::Unrecorded,
    }
}

/// Parse version string into (major, minor) tuple.
///
/// The matrix keys on major.minor only, so **patch-level drift is not tracked**.
/// This is a known, accepted limitation: versions 10.5.1 and 10.5.67 are
/// treated identically.
///
/// # Arguments
///
/// * `version` - Version string (e.g., "10.5.67")
///
/// # Returns
///
/// Returns `(major, minor)` as `(u32, u32)`. Anything unparseable sorts as
/// `(0, 0)`.
///
/// # Examples
///
/// ```
/// # use rustunifimcp_core::version::major_minor;
/// assert_eq!(major_minor("10.5.67"), (10, 5));
/// assert_eq!(major_minor("10.5.1"), (10, 5));
/// assert_eq!(major_minor("invalid"), (0, 0));
/// ```
#[must_use]
pub fn major_minor(version: &str) -> (u32, u32) {
    let mut parts = version.split('.');
    let major = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    (major, minor)
}
