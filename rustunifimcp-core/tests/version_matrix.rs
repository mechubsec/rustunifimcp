//! Which endpoints exist on which controller version.
//!
//! This is where private-API drift is caught, and it is the reason every
//! endpoint carries a surface tag. A private route that disappears in a
//! controller upgrade should fail here, in CI, rather than in a tool call at
//! 03:00.

use rustunifimcp_core::model::ResourceKind;
use rustunifimcp_core::testing::{
    capture_attempted, has_fixture, is_absent, recorded_fixtures_available,
};
use rustunifimcp_core::version::{Availability, endpoint_availability};

/// Every recorded controller version under tests/fixtures/.
///
/// The committed synthetic set is deliberately not one. It is hand-written, so
/// it is evidence about the parsers and nothing at all about which endpoints a
/// real controller version serves -- which is the only question this file asks.
fn recorded_versions() -> Vec<String> {
    rustunifimcp_core::testing::recorded_versions()
}

#[test]
fn at_least_two_controller_versions_are_recorded() {
    if !recorded_fixtures_available() {
        eprintln!("SKIPPED: no recorded fixtures; Phase 1's exit criterion needs two captures.");
        return;
    }
    let versions = recorded_versions();
    assert!(
        versions.len() >= 2,
        "the matrix cannot distinguish versions with only {versions:?}; \
         Phase 1's exit criterion is two"
    );
}

#[test]
fn the_matrix_agrees_with_what_was_recorded() {
    if !recorded_fixtures_available() {
        eprintln!(
            "SKIPPED: no recorded fixtures. Only a live capture is evidence about a \
             controller version; run scripts/capture-fixtures.sh against a controller."
        );
        return;
    }
    for version in recorded_versions() {
        for kind in ResourceKind::ALL {
            let fixture_name = kind_fixture_name(*kind);
            let recorded_absent = is_absent(&version, fixture_name);
            let availability = endpoint_availability(&version, *kind);

            let fixture_exists = has_fixture(&version, fixture_name);

            // Neither fixture nor marker: only a manifest that never listed the
            // kind proves the capture predates it.
            if !recorded_absent && !fixture_exists {
                match capture_attempted(&version, fixture_name) {
                    Some(false) => {
                        eprintln!("SKIPPED: the {version} capture predates {kind:?}");
                        continue;
                    }
                    Some(true) => panic!(
                        "{kind:?} on {version} was attempted but left no fixture or .absent \
                         marker: an unexpected status or a deleted file; recapture"
                    ),
                    None => panic!(
                        "{kind:?} on {version} has no fixture or marker and {version} has no \
                         manifest.txt; recapture with the current script, or write manifest.txt \
                         listing what the old capture fetched"
                    ),
                }
            }

            // Determine expected availability based on evidence
            let expected = if recorded_absent {
                // .absent marker must mean Absent
                assert!(
                    !fixture_exists,
                    "{kind:?} on {version} has .absent marker but fixture file also exists"
                );
                Availability::Absent
            } else {
                // Fixture file must mean Present
                Availability::Present
            };

            assert_eq!(
                availability, expected,
                "matrix and fixtures disagree for {kind:?} on {version}: \
                 fixture_exists={fixture_exists}, recorded_absent={recorded_absent}, \
                 matrix={availability:?}, expected={expected:?}"
            );
        }
    }
}

#[test]
fn unrecorded_versions_return_unrecorded_for_private_endpoints() {
    let unrecorded_version = "99.9.9";

    // Supported API endpoints are always Present
    for kind in ResourceKind::ALL {
        if kind.surface() == rustunifimcp_core::ApiSurface::Supported {
            assert_eq!(
                endpoint_availability(unrecorded_version, *kind),
                Availability::Present,
                "Supported endpoint {kind:?} should be Present even on unrecorded version"
            );
        } else {
            assert_eq!(
                endpoint_availability(unrecorded_version, *kind),
                Availability::Unrecorded,
                "Private endpoint {kind:?} should be Unrecorded on unrecorded version"
            );
        }
    }
}

/// Map a kind to the fixture basename `capture-fixtures.sh` wrote.
fn kind_fixture_name(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Station => "clients",
        ResourceKind::Device => "devices",
        ResourceKind::Network => "networkconf",
        ResourceKind::Wlan => "wlanconf",
        ResourceKind::PortProfile => "portconf",
        ResourceKind::DhcpReservation => "user",
        ResourceKind::FirewallGroup => "firewallgroup",
        ResourceKind::RadiusProfile => "radiusprofile",
        ResourceKind::FirewallPolicy => "policies",
        ResourceKind::FirewallZone => "zones",
        ResourceKind::TrafficRoute => "traffic_routes",
        ResourceKind::FirewallRule => "firewallrule",
        ResourceKind::PortForward => "portforward",
        ResourceKind::StaticRoute => "routing",
        // ResourceKind is #[non_exhaustive]: a future kind has no fixture name
        // yet, so point at a file that never exists and let the test skip it.
        _ => "__unmapped_kind__",
    }
}
