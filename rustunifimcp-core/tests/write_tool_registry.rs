//! Guard for the registry `mecmcp-server` authorizes against.
//!
//! `--tools '*'` grants read-only tools only, and that rule is enforced against
//! a registry this server supplies as a parameter. mecmcp's own
//! `an_empty_write_tool_registry_lets_a_wildcard_reach_a_write_tool` pins the failure mode: an empty registry turns every
//! wildcard token into a writer. So the registry is asserted by name here, not
//! by count -- a count passes a refactor that renames a tool out of it.

use rustunifimcp_core::tools::{TOOL_NAMES, WRITE_TOOLS};

#[test]
fn the_write_tool_registry_is_never_empty() {
    assert!(
        !WRITE_TOOLS.is_empty(),
        "an empty write-tool registry makes every wildcard token a writer"
    );
}

/// The exact list, by name. Update this deliberately when the surface changes;
/// that is the point.
#[test]
fn the_write_tool_registry_holds_exactly_the_mutating_tools() {
    let mut actual: Vec<&str> = WRITE_TOOLS.to_vec();
    actual.sort_unstable();

    // Phase 3 registers the three operational tools (`unifi_run_speed_test`
    // was removed as an unwired stub -- see MEC-505).
    // Phase 6 adds the change-set tools (cancel followed in #145). Extend this list in the task
    // that adds them, never ahead of it -- a name here with no tool behind it
    // is not a guard.
    let mut expected = vec![
        "unifi_add_controller",
        "unifi_backup_action",
        "unifi_client_action",
        "unifi_device_action",
        "unifi_create_change_set",
        "unifi_stage_change",
        "unifi_diff_change_set",
        "unifi_validate_change_set",
        "unifi_approve_change_set",
        "unifi_apply_change_set",
        "unifi_get_change_set",
        "unifi_cancel_change_set",
    ];
    expected.sort_unstable();

    assert_eq!(actual, expected);
}

#[test]
fn every_write_tool_is_a_registered_tool() {
    for name in WRITE_TOOLS {
        assert!(
            TOOL_NAMES.contains(name),
            "{name} is in WRITE_TOOLS but is not a registered tool; \
             a name with no tool behind it guards nothing"
        );
    }
}

/// Every tool whose name implies mutation must be in WRITE_TOOLS unless
/// explicitly allowlisted as read-only. This test derives expectation from
/// semantics, catching tools like `unifi_delete_*` that the by-name test
/// would miss if the author was mistaken.
#[test]
fn every_mutating_name_is_in_the_write_registry() {
    // Tool names containing these verbs imply mutation.
    const MUTATION_VERBS: &[&str] = &[
        "add", "create", "update", "delete", "set", "apply", "approve", "stage", "action",
        "restart", "run", "remove", "destroy", "modify", "write",
    ];

    // Tools that match a verb but are genuinely read-only. Each entry must
    // carry a comment explaining why it is safe.
    const READ_ONLY_ALLOWLIST: &[&str] = &[
        // None yet. The operational tools (`*_action`) and
        // `add_controller` are all genuine writes.
    ];

    for &tool in TOOL_NAMES {
        let name_lower = tool.to_lowercase();
        let matches_verb = MUTATION_VERBS.iter().any(|verb| name_lower.contains(verb));

        if matches_verb && !READ_ONLY_ALLOWLIST.contains(&tool) {
            assert!(
                WRITE_TOOLS.contains(&tool),
                "{tool} implies mutation but is absent from WRITE_TOOLS"
            );
        }
    }
}

#[test]
fn no_tool_name_is_duplicated() {
    let mut seen = TOOL_NAMES.to_vec();
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "duplicate tool name in TOOL_NAMES");
}
