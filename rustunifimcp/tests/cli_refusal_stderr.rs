//! Pins the operator-visible text of the startup refusals, and their ordering
//! against config errors.
//!
//! This binary used to skip `mecmcp_runtime::cli_validate` entirely. The
//! listener still refused an unsafe bind — `mecmcp_transport::serve_router`
//! owns that check — but the refusal surfaced as `Fatal: failed to serve HTTP
//! router`, with the reason discarded, so an operator had no path from the
//! message to the flag. See mecmcp#358.
//!
//! These assertions run the real binary. The posture was never the problem:
//! the bind was refused correctly throughout. What was wrong was what reached
//! stderr, and what order the checks ran in — neither is observable from
//! inside the process.

use std::io::Write;
use std::process::{Command, Output};

/// A controllers file that parses and is mode 0600, so a run reaches CLI
/// validation rather than stopping on the inventory first.
fn controllers_file() -> tempfile::NamedTempFile {
    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    secure(key.path());
    // Leak the key file so it outlives this call; the registry only needs the
    // path to exist while the binary starts.
    let key_path = key.into_temp_path();
    let key_path = key_path.keep().expect("persist api key file");

    let mut file = tempfile::NamedTempFile::new().expect("create controllers file");
    let body = format!(
        r#"{{"version":1,"devices":{{"home":{{"endpoint":"https://unifi.example.org","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
        key_path.display()
    );
    file.write_all(body.as_bytes())
        .expect("write controllers file");
    file.flush().expect("flush controllers file");
    secure(file.path());
    file
}

fn tokens_file() -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("create tokens file");
    file.write_all(br#"{"tokens":[]}"#)
        .expect("write tokens file");
    file.flush().expect("flush tokens file");
    secure(file.path());
    file
}

fn secure(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustunifimcp"))
        .args(args)
        .output()
        .expect("spawn rustunifimcp")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn off_loopback_without_allowed_origin_names_the_flag() {
    let controllers = controllers_file();
    let tokens = tokens_file();
    let output = run(&[
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "30033",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--allow-insecure-bind",
        "--allowed-host",
        "10.0.0.1:30033",
    ]);
    let stderr = stderr_of(&output);

    assert!(
        stderr.contains("requires at least one --allowed-origin"),
        "the refusal must name the flag, got:\n{stderr}"
    );
    // The regression guard. This is the string the binary printed before the
    // shared validator was called, and it is what a reintroduced skip looks
    // like: the bind is still refused, but the reason is gone.
    assert!(
        !stderr.contains("failed to serve HTTP router"),
        "the reason was swallowed by the generic serve error:\n{stderr}"
    );
    assert!(!output.status.success(), "a refused CLI must exit non-zero");
}

#[test]
fn off_loopback_without_allowed_host_names_the_flag() {
    let controllers = controllers_file();
    let tokens = tokens_file();
    let output = run(&[
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "30033",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--allow-insecure-bind",
    ]);
    let stderr = stderr_of(&output);

    assert!(
        stderr.contains("requires at least one --allowed-host"),
        "the refusal must name the flag, got:\n{stderr}"
    );
    assert!(!output.status.success(), "a refused CLI must exit non-zero");
}

/// `token add` must refuse to mint a token whose `--tools` combine both
/// change-set control scopes, and must not touch the token store while
/// refusing.
///
/// `run_inner` dispatches `token` subcommands from raw `argv` before
/// `UnifiCli`/`clap::Parser` ever see them (see the comment above that
/// dispatch in `main.rs`), so a unit test that calls
/// `validate_token_command` or `TokenCli::parse_from` directly cannot notice
/// if `run_inner` stops calling it. Running the real binary end to end is
/// what actually proves the wiring holds.
#[test]
fn token_add_with_both_changeset_control_scopes_is_refused() {
    let tokens = tokens_file();
    let output = run(&[
        "token",
        "add",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--name",
        "test",
        "--devices",
        "*",
        "--tools",
        "unifi_stage_change,unifi_approve_change_set",
    ]);
    let stderr = stderr_of(&output);

    assert!(
        stderr.contains("unifi_stage_change") && stderr.contains("unifi_approve_change_set"),
        "the refusal must name both scopes, got:\n{stderr}"
    );
    assert!(
        !output.status.success(),
        "minting both scopes on one token must exit non-zero"
    );

    let stored = std::fs::read_to_string(tokens.path()).expect("read tokens file");
    assert!(
        !stored.contains("\"test\""),
        "a refused token mint must not reach the token store: {stored}"
    );
}

/// The single-scope case -- the normal way to issue a stage or approve
/// token -- must still work end to end through the real binary.
#[test]
fn token_add_with_a_single_changeset_control_scope_is_allowed() {
    let tokens = tokens_file();
    let output = run(&[
        "token",
        "add",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--name",
        "stager",
        "--devices",
        "*",
        "--tools",
        "unifi_stage_change",
    ]);
    let stderr = stderr_of(&output);

    assert!(
        output.status.success(),
        "a single change-set control scope must be permitted, got stderr:\n{stderr}"
    );

    let stored = std::fs::read_to_string(tokens.path()).expect("read tokens file");
    assert!(
        stored.contains("\"stager\""),
        "the permitted token must reach the token store: {stored}"
    );
}

/// Ordering, not just wording.
///
/// Validation must run before any file is read, so an argument mistake is
/// reported as an argument mistake. Before this was fixed, the controllers
/// file was parsed first and a wrong file mode masked the CLI error entirely —
/// the opposite order from every other server in the family.
#[test]
fn argument_errors_are_not_masked_by_config_errors() {
    let controllers = controllers_file();
    let tokens = tokens_file();

    // Deliberately make the inventory unreadable-by-policy as well.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(controllers.path(), std::fs::Permissions::from_mode(0o644))
            .expect("chmod 644");
    }

    let output = run(&[
        "--controllers-file",
        controllers.path().to_str().expect("utf-8 path"),
        "--transport",
        "streamable-http",
        "--host",
        "0.0.0.0",
        "--port",
        "30033",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--allow-insecure-bind",
        "--allowed-host",
        "10.0.0.1:30033",
    ]);
    let stderr = stderr_of(&output);

    assert!(
        stderr.contains("requires at least one --allowed-origin"),
        "the argument error must win over the inventory error, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("group- or world-accessible"),
        "the inventory error masked the argument error:\n{stderr}"
    );
}

/// MEC-503 F2: `--allow-self-approval` is the explicit, issuance-time opt-in
/// for a lab-mode single operator; without it the combination is refused
/// (see `token_add_with_both_changeset_control_scopes_is_refused`).
#[test]
fn token_add_with_both_scopes_and_allow_self_approval_is_accepted() {
    let tokens = tokens_file();
    let output = run(&[
        "token",
        "add",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--name",
        "lab-operator",
        "--devices",
        "*",
        "--tools",
        "unifi_stage_change,unifi_approve_change_set",
        "--allow-self-approval",
    ]);
    assert!(
        output.status.success(),
        "an explicit --allow-self-approval mint must succeed, stderr:\n{}",
        stderr_of(&output)
    );
    let stored = std::fs::read_to_string(tokens.path()).expect("read tokens file");
    assert!(
        stored.contains("\"lab-operator\""),
        "token must be stored: {stored}"
    );
}

/// Reads the stored entry named `name` from a tokens file.
fn stored_entry(path: &std::path::Path, name: &str) -> serde_json::Value {
    let raw = std::fs::read_to_string(path).expect("read tokens file");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("tokens file is JSON");
    parsed["tokens"]
        .as_array()
        .expect("tokens array")
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap_or_else(|| panic!("token {name} not stored: {raw}"))
        .clone()
}

/// Issue #126: the opt-in is recorded on the token, and a token minted
/// without it carries no `self_approval` key at all.
#[test]
fn token_add_records_self_approval_only_when_opted_in() {
    let tokens = tokens_file();
    let path = tokens.path().to_str().expect("utf-8 path");
    let both = "unifi_stage_change,unifi_approve_change_set";
    let opted = run(&[
        "token",
        "add",
        "--tokens-file",
        path,
        "--name",
        "lab-operator",
        "--devices",
        "*",
        "--tools",
        both,
        "--allow-self-approval",
    ]);
    assert!(opted.status.success(), "{}", stderr_of(&opted));
    let plain = run(&[
        "token",
        "add",
        "--tokens-file",
        path,
        "--name",
        "stager",
        "--devices",
        "*",
        "--tools",
        "unifi_stage_change",
    ]);
    assert!(plain.status.success(), "{}", stderr_of(&plain));

    let opted_grant = &stored_entry(tokens.path(), "lab-operator")["grant"];
    assert_eq!(opted_grant["self_approval"], true);
    assert_eq!(opted_grant["sites"], serde_json::json!(["*"]));
    assert!(stored_entry(tokens.path(), "stager").get("grant").is_none());
}

/// `set-scope --allow-self-approval` without `--sites` records the opt-in and
/// keeps the token's existing sites.
#[test]
fn token_set_scope_records_self_approval_and_preserves_sites() {
    let tokens = tokens_file();
    let path = tokens.path().to_str().expect("utf-8 path");
    let minted = run(&[
        "token",
        "add",
        "--tokens-file",
        path,
        "--name",
        "op",
        "--devices",
        "*",
        "--tools",
        "unifi_stage_change",
        "--sites",
        "site-a",
    ]);
    assert!(minted.status.success(), "{}", stderr_of(&minted));

    let updated = run(&[
        "token",
        "set-scope",
        "--tokens-file",
        path,
        "--name",
        "op",
        "--tools",
        "unifi_stage_change,unifi_approve_change_set",
        "--allow-self-approval",
        "--yes",
    ]);
    assert!(updated.status.success(), "{}", stderr_of(&updated));

    let grant = &stored_entry(tokens.path(), "op")["grant"];
    assert_eq!(grant["self_approval"], true);
    assert_eq!(grant["sites"], serde_json::json!(["site-a"]));
}

/// The refusal tells a lab-mode operator how to opt in.
#[test]
fn combined_scope_refusal_names_the_opt_in() {
    let tokens = tokens_file();
    let output = run(&[
        "token",
        "add",
        "--tokens-file",
        tokens.path().to_str().expect("utf-8 path"),
        "--name",
        "x",
        "--devices",
        "*",
        "--tools",
        "unifi_stage_change,unifi_approve_change_set",
    ]);
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("--allow-self-approval") && stderr.contains("--lab-mode"),
        "{stderr}"
    );
}

/// Every shared refusal fixture must reach stderr exactly as the shared
/// validator words it, so this server cannot drift from the rest of the
/// family again. See mecmcp#358.
#[test]
fn shared_refusal_fixtures_match_expected_stderr() {
    use mecmcp_runtime::cli_validate::testing::{expected_stderr, refusal_fixtures};

    for (args, refusal) in refusal_fixtures() {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(1), "args: {args:?}");
        assert_eq!(
            stderr_of(&output).trim_end(),
            expected_stderr(&refusal),
            "args: {args:?}"
        );
    }
}
