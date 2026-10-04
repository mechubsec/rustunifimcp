//! The systemd/LXC deployment must key its audit sink too (mecmcp#376 /
//! MEC-978): `packaging/systemd/rustunifimcp.service` and
//! `packaging/lxc/install.sh` must generate and wire in an audit HMAC key.

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn the_systemd_unit_passes_an_audit_hmac_key_file() {
    let text = std::fs::read_to_string(repo_root().join("packaging/systemd/rustunifimcp.service"))
        .expect("read rustunifimcp.service");
    let exec_start = text
        .find("ExecStart=")
        .expect("unit has an ExecStart directive");
    // ExecStart's backslash-continued lines run until the first line that
    // does not end in a continuation.
    let mut end = exec_start;
    for line in text[exec_start..].lines() {
        end += line.len() + 1;
        if !line.trim_end().ends_with('\\') {
            break;
        }
    }
    let exec_start_block = &text[exec_start..end];

    assert!(
        exec_start_block.contains("--audit-hmac-key-file"),
        "ExecStart must carry --audit-hmac-key-file so the LXC deployment \
         starts keyed by default, got: {exec_start_block}"
    );
}

#[test]
fn the_lxc_installer_generates_the_audit_hmac_key() {
    let text = std::fs::read_to_string(repo_root().join("packaging/lxc/install.sh"))
        .expect("read install.sh");
    let audit_key_block_start = text
        .find("audit_key=/var/lib/unifimcp/audit-hmac.key")
        .expect("install.sh declares audit_key");
    let audit_key_block = &text[audit_key_block_start..];

    assert!(
        audit_key_block.contains("openssl rand -hex 32"),
        "install.sh must generate /var/lib/unifimcp/audit-hmac.key on first \
         install, mirroring rust-junosmcp's install.sh"
    );
    assert!(
        audit_key_block.contains("install -m 0600 -o unifimcp -g unifimcp"),
        "the generated key must be installed with a fixed owner and mode, \
         got: {audit_key_block}"
    );
}

#[test]
fn the_lxc_installer_refuses_a_non_regular_audit_hmac_key_path() {
    let text = std::fs::read_to_string(repo_root().join("packaging/lxc/install.sh"))
        .expect("read install.sh");
    assert!(
        text.contains("-L \"$audit_key\""),
        "install.sh must refuse a non-regular audit-hmac.key path before \
         touching it, got: {text}"
    );
}
