//! The systemd/LXC deployment must not ship unkeyed audit either (mecmcp#376
//! / MEC-978): `dockerfile_audit_key.rs` pinned the container ENTRYPOINT, but
//! `packaging/systemd/rustunifimcp.service` shipped with no
//! `--audit-hmac-key-file` at all, and `packaging/lxc/install.sh` never
//! generated one -- the one deployment path this repo's own container-image
//! test comment claimed was already keyed.

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
         generates a keyed audit HMAC key on first run instead of shipping \
         unkeyed by omission, got: {exec_start_block}"
    );
}

#[test]
fn the_lxc_installer_generates_the_audit_hmac_key() {
    let text = std::fs::read_to_string(repo_root().join("packaging/lxc/install.sh"))
        .expect("read install.sh");
    assert!(
        text.contains("audit-hmac.key"),
        "install.sh must generate /var/lib/unifimcp/audit-hmac.key on first \
         install, mirroring rust-junosmcp's install.sh, so a fresh LXC \
         deployment starts keyed rather than relying solely on the binary's \
         own on-demand generation"
    );
}
