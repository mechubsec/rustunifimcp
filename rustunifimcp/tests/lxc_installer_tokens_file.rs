//! `packaging/lxc/install.sh` provisions `/var/lib/unifimcp/tokens.json` on
//! first install. The installer must refuse a non-regular path at that
//! location and install the file's contents with a fixed owner and mode.

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn install_sh() -> String {
    std::fs::read_to_string(repo_root().join("packaging/lxc/install.sh")).expect("read install.sh")
}

#[test]
fn the_lxc_installer_refuses_a_non_regular_tokens_file_path() {
    let text = install_sh();
    assert!(
        text.contains("-L \"$tokens_file\""),
        "install.sh must refuse a non-regular tokens.json path before \
         touching it, got: {text}"
    );
}

#[test]
fn the_lxc_installer_installs_the_tokens_file_with_a_fixed_owner_and_mode() {
    let text = install_sh();
    let tokens_block_start = text
        .find("tokens_file=/var/lib/unifimcp/tokens.json")
        .expect("install.sh declares tokens_file");
    let tokens_block_end = text[tokens_block_start..]
        .find("audit_key=/var/lib/unifimcp/audit-hmac.key")
        .expect("tokens block precedes the audit-hmac-key block");
    let tokens_block = &text[tokens_block_start..tokens_block_start + tokens_block_end];

    assert!(
        tokens_block.contains("install -m 0600 -o unifimcp -g unifimcp"),
        "tokens.json must be provisioned with install(1) at a fixed owner \
         and mode, got: {tokens_block}"
    );
    assert!(
        !tokens_block.contains("> \"$tokens_file\""),
        "tokens.json must be provisioned with install(1), not a direct \
         redirect, got: {tokens_block}"
    );
    assert!(
        !tokens_block.contains("chown unifimcp:unifimcp \"$tokens_file\""),
        "tokens.json's owner and mode must come from install(1), not a \
         separate chown, got: {tokens_block}"
    );
}
