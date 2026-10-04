//! `packaging/lxc/install.sh` provisions `/var/lib/unifimcp/tokens.json` on
//! first install. `/var/lib/unifimcp` is writable by the unifimcp service
//! account, so the installer must refuse a non-regular path at that
//! location and install the file's contents rather than writing through
//! an existing path and chown/chmod-ing it in place -- the same pattern
//! already applied to the audit-hmac-key block in this file.

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
        "install.sh must refuse a symlinked tokens.json path before \
         touching it, got: {text}"
    );
}

#[test]
fn the_lxc_installer_installs_rather_than_writes_through_the_tokens_file() {
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
        "a freshly generated tokens.json must be installed into place with \
         `install`, not written through an existing path and chowned/\
         chmoded after the fact, got: {tokens_block}"
    );
    assert!(
        !tokens_block.contains("> \"$tokens_file\""),
        "tokens.json content must not be redirected directly onto the \
         service-writable target path, got: {tokens_block}"
    );
    assert!(
        !tokens_block.contains("chown unifimcp:unifimcp \"$tokens_file\""),
        "install.sh must not chown the tokens.json path directly after a \
         separate write; ownership must be set by `install` on the file \
         it just created, got: {tokens_block}"
    );
}
