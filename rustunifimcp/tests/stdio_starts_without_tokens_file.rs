//! The container ENTRYPOINT bakes in a fixed `--tokens-file
//! /var/lib/unifimcp/tokens.json`. That flag only matters for HTTP bearer
//! auth; a stdio session carries no caller context and never consults the
//! token store (see `serve_http` vs. `serve_stdio` in `main.rs`). A stdio
//! start must not fail just because the baked-in tokens file does not exist
//! yet on a fresh container -- MEC-2121 / mechubsec/mecmcp#386 catalog audit.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

fn secure(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn controllers_file() -> tempfile::NamedTempFile {
    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    secure(key.path());
    let key_path = key.into_temp_path().keep().expect("persist api key file");

    let mut file = tempfile::NamedTempFile::new().expect("create controllers file");
    let body = format!(
        r#"{{"version":1,"devices":{{"home":{{"endpoint":"https://127.0.0.1:1","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
        key_path.display()
    );
    file.write_all(body.as_bytes())
        .expect("write controllers file");
    file.flush().expect("flush controllers file");
    secure(file.path());
    file
}

/// A stdio session reaches `tools/list` with no bearer-token store on disk,
/// and starting the process never creates one at the baked-in path either.
#[test]
fn stdio_starts_when_tokens_file_points_to_a_missing_path() {
    let controllers = controllers_file();

    let tokens_dir = tempfile::tempdir().expect("create tokens dir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    assert!(
        !tokens_path.exists(),
        "tokens file must not exist before the process starts"
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_rustunifimcp"))
        .args([
            "--controllers-file",
            controllers.path().to_str().expect("utf-8 path"),
            "--tokens-file",
            tokens_path.to_str().expect("utf-8 path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn rustunifimcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        for line in [
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        ] {
            writeln!(stdin, "{line}").expect("write request");
        }
        stdin.flush().expect("flush");
    }

    let stdout = child.stdout.take().expect("stdout");
    let mut lines = BufReader::new(stdout).lines();

    // Response to `initialize` (id 0), then the `tools/list` response (id 1).
    let _initialize_response = lines
        .next()
        .expect("initialize response")
        .expect("read initialize response");
    let tools_response = lines
        .next()
        .expect("tools/list response")
        .expect("read tools/list response");

    assert!(
        tools_response.contains("\"id\":1") && tools_response.contains("unifi_device_action"),
        "tools/list must succeed over stdio with no tokens file present: {tools_response}"
    );

    drop(child.stdin.take());
    let _ = child.wait_timeout_or_kill(Duration::from_secs(5));

    assert!(
        !tokens_path.exists(),
        "a stdio start must never create the bearer-token store as a side effect"
    );
}

/// Small helper so the test does not hang forever if the child misbehaves.
trait WaitTimeoutOrKill {
    fn wait_timeout_or_kill(&mut self, timeout: Duration) -> std::io::Result<()>;
}

impl WaitTimeoutOrKill for std::process::Child {
    fn wait_timeout_or_kill(&mut self, timeout: Duration) -> std::io::Result<()> {
        let start = std::time::Instant::now();
        loop {
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                let _ = self.kill();
                let _ = self.wait();
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
