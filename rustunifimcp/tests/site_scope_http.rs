//! Proves per-token site scoping on the real, authenticated request path
//! (MEC-508).
//!
//! Before this grant existed, any token holding `unifi_device_action` scope
//! for a controller could write to any site on it -- the four operational
//! write tools already accepted a caller-supplied `site`, but nothing
//! restricted which site a given token could name. These tests drive the
//! real HTTP router, the same way `two_person_control_http.rs` proves
//! two-person control at the call site rather than only in a unit test of the
//! helper it calls.
//!
//! The controller endpoint is an address nothing listens on
//! (`https://127.0.0.1:1`), so a call that gets past the site check fails
//! fast on a connection error rather than reaching a real network. That
//! failure is exactly the signal these tests need: it proves authorization
//! passed and the call reached the controller-facing code, without needing a
//! real UniFi controller.

use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_transport::{LimitsConfig, serve_router, test_client::McpClient};
use rustunifimcp::grant::UnifiGrant;
use rustunifimcp::server::UnifiServer;
use rustunifimcp_core::inventory::ControllerRegistry;
use rustunifimcp_core::tools::TOOL_NAMES;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// One controller, `home`, at an address nothing listens on. Every test here
/// either gets refused before the controller is ever contacted (the denial
/// cases) or reaches a fast, deterministic connection failure (the allowed
/// cases) -- neither needs a real UniFi controller.
fn registry_with_unreachable_controller() -> Arc<ControllerRegistry> {
    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");
    }
    let key_path = key.into_temp_path().keep().expect("persist api key file");

    let mut controllers = tempfile::NamedTempFile::new().expect("create controllers file");
    let body = format!(
        r#"{{"version":1,"devices":{{"home":{{"endpoint":"https://127.0.0.1:1","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
        key_path.display()
    );
    controllers
        .write_all(body.as_bytes())
        .expect("write controllers file");
    controllers.flush().expect("flush controllers file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(controllers.path(), std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");
    }

    Arc::new(ControllerRegistry::load(controllers.path()).expect("load controllers"))
}

/// Mint a token with write-tool scope and an optional site grant, writing
/// straight to the token store file (not through the CLI, which is covered
/// elsewhere).
fn mint_token(path: &std::path::Path, name: &str, sites: Option<Vec<String>>) -> String {
    let known = KnownNames {
        devices: None,
        tools: TOOL_NAMES,
    };
    let grant = sites.map(|sites| UnifiGrant {
        sites: ScopeSet::Allowlist(sites),
    });
    let secret = TokenStoreFile::<UnifiGrant>::add_with_options(
        path,
        name,
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["unifi_device_action".to_owned()]),
        None,
        grant,
        None,
        None,
        None,
        None,
        None,
        &known,
    )
    .expect("mint token");
    secret.expose_secret().to_owned()
}

async fn start_server(
    token_store: Arc<TokenStoreFile<UnifiGrant>>,
) -> (String, CancellationToken, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let registry = registry_with_unreachable_controller();
    let coordinator = rustunifimcp::changeset_state::build_coordinator(
        None,
        Duration::from_secs(300),
        false,
        None,
        None,
    )
    .expect("coordinator");
    let handler = UnifiServer::new(
        registry,
        false,
        coordinator,
        None,
        mecmcp_audit::DirectCommitPolicy::new(false),
    )
    .expect("server");

    let shutdown = CancellationToken::new();
    let plan = rustunifimcp::http_transport::build_http_router(
        handler,
        Some(token_store),
        Vec::new(),
        Vec::new(),
        LimitsConfig::default(),
        false,
        false,
        shutdown.clone(),
    )
    .expect("build router");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);

    let shutdown_for_task = shutdown.clone();
    let task = tokio::spawn(async move {
        serve_router(
            plan,
            format!("127.0.0.1:{port}").parse().expect("address"),
            None,
            Duration::from_millis(50),
        )
        .await
        .expect("serve_router");
        drop(shutdown_for_task);
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    (format!("http://127.0.0.1:{port}"), shutdown, task)
}

/// Call `unifi_device_action` against `site` and return the tool result.
fn call_device_action(base_url: String, bearer: String, site: &str) -> serde_json::Value {
    let site = site.to_owned();
    let session_id = {
        let base_url = base_url.clone();
        let bearer = bearer.clone();
        McpClient::new(base_url)
            .expect("client")
            .with_bearer(bearer)
            .initialize()
            .expect("initialize")
    };

    McpClient::new(base_url)
        .expect("client")
        .with_bearer(bearer)
        .tools_call(
            &session_id,
            "unifi_device_action",
            serde_json::json!({
                "controller": "home",
                "device": "aa:bb:cc:dd:ee:ff",
                "action": "restart",
                "site": site,
            }),
        )
        .expect("tools/call")
}

/// A token scoped to `site-a` must be refused -- not silently redirected to
/// `site-a` or to the controller's default site -- when the call targets
/// `site-b`.
#[tokio::test]
async fn a_token_scoped_to_one_site_is_refused_for_another_site() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(
        &tokens_path,
        "site-a-writer",
        Some(vec!["site-a".to_owned()]),
    );
    let store = Arc::new(TokenStoreFile::<UnifiGrant>::load(&tokens_path).expect("load store"));

    let (base_url, shutdown, task) = start_server(store).await;

    let result =
        tokio::task::spawn_blocking(move || call_device_action(base_url, bearer, "site-b"))
            .await
            .expect("blocking task");

    let text = result["content"][0]["text"].as_str().expect("text content");
    assert!(
        result["isError"].as_bool().unwrap_or(false),
        "a token scoped to site-a must be refused for site-b, got: {result}"
    );
    assert!(
        text.contains("not authorized to write to site") && text.contains("site-b"),
        "the refusal must name the out-of-scope site, got: {text}"
    );
    // mecmcp-server redacts every tool_error unconditionally (mecmcp v0.25.0,
    // MEC-1020), and mecmcp-redact's key denylist matches "token" as a
    // substring; a denylisted-key match blanks the rest of the line, not
    // just the value. `SiteNotInScope`'s message says "caller", not "token",
    // specifically so this non-secret identifier survives that pass.
    assert!(
        text.contains("site-a-writer"),
        "the refusal must name the token, got: {text}"
    );

    shutdown.cancel();
    task.abort();
}

/// A token scoped to more than one site must be authorized for each of its
/// scoped sites -- the check is a positive allowlist over all named sites,
/// not just the first.
#[tokio::test]
async fn a_token_scoped_to_multiple_sites_writes_to_each() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(
        &tokens_path,
        "multi-site-writer",
        Some(vec!["site-a".to_owned(), "site-b".to_owned()]),
    );
    let store = Arc::new(TokenStoreFile::<UnifiGrant>::load(&tokens_path).expect("load store"));

    let (base_url, shutdown, task) = start_server(store).await;

    for site in ["site-a", "site-b"] {
        let result = tokio::task::spawn_blocking({
            let base_url = base_url.clone();
            let bearer = bearer.clone();
            let site = site.to_owned();
            move || call_device_action(base_url, bearer, &site)
        })
        .await
        .expect("blocking task");

        let text = result["content"][0]["text"].as_str().unwrap_or_default();
        assert!(
            !text.contains("not authorized to write to site"),
            "a token scoped to {site} must not be refused for it, got: {text}"
        );
        assert!(
            !text.is_empty(),
            "the call must still get a real answer for {site}: {result}"
        );
    }

    shutdown.cancel();
    task.abort();
}

/// A token minted with no `--sites` grant is unrestricted by site -- the
/// pre-MEC-508 default, kept so every token issued before per-site scoping
/// existed keeps working unchanged.
#[tokio::test]
async fn a_token_with_no_site_grant_is_unrestricted_by_site() {
    let tokens_dir = tempfile::tempdir().expect("tempdir");
    let tokens_path = tokens_dir.path().join("tokens.json");
    let bearer = mint_token(&tokens_path, "legacy-writer", None);
    let store = Arc::new(TokenStoreFile::<UnifiGrant>::load(&tokens_path).expect("load store"));

    let (base_url, shutdown, task) = start_server(store).await;

    let result = tokio::task::spawn_blocking(move || {
        call_device_action(base_url, bearer, "any-site-at-all")
    })
    .await
    .expect("blocking task");

    let text = result["content"][0]["text"].as_str().unwrap_or_default();
    assert!(
        !text.contains("not authorized to write to site"),
        "a grantless token must not be refused by site scope, got: {text}"
    );
    assert!(
        !text.is_empty(),
        "the call must still get a real answer: {result}"
    );

    shutdown.cancel();
    task.abort();
}
