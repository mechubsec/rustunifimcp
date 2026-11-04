//! `unifi_cancel_change_set` frees the one-pending-set-per-token slot (#145).
//!
//! A change set that fails `unifi_validate_change_set` stays `planned`, and
//! until this tool existed it blocked its owner from creating another for the
//! whole approval window. These drive the real tool router over stdio, so the
//! caller is the single stdio principal: refusing a non-owner is the
//! coordinator's own check, covered in mecmcp-changeset.

use mecmcp_changeset::{ChangeSetState, ChangesetCoordinator};
use rmcp::{ServiceExt, model::CallToolRequestParams};
use rustunifimcp::changeset_state::build_coordinator;
use rustunifimcp::server::UnifiServer;
use rustunifimcp_core::inventory::ControllerRegistry;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

const CONTROLLER: &str = "home";

fn secure(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).expect("chmod 600");
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// A controller whose endpoint is never reachable and, for the `create`
/// mutation this test stages, never contacted: `create` has no pre-image to
/// fetch, so a passing test here never depends on the network.
fn server() -> UnifiServer {
    server_with_coordinator().0
}

fn server_with_coordinator() -> (UnifiServer, Arc<ChangesetCoordinator>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let mut key = tempfile::NamedTempFile::new().expect("create api key file");
    key.write_all(b"dummy-api-key\n").expect("write api key");
    key.flush().expect("flush api key");
    secure(key.path());
    let key_path = key.into_temp_path().keep().expect("persist api key file");

    let mut controllers = tempfile::NamedTempFile::new().expect("create controllers file");
    let body = format!(
        r#"{{"version":1,"devices":{{"{CONTROLLER}":{{"endpoint":"https://unifi.example.org","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
        key_path.display()
    );
    controllers
        .write_all(body.as_bytes())
        .expect("write controllers file");
    controllers.flush().expect("flush controllers file");
    secure(controllers.path());

    let registry =
        Arc::new(ControllerRegistry::load(controllers.path()).expect("load controllers"));
    let coordinator =
        build_coordinator(None, Duration::from_secs(300), true, None, None).expect("coordinator");
    let handler = UnifiServer::new(
        registry,
        true,
        coordinator.clone(),
        None,
        mecmcp_audit::DirectCommitPolicy::new(false),
    )
    .expect("server");
    (handler, coordinator)
}

async fn call(
    handler: UnifiServer,
    tool: &str,
    arguments: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move {
        handler
            .serve(server_transport)
            .await
            .expect("server initialization")
            .waiting()
            .await
    });
    let client = ().serve(client_transport).await.expect("client initialization");
    let result = client
        .call_tool(
            CallToolRequestParams::new(tool.to_owned())
                .with_arguments(serde_json::from_value(arguments).expect("arguments")),
        )
        .await;
    client.cancel().await.expect("client shutdown");
    server_task.abort();

    let result = result.map_err(|error| error.to_string())?;
    let text = result.content[0]
        .as_text()
        .expect("text result")
        .text
        .clone();
    if result.is_error == Some(true) {
        return Err(text);
    }
    Ok(serde_json::from_str(&text).expect("JSON envelope"))
}

async fn create_change_set(handler: UnifiServer) -> String {
    let created = call(
        handler,
        "unifi_create_change_set",
        serde_json::json!({"controller": CONTROLLER, "description": "test"}),
    )
    .await
    .expect("create");
    created["change_set_id"]
        .as_str()
        .expect("change_set_id")
        .to_owned()
}

fn stage_policy(id: &str) -> serde_json::Value {
    serde_json::json!({
        "controller": CONTROLLER,
        "change_set_id": id,
        "mutations": [
            {"operation": "create", "kind": "firewall_policy", "body": {"name": "a"}}
        ]
    })
}

/// The #145 scenario: a planned set blocks the next create until cancelled,
/// and cancelling it lets the owner start again at once.
#[tokio::test]
async fn cancelling_a_planned_set_frees_the_owner_to_create_another() {
    let handler = server();
    let id = create_change_set(handler.clone()).await;
    call(handler.clone(), "unifi_stage_change", stage_policy(&id))
        .await
        .expect("stage");

    let blocked = call(
        handler.clone(),
        "unifi_create_change_set",
        serde_json::json!({"controller": CONTROLLER, "description": "second"}),
    )
    .await
    .expect_err("a planned set must block the next create");
    assert!(blocked.contains("still planned"), "got: {blocked}");

    let cancelled = call(
        handler.clone(),
        "unifi_cancel_change_set",
        serde_json::json!({"controller": CONTROLLER, "change_set_id": id}),
    )
    .await
    .expect("cancel");
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["previous_state"], "planned");

    let fetched = call(
        handler.clone(),
        "unifi_get_change_set",
        serde_json::json!({"controller": CONTROLLER, "change_set_id": id}),
    )
    .await
    .expect("get");
    assert_eq!(
        fetched["state"], "cancelled",
        "the record is kept, not deleted"
    );

    create_change_set(handler).await;
}

/// A draft has no stored record; cancelling it drops it and frees the slot.
#[tokio::test]
async fn cancelling_a_draft_frees_the_owner_to_create_another() {
    let handler = server();
    let id = create_change_set(handler.clone()).await;

    let cancelled = call(
        handler.clone(),
        "unifi_cancel_change_set",
        serde_json::json!({"controller": CONTROLLER, "change_set_id": id}),
    )
    .await
    .expect("cancel");
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["previous_state"], "draft");

    call(handler.clone(), "unifi_stage_change", stage_policy(&id))
        .await
        .expect_err("a cancelled draft must not be stageable");

    create_change_set(handler).await;
}

/// A cancelled set stays cancelled: a second cancel reports it, and approve
/// cannot bring it back.
#[tokio::test]
async fn a_cancelled_set_cannot_be_approved() {
    let handler = server();
    let id = create_change_set(handler.clone()).await;
    call(handler.clone(), "unifi_stage_change", stage_policy(&id))
        .await
        .expect("stage");
    let args = serde_json::json!({"controller": CONTROLLER, "change_set_id": id});
    call(handler.clone(), "unifi_cancel_change_set", args.clone())
        .await
        .expect("cancel");

    let again = call(handler.clone(), "unifi_cancel_change_set", args.clone())
        .await
        .expect("a second cancel is idempotent");
    assert_eq!(again["state"], "cancelled");

    call(handler, "unifi_approve_change_set", args)
        .await
        .expect_err("a cancelled set must not be approvable");
}

/// A partial apply is stored as `failed` with writes already on the
/// controller; cancelling would relabel it and hide them.
#[tokio::test]
async fn a_failed_set_cannot_be_cancelled() {
    let (handler, coordinator) = server_with_coordinator();
    let id = create_change_set(handler.clone()).await;
    call(handler.clone(), "unifi_stage_change", stage_policy(&id))
        .await
        .expect("stage");

    let mut failed = coordinator
        .change_set(&id, CONTROLLER)
        .await
        .expect("staged record");
    failed.id = "f".repeat(64);
    failed.state = ChangeSetState::Failed;
    coordinator
        .seed_change_set_for_test(failed.clone())
        .await
        .expect("seed a failed set");

    let refused = call(
        handler,
        "unifi_cancel_change_set",
        serde_json::json!({"controller": CONTROLLER, "change_set_id": failed.id}),
    )
    .await
    .expect_err("a failed set must not be cancellable");
    assert!(refused.contains("failed apply"), "got: {refused}");
    assert_eq!(
        coordinator
            .change_set(&failed.id, CONTROLLER)
            .await
            .expect("record")
            .state,
        ChangeSetState::Failed
    );
}
