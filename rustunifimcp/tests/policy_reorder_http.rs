//! A staged firewall-policy reorder, driven through the real `UnifiClient`
//! against a stateful fake controller.
//!
//! The fake's batch-reorder follows the spike on UniFi Network 10.6.109: the
//! request body is `{"source_zone_id", "destination_zone_id",
//! "before_predefined_ids": [], "after_predefined_ids": [ids...]}`, the listed
//! policies are re-indexed to 40000, 40001, ..., and the reply is 200 with the
//! re-indexed list. A create ignores any `index` and takes the next free value.
//! Refusing a body that is not a full permutation of the pair is the fake's
//! assumption, not something the spike checked.

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Json};
use axum::routing::any;
use rustunifimcp::server::UnifiServer;
use rustunifimcp_core::changeset::apply::{State as ApplyState, apply_sequentially};
use rustunifimcp_core::changeset::{
    CreatedRef, OrderEntry, Preimage, StagedMutation, check_policy_reorders,
};
use rustunifimcp_core::client::UnifiClient;
use rustunifimcp_core::inventory::ControllerRegistry;
use serde_json::{Value, json};
use std::io::Write as _;
use std::sync::{Arc, Mutex};

const LAN: &str = "000000000000000000000101";
const WAN: &str = "000000000000000000000102";
const A: &str = "000000000000000000000201";
const B: &str = "000000000000000000000203";
const PREDEFINED: &str = "000000000000000000000202";
const OTHER_PAIR: &str = "000000000000000000000299";
const POLICIES: &str = "/proxy/network/v2/api/site/default/firewall-policies";
const ZONES: &str = "/proxy/network/v2/api/site/default/firewall/zone";

#[derive(Default)]
struct Fake {
    policies: Vec<Value>,
    next_id: u32,
    reorder_bodies: Vec<Value>,
    /// Answer a DELETE of this id with 500.
    fail_delete: Option<String>,
    /// Answer batch-reorder 200 without re-indexing anything.
    ignore_reorder: bool,
}

type Shared = Arc<Mutex<Fake>>;

fn policy(id: &str, index: u64, predefined: bool, source: &str, destination: &str) -> Value {
    json!({
        "_id": id, "name": id, "action": "ALLOW", "enabled": true,
        "index": index, "predefined": predefined,
        "source": {"zone_id": source}, "destination": {"zone_id": destination}
    })
}

fn seeded() -> Shared {
    Arc::new(Mutex::new(Fake {
        policies: vec![
            policy(PREDEFINED, 30000, true, LAN, WAN),
            policy(A, 40000, false, LAN, WAN),
            policy(B, 40001, false, LAN, WAN),
            policy(OTHER_PAIR, 40002, false, WAN, WAN),
        ],
        next_id: 0x300,
        ..Fake::default()
    }))
}

fn custom_order(fake: &Fake, source: &str, destination: &str) -> Vec<String> {
    let mut custom: Vec<(u64, String)> = fake
        .policies
        .iter()
        .filter(|p| {
            p["predefined"] == json!(false)
                && p["source"]["zone_id"] == json!(source)
                && p["destination"]["zone_id"] == json!(destination)
        })
        .map(|p| {
            (
                p["index"].as_u64().unwrap_or_default(),
                p["_id"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    custom.sort();
    custom.into_iter().map(|(_, id)| id).collect()
}

async fn handler(
    State(shared): State<Shared>,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> axum::response::Response {
    let mut fake = shared.lock().expect("fake lock");
    let path = uri.path();
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);

    if path == ZONES && method == Method::GET {
        return Json(json!([{"_id": LAN, "name": "Internal"}, {"_id": WAN, "name": "External"}]))
            .into_response();
    }
    if path == POLICIES && method == Method::GET {
        return Json(Value::Array(fake.policies.clone())).into_response();
    }
    if path == POLICIES && method == Method::POST {
        let next_index = fake
            .policies
            .iter()
            .filter_map(|p| p["index"].as_u64())
            .max()
            .unwrap_or(0)
            + 1;
        fake.next_id += 1;
        let mut created = parsed;
        created["_id"] = json!(format!("{:024x}", fake.next_id));
        created["index"] = json!(next_index);
        created["predefined"] = json!(false);
        fake.policies.push(created.clone());
        return Json(created).into_response();
    }
    if path == format!("{POLICIES}/batch-reorder") && method == Method::PUT {
        fake.reorder_bodies.push(parsed.clone());
        let keys: Vec<&String> = parsed
            .as_object()
            .map(|o| o.keys().collect())
            .unwrap_or_default();
        let (Some(source), Some(destination), Some(after)) = (
            parsed["source_zone_id"].as_str(),
            parsed["destination_zone_id"].as_str(),
            parsed["after_predefined_ids"].as_array(),
        ) else {
            return (StatusCode::BAD_REQUEST, "bad body").into_response();
        };
        let after: Vec<String> = after
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let mut expected = custom_order(&fake, source, destination);
        let mut sent = after.clone();
        expected.sort();
        sent.sort();
        if keys.len() != 4 || parsed["before_predefined_ids"] != json!([]) || expected != sent {
            return (StatusCode::BAD_REQUEST, "not a permutation").into_response();
        }
        if fake.ignore_reorder {
            return Json(json!([])).into_response();
        }
        let mut reindexed = Vec::new();
        for (offset, id) in after.iter().enumerate() {
            if let Some(found) = fake.policies.iter_mut().find(|p| p["_id"] == json!(id)) {
                found["index"] = json!(40000 + offset as u64);
                reindexed.push(found.clone());
            }
        }
        return Json(Value::Array(reindexed)).into_response();
    }
    if let Some(id) = path.strip_prefix(&format!("{POLICIES}/")) {
        let id = id.to_owned();
        if method == Method::DELETE {
            if fake.fail_delete.as_deref() == Some(id.as_str()) {
                return (StatusCode::INTERNAL_SERVER_ERROR, "boom").into_response();
            }
            fake.policies.retain(|p| p["_id"] != json!(id));
            return StatusCode::OK.into_response();
        }
        if method == Method::GET {
            return match fake.policies.iter().find(|p| p["_id"] == json!(id)) {
                Some(found) => Json(found.clone()).into_response(),
                None => StatusCode::NOT_FOUND.into_response(),
            };
        }
    }
    (StatusCode::NOT_FOUND, "no route").into_response()
}

fn write_temp(contents: &[u8]) -> std::path::PathBuf {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(contents).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("chmod 600");
    }
    file.into_temp_path().keep().expect("persist")
}

async fn client_for(shared: Shared) -> UnifiClient {
    let registry = registry_for(shared).await;
    UnifiClient::new(registry.get("fake").expect("controller")).expect("client")
}

async fn registry_for(shared: Shared) -> ControllerRegistry {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
    let key_pair = rcgen::KeyPair::generate().expect("keypair");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    let cert = params.self_signed(&key_pair).expect("cert");
    let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert.pem().into_bytes(),
        key_pair.serialize_pem().into_bytes(),
    )
    .await
    .expect("tls config");
    let service = Router::new()
        .fallback(any(handler))
        .with_state(shared)
        .into_make_service();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    listener.set_nonblocking(true).expect("nonblocking");
    tokio::spawn(async move {
        let _ = axum_server::from_tcp_rustls(listener, tls)
            .expect("acceptor")
            .serve(service)
            .await;
    });

    let controllers = json!({
        "version": 1,
        "devices": {"fake": {
            "endpoint": format!("https://localhost:{port}"),
            "site": "default",
            "api_key_file": write_temp(b"reorder-test-key\n"),
            "ca_pem_path": write_temp(cert.pem().as_bytes()),
            "allow_private_api": true,
        }}
    });
    ControllerRegistry::load(write_temp(controllers.to_string().as_bytes())).expect("inventory")
}

/// One tool call against a real `UnifiServer` over an in-process transport.
async fn call(handler: UnifiServer, tool: &str, arguments: Value) -> Result<Value, String> {
    use rmcp::ServiceExt as _;
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
            rmcp::model::CallToolRequestParams::new(tool.to_owned())
                .with_arguments(serde_json::from_value(arguments).expect("arguments")),
        )
        .await;
    client.cancel().await.expect("client shutdown");
    server_task.abort();
    let result = result.map_err(|error| error.to_string())?;
    let text = result.content[0].as_text().expect("text").text.clone();
    if result.is_error == Some(true) {
        return Err(text);
    }
    Ok(serde_json::from_str(&text).expect("JSON envelope"))
}

async fn server_for(shared: Shared) -> UnifiServer {
    let registry = Arc::new(registry_for(shared).await);
    let coordinator = rustunifimcp::changeset_state::build_coordinator(
        None,
        std::time::Duration::from_secs(300),
        true,
        None,
        None,
    )
    .expect("coordinator");
    UnifiServer::new(
        registry,
        true,
        coordinator,
        None,
        mecmcp_audit::DirectCommitPolicy::new(false),
    )
    .expect("server")
}

/// Stage `mutations` (as JSON) into a fresh change set through the tool.
async fn stage_through_tool(
    handler: &UnifiServer,
    mutations: Value,
) -> (String, Result<Value, String>) {
    let created = call(
        handler.clone(),
        "unifi_create_change_set",
        json!({"controller": "fake", "description": "reorder"}),
    )
    .await
    .expect("create");
    let id = created["change_set_id"].as_str().expect("id").to_owned();
    let staged = call(
        handler.clone(),
        "unifi_stage_change",
        json!({"controller": "fake", "change_set_id": id, "mutations": mutations}),
    )
    .await;
    (id, staged)
}

fn id(value: &str) -> OrderEntry {
    OrderEntry::Id(value.to_owned())
}

fn created(name: &str) -> OrderEntry {
    OrderEntry::Created(CreatedRef {
        created_name: name.to_owned(),
    })
}

fn create_in_pair(name: &str) -> StagedMutation {
    StagedMutation::create(
        "firewall_policy",
        json!({"name": name, "action": "BLOCK", "create_allow_respond": false, "source": {"zone_id": LAN},
               "destination": {"zone_id": WAN}}),
    )
}

/// Stage: capture and validate, as `unifi_stage_change` does.
async fn stage(client: &UnifiClient, mutations: &[StagedMutation]) -> Preimage {
    let preimage = Preimage::capture_preimage(client, mutations)
        .await
        .expect("capture");
    check_policy_reorders(&preimage, mutations).expect("valid");
    preimage
}

#[tokio::test]
async fn a_policy_created_in_the_set_is_placed_first_by_name() {
    let shared = seeded();
    let client = client_for(shared.clone()).await;
    let mutations = vec![
        create_in_pair("mi-block"),
        StagedMutation::reorder(LAN, WAN, vec![created("mi-block"), id(A), id(B)]),
    ];
    let preimage = stage(&client, &mutations).await;

    let outcome = apply_sequentially(&client, &preimage, &mutations).await;
    assert_eq!(outcome.state, ApplyState::Applied, "{outcome:?}");

    let fake = shared.lock().expect("lock");
    let new_id = format!("{:024x}", 0x301);
    assert_eq!(
        fake.reorder_bodies,
        vec![json!({
            "source_zone_id": LAN, "destination_zone_id": WAN,
            "before_predefined_ids": [], "after_predefined_ids": [new_id, A, B]
        })]
    );
    assert_eq!(custom_order(&fake, LAN, WAN), vec![new_id.as_str(), A, B]);
    let untouched = fake.policies.iter().find(|p| p["_id"] == json!(PREDEFINED));
    assert_eq!(untouched.expect("predefined")["index"], json!(30000));
}

#[tokio::test]
async fn an_order_moved_since_staging_is_refused_stale() {
    let shared = seeded();
    let client = client_for(shared.clone()).await;
    let mutations = vec![StagedMutation::reorder(LAN, WAN, vec![id(B), id(A)])];
    let preimage = stage(&client, &mutations).await;

    // Someone swaps the two in the controller UI between approval and apply.
    for policy in &mut shared.lock().expect("lock").policies {
        if policy["_id"] == json!(A) {
            policy["index"] = json!(40001);
        } else if policy["_id"] == json!(B) {
            policy["index"] = json!(40000);
        }
    }

    let outcome = apply_sequentially(&client, &preimage, &mutations).await;
    assert_eq!(outcome.state, ApplyState::RefusedStale);
    assert!(shared.lock().expect("lock").reorder_bodies.is_empty());
}

#[tokio::test]
async fn a_later_failure_restores_the_order_and_deletes_the_created_policy() {
    let shared = seeded();
    shared.lock().expect("lock").fail_delete = Some(OTHER_PAIR.to_owned());
    let client = client_for(shared.clone()).await;
    let mutations = vec![
        create_in_pair("mi-block"),
        StagedMutation::reorder(LAN, WAN, vec![created("mi-block"), id(A), id(B)]),
        StagedMutation::delete("firewall_policy", OTHER_PAIR),
    ];
    let preimage = stage(&client, &mutations).await;

    let outcome = apply_sequentially(&client, &preimage, &mutations).await;
    assert_eq!(outcome.state, ApplyState::Partial, "{outcome:?}");

    let fake = shared.lock().expect("lock");
    let new_id = format!("{:024x}", 0x301);
    let sent: Vec<&Value> = fake
        .reorder_bodies
        .iter()
        .map(|body| &body["after_predefined_ids"])
        .collect();
    // Restored while the created policy still exists (it goes last), then deleted.
    assert_eq!(sent, vec![&json!([new_id, A, B]), &json!([A, B, new_id])]);
    assert_eq!(custom_order(&fake, LAN, WAN), vec![A, B]);
    assert!(!fake.policies.iter().any(|p| p["_id"] == json!(new_id)));
}

#[tokio::test]
async fn a_reorder_the_controller_ignored_is_applied_unverified() {
    let shared = seeded();
    shared.lock().expect("lock").ignore_reorder = true;
    let client = client_for(shared.clone()).await;
    let mutations = vec![StagedMutation::reorder(LAN, WAN, vec![id(B), id(A)])];
    let preimage = stage(&client, &mutations).await;

    let outcome = apply_sequentially(&client, &preimage, &mutations).await;
    assert_eq!(outcome.state, ApplyState::AppliedUnverified);
    let reason = outcome.verification_failure.expect("names why");
    assert!(reason.contains("did not read back"), "{reason}");
}

#[tokio::test]
async fn an_unknown_zone_is_refused_at_staging() {
    let client = client_for(seeded()).await;
    let missing = "000000000000000000000199";
    let mutations = vec![StagedMutation::reorder(missing, WAN, vec![id(A), id(B)])];
    let error = Preimage::capture_preimage(&client, &mutations)
        .await
        .expect_err("unknown zone");
    assert!(error.to_string().contains(missing), "{error}");
}

#[tokio::test]
async fn the_stage_tool_refuses_an_order_that_is_not_a_permutation() {
    let handler = server_for(seeded()).await;
    let (_, staged) = stage_through_tool(
        &handler,
        json!([{"operation": "reorder", "kind": "firewall_policy",
                "source_zone_id": LAN, "destination_zone_id": WAN, "order": [B]}]),
    )
    .await;
    let error = staged.expect_err("drops a policy");
    assert!(error.contains("not a permutation"), "{error}");
}

#[tokio::test]
async fn the_diff_tool_shows_the_old_and_new_order() {
    let handler = server_for(seeded()).await;
    let (id, staged) = stage_through_tool(
        &handler,
        json!([
            {"operation": "create", "kind": "firewall_policy",
             "body": {"name": "mi-block", "action": "BLOCK", "create_allow_respond": false,
                      "source": {"zone_id": LAN}, "destination": {"zone_id": WAN}}},
            {"operation": "reorder", "kind": "firewall_policy",
             "source_zone_id": LAN, "destination_zone_id": WAN,
             "order": [{"created_name": "mi-block"}, A, B]}
        ]),
    )
    .await;
    staged.expect("a created policy placed by name stages");
    let diff = call(
        handler,
        "unifi_diff_change_set",
        json!({"controller": "fake", "change_set_id": id}),
    )
    .await
    .expect("diff");
    let change = &diff["changes"][1];
    assert_eq!(change["before"]["order"], json!([A, B]), "{diff}");
    assert_eq!(
        change["after"]["order"],
        json!([{"created_name": "mi-block"}, A, B]),
        "{diff}"
    );
}
