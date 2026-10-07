//! The MCP server handler.

use crate::grant::UnifiGrant;
use mecmcp_auth::Grant as _;
use mecmcp_changeset::{
    ApplyHandle, ChangeSetRecord, ChangeSetState, ChangesetCoordinator, PreviewRecord,
    change_set_digest, preview_digest,
};
use mecmcp_server::{
    OutputRedaction, ResultFormat, ResultLimits, authorize_call, caller_from_extensions,
    filter_tools_for_scope, tool_error, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerConfig,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rustunifimcp_core::{
    changeset::{
        Preimage, StagedMutation, State, UnifiTransaction, ZoneIndex, actions_for,
        apply_sequentially, check_writable_fields, check_zone_deletions, check_zone_references,
        diff_against_preimage, fingerprint_of, mutations_of, preimage_of, referenced_zone_ids,
        validate_locally,
    },
    client::UnifiClient,
    error::UnifiError,
    inventory::ControllerRegistry,
    model::ResourceKind,
    tools::{WRITE_TOOLS, admin, changeset, ops, read, workflow},
};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Empty arguments for parameterless tools.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
struct NoArgs {}

/// Result size limits for MCP tool responses.
const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

/// Headroom subtracted from `RESULT_LIMITS.max_json_bytes` before shrinking a
/// response, so the pretty-printed rendering `mecmcp_server` measures --
/// which adds the MCP envelope around the value truncated here -- still lands
/// inside the real limit rather than a value this module computed in
/// isolation.
const TRUNCATION_MARGIN_BYTES: usize = 8 * 1024;

/// Render a tool result, shrinking an oversized list rather than refusing it.
///
/// `mecmcp_server::tool_result` refuses an oversized response outright by
/// design: "a caller cannot tell a truncated result from a complete one." That
/// is the right default for a single resource, which has no smaller true
/// answer. It is the wrong one for a list tool pointed at a large site, which
/// has an obvious smaller answer -- fewer items, explicitly marked as fewer --
/// and refusing outright just means the operator learns nothing about a site
/// too big to describe in 512 KiB. So the largest array in the response is
/// shortened here, before the transport ever measures it, with a nested
/// `truncation` marker naming how many of how many are shown. `tool_result`
/// still has the final word: if even the shrunk response cannot fit, it
/// refuses exactly as before, so this can only make an oversized answer
/// smaller, never turn a correct refusal into a silent lie.
fn json_tool_result<T: serde::Serialize>(value: T) -> CallToolResult {
    let budget = RESULT_LIMITS
        .max_json_bytes
        .saturating_sub(TRUNCATION_MARGIN_BYTES);

    match serde_json::to_value(&value) {
        Ok(json) => tool_result(
            Ok::<_, String>(shrink_largest_array(json, budget)),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        ),
        Err(_) => tool_result(
            Ok::<_, String>(value),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        ),
    }
}

/// The rendered size `mecmcp_server::tool_result` would measure for `value`.
fn rendered_len(value: &serde_json::Value) -> usize {
    serde_json::to_string_pretty(value).map_or(usize::MAX, |s| s.len())
}

/// Shrink the largest top-level array in `value` until it fits `budget` bytes.
///
/// A bare array (`unifi_list_resources`'s shape) is wrapped under `data`; an
/// object keeps its own keys and only the largest array-valued field is cut.
/// Binary searches the largest prefix of that array whose rendering fits,
/// rather than trimming one item at a time, so a response with thousands of
/// items still costs a handful of serializations. Returns `value` unchanged
/// if it already fits or has no array to shrink -- a scalar or single-object
/// response has no smaller true answer, and is left for `tool_result`'s own
/// refusal.
///
/// The marker lives under its own `truncation` key rather than top-level
/// `truncated`/`shown`/`total` fields, because `unifi_query_stats` and the
/// workflow reports already fill an object with `offset`/`limit`/`total` from
/// [`crate::tools::pagination`] before this ever runs -- top-level fields
/// here used to overwrite that site-wide `total` with the shrunk array's own
/// length, so a caller advancing `offset` by the (now wrong) `limit` skipped
/// items it never saw. Existing keys are never overwritten. `partial` is
/// forced `true` when it is already present, since a shrunk response is
/// partial by definition. When the object carries a numeric `offset`,
/// `next_offset` names the correct cursor for the next call: `offset` plus
/// however many of this field's items are actually shown, not `limit`, since
/// the shrunk count is very likely a strict fraction of it.
fn shrink_largest_array(value: serde_json::Value, budget: usize) -> serde_json::Value {
    if rendered_len(&value) <= budget {
        return value;
    }

    let (key, items, rest) = match value {
        serde_json::Value::Array(items) => (None, items, serde_json::Map::new()),
        serde_json::Value::Object(mut map) => {
            let Some(key) = map
                .iter()
                .filter_map(|(k, v)| v.as_array().map(|a| (k.clone(), a.len())))
                .max_by_key(|(_, len)| *len)
                .map(|(k, _)| k)
            else {
                return serde_json::Value::Object(map);
            };
            let Some(serde_json::Value::Array(items)) = map.remove(&key) else {
                unreachable!("key was chosen because its value is an array")
            };
            (Some(key), items, map)
        }
        other => return other,
    };

    let total = items.len();
    let field = key.unwrap_or_else(|| "data".to_owned());
    let offset = rest.get("offset").and_then(serde_json::Value::as_u64);
    let build = |n: usize| -> serde_json::Value {
        let mut map = rest.clone();
        map.insert(field.clone(), serde_json::Value::Array(items[..n].to_vec()));
        if map.contains_key("partial") {
            map.insert("partial".to_owned(), serde_json::Value::Bool(true));
        }
        if let Some(offset) = offset {
            map.insert(
                "next_offset".to_owned(),
                serde_json::json!(offset.saturating_add(n as u64)),
            );
        }
        map.insert(
            "truncation".to_owned(),
            serde_json::json!({ "field": field, "shown": n, "of": total }),
        );
        serde_json::Value::Object(map)
    };

    let mut lo = 0usize;
    let mut hi = total;
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if rendered_len(&build(mid)) <= budget {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }

    build(lo)
}

/// Seconds since the Unix epoch.
///
/// A clock before the epoch is not a case worth branching on; it reports 0,
/// which makes every approval look old and therefore expired -- the safe
/// direction for a gate.
fn unix_seconds_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The UniFi MCP server.
#[derive(Clone)]
pub struct UnifiServer {
    /// Controller inventory.
    registry: Arc<ControllerRegistry>,
    /// Clients per controller. RwLock allows rebuild on SIGHUP.
    clients: Arc<std::sync::RwLock<BTreeMap<String, UnifiClient>>>,
    /// Whether lab mode is enabled.
    lab_mode: bool,
    /// The change-set lifecycle.
    ///
    /// `mecmcp-changeset`'s coordinator, not a map: it owns the transition
    /// policy, the claim-before-apply and the preview-bound approval, and the
    /// approval TTL that `--approval-timeout-secs` configures.
    coordinator: Arc<ChangesetCoordinator>,
    /// Change sets created but not yet staged into.
    ///
    /// The coordinator cannot hold one. Its persistence layer refuses to load
    /// a state file containing a change set with no actions, so persisting an
    /// empty plan makes the *whole* store unloadable at the next start -- a
    /// fault that CI cannot see, because nothing in a test run restarts. And
    /// an empty change set has nothing to protect: no plan, no pre-image, no
    /// approval. So it is held here until the first mutation is staged, and a
    /// restart loses exactly nothing.
    drafts: Arc<std::sync::RwLock<BTreeMap<String, Draft>>>,
    /// SSDF evidence, when the pipeline is configured.
    ///
    /// The coordinator emits the approval records itself. The proposal and the
    /// two apply records belong to paths this server drives, so it needs the
    /// recorder too.
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    /// Serialises changing a plan against approving one.
    ///
    /// The recorder keys its diff hash by change-set id, and the coordinator
    /// copies that context into the approval record it emits. Publishing a new
    /// plan is therefore two writes -- the coordinator's and the recorder's --
    /// that an approval must not land between, and there is no ordering of the
    /// two that survives on its own: publish first and a concurrent approval of
    /// the *old* plan is attested with the new digest; publish second and one
    /// of the new plan is attested with the old. Both are false attestations,
    /// which is the one thing the evidence chain exists to rule out.
    ///
    /// So the window is closed rather than shrunk. Contention is negligible:
    /// the coordinator already allows one pending change set per principal per
    /// controller, so these paths are near-serial anyway.
    plan_lock: Arc<tokio::sync::Mutex<()>>,
    /// Whether direct-commit tools (`unifi_device_action`'s `restart`,
    /// `unifi_client_action`'s `block`/`unblock`/`reconnect`) may run without
    /// change-set approval. Set via `--allow-direct-commit`; off by default.
    direct_commit: mecmcp_audit::DirectCommitPolicy,
    /// Tool router.
    tool_router: ToolRouter<Self>,
}

/// A change set that exists but has nothing staged into it.
#[derive(Debug, Clone)]
pub struct Draft {
    /// The controller it was created against.
    controller: String,
    /// The principal who created it.
    owner: String,
    /// What it is for, which becomes the preview's description.
    description: String,
    /// When it was created, so a forgotten draft does not live forever.
    created_at_unix: u64,
}

/// How many unstaged change sets may be held at once.
///
/// Bounded because a draft is reachable without touching a controller, so an
/// unbounded map is a way to grow the process with no write ever happening.
const MAX_DRAFTS: usize = 32;

impl UnifiServer {
    /// Create a new server with the given registry, lab mode, and coordinator.
    ///
    /// # Errors
    ///
    /// Returns an error if any client cannot be built.
    pub fn new(
        registry: Arc<ControllerRegistry>,
        lab_mode: bool,
        coordinator: Arc<ChangesetCoordinator>,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
        direct_commit: mecmcp_audit::DirectCommitPolicy,
    ) -> Result<Self, UnifiError> {
        let clients = Self::build_clients(&registry)?;
        Ok(Self {
            registry,
            clients: Arc::new(std::sync::RwLock::new(clients)),
            lab_mode,
            coordinator,
            drafts: Arc::new(std::sync::RwLock::new(BTreeMap::new())),
            evidence,
            plan_lock: Arc::new(tokio::sync::Mutex::new(())),
            direct_commit,
            tool_router: Self::unifi_tool_router(),
        })
    }

    /// Build HTTP clients for all controllers in the registry.
    fn build_clients(
        registry: &ControllerRegistry,
    ) -> Result<BTreeMap<String, UnifiClient>, UnifiError> {
        let mut clients = BTreeMap::new();
        for name in registry.names() {
            let controller = registry.get(&name)?;
            clients.insert(name.clone(), UnifiClient::new(controller)?);
        }
        Ok(clients)
    }

    /// Rebuild all clients from the current registry state.
    ///
    /// This is called on SIGHUP after the registry has been reloaded, so that
    /// configuration changes (endpoint, credential, allow_private_api) take
    /// effect without restarting the server.
    ///
    /// # Errors
    ///
    /// Returns an error if any client cannot be built. On error, the previous
    /// clients are retained.
    pub fn rebuild_clients(&self) -> Result<usize, UnifiError> {
        let new_clients = Self::build_clients(&self.registry)?;
        let count = new_clients.len();

        let mut clients = self
            .clients
            .write()
            .map_err(|_| UnifiError::Malformed("clients lock poisoned".to_owned()))?;

        *clients = new_clients;
        Ok(count)
    }

    /// Get a reference to the client for a controller.
    ///
    /// Returns an owned client since we cannot return a reference that outlives
    /// the RwLock guard. UnifiClient is cheap to clone (Arc-wrapped internals).
    fn client_for(&self, controller: &str) -> Result<UnifiClient, Box<CallToolResult>> {
        let clients = self
            .clients
            .read()
            .map_err(|_| Box::new(tool_error("clients lock poisoned".to_owned())))?;

        clients
            .get(controller)
            .cloned()
            .ok_or_else(|| Box::new(tool_error(format!("unknown controller: {controller}"))))
    }

    /// Recover the caller from the request context.
    fn caller(context: &RequestContext<RoleServer>) -> Option<mecmcp_auth::CallerCtx<UnifiGrant>> {
        caller_from_extensions::<UnifiGrant>(&context.extensions).cloned()
    }

    /// The principal behind this call.
    fn principal(caller: Option<&mecmcp_auth::CallerCtx<UnifiGrant>>) -> String {
        caller.map_or_else(|| "unknown".to_owned(), |ctx| ctx.token_name.clone())
    }

    /// Require the caller's grant, if any, to permit writing to `site`.
    ///
    /// A caller with no grant (`grant: None`) is unrestricted by site: that
    /// is the pre-MEC-508 default, and it is what every token minted before
    /// per-site scoping existed carries, so this preserves their behavior
    /// unchanged. A caller whose grant is `Some` must name `site` explicitly
    /// -- a positive allowlist, so a widened default site is never assumed.
    ///
    /// The `None` caller (stdio) is also unrestricted, for the same reason
    /// [`authorize_call`] treats it that way: stdio has no bearer token
    /// because it has no network, and the process on the other end already
    /// runs as whoever started it.
    ///
    /// # Errors
    /// Returns [`UnifiError::SiteNotInScope`] if the caller's grant does not
    /// name `site`.
    fn authorize_site(
        caller: Option<&mecmcp_auth::CallerCtx<UnifiGrant>>,
        site: &str,
    ) -> Result<(), UnifiError> {
        let Some(caller) = caller else {
            return Ok(());
        };
        let Some(grant) = &caller.grant else {
            return Ok(());
        };
        if grant.allows_subject(site) {
            Ok(())
        } else {
            Err(UnifiError::SiteNotInScope {
                token: caller.token_name.clone(),
                site: site.to_owned(),
            })
        }
    }

    /// Resolve the effective site for a write call, enforce the caller's
    /// site grant against it, and audit the outcome either way.
    ///
    /// The audit event lives here rather than once per call site so a
    /// handler cannot add a new site-scoped write tool and forget the audit
    /// half of the check -- there is exactly one place that decides and
    /// records which site a mutating call targeted.
    ///
    /// # Errors
    /// Returns the boxed `CallToolResult` [`tool_error`] renders for
    /// [`UnifiError::SiteNotInScope`], for a handler to `return *result`.
    fn authorize_write_site(
        caller: Option<&mecmcp_auth::CallerCtx<UnifiGrant>>,
        tool: &str,
        controller: &str,
        client: &UnifiClient,
        requested_site: Option<&str>,
    ) -> Result<String, Box<CallToolResult>> {
        let site = requested_site
            .unwrap_or_else(|| client.default_site())
            .to_owned();
        let principal = Self::principal(caller);
        if let Err(error) = Self::authorize_site(caller, &site) {
            tracing::warn!(
                target: "audit",
                event = "unifi_site_write_denied",
                tool = %tool,
                controller = %controller,
                site = %site,
                principal = %principal,
                "write denied: site not in caller's grant"
            );
            return Err(Box::new(tool_error(error)));
        }
        tracing::info!(
            target: "audit",
            event = "unifi_site_write",
            tool = %tool,
            controller = %controller,
            site = %site,
            principal = %principal,
            "site-scoped write authorized"
        );
        Ok(site)
    }

    /// Enforce the direct-commit gate for an operational action that mutates
    /// a device or client in one call with no change-set approval, and audit
    /// the outcome.
    ///
    /// Refuses unless the server was started with `--allow-direct-commit`.
    /// Unlike [`authorize_write_site`](Self::authorize_write_site), which
    /// logs through this crate's own `tracing`-based audit convention, this
    /// emits its event through `mecmcp_audit::AuditScope` -- the same
    /// mechanism `mecmcp_audit::DirectCommitPolicy::check` requires and the
    /// one `rustjunosmcp` uses for the identical gate, so the two servers'
    /// direct-commit records share one shape.
    ///
    /// On refusal the returned `CallToolResult` is final and the `AuditScope`
    /// has already been dropped (and so emitted) recording the denial. On
    /// success the caller gets back the *live* `AuditScope` instead of a
    /// dropped one: it must call [`AuditScope::succeed`] or
    /// [`AuditScope::fail`] once the gated device/client mutation has
    /// actually run, then let it drop. Finalizing here -- before the caller
    /// has performed the mutation -- would record `result=ok` for a call that
    /// had not executed yet, and still `result=ok` if it went on to fail.
    ///
    /// # Errors
    /// Returns the boxed `CallToolResult` [`tool_error`] renders for
    /// [`mecmcp_audit::DirectCommitRefused`], for a handler to `return *result`.
    fn gate_direct_commit(
        &self,
        caller: Option<&mecmcp_auth::CallerCtx<UnifiGrant>>,
        tool: &'static str,
        action: &'static str,
        target: &str,
    ) -> Result<mecmcp_audit::AuditScope, Box<CallToolResult>> {
        let mut scope = match caller {
            Some(ctx) => {
                mecmcp_audit::AuditScope::from_caller(ctx, tool, action, vec![target.to_owned()])
            }
            None => mecmcp_audit::AuditScope::stdio(tool, action, vec![target.to_owned()]),
        };
        match self.direct_commit.check(&mut scope) {
            Ok(()) => Ok(scope),
            Err(error) => Err(Box::new(tool_error(error))),
        }
    }

    /// The owner's identity binding, copied from the token when one is configured.
    ///
    /// Absent when the token has none. This server does not invent a binding,
    /// and it does not drop one the token entry already carries.
    fn owner_subject_of(
        caller: Option<&mecmcp_auth::CallerCtx<UnifiGrant>>,
    ) -> Option<mecmcp_changeset::OwnerSubject> {
        let subject = caller.and_then(|ctx| ctx.oidc_subject.as_ref())?;
        Some(mecmcp_changeset::OwnerSubject {
            issuer: subject.issuer.clone(),
            subject: subject.subject.clone(),
        })
    }

    /// The approver identity the change-set coordinator judges.
    ///
    /// A verified assertion already on the caller wins. Otherwise the identity
    /// is the token's declared actor type. `principal` is used only when there
    /// is no caller context (stdio): that path is token-asserted and unknown,
    /// never an invented human.
    fn approver_identity(
        caller: Option<&mecmcp_auth::CallerCtx<UnifiGrant>>,
        principal: &str,
    ) -> mecmcp_changeset::ApproverIdentity {
        match caller {
            Some(ctx) => mecmcp_changeset::ApproverIdentity::from_attribution(
                &mecmcp_audit::Attribution::from_caller(ctx),
            ),
            None => mecmcp_changeset::ApproverIdentity::TokenAsserted {
                principal: principal.to_owned(),
                actor_type: Self::approver_actor_type(caller),
            },
        }
    }

    /// Map a caller's server-verified `mecmcp_auth::ActorType` to the
    /// `mecmcp_audit::ActorType` the change-set approver identity carries.
    ///
    /// `None` -- no authenticated caller context, i.e. the stdio transport --
    /// maps to `Unknown` rather than `Human`. Inventing `Human` for an
    /// unattributed caller would let stdio silently satisfy the human-approver
    /// gate; `Unknown` is the honest fact, and the coordinator refuses it
    /// exactly like it refuses `Agent`.
    fn approver_actor_type(
        caller: Option<&mecmcp_auth::CallerCtx<UnifiGrant>>,
    ) -> mecmcp_audit::ActorType {
        match caller {
            Some(ctx) => match ctx.actor_type {
                mecmcp_auth::ActorType::Human => mecmcp_audit::ActorType::Human,
                mecmcp_auth::ActorType::Agent => mecmcp_audit::ActorType::Agent,
                mecmcp_auth::ActorType::Unknown => mecmcp_audit::ActorType::Unknown,
            },
            None => mecmcp_audit::ActorType::Unknown,
        }
    }

    /// Whether `caller`'s tool scope would let it both stage and approve a
    /// change set.
    ///
    /// Two-person control used to rest entirely on an operational convention
    /// (CLAUDE.md: issue tokens that don't combine stage+approve rights) that
    /// nothing enforced. `unifi_approve_change_set` refuses an approver who
    /// *is* a set's owner, but that check says nothing about a second token
    /// minted for a different principal name that nonetheless carries both
    /// scopes -- such a token satisfies the owner check on every call and
    /// still lets one credential complete the whole lifecycle alone.
    ///
    /// Checked here, at call time, rather than only at token issuance:
    /// issuance can refuse minting such a token, but a token store loaded
    /// from a hand-edited file never went through issuance at all. This is
    /// the check a hand-edited store cannot bypass.
    fn holds_combined_two_person_control_scope(
        caller: Option<&mecmcp_auth::CallerCtx<UnifiGrant>>,
    ) -> bool {
        let Some(caller) = caller else {
            return false;
        };
        caller.tools.allows_tool("unifi_stage_change", WRITE_TOOLS)
            && caller
                .tools
                .allows_tool("unifi_approve_change_set", WRITE_TOOLS)
    }

    /// Fetch a change set, refusing a controller that does not own it.
    ///
    /// The coordinator addresses a change set by `(id, device)` and refuses a
    /// mismatch itself, which closes a hole the map-backed store had: every
    /// change-set tool takes a `controller` argument and used it to pick the
    /// client without ever comparing it to the controller the set was planned
    /// against, so a set could be validated -- and applied -- against another.
    async fn record_for(
        &self,
        change_set_id: &str,
        controller: &str,
    ) -> Result<ChangeSetRecord, Box<CallToolResult>> {
        self.coordinator
            .change_set(change_set_id, controller)
            .await
            .map_err(|error| {
                Box::new(tool_error(format!(
                    "change set {change_set_id} on {controller} ({}): {}",
                    error.field(),
                    error.message()
                )))
            })
    }

    /// Read the plan back off a stored record.
    fn plan_of(
        record: &ChangeSetRecord,
    ) -> Result<(Vec<StagedMutation>, Preimage), Box<CallToolResult>> {
        let mutations = mutations_of(&record.actions)
            .map_err(|error| Box::new(tool_error(format!("stored change set: {error}"))))?;
        let preimage = preimage_of(&record.actions)
            .map_err(|error| Box::new(tool_error(format!("stored change set: {error}"))))?;
        Ok((mutations, preimage))
    }

    /// Render the preview an approver signs off on.
    ///
    /// Stored as JSON rather than prose because it is read by a model relaying
    /// to an operator, and because it is also where the description lives:
    /// `ChangeSetRecord` has no field for one, and a side-car map holding it
    /// would be a second store to disagree with the first.
    ///
    /// The atomicity declaration is part of the preview deliberately. UniFi
    /// offers no atomic apply, no dry run and no guaranteed rollback, and an
    /// approver who is not told that is approving something else.
    fn render_preview(
        controller: &str,
        description: &str,
        mutations: &[StagedMutation],
        preimage: &Preimage,
    ) -> Result<String, Box<CallToolResult>> {
        let diff = diff_against_preimage(preimage, mutations)
            .map_err(|error| Box::new(tool_error(format!("failed to compute diff: {error}"))))?;
        let atomicity = UnifiTransaction::atomicity();

        serde_json::to_string_pretty(&serde_json::json!({
            "controller": controller,
            "description": description,
            "staged_count": mutations.len(),
            "atomicity": {
                "atomic_apply": atomicity.atomic_apply,
                "dry_run_validation": atomicity.dry_run_validation,
                "guaranteed_rollback": atomicity.guaranteed_rollback,
                "note": "UniFi writes directly to running state: a partial apply is \
                         reachable and rollback is best-effort",
            },
            "changes": diff.changes,
        }))
        .map_err(|error| Box::new(tool_error(format!("failed to render the preview: {error}"))))
    }

    /// The description carried in a record's preview.
    fn description_of(record: &ChangeSetRecord) -> Result<String, Box<CallToolResult>> {
        let Some(preview) = record.preview.as_ref() else {
            return Err(Box::new(tool_error(
                "change set has no stored preview; create it again",
            )));
        };
        let parsed: serde_json::Value = serde_json::from_str(&preview.artifact).map_err(|_| {
            Box::new(tool_error(
                "stored change set: the preview is not the shape this server writes",
            ))
        })?;
        Ok(parsed
            .get("description")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned())
    }

    /// Record a change set that has nothing staged yet.
    ///
    /// Mirrors the coordinator's own rule -- one pending change set per
    /// principal per controller -- so a draft cannot be used to sidestep it,
    /// and sweeps drafts older than the approval window on the way in.
    async fn hold_draft(&self, id: String, draft: Draft) -> Result<(), Box<CallToolResult>> {
        // Across *both* stores. Checking only the draft map let a principal who
        // already had a staged set create another, spend a stage's worth of
        // controller reads building its pre-image, and only then hit the
        // coordinator's guard -- leaving a draft that can never become one.
        if let Some(blocker) = self
            .coordinator
            .change_sets()
            .await
            .into_iter()
            .find(|record| {
                if record.owner != draft.owner || record.device != draft.controller {
                    return false;
                }
                match record.state {
                    // In flight. Blocks regardless of the clock: the deadline
                    // does not retire a claimed record, and nor should it.
                    ChangeSetState::Applying => true,
                    // Pending, but only while its window is open. The
                    // coordinator's own guard sweeps a lapsed record to
                    // `Expired` before it looks, so reading the raw state here
                    // would block a principal for having let a TTL elapse --
                    // where the coordinator would have let them straight
                    // through.
                    ChangeSetState::Planned | ChangeSetState::Approved => {
                        unix_seconds_now() < record.expires_at_unix
                    }
                    _ => false,
                }
            })
        {
            return Err(Box::new(tool_error(format!(
                "change set {} on '{}' is still {}; finish or cancel it before creating \
                 another",
                blocker.id,
                draft.controller,
                blocker.state.as_str()
            ))));
        }

        let deadline = self.coordinator.approval_ttl().as_secs();
        let now = unix_seconds_now();

        let mut drafts = self
            .drafts
            .write()
            .map_err(|_| Box::new(tool_error("drafts lock poisoned".to_owned())))?;

        // `<`, not `<=`: a stored change set expires at `now >= expires_at_unix`,
        // and a draft that outlived its window by exactly nothing is still
        // outlived. The two boundaries have to agree or a draft can be staged
        // at the instant an equivalent change set would have lapsed.
        drafts.retain(|_, held| now.saturating_sub(held.created_at_unix) < deadline);

        if let Some((existing, _)) = drafts
            .iter()
            .find(|(_, held)| held.owner == draft.owner && held.controller == draft.controller)
        {
            return Err(Box::new(tool_error(format!(
                "change set {existing} on '{}' has nothing staged yet; stage into it or \
                 let it lapse before creating another",
                draft.controller
            ))));
        }

        if drafts.len() >= MAX_DRAFTS {
            return Err(Box::new(tool_error(format!(
                "{MAX_DRAFTS} change sets are open with nothing staged; stage into one or \
                 let them lapse"
            ))));
        }

        drafts.insert(id, draft);
        Ok(())
    }

    /// The draft for this id, if it is one, the caller named its controller,
    /// and it has not lapsed.
    ///
    /// Expiry is enforced here rather than only in `hold_draft`'s sweep. A
    /// lapsed draft that was still returned could be staged and persisted with
    /// a fresh deadline, so whether a draft had expired depended on whether an
    /// unrelated create happened to run the sweep first.
    fn draft(&self, change_set_id: &str, controller: &str) -> Option<Draft> {
        let deadline = self.coordinator.approval_ttl().as_secs();
        let now = unix_seconds_now();

        let held = self
            .drafts
            .read()
            .ok()?
            .get(change_set_id)
            .filter(|draft| draft.controller == controller)
            .cloned()?;

        if now.saturating_sub(held.created_at_unix) >= deadline {
            self.release_draft(change_set_id);
            return None;
        }

        Some(held)
    }

    /// Forget a draft that has become a real change set.
    fn release_draft(&self, change_set_id: &str) {
        if let Ok(mut drafts) = self.drafts.write() {
            drafts.remove(change_set_id);
        }
    }

    /// Refuse a plan the state file could not be reloaded with.
    ///
    /// Neither `insert_change_set` nor `update_change_set` checks the
    /// configured ceilings against a record's actions -- only
    /// `create_change_set` does, and this server cannot use it because a change
    /// set is created before anything is staged into it. Without this a caller
    /// can stage past the limits, have the record persist, and find the server
    /// refusing to start afterwards because the load path enforces a structural
    /// cap the write path did not.
    fn check_plan_limits(record: &ChangeSetRecord) -> Result<(), Box<CallToolResult>> {
        let limits = crate::changeset_state::limits();

        mecmcp_changeset::validate_change_set_actions(&record.actions, &limits).map_err(
            |error| {
                Box::new(tool_error(format!(
                    "staged plan refused ({}): {}",
                    error.field(),
                    error.message()
                )))
            },
        )?;

        if let Some(preview) = record.preview.as_ref()
            && preview.artifact.len() > limits.max_preview_bytes
        {
            return Err(Box::new(tool_error(format!(
                "the preview for this change set is {} bytes, over the {} the store \
                 accepts; stage fewer changes at once",
                preview.artifact.len(),
                limits.max_preview_bytes
            ))));
        }

        Ok(())
    }

    /// Rewrite a record's plan, its fingerprint, its digest and its preview.
    ///
    /// All four move together. The digest binds `(owner, device, fingerprint,
    /// actions)` and the approval binds the digest, so a plan changed without
    /// its digest would carry an approval for a plan nobody approved.
    fn with_plan(
        mut record: ChangeSetRecord,
        mutations: &[StagedMutation],
        preimage: &Preimage,
        description: &str,
    ) -> Result<ChangeSetRecord, Box<CallToolResult>> {
        let actions = actions_for(mutations, preimage);
        let fingerprint = fingerprint_of(&actions)
            .map_err(|error| Box::new(tool_error(format!("failed to fingerprint: {error}"))))?;
        let artifact = Self::render_preview(&record.device, description, mutations, preimage)?;

        record.actions = actions
            .iter()
            .map(serde_json::to_value)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| Box::new(tool_error(format!("failed to store the plan: {error}"))))?;
        record.expected_candidate_fingerprint = fingerprint;
        record.digest = change_set_digest(
            &record.owner,
            &record.device,
            &record.expected_candidate_fingerprint,
            &record.actions,
        )
        .map_err(|error| Box::new(tool_error(format!("failed to digest the plan: {error}"))))?;
        record.preview = Some(PreviewRecord {
            digest: preview_digest(&artifact),
            artifact,
            job_id: None,
        });

        Ok(record)
    }
}

#[tool_router(router = unifi_tool_router, vis = "pub(crate)")]
impl UnifiServer {
    #[tool(
        name = "unifi_list_resources",
        description = "List UniFi resources by type and site. Output is redacted: WLAN passphrases, VPN/RADIUS secrets, WireGuard private keys, and PPPoE passwords are stripped; identifying fields (name, VLAN, subnet, MAC/IP) remain."
    )]
    async fn unifi_list_resources(
        &self,
        Parameters(args): Parameters<read::ListResourcesArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_list_resources",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::list_resources(&client, &args).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_get_resource",
        description = "Get a specific UniFi resource by type and id. Output is redacted: WLAN passphrases, VPN/RADIUS secrets, WireGuard private keys, and PPPoE passwords are stripped; identifying fields (name, VLAN, subnet, MAC/IP) remain."
    )]
    async fn unifi_get_resource(
        &self,
        Parameters(args): Parameters<read::GetResourceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_get_resource",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::get_resource(&client, &args).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_query_stats",
        description = "Query statistics for UniFi resources. Output is redacted: device/station stats are narrowed to their typed field set, site/WLAN/flow stats pass through a best-effort secret scan."
    )]
    async fn unifi_query_stats(
        &self,
        Parameters(args): Parameters<read::QueryStatsArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_query_stats",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::query_stats(&client, &args).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_search",
        description = "Search UniFi resources with filters. Output is redacted: results are filtered on the same typed, secret-stripped shape unifi_list_resources returns."
    )]
    async fn unifi_search(
        &self,
        Parameters(args): Parameters<read::SearchArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_search",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::search(&client, &args).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_list_sites",
        description = "List all sites on a UniFi controller"
    )]
    async fn unifi_list_sites(
        &self,
        Parameters(args): Parameters<read::ListSitesArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_list_sites",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match read::list_sites(&client, &args).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_list_controllers",
        description = "List all configured UniFi controllers"
    )]
    async fn unifi_list_controllers(
        &self,
        _params: Parameters<NoArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) =
            authorize_call(caller.as_ref(), "unifi_list_controllers", None, WRITE_TOOLS)
        {
            return tool_error(error);
        }

        match admin::unifi_list_controllers(&self.registry).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifimcp_status",
        description = "Get server status and controller connectivity"
    )]
    async fn unifimcp_status(
        &self,
        _params: Parameters<NoArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(caller.as_ref(), "unifimcp_status", None, WRITE_TOOLS) {
            return tool_error(error);
        }

        // Reuses the clients this server already built rather than
        // constructing a fresh one per controller per call: `UnifiClient::new`
        // reads the credential from disk and stands up a whole connection
        // pool, so status calls -- the tool an operator polls most often --
        // were paying that cost on every controller on every call instead of
        // reusing the pool the server already holds.
        let clients = match self.clients.read() {
            Ok(guard) => guard.clone(),
            Err(_) => return tool_error("clients lock poisoned".to_owned()),
        };

        match admin::unifimcp_status(&clients, self.lab_mode).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_add_controller",
        description = "Add a controller to the inventory (fails in production - edit config instead)"
    )]
    async fn unifi_add_controller(
        &self,
        Parameters(_args): Parameters<NoArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) =
            authorize_call(caller.as_ref(), "unifi_add_controller", None, WRITE_TOOLS)
        {
            return tool_error(error);
        }

        match admin::unifi_add_controller("", "", "", None, None).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_device_action",
        description = "Execute an operational action on a device (restart, locate, adopt, upgrade, port_action)"
    )]
    async fn unifi_device_action(
        &self,
        Parameters(args): Parameters<ops::DeviceActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_device_action",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        if let Err(result) = Self::authorize_write_site(
            caller.as_ref(),
            "unifi_device_action",
            &args.controller,
            &client,
            args.site.as_deref(),
        ) {
            return *result;
        }

        // Validated before the gate below reads `args.device` into the audit
        // record: an unvalidated MAC would otherwise let a caller write an
        // arbitrary string into that record before it was ever checked.
        if let Err(error) = args.validate() {
            return tool_error(error);
        }

        // `restart`, `adopt`, `upgrade`, and `port_action` each mutate the
        // device in one call with no change-set approval. `locate` is exempt:
        // it is self-reverting and carries no lasting effect. Whether a
        // variant is gated is decided by `DeviceAction::requires_direct_commit`
        // below -- an exhaustive match in `rustunifimcp-core` that is a
        // compile error there until a future variant says explicitly whether
        // it belongs in the gate. `#[non_exhaustive]` still forces a wildcard
        // here for the display name only, which carries no gating decision.
        let action_name = match args.action {
            ops::DeviceAction::Restart => "restart",
            ops::DeviceAction::Adopt => "adopt",
            ops::DeviceAction::Upgrade => "upgrade",
            ops::DeviceAction::PortAction => "port_action",
            ops::DeviceAction::Locate => "locate",
            _ => "unknown",
        };
        let mut gate_scope = if args.action.requires_direct_commit() {
            match self.gate_direct_commit(
                caller.as_ref(),
                "unifi_device_action",
                action_name,
                &args.device,
            ) {
                Ok(scope) => Some(scope),
                Err(result) => return *result,
            }
        } else {
            None
        };
        if let Some(scope) = gate_scope.as_mut() {
            if let Some(firmware_version) = args.firmware_version.as_deref() {
                scope.meta("firmware_version", firmware_version.to_owned());
            }
            if let Some(port_index) = args.port_index {
                scope.meta("port_idx", u64::from(port_index));
            }
        }

        let result = ops::device_action(args, &client).await;
        if let Some(scope) = gate_scope.as_mut() {
            match &result {
                Ok(_) => scope.succeed(),
                Err(error) => scope.fail(error),
            }
        }

        match result {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_client_action",
        description = "Execute an operational action on a client (block, unblock, reconnect)"
    )]
    async fn unifi_client_action(
        &self,
        Parameters(args): Parameters<ops::ClientActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_client_action",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        if let Err(result) = Self::authorize_write_site(
            caller.as_ref(),
            "unifi_client_action",
            &args.controller,
            &client,
            args.site.as_deref(),
        ) {
            return *result;
        }

        // Validated before the gate below reads `args.client` into the audit
        // record: an unvalidated MAC would otherwise let a caller write an
        // arbitrary string into that record before it was ever checked.
        if let Err(error) = args.validate() {
            return tool_error(error);
        }

        // `block`, `unblock`, and `reconnect` mutate the client in one call
        // with no change-set approval. Whether a variant is gated is decided by
        // `ClientAction::requires_direct_commit` below -- an exhaustive match
        // in `rustunifimcp-core` that is a compile error there until a future
        // variant says explicitly whether it belongs in the gate.
        // `#[non_exhaustive]` still forces a wildcard here for the display
        // name only, which carries no gating decision.
        let action_name = match args.action {
            ops::ClientAction::Block => "block",
            ops::ClientAction::Unblock => "unblock",
            ops::ClientAction::Reconnect => "reconnect",
            _ => "unknown",
        };
        let mut gate_scope = if args.action.requires_direct_commit() {
            match self.gate_direct_commit(
                caller.as_ref(),
                "unifi_client_action",
                action_name,
                &args.client,
            ) {
                Ok(scope) => Some(scope),
                Err(result) => return *result,
            }
        } else {
            None
        };

        let result = ops::client_action(args, &client).await;
        if let Some(scope) = gate_scope.as_mut() {
            match &result {
                Ok(_) => scope.succeed(),
                Err(error) => scope.fail(error),
            }
        }

        match result {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_backup_action",
        description = "Execute a backup action (trigger, list). `trigger` starts an asynchronous, non-idempotent job on the controller: if the request times out, do not retry it, since the controller may still complete the job and a retry can leave duplicate backup files behind. `restore` is not an operational action — it is governed by the change-set lifecycle (Phase 6): `unifi_create_change_set` -> `unifi_stage_change` -> `unifi_approve_change_set` -> `unifi_apply_change_set`."
    )]
    async fn unifi_backup_action(
        &self,
        Parameters(args): Parameters<ops::BackupActionArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_backup_action",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        if let Err(result) = Self::authorize_write_site(
            caller.as_ref(),
            "unifi_backup_action",
            &args.controller,
            &client,
            args.site.as_deref(),
        ) {
            return *result;
        }

        match ops::backup_action(args, &client).await {
            Ok(json) => json_tool_result(json),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_site_health_report",
        description = "Generate a site health report joining devices, health metrics, and statistics. Output is redacted: device fields are narrowed to the device allowlist, health/stats pass through a best-effort secret scan."
    )]
    async fn unifi_site_health_report(
        &self,
        Parameters(args): Parameters<workflow::SiteHealthReportArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_site_health_report",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::site_health_report(&client, &args).await {
            Ok(report) => json_tool_result(report),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_topology_report",
        description = "Generate a network topology report joining edges, devices, and networks. Output is redacted: device and network fields are narrowed to their allowlists, so VPN/PSK/WireGuard secrets on a network are stripped."
    )]
    async fn unifi_topology_report(
        &self,
        Parameters(args): Parameters<workflow::TopologyReportArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_topology_report",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::topology_report(&client, &args).await {
            Ok(report) => json_tool_result(report),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_traffic_flow_report",
        description = "Generate a traffic flow report joining clients, statistics, and top applications. Output is redacted: client fields are narrowed to the station allowlist, joined flow stats pass through a best-effort secret scan."
    )]
    async fn unifi_traffic_flow_report(
        &self,
        Parameters(args): Parameters<workflow::TrafficFlowReportArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_traffic_flow_report",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::traffic_flow_report(&client, &args).await {
            Ok(report) => json_tool_result(report),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "unifi_client_troubleshoot",
        description = "Troubleshoot a client by correlating association, uplink, and firewall policy. Output is redacted: the station and device are narrowed to their allowlists, and any matched firewall policy is scanned for secret-named fields."
    )]
    async fn unifi_client_troubleshoot(
        &self,
        Parameters(args): Parameters<workflow::ClientTroubleshootArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_client_troubleshoot",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        match workflow::client_troubleshoot(&client, &args).await {
            Ok(report) => json_tool_result(report),
            Err(error) => tool_error(error),
        }
    }

    // Change-set lifecycle tools (Phase 6)
    // Full implementation deferred to change-set integration

    #[tool(
        name = "unifi_create_change_set",
        description = "Creates a new change set with a fingerprint snapshot of current running configuration"
    )]
    async fn unifi_create_change_set(
        &self,
        Parameters(args): Parameters<changeset::CreateChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_create_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let owner = Self::principal(caller.as_ref());

        // The controller has to be one this server knows before a change set
        // names it: the coordinator addresses records by device, and a record
        // naming a controller absent from the inventory can never be applied.
        if let Err(result) = self.client_for(&args.controller) {
            return *result;
        }

        // Held as a draft, not written to the store. The coordinator's
        // persistence layer refuses to load a state file containing a change
        // set with no actions, so writing an empty plan here would make the
        // whole store unloadable at the next restart -- and nothing in a test
        // run restarts, so CI would never see it. The record is created on the
        // first stage, which is also when there is a plan to propose.
        // The description ends up inside the preview, so one that cannot fit
        // there produces an id that can never become a change set: every first
        // stage would rebuild the preview around it and be refused, after the
        // controller reads. Refused here instead, where it costs nothing.
        //
        // Measured on the *rendered* preview rather than on the raw
        // description, because the artifact is JSON: escaping, the pretty
        // printing, the controller name and the atomicity block all add to it.
        // Comparing the raw length against the whole budget passes a
        // description that the smallest possible preview around it would not.
        let preview_budget = crate::changeset_state::limits().max_preview_bytes;
        let smallest_preview = match Self::render_preview(
            &args.controller,
            &args.description,
            &[],
            &Preimage::from_resources(Vec::new()),
        ) {
            Ok(rendered) => rendered.len(),
            Err(result) => return *result,
        };
        if smallest_preview >= preview_budget {
            return tool_error(format!(
                "the description does not leave room for a preview: an empty change set \
                 carrying it already renders to {smallest_preview} bytes, against a cap \
                 of {preview_budget}"
            ));
        }

        let id = crate::changeset_state::new_change_set_id();
        let draft = Draft {
            controller: args.controller.clone(),
            owner,
            description: args.description,
            created_at_unix: unix_seconds_now(),
        };

        if let Err(result) = self.hold_draft(id.clone(), draft).await {
            return *result;
        }

        let result = serde_json::json!({
            "change_set_id": id,
            "controller": args.controller,
            "state": "draft",
            "note": "nothing is staged yet; a draft is held in memory and is lost on \
                     restart. It becomes a change set on the first unifi_stage_change.",
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "unifi_stage_change",
        description = "Stages one or more changes into a draft change set. mecmcp v0.25.0 \
                        fixes a change set's plan digest at creation, so this can only be \
                        called once per change_set_id (on the draft from \
                        unifi_create_change_set); a change set that already has a staged \
                        plan must be cancelled and recreated with the combined mutations."
    )]
    async fn unifi_stage_change(
        &self,
        Parameters(args): Parameters<changeset::StageChangeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_stage_change",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        // Under --lab-mode a single operator may hold both scopes on purpose
        // (issued with `token add --allow-self-approval`); the change-set
        // lab-mode waiver then records the self-approval as a distinct fact.
        if !self.lab_mode && Self::holds_combined_two_person_control_scope(caller.as_ref()) {
            return tool_error(
                "two-person control: this caller holds both unifi_stage_change and \
                 unifi_approve_change_set; use separate callers for staging and approving",
            );
        }

        // Only a draft can be staged into. mecmcp-changeset v0.25.0 (MEC-525)
        // fixes a change set's owner, device and plan digest at creation:
        // `update_change_set_from` now refuses any write that would change
        // the digest, which a second stage always would. Refusing a second
        // stage here, before touching the controller, gives a caller a clear
        // instruction instead of a coordinator error about a digest they
        // never named.
        let Some(draft) = self.draft(&args.change_set_id, &args.controller) else {
            return match self.record_for(&args.change_set_id, &args.controller).await {
                Ok(record) if record.state == ChangeSetState::Planned => tool_error(
                    "this change set already has a staged plan; a change set's plan digest \
                     is fixed at creation (mecmcp v0.25.0), so it cannot be staged into a \
                     second time. Cancel it and create a new change set with all the \
                     mutations you want, or let it expire.",
                ),
                Ok(record) => tool_error(format!(
                    "change set is {} and can no longer be staged into; create a new one",
                    record.state.as_str()
                )),
                Err(result) => *result,
            };
        };

        let description = draft.description.clone();
        let owner = draft.owner.clone();

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let mut mutations = Vec::new();

        for spec in args.mutations {
            mutations.push(match spec {
                changeset::MutationSpec::Create { kind, body } => {
                    StagedMutation::create(kind, body)
                }
                changeset::MutationSpec::Update { kind, id, body } => {
                    StagedMutation::update(kind, id, body)
                }
                changeset::MutationSpec::Delete { kind, id } => StagedMutation::delete(kind, id),
                changeset::MutationSpec::Restore { backup_id } => {
                    StagedMutation::restore(backup_id)
                }
            });
        }

        // Checked over the whole plan, not only the new mutations, and before
        // the pre-image is captured: a mutation naming a read-only kind or a
        // disallowed field must never enter a change set a human could
        // approve, so it is refused here rather than left for
        // unifi_validate_change_set, which a caller can skip entirely.
        if let Err(e) = check_writable_fields(&mutations) {
            return tool_error(format!("staged mutation refused: {e}"));
        }

        // Re-captured over the whole plan, not only the new mutations: the
        // fingerprint stands in for a candidate UniFi does not have, so it has
        // to describe the state the plan as a whole was built against.
        let preimage = match Preimage::capture_preimage(&client, &mutations).await {
            Ok(preimage) => preimage,
            Err(e) => return tool_error(format!("failed to capture pre-image: {e}")),
        };

        let staged_count = mutations.len();
        let base = ChangeSetRecord {
            id: args.change_set_id.clone(),
            owner,
            device: args.controller.clone(),
            expected_candidate_fingerprint: String::new(),
            actions: Vec::new(),
            digest: String::new(),
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now()
                .saturating_add(self.coordinator.approval_ttl().as_secs()),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: None,
            task_id: None,
            apply_without_handle: false,
            owner_subject: Self::owner_subject_of(caller.as_ref()),
        };

        let staged = match Self::with_plan(base, &mutations, &preimage, &description) {
            Ok(record) => record,
            Err(result) => return *result,
        };

        if let Err(result) = Self::check_plan_limits(&staged) {
            return *result;
        }

        let (digest, device, owner) = (
            staged.digest.clone(),
            staged.device.clone(),
            staged.owner.clone(),
        );

        // Held across both writes, so no approval can land between the plan
        // becoming visible and its proposal being published. See `plan_lock`:
        // neither ordering of the two is safe on its own.
        let _publishing = self.plan_lock.lock().await;

        // The plan exists now, so the change set does too. `insert_change_set`
        // is what enforces one pending set per principal per controller.
        // `unifi_stage_change` never updates an existing record -- the guard
        // above already refused that, since mecmcp v0.25.0 would reject the
        // digest change anyway.
        if let Err(error) = self.coordinator.insert_change_set(staged).await {
            return tool_error(format!(
                "failed to store change set ({}): {}",
                error.field(),
                error.message()
            ));
        }
        self.release_draft(&args.change_set_id);

        // After the write, so a write that failed leaves no proposal for a
        // plan that never landed. Safe to be second only because the lock is
        // still held.
        //
        // The coordinator emits this from `create_change_set`, which this
        // server cannot use because that call wants the actions up front and
        // a change set here exists before anything is staged into it.
        if let Some(recorder) = self.evidence.as_ref() {
            recorder.proposal(
                &args.change_set_id,
                &args.change_set_id,
                &device,
                &owner,
                &digest,
            );
        }

        drop(_publishing);

        let result = serde_json::json!({
            "change_set_id": args.change_set_id,
            "staged_count": staged_count,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "unifi_diff_change_set",
        description = "Returns a diff showing what applying the change set would do. Both sides of the diff are redacted: the pre-image and staged body are narrowed to the resource's allowlist before the diff is built."
    )]
    async fn unifi_diff_change_set(
        &self,
        Parameters(args): Parameters<changeset::DiffChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_diff_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let record = match self.record_for(&args.change_set_id, &args.controller).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let (mutations, preimage) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };

        let diff = match diff_against_preimage(&preimage, &mutations) {
            Ok(diff) => diff,
            Err(e) => return tool_error(format!("failed to compute diff: {e}")),
        };

        let result = serde_json::json!({
            "change_set_id": record.id,
            "computed": diff.computed,
            "changes": diff.changes,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "unifi_validate_change_set",
        description = "Validates the change set as far as possible without applying it"
    )]
    async fn unifi_validate_change_set(
        &self,
        Parameters(args): Parameters<changeset::ValidateChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_validate_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let record = match self.record_for(&args.change_set_id, &args.controller).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let (mutations, preimage) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };

        if let Err(e) = validate_locally(&preimage, &mutations) {
            return tool_error(format!("local validation failed: {e}"));
        }

        // Schema constraints: a read-only kind or a disallowed field. Staging
        // already refuses these, but a change set can outlive a server
        // restart (it round-trips through --state-file), so a plan built
        // before this check existed must still be caught by the tool whose
        // description already promises "schema constraints".
        if let Err(e) = check_writable_fields(&mutations) {
            return tool_error(format!("schema constraints failed: {e}"));
        }

        // A zone this set deletes must not be left referenced by anything else
        // in the set. Checked first because it needs no controller round trip:
        // it compares the set against itself and against the pre-image.
        if let Err(e) = check_zone_deletions(&preimage, &mutations) {
            return tool_error(format!("reference check failed: {e}"));
        }

        // Referential integrity is checked against the controller's live zone
        // list, not the pre-image. The pre-image records nothing for a create,
        // and it was being searched for a resource with `_id == "_all_"` that
        // no controller ever returns -- so the zone index was empty for every
        // `firewall_policy` create and each one was refused as referencing a
        // zone that did not exist. Fetch only when a staged body names a zone,
        // so a change set that touches no firewall does not start depending on
        // the firewall surface being reachable.
        if !referenced_zone_ids(&mutations).is_empty() {
            let client = match self.client_for(&args.controller) {
                Ok(client) => client,
                Err(result) => return *result,
            };

            let zone_args = read::ListResourcesArgs {
                controller: args.controller.clone(),
                kind: ResourceKind::FirewallZone,
                site: None,
                limit: None,
                offset: None,
            };

            let raw = match read::list_resources(&client, &zone_args).await {
                Ok(raw) => raw,
                Err(e) => {
                    return tool_error(format!(
                        "could not read the firewall zone list from controller '{}', so zone                          references cannot be checked: {e}",
                        args.controller
                    ));
                }
            };

            let zones = match ZoneIndex::from_zone_list(&raw) {
                Ok(zones) => zones,
                Err(e) => {
                    return tool_error(format!(
                        "could not read the firewall zone list from controller '{}', so zone                          references cannot be checked: {e}",
                        args.controller
                    ));
                }
            };

            if let Err(e) = check_zone_references(&zones, &mutations) {
                return tool_error(format!("reference check failed: {e}"));
            }
        }

        let result = serde_json::json!({
            "change_set_id": record.id,
            "valid": true,
            "note": "UniFi has no server-side dry-run validation; this is client-side only"
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "unifi_approve_change_set",
        description = "Approves a change set for apply. Two-person control: the creating \
                       token cannot approve its own set unless lab mode waives it, and a \
                       waiver is recorded as a waiver rather than as an approval. Pass \
                       expected_digest to bind the approval to the plan you read."
    )]
    async fn unifi_approve_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApproveChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_approve_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }
        // Under --lab-mode a single operator may hold both scopes on purpose
        // (issued with `token add --allow-self-approval`); the change-set
        // lab-mode waiver then records the self-approval as a distinct fact.
        if !self.lab_mode && Self::holds_combined_two_person_control_scope(caller.as_ref()) {
            return tool_error(
                "two-person control: this caller holds both unifi_stage_change and \
                 unifi_approve_change_set; use separate callers for staging and approving",
            );
        }

        let approver = Self::principal(caller.as_ref());

        let record = match self.record_for(&args.change_set_id, &args.controller).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        // An approval is a statement about specific staged changes. A set with
        // nothing staged has nothing to attest to, and recording an approval
        // against it puts a signature in the audit trail for a decision nobody
        // could have reviewed. Observed live: a change set whose staging failed
        // was still approvable, and only apply refused it.
        if record.actions.is_empty() {
            return tool_error("change set has nothing staged; there is nothing to approve");
        }

        // And it must be a statement about something the approver could read.
        // The preview is written at create and rewritten at every stage, so an
        // absent one means a record this server did not write.
        let Some(preview) = record.preview.clone() else {
            return tool_error(
                "approval refused: this change set has no stored preview, so there is \
                 nothing to review. Create it again.",
            );
        };

        // Belt-and-suspenders with the same check in `unifi_apply_change_set`:
        // a plan staged before a writable-field rule tightened, or restored
        // from `--state-file` into a build that tightened one, should not be
        // approved into a state where only apply's check stands between it
        // and the controller. An approver's signature should attest to a plan
        // that can actually be applied.
        let (approval_mutations, _) = match Self::plan_of(&record) {
            Ok(plan) => plan,
            Err(result) => return *result,
        };
        if let Err(e) = check_writable_fields(&approval_mutations) {
            return tool_error(format!("approval refused: {e}"));
        }

        // An approver who names the digest they read is bound to that plan. Not
        // naming one falls back to the stored digest, which makes the
        // lifecycle's digest check a tautology -- it compares the stored value
        // with itself -- so the argument is the only way an approval can
        // actually attest to a specific plan rather than to whatever the record
        // holds when the call lands.
        if let Some(ref expected) = args.expected_digest
            && expected != &record.digest
        {
            return tool_error(format!(
                "approval refused: the plan has changed since you read it. You named \
                 digest {expected}; the change set now holds {}. Read it again before \
                 approving.",
                record.digest
            ));
        }

        // Two-person control when a second principal is present; the lab-mode
        // waiver only when the owner is approving their own set. The waiver is
        // a distinct call, not a flag on the approval, so the record says which
        // of the two happened -- `approver: None` cannot tell "nobody has
        // approved this" from "this was approved without review".
        // The same lock staging holds. The coordinator emits the approval
        // record itself, copying the recorder's diff hash for this change set,
        // so an approval must not run while a plan is half-published.
        let _approving = self.plan_lock.lock().await;

        // Truthful, not permissive: a stdio caller carries no verified token
        // entry, so its actor type is unknown rather than assumed human. The
        // coordinator refuses anything but a human approver (the house rule
        // that a human approves), which is exactly the outcome an unattributed
        // caller should get. A verified assertion is used only when the caller
        // context already carries one.
        let approver_identity = Self::approver_identity(caller.as_ref(), &approver);

        let outcome = if approver == record.owner {
            if !self.lab_mode {
                return tool_error(
                    "two-person control: the creating token cannot approve its own change set",
                );
            }
            self.coordinator
                .waive_approval(
                    args.change_set_id.clone(),
                    args.controller.clone(),
                    approver.clone(),
                    record.digest.clone(),
                )
                .await
        } else {
            self.coordinator
                .approve_change_set(
                    args.change_set_id.clone(),
                    args.controller.clone(),
                    &approver_identity,
                    record.digest.clone(),
                )
                .await
        };

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                return tool_error(format!(
                    "approval refused ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
        };

        let result = serde_json::json!({
            "change_set_id": outcome.change_set_id,
            "state": outcome.state.as_str(),
            "approved_by": outcome.approver,
            "approval_waiver": outcome.approval_waiver,
            "expires_at_unix": outcome.expires_at_unix,
            "approved_digest": outcome.digest,
            "preview": preview.artifact,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "unifi_apply_change_set",
        description = "Applies the staged changes as a sequence of independent REST calls"
    )]
    async fn unifi_apply_change_set(
        &self,
        Parameters(args): Parameters<changeset::ApplyChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_apply_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        let client = match self.client_for(&args.controller) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // Claim first, and only then read the plan. The claim is the single
        // legal route from `Approved` to `Applying`, and it does the check and
        // the write under one lock -- so two concurrent applies cannot both
        // observe `Approved` and both proceed, which the map-backed store
        // allowed. It is also what enforces the approval window and refuses a
        // set that has already run: an approval reaches `Applying` once and
        // there is no route back.
        //
        // `ApplyHandle::None` because UniFi returns no task handle to re-probe.
        // A crash mid-apply therefore leaves the record `Applying` rather than
        // being read as `Failed` at the next start: the writes are not
        // idempotent, a partial apply is a reachable outcome, and only the
        // controller knows which of them landed. Detectable, not recoverable,
        // and a human has to look -- which is the honest state, and keeps the
        // approval from being spent twice.
        // Retires a `Planned` set whose window has closed, so the common case
        // reports "expired" rather than "not approved". It does not cover an
        // `Approved` one: `retire_if_deadline_passed` only applies the approval
        // TTL to `Planned`, and otherwise expires only a lapsed lab-mode
        // waiver. The real gate is after the claim.
        if let Err(error) = self
            .coordinator
            .change_set_status(args.change_set_id.clone(), args.controller.clone())
            .await
        {
            return tool_error(format!(
                "apply refused ({}): {}",
                error.field(),
                error.message()
            ));
        }

        let claimed = match self
            .coordinator
            .claim_change_set_for_apply(&args.change_set_id, &args.controller, ApplyHandle::None)
            .await
        {
            Ok(record) => record,
            Err(error) => {
                return tool_error(format!(
                    "apply refused ({}): {}",
                    error.field(),
                    error.message()
                ));
            }
        };

        // The deadline, enforced on the record the claim just returned. Nothing
        // upstream does it: `claim_change_set_for_apply` checks the state and
        // not the clock, and `change_set_status` applies the approval TTL only
        // to a `Planned` record -- so an ordinary two-person approval granted
        // inside the window and applied long after it reached the controller,
        // which is precisely what `--approval-timeout-secs` exists to stop.
        //
        // Here rather than before the claim because the claim is what
        // serialises: one caller holds it, and it refuses before anything is
        // written. A pre-claim check alone is a check-then-act race.
        if unix_seconds_now() >= claimed.expires_at_unix {
            let deadline = claimed.expires_at_unix;
            let mut lapsed = claimed;
            lapsed.state = ChangeSetState::Failed;
            if let Err(error) = self.coordinator.update_change_set(lapsed).await {
                tracing::error!(
                    change_set_id = %args.change_set_id,
                    field = error.field(),
                    message = error.message(),
                    "an expired change set could not be settled after its claim"
                );
            }
            return tool_error(format!(
                "apply refused: the approval window closed at {deadline}; nothing was \
                 written. Re-plan and re-approve before applying."
            ));
        }

        // A claim has no route back to `Approved`, so a failure between here
        // and the first write has to settle the record itself or it sits in
        // `Applying` for good, with its approval neither spent nor spendable.
        // Nothing has been written at this point, so `Failed` is accurate.
        let (mutations, preimage) = match Self::plan_of(&claimed) {
            Ok(plan) => plan,
            Err(result) => {
                let mut abandoned = claimed;
                abandoned.state = ChangeSetState::Failed;
                if let Err(error) = self.coordinator.update_change_set(abandoned).await {
                    tracing::error!(
                        change_set_id = %args.change_set_id,
                        field = error.field(),
                        message = error.message(),
                        "a claimed change set could not be settled after its plan \
                         failed to read; it will stay Applying"
                    );
                }
                return *result;
            }
        };

        // A change set can be staged before a writable-field rule tightens,
        // or -- with `--state-file` -- survive a restart into a build that
        // tightened one. Staging and `unifi_validate_change_set` already run
        // this check, but neither is mandatory before apply, so the same
        // refusal has to be enforced here too. Mirrors the `plan_of` error
        // arm above: nothing has been written yet, so `Failed` is accurate.
        if let Err(e) = check_writable_fields(&mutations) {
            let mut abandoned = claimed;
            abandoned.state = ChangeSetState::Failed;
            if let Err(error) = self.coordinator.update_change_set(abandoned).await {
                tracing::error!(
                    change_set_id = %args.change_set_id,
                    field = error.field(),
                    message = error.message(),
                    "a claimed change set could not be settled after its writable-field \
                     check failed; it will stay Applying"
                );
            }
            return tool_error(format!("apply refused: {e}"));
        }

        let principal = Self::principal(caller.as_ref());

        // Recorded before the controller is touched, and the apply is refused
        // if it cannot be made durable. An intent that survives only in memory
        // proves nothing about a crash, and the point of the record is to
        // establish that this write was going to happen before it did.
        if let Some(recorder) = self.evidence.as_ref()
            && let Err(error) = recorder.apply_intent(
                &args.change_set_id,
                &args.change_set_id,
                &args.controller,
                &principal,
            )
        {
            let mut abandoned = claimed;
            abandoned.state = ChangeSetState::Failed;
            let _ = self.coordinator.update_change_set(abandoned).await;
            return tool_error(format!(
                "apply refused: the SSDF apply-intent record could not be made durable, \
                 so the write was not attempted: {error}"
            ));
        }

        let outcome = apply_sequentially(&client, &preimage, &mutations).await;

        let state_str = match outcome.state {
            State::Applied => "applied",
            State::AppliedUnverified => "applied_unverified",
            State::Partial => "partial",
            State::PartialRollbackFailed => "partial_rollback_failed",
            State::RefusedStale => "refused_stale",
        };

        let succeeded = matches!(outcome.state, State::Applied | State::AppliedUnverified);

        // The breakdown goes to the audit trail, which is where an event
        // belongs -- the state file holds state. It has no home on
        // `ChangeSetRecord`, which is `deny_unknown_fields`, and the shared
        // crate's `OperationRecord` was the wrong container: its non-terminal
        // states make every later operation on the device refuse as
        // unreconciled, which is right for a vendor whose commit either lands
        // or does not, and would wedge this one -- a partial apply here is a
        // routine outcome and there is no tool to clear it.
        //
        // Emitted before the state write, so the record of what happened
        // survives even if recording the verdict fails.
        tracing::info!(
            target: "audit",
            event = "unifi_change_set_applied",
            change_set_id = %args.change_set_id,
            controller = %args.controller,
            principal = %principal,
            outcome = state_str,
            succeeded = outcome.succeeded.len(),
            failed = outcome.failed.len(),
            attempted_and_failed = outcome.attempted_and_failed.len(),
            never_attempted = outcome.never_attempted.len(),
            rollback_failures = outcome.rollback_failures.len(),
            "change set applied"
        );

        // `Applied` when every write landed, and for an apply that landed but
        // could not be re-read to confirm it: it did apply, and calling that
        // `Failed` asserts an outcome nobody observed. The distinction between
        // the two lives in the audit record above and in the result below.
        // Everything else is `Failed`, a partial included -- a record claiming
        // a change landed when only some of it did is worse than one an
        // operator has to go and read.
        let mut settled = claimed;
        settled.state = if succeeded {
            ChangeSetState::Applied
        } else {
            ChangeSetState::Failed
        };

        // The device has acted, so this cannot fail closed -- refusing now
        // would not un-act it. Reported instead.
        if let Some(recorder) = self.evidence.as_ref()
            && let Err(error) = recorder.result_receipt(
                &args.change_set_id,
                &args.change_set_id,
                &args.controller,
                &principal,
                succeeded,
                // Failures only. The schema reads a non-empty `error` as an
                // execution failure, so passing the outcome unconditionally
                // made every successful receipt carry `error: "applied"` and
                // read as a failure to anything filtering on it.
                if succeeded { "" } else { state_str },
            )
        {
            tracing::error!(
                change_set_id = %args.change_set_id,
                %error,
                "the SSDF result receipt could not be made durable"
            );
        }

        if let Err(error) = self.coordinator.update_change_set(settled).await {
            // The writes have already happened, so this is reported rather than
            // returned as the outcome: the caller needs the apply result, and
            // an unrecorded outcome is a separate fault.
            tracing::error!(
                change_set_id = %args.change_set_id,
                field = error.field(),
                message = error.message(),
                "the apply outcome could not be recorded"
            );
        }

        let result = serde_json::json!({
            "change_set_id": args.change_set_id,
            "state": state_str,
            "succeeded": outcome.succeeded.len(),
            "failed": outcome.failed.len(),
            "attempted_and_failed": outcome.attempted_and_failed.len(),
            "never_attempted": outcome.never_attempted.len(),
            "rollback_failures": outcome.rollback_failures,
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "unifi_get_change_set",
        description = "Returns the current status and contents of a change set"
    )]
    async fn unifi_get_change_set(
        &self,
        Parameters(args): Parameters<changeset::GetChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "unifi_get_change_set",
            Some(&args.controller),
            WRITE_TOOLS,
        ) {
            return tool_error(error);
        }

        // A draft has no record yet, and reporting "not found" for a change set
        // this server just handed out an id for would read as a fault.
        if let Some(draft) = self.draft(&args.change_set_id, &args.controller) {
            return tool_result(
                Ok::<_, String>(serde_json::json!({
                    "change_set_id": args.change_set_id,
                    "controller": draft.controller,
                    "description": draft.description,
                    "creator": draft.owner,
                    "state": "draft",
                    "mutation_count": 0,
                    "note": "nothing is staged yet; this draft is held in memory and is \
                             lost on restart",
                })),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }

        // Through `change_set_status`, because it is the path that transitions
        // and persists a set whose deadline has passed. Reading the record raw
        // reports `planned` beside an `expires_at_unix` already in the past.
        if let Err(error) = self
            .coordinator
            .change_set_status(args.change_set_id.clone(), args.controller.clone())
            .await
        {
            return tool_error(format!(
                "change set {} on {} ({}): {}",
                args.change_set_id,
                args.controller,
                error.field(),
                error.message()
            ));
        }

        let record = match self.record_for(&args.change_set_id, &args.controller).await {
            Ok(record) => record,
            Err(result) => return *result,
        };

        let description = Self::description_of(&record).unwrap_or_default();

        // The state is the lifecycle's, not a string derived from which fields
        // happen to be populated. `approved` and `pending` used to be inferred
        // from whether an approver was set, which cannot distinguish an expired
        // approval or a cancelled set from a pending one.
        let result = serde_json::json!({
            "change_set_id": record.id,
            "controller": record.device,
            "description": description,
            "creator": record.owner,
            "approver": record.approval.as_ref().and_then(|a| a.approver.clone()),
            "approval_waiver": record
                .approval
                .as_ref()
                .and_then(|a| a.waived.as_ref())
                .map(|waiver| waiver.kind.as_str()),
            "state": record.state.as_str(),
            "mutation_count": record.actions.len(),
            "expires_at_unix": record.expires_at_unix,
            "plan_digest": record.digest,
            "expected_preimage_fingerprint": record.expected_candidate_fingerprint,
            "preview": record.preview.as_ref().map(|preview| preview.artifact.clone()),
        });

        tool_result(
            Ok::<_, String>(result),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }
}

/// Apply cache hints to a tool list when the client negotiated 2026-07-28 or later.
fn listed_tools(tools: Vec<rmcp::model::Tool>, add_cache_hints: bool) -> ListToolsResult {
    let listed = ListToolsResult::with_all_items(tools);
    if add_cache_hints {
        listed
            .with_ttl_ms(300_000)
            .with_cache_scope(rmcp::model::CacheScope::Private)
    } else {
        listed
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for UnifiServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rustunifimcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "UniFi Network MCP server. Controller-addressed tools take (controller, ...); \
                 the server routes to the controller by name.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<UnifiGrant>(&context.extensions);
        let all_tools = self.tool_router.list_all();
        let visible = filter_tools_for_scope(all_tools, caller, WRITE_TOOLS);
        // `with_all_items` leaves `ttl_ms` and `cache_scope` unset, and both
        // are omitted on the wire. A 2026-07-28 client validates the tools/list
        // result and rejects one without them — reported as "tools fetch
        // failed" against a server that is otherwise healthy and fast. Servers
        // that do not override `list_tools` get these from rmcp's generated
        // handler; this one filters by scope, so it supplies them itself.
        //
        // `private`: the list is per token, so a cache keyed only on the URL
        // must not serve one caller's surface to another.
        let cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(listed_tools(visible, cache_hints))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rmcp::ServiceExt;
    use std::time::Duration;

    /// Build a `CallerCtx` with the given tool scope, mirroring the pattern
    /// `mecmcp-server::authorize`'s own tests use.
    fn caller_with_tools(tools: mecmcp_auth::ScopeSet) -> mecmcp_auth::CallerCtx<UnifiGrant> {
        mecmcp_auth::CallerCtx {
            token_name: "caller".to_owned(),
            devices: mecmcp_auth::ScopeSet::Wildcard,
            tools,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        }
    }

    /// Build a `CallerCtx` carrying the given site grant, for
    /// `authorize_site` tests.
    fn caller_with_site_grant(grant: Option<UnifiGrant>) -> mecmcp_auth::CallerCtx<UnifiGrant> {
        mecmcp_auth::CallerCtx {
            grant,
            ..caller_with_tools(mecmcp_auth::ScopeSet::Wildcard)
        }
    }

    /// A token scoped to `site-a` must be refused for `site-b` -- the
    /// regression this issue exists for.
    #[test]
    fn authorize_site_refuses_a_site_outside_the_grant() {
        let caller = caller_with_site_grant(Some(UnifiGrant {
            sites: mecmcp_auth::ScopeSet::Allowlist(vec!["site-a".to_owned()]),
        }));
        assert!(UnifiServer::authorize_site(Some(&caller), "site-b").is_err());
    }

    /// A token scoped to more than one site must be authorized for each one.
    #[test]
    fn authorize_site_permits_each_site_in_a_multi_site_grant() {
        let caller = caller_with_site_grant(Some(UnifiGrant {
            sites: mecmcp_auth::ScopeSet::Allowlist(vec!["site-a".to_owned(), "site-b".to_owned()]),
        }));
        assert!(UnifiServer::authorize_site(Some(&caller), "site-a").is_ok());
        assert!(UnifiServer::authorize_site(Some(&caller), "site-b").is_ok());
        assert!(UnifiServer::authorize_site(Some(&caller), "site-c").is_err());
    }

    /// A caller with no grant at all is unrestricted by site -- the
    /// pre-MEC-508 default that keeps existing tokens working unchanged.
    #[test]
    fn authorize_site_permits_any_site_with_no_grant() {
        let caller = caller_with_site_grant(None);
        assert!(UnifiServer::authorize_site(Some(&caller), "any-site").is_ok());
    }

    /// The stdio path (`caller: None`) is unrestricted, consistent with every
    /// other authorization check in this module.
    #[test]
    fn authorize_site_permits_any_site_with_no_caller() {
        assert!(UnifiServer::authorize_site(None, "any-site").is_ok());
    }

    /// A wildcard site grant permits every site, same as an absent grant --
    /// `--sites '*'` and omitting the flag both authorize identically, just
    /// through different representations.
    #[test]
    fn authorize_site_permits_any_site_with_a_wildcard_grant() {
        let caller = caller_with_site_grant(Some(UnifiGrant {
            sites: mecmcp_auth::ScopeSet::Wildcard,
        }));
        assert!(UnifiServer::authorize_site(Some(&caller), "site-a").is_ok());
        assert!(UnifiServer::authorize_site(Some(&caller), "site-z").is_ok());
    }

    /// The check this test guards: `unifi_stage_change` and
    /// `unifi_approve_change_set` are both in `WRITE_TOOLS`, and this crate's
    /// only means of reaching a write tool is an explicit allowlist naming
    /// it (`ScopeSet::Wildcard` excludes every write tool). A token whose
    /// allowlist names both must be refused at call time -- this is the
    /// check a hand-edited token store cannot bypass, unlike the
    /// issuance-time refusal in `main.rs`.
    #[test]
    fn a_token_scoped_to_both_stage_and_approve_is_refused_at_call_time() {
        let caller = caller_with_tools(mecmcp_auth::ScopeSet::Allowlist(vec![
            "unifi_stage_change".to_owned(),
            "unifi_approve_change_set".to_owned(),
        ]));
        assert!(UnifiServer::holds_combined_two_person_control_scope(Some(
            &caller
        )));
    }

    /// Holding only one of the two scopes -- the normal shape for a staging
    /// or an approving token -- must not be refused.
    #[test]
    fn a_token_scoped_to_only_one_changeset_control_tool_is_not_refused() {
        let stager = caller_with_tools(mecmcp_auth::ScopeSet::Allowlist(vec![
            "unifi_stage_change".to_owned(),
        ]));
        assert!(!UnifiServer::holds_combined_two_person_control_scope(Some(
            &stager
        )));

        let approver = caller_with_tools(mecmcp_auth::ScopeSet::Allowlist(vec![
            "unifi_approve_change_set".to_owned(),
        ]));
        assert!(!UnifiServer::holds_combined_two_person_control_scope(Some(
            &approver
        )));
    }

    /// A wildcard tool scope excludes every `WRITE_TOOLS` entry, so it can
    /// never combine the two change-set control tools -- it cannot reach
    /// either of them at all.
    #[test]
    fn a_wildcard_tool_scope_never_combines_the_two_control_tools() {
        let caller = caller_with_tools(mecmcp_auth::ScopeSet::Wildcard);
        assert!(!UnifiServer::holds_combined_two_person_control_scope(Some(
            &caller
        )));
    }

    /// The stdio path (`caller: None`) is documented elsewhere as authorized
    /// for everything; this check must not contradict that by refusing a
    /// `None` caller.
    #[test]
    fn a_none_caller_is_not_refused() {
        assert!(!UnifiServer::holds_combined_two_person_control_scope(None));
    }

    #[test]
    fn write_tools_is_not_empty() {
        assert!(
            !WRITE_TOOLS.is_empty(),
            "WRITE_TOOLS must never be empty — an empty registry lets wildcards reach writes"
        );
    }

    /// A response already under budget must pass through untouched -- no
    /// `truncated` marker on an answer that was never shortened.
    #[test]
    fn a_response_within_budget_is_returned_whole() {
        let value = serde_json::json!({ "data": [1, 2, 3] });
        let out = shrink_largest_array(value.clone(), 10_000);
        assert_eq!(out, value);
    }

    /// The reported defect: a response too large for the transport's budget
    /// must come back shortened with a marker, not be handed to `tool_result`
    /// unmodified where it would be refused outright.
    #[test]
    fn an_oversized_array_is_shortened_with_a_truncation_marker() {
        let items: Vec<serde_json::Value> = (0..2000)
            .map(|i| serde_json::json!({ "id": i, "note": "x".repeat(200) }))
            .collect();
        let value = serde_json::json!({ "devices": items, "partial": false });

        let budget = 20_000;
        let out = shrink_largest_array(value, budget);

        assert!(
            rendered_len(&out) <= budget,
            "shrunk response still over budget"
        );
        assert_eq!(out["truncation"]["field"], serde_json::json!("devices"));
        assert_eq!(out["truncation"]["of"], serde_json::json!(2000));

        let shown = out["truncation"]["shown"]
            .as_u64()
            .expect("shown is a number") as usize;
        assert!(shown < 2000, "nothing was actually dropped");
        assert_eq!(
            out["devices"]
                .as_array()
                .expect("devices is an array")
                .len(),
            shown,
            "shown must match the array actually returned"
        );

        // `partial` was already present, so a shrunk response must say so.
        assert_eq!(out["partial"], serde_json::json!(true));
    }

    /// A bare top-level array (`unifi_list_resources`'s shape) is wrapped
    /// under `data` rather than dropped, so the truncation marker has
    /// somewhere to live.
    #[test]
    fn a_bare_array_is_wrapped_under_data_when_shrunk() {
        let items: Vec<serde_json::Value> = (0..2000)
            .map(|i| serde_json::json!({ "id": i, "note": "x".repeat(200) }))
            .collect();
        let value = serde_json::Value::Array(items);

        let out = shrink_largest_array(value, 20_000);

        assert!(out["data"].is_array());
        assert_eq!(out["truncation"]["field"], serde_json::json!("data"));
        assert_eq!(out["truncation"]["of"], serde_json::json!(2000));
    }

    /// A single object with no array has no smaller true answer; it must be
    /// left for `tool_result`'s own refusal rather than silently mangled.
    #[test]
    fn an_oversized_scalar_object_is_left_for_tool_result_to_refuse() {
        let value = serde_json::json!({ "note": "x".repeat(1000) });
        let out = shrink_largest_array(value.clone(), 10);
        assert_eq!(out, value, "no array to shrink means no change");
    }

    /// Percy review F1 (MEC-549): the marker used to be written as top-level
    /// `truncated`/`shown`/`total` fields, which collided with the
    /// site-wide `total` that `unifi_query_stats` and the workflow reports
    /// already fill in from `tools::pagination::paginate`. A caller advancing
    /// `offset` by `limit` on the corrupted `total` would then skip whatever
    /// sat between the shrunk count and the real page size. The site-wide
    /// `total` must survive shrinking untouched, and the object must carry a
    /// correct cursor for the next call.
    #[test]
    fn shrinking_a_paged_object_preserves_its_site_wide_total_and_cursor() {
        let items: Vec<serde_json::Value> = (0..2000)
            .map(|i| serde_json::json!({ "id": i, "note": "x".repeat(200) }))
            .collect();
        let value = serde_json::json!({
            "data": items,
            "offset": 100u64,
            "limit": 2000,
            "total": 50_000,
        });

        let budget = 20_000;
        let out = shrink_largest_array(value, budget);

        assert!(
            rendered_len(&out) <= budget,
            "shrunk response still over budget"
        );
        // The pagination cursor's site-wide total must not be clobbered by
        // the shrunk array's own length.
        assert_eq!(out["total"], serde_json::json!(50_000));
        assert_eq!(out["offset"], serde_json::json!(100));

        let shown = out["truncation"]["shown"]
            .as_u64()
            .expect("shown is a number");
        assert!(shown < 2000, "nothing was actually dropped");
        assert_eq!(
            out["next_offset"],
            serde_json::json!(100 + shown),
            "next_offset must reflect what was actually shown, not the requested limit"
        );
    }

    /// MEC-504: a stdio caller (no verified token entry) must map to
    /// `Unknown`, never `Human`. `Human` is what mecmcp's
    /// `approve_change_set` requires, so inventing it for an unattributed
    /// caller would let stdio silently satisfy the human-approver gate.
    #[test]
    fn approver_actor_type_maps_stdio_to_unknown_not_human() {
        assert_eq!(
            UnifiServer::approver_actor_type(None),
            mecmcp_audit::ActorType::Unknown
        );
    }

    /// A token minted with `actor_type: agent` must carry `Agent` through to
    /// the coordinator, not `Human` — an agent-held token must not be able to
    /// approve its own change set by riding through this mapping.
    #[test]
    fn approver_actor_type_carries_agent_through_not_human() {
        let caller = mecmcp_auth::CallerCtx::<UnifiGrant> {
            token_name: "agent-token".to_owned(),
            devices: mecmcp_auth::ScopeSet::Wildcard,
            tools: mecmcp_auth::ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Agent,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        assert_eq!(
            UnifiServer::approver_actor_type(Some(&caller)),
            mecmcp_audit::ActorType::Agent
        );
    }

    /// A token minted with `actor_type: human` must carry `Human` through —
    /// the one case `approve_change_set` actually accepts.
    #[test]
    fn approver_actor_type_carries_human_through() {
        let caller = mecmcp_auth::CallerCtx::<UnifiGrant> {
            token_name: "human-token".to_owned(),
            devices: mecmcp_auth::ScopeSet::Wildcard,
            tools: mecmcp_auth::ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Human,
            oidc_subject: None,
            verified_approver: None,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };
        assert_eq!(
            UnifiServer::approver_actor_type(Some(&caller)),
            mecmcp_audit::ActorType::Human
        );
    }

    /// No configured binding means none is recorded. A configured binding is
    /// copied through, not dropped.
    #[test]
    fn owner_subject_follows_the_token_binding() {
        let unbound = caller_with_tools(mecmcp_auth::ScopeSet::Wildcard);
        assert!(UnifiServer::owner_subject_of(Some(&unbound)).is_none());
        assert!(UnifiServer::owner_subject_of(None).is_none());

        let mut bound = unbound;
        bound.oidc_subject = Some(mecmcp_auth::OidcSubject {
            issuer: "https://idp.example.test".to_owned(),
            subject: "subject-1".to_owned(),
        });
        let copied = UnifiServer::owner_subject_of(Some(&bound)).expect("binding copied");
        assert_eq!(copied.issuer, "https://idp.example.test");
        assert_eq!(copied.subject, "subject-1");
    }

    /// With no verified assertion configured, approval stays on the token's
    /// declared actor type. Stdio stays unknown.
    #[test]
    fn approver_identity_stays_token_asserted_without_a_configured_assertion() {
        let caller = caller_with_tools(mecmcp_auth::ScopeSet::Wildcard);
        let identity = UnifiServer::approver_identity(Some(&caller), "ignored");
        assert!(matches!(
            identity,
            mecmcp_changeset::ApproverIdentity::TokenAsserted {
                ref principal,
                actor_type,
            } if principal == "caller" && actor_type == mecmcp_audit::ActorType::Human
        ));

        let stdio = UnifiServer::approver_identity(None, "unknown");
        assert!(matches!(
            stdio,
            mecmcp_changeset::ApproverIdentity::TokenAsserted {
                ref principal,
                actor_type,
            } if principal == "unknown" && actor_type == mecmcp_audit::ActorType::Unknown
        ));
    }

    /// The router and the registry must agree, in both directions.
    ///
    /// A name in `TOOL_NAMES` the server does not serve is a promise it cannot
    /// keep — `unifi_add_controller` was exactly that, so its documented
    /// "edit the file and HUP" guidance could never reach a caller. A tool the
    /// server serves that is absent from `TOOL_NAMES` is worse: it escapes the
    /// `WRITE_TOOLS` classification entirely, which is how a mutating tool
    /// becomes reachable by a wildcard token.
    #[test]
    fn the_router_serves_exactly_the_registered_tools() {
        use rustunifimcp_core::tools::TOOL_NAMES;
        use std::collections::BTreeSet;

        let router = UnifiServer::unifi_tool_router();
        let all_tools = router.list_all();
        let served_names: BTreeSet<String> =
            all_tools.iter().map(|tool| tool.name.to_string()).collect();
        let registered_names: BTreeSet<String> =
            TOOL_NAMES.iter().map(|s| (*s).to_owned()).collect();

        // Check for tools in TOOL_NAMES but not served.
        let missing_from_router: Vec<String> = registered_names
            .difference(&served_names)
            .cloned()
            .collect();
        assert!(
            missing_from_router.is_empty(),
            "TOOL_NAMES declares tools the server does not serve: {:?}",
            missing_from_router
        );

        // Check for tools served but not in TOOL_NAMES.
        let missing_from_registry: Vec<String> = served_names
            .difference(&registered_names)
            .cloned()
            .collect();
        assert!(
            missing_from_registry.is_empty(),
            "Server serves tools absent from TOOL_NAMES: {:?}",
            missing_from_registry
        );

        // Both directions pass — the sets are equal.
    }

    /// A human approver known only by token name. Tests do not configure an
    /// assertion, so this is the identity the coordinator accepts.
    fn human_approver(principal: &str) -> mecmcp_changeset::ApproverIdentity {
        mecmcp_changeset::ApproverIdentity::TokenAsserted {
            principal: principal.to_owned(),
            actor_type: mecmcp_audit::ActorType::Human,
        }
    }

    /// Build a `Planned` record the way `unifi_create_change_set` does.
    fn planned_record(owner: &str, controller: &str, ttl: u64) -> ChangeSetRecord {
        let record = ChangeSetRecord {
            id: crate::changeset_state::new_change_set_id(),
            owner: owner.to_owned(),
            device: controller.to_owned(),
            expected_candidate_fingerprint: String::new(),
            actions: Vec::new(),
            digest: String::new(),
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now().saturating_add(ttl),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: None,
            task_id: None,
            apply_without_handle: false,
            owner_subject: None,
        };
        let staged = vec![StagedMutation::create(
            "firewall_policy",
            serde_json::json!({ "name": "probe" }),
        )];
        UnifiServer::with_plan(
            record,
            &staged,
            &Preimage::from_resources(Vec::new()),
            "test",
        )
        .map_err(|_| "with_plan refused a freshly built record")
        .expect("a freshly built record must plan")
    }

    fn coordinator_at(path: Option<&std::path::Path>) -> Arc<ChangesetCoordinator> {
        crate::changeset_state::build_coordinator(path, Duration::from_secs(300), true, None, None)
            .expect("coordinator")
    }

    /// An approval that does not survive a restart is not an approval, and the
    /// pre-image that went with it is what stands between a partial apply and
    /// an unrecoverable one.
    #[tokio::test]
    async fn change_set_survives_state_file_round_trip() {
        let temp = tempfile::NamedTempFile::new().expect("temp file");
        let path = temp.path().to_path_buf();

        let id = {
            let coordinator = coordinator_at(Some(&path));
            let record = planned_record("alice", "home", 300);
            let id = record.id.clone();
            coordinator.insert_change_set(record).await.expect("insert");
            id
        };

        let reloaded = coordinator_at(Some(&path));
        let record = reloaded
            .change_set(&id, "home")
            .await
            .expect("the record must survive the restart");
        assert_eq!(record.owner, "alice");
        assert_eq!(record.state, ChangeSetState::Planned);
        assert!(
            record.owner_subject.is_none(),
            "a plan with no configured binding must not gain one across a restart"
        );
        assert!(
            record.preview.is_some(),
            "the preview an approver reads must survive too"
        );
        assert_eq!(
            UnifiServer::plan_of(&record)
                .map_err(|_| "plan_of")
                .expect("the plan must survive")
                .0
                .len(),
            1
        );
    }

    /// `approver: None` cannot tell "nobody has approved this" from "this was
    /// approved without review", so a waiver has to be recorded as its own
    /// fact. It is also the one thing lab mode changes about the lifecycle.
    #[tokio::test]
    async fn lab_mode_records_the_waiver_as_a_distinct_fact() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        coordinator.insert_change_set(record).await.expect("insert");

        let outcome = coordinator
            .waive_approval(id.clone(), "home".to_owned(), "alice".to_owned(), digest)
            .await
            .expect("lab mode waives the second principal");

        assert_eq!(outcome.state, ChangeSetState::Approved);
        assert_eq!(
            outcome.approval_waiver.as_deref(),
            Some("lab-mode"),
            "a waived approval must say so rather than look unapproved"
        );

        let stored = coordinator.change_set(&id, "home").await.expect("stored");
        assert!(
            stored.approval.is_some(),
            "the waiver must be recorded on the record, not only returned"
        );
    }

    /// Without lab mode the same call is a self-approval and must be refused
    /// by the lifecycle, not only by this server's own check.
    #[tokio::test]
    async fn a_waiver_is_refused_when_lab_mode_is_off() {
        let coordinator = crate::changeset_state::build_coordinator(
            None,
            Duration::from_secs(300),
            false,
            None,
            None,
        )
        .expect("coordinator");
        let record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        coordinator.insert_change_set(record).await.expect("insert");

        assert!(
            coordinator
                .waive_approval(id, "home".to_owned(), "alice".to_owned(), digest)
                .await
                .is_err(),
            "a waiver outside lab mode is a self-approval"
        );
    }

    /// The claim is the only legal route to `Applying`, and an unapproved set
    /// must not reach it.
    #[tokio::test]
    async fn an_unapproved_change_set_cannot_be_claimed_for_apply() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        assert!(
            coordinator
                .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
                .await
                .is_err(),
            "a Planned change set has no approval to spend"
        );
    }

    /// And an approval is spent once. The map-backed store let two concurrent
    /// applies both observe `Approved` and both proceed.
    #[tokio::test]
    async fn an_approval_can_only_be_claimed_once() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        coordinator.insert_change_set(record).await.expect("insert");
        coordinator
            .approve_change_set(
                id.clone(),
                "home".to_owned(),
                &human_approver("bob"),
                digest,
            )
            .await
            .expect("a second principal approves");

        coordinator
            .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
            .await
            .expect("the first claim takes the approval");
        assert!(
            coordinator
                .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
                .await
                .is_err(),
            "the second claim must find the approval spent"
        );
    }

    /// An approval is a statement about a controller state at a moment. The
    /// packaged deployment advertises a 300-second window; the lifecycle is
    /// what now honours it.
    #[tokio::test]
    async fn an_expired_approval_cannot_be_claimed() {
        let coordinator = coordinator_at(None);
        let mut record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        record.expires_at_unix = unix_seconds_now().saturating_sub(1);
        coordinator.insert_change_set(record).await.expect("insert");

        // Approval itself is refused once the window has passed, which is the
        // earlier of the two gates.
        assert!(
            coordinator
                .approve_change_set(
                    id.clone(),
                    "home".to_owned(),
                    &human_approver("bob"),
                    digest,
                )
                .await
                .is_err(),
            "an expired change set must not be approvable"
        );
        assert!(
            coordinator
                .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
                .await
                .is_err()
        );
    }

    /// mecmcp-changeset v0.25.0 (MEC-525) freezes owner, device and digest at
    /// creation: `check_change_set_write` now refuses any write that changes
    /// them, so a plan can no longer move out from under an in-flight approval
    /// via `update_change_set_from` on the same id. That used to be caught one
    /// step later, at `approve_change_set`, by comparing the approval's digest
    /// against the (by-then-moved) stored one; this test pins the earlier,
    /// stronger refusal that replaced it -- restaging under an existing id
    /// with different actions is rejected before it ever reaches a digest an
    /// approver could race against. A caller that wants to change the plan
    /// must stage it under a new change_set_id instead.
    #[tokio::test]
    async fn restaging_an_existing_change_set_with_a_different_plan_is_refused() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let (id, original_digest) = (record.id.clone(), record.digest.clone());
        coordinator.insert_change_set(record).await.expect("insert");

        // Stage again: same change set, different plan, different digest.
        let stored = coordinator.change_set(&id, "home").await.expect("stored");
        let restaged = UnifiServer::with_plan(
            stored,
            &[
                StagedMutation::create("firewall_policy", serde_json::json!({ "name": "a" })),
                StagedMutation::create("firewall_policy", serde_json::json!({ "name": "b" })),
            ],
            &Preimage::from_resources(Vec::new()),
            "test",
        )
        .map_err(|_| "with_plan")
        .expect("replan");
        assert_ne!(restaged.digest, original_digest, "the plan moved");

        assert!(
            coordinator
                .update_change_set_from(ChangeSetState::Planned, restaged)
                .await
                .is_err(),
            "a change set's digest is fixed at creation; a moved plan must be staged \
             under a new change_set_id, not written over the old one"
        );
    }

    /// A lapsed pending set must not block a new one. The coordinator sweeps
    /// an expired record before its own guard looks, so reading the raw state
    /// would block a principal for having let a TTL elapse -- where the
    /// coordinator would have let them straight through.
    #[tokio::test]
    async fn a_lapsed_pending_set_does_not_block_a_new_change_set() {
        let coordinator = coordinator_at(None);
        let mut lapsed = planned_record("alice", "home", 300);
        lapsed.expires_at_unix = unix_seconds_now().saturating_sub(1);
        coordinator.insert_change_set(lapsed).await.expect("insert");

        // The coordinator itself accepts a second plan, having swept the first.
        coordinator
            .insert_change_set(planned_record("alice", "home", 300))
            .await
            .expect("the lapsed record must not block a new plan");
    }

    /// The gate the claim does not provide. `claim_change_set_for_apply`
    /// checks the state and not the clock, and `change_set_status` applies the
    /// approval TTL only to a `Planned` record -- so an ordinary two-person
    /// approval granted inside the window stays claimable indefinitely, which
    /// is what this asserts is no longer true of the record apply acts on.
    #[tokio::test]
    async fn an_approved_change_set_past_its_deadline_is_still_claimable_upstream() {
        let coordinator = coordinator_at(None);
        let mut record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        record.expires_at_unix = unix_seconds_now().saturating_add(2);
        coordinator.insert_change_set(record).await.expect("insert");
        coordinator
            .approve_change_set(
                id.clone(),
                "home".to_owned(),
                &human_approver("bob"),
                digest,
            )
            .await
            .expect("approved inside the window");

        // Move the deadline into the past, which is what the clock does on a
        // set left approved overnight.
        let mut approved = coordinator.change_set(&id, "home").await.expect("stored");
        approved.expires_at_unix = unix_seconds_now().saturating_sub(1);
        coordinator
            .update_change_set(approved)
            .await
            .expect("update");

        // Neither upstream gate refuses it...
        let status = coordinator
            .change_set_status(id.clone(), "home".to_owned())
            .await
            .expect("status");
        assert_eq!(
            status.state,
            ChangeSetState::Approved,
            "change_set_status retires Planned records only"
        );
        let claimed = coordinator
            .claim_change_set_for_apply(&id, "home", ApplyHandle::None)
            .await
            .expect("the claim checks the state, not the clock");

        // ...so the deadline on the claimed record is what apply has to read.
        assert!(
            unix_seconds_now() >= claimed.expires_at_unix,
            "the record apply acts on carries the lapsed deadline"
        );
    }

    /// The write path does not enforce the configured ceilings -- only
    /// `create_change_set` does, and this server cannot use it -- while the
    /// load path enforces a structural cap. Staging past the limit would
    /// persist and then refuse to reload, so it is refused at stage.
    #[test]
    fn an_oversized_plan_is_refused_before_it_is_stored() {
        let limit = crate::changeset_state::limits().max_actions_per_set;
        let staged: Vec<StagedMutation> = (0..=limit)
            .map(|n| StagedMutation::create("firewall_policy", serde_json::json!({ "name": n })))
            .collect();

        let record = UnifiServer::with_plan(
            planned_record("alice", "home", 300),
            &staged,
            &Preimage::from_resources(Vec::new()),
            "too much at once",
        )
        .map_err(|_| "with_plan")
        .expect("planning is not where it is refused");

        assert!(
            UnifiServer::check_plan_limits(&record).is_err(),
            "{} actions is over the {limit} the store accepts",
            staged.len()
        );
    }

    /// And a plan inside the ceiling is not.
    #[test]
    fn a_plan_within_the_limits_is_accepted() {
        let record = planned_record("alice", "home", 300);
        assert!(UnifiServer::check_plan_limits(&record).is_ok());
    }

    /// The window runs from when the plan was written, so approving does not
    /// restart it. That is what makes `--approval-timeout-secs` bound the age
    /// of the pre-image the plan was built against, and it is a shorter window
    /// than the code this replaces enforced -- worth pinning rather than
    /// rediscovering.
    #[tokio::test]
    async fn approval_does_not_restart_the_window() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        let planned_deadline = record.expires_at_unix;
        coordinator.insert_change_set(record).await.expect("insert");

        coordinator
            .approve_change_set(
                id.clone(),
                "home".to_owned(),
                &human_approver("bob"),
                digest,
            )
            .await
            .expect("approve");

        let approved = coordinator.change_set(&id, "home").await.expect("stored");
        assert_eq!(
            approved.expires_at_unix, planned_deadline,
            "the deadline is stamped at creation and approval must not move it"
        );
    }

    /// One pending change set per principal per controller. A second create is
    /// refused until the first reaches an outcome, which is a behaviour change
    /// from the map-backed store.
    #[tokio::test]
    async fn a_second_pending_change_set_on_one_controller_is_refused() {
        let coordinator = coordinator_at(None);
        coordinator
            .insert_change_set(planned_record("alice", "home", 300))
            .await
            .expect("the first plan is accepted");

        assert!(
            coordinator
                .insert_change_set(planned_record("alice", "home", 300))
                .await
                .is_err(),
            "one pending change set per principal per controller"
        );

        // Another controller is a different plan, and another principal is a
        // different queue.
        coordinator
            .insert_change_set(planned_record("alice", "office", 300))
            .await
            .expect("a different controller is a different plan");
        coordinator
            .insert_change_set(planned_record("bob", "home", 300))
            .await
            .expect("a different principal has their own");
    }

    /// A change set is addressed by `(id, controller)`. Naming another
    /// controller must not reach it: its resource ids mean nothing there.
    #[tokio::test]
    async fn a_change_set_is_not_reachable_from_another_controller() {
        let coordinator = coordinator_at(None);
        let record = planned_record("alice", "home", 300);
        let id = record.id.clone();
        coordinator.insert_change_set(record).await.expect("insert");

        assert!(coordinator.change_set(&id, "home").await.is_ok());
        assert!(
            coordinator.change_set(&id, "office").await.is_err(),
            "a set planned against one controller must not be readable from another"
        );
    }

    /// Guards against a handler being reduced to a stub again.
    ///
    /// Phase 6 shipped the seven change-set tools as honest refusals before
    /// they were wired to the machinery. That was the correct interim state,
    /// but it must not silently return: a stubbed handler advertises a tool
    /// that cannot do its job. This asserts the refusal literal is absent
    /// from the handler code, so re-stubbing one fails the test run.
    #[test]
    fn no_change_set_handler_is_a_stub() {
        let source = include_str!("mod.rs");
        let handlers = source
            .split("#[cfg(test)]")
            .next()
            .expect("source has a non-test prefix");
        // Assembled at runtime so this assertion cannot match itself.
        let needle = ["not", "yet", "implemented"].join(" ");
        assert!(
            !handlers.contains(&needle),
            "a change-set handler still returns the {needle:?} refusal; \
             Phase 6 requires all seven wired to the change-set machinery"
        );
        for tool in WRITE_TOOLS {
            assert!(
                source.contains(tool),
                "write tool {tool} has no handler in this module"
            );
        }
    }

    /// A controller `client_for` can build a client for, but that this test
    /// never actually reaches: every mutation below is refused before the
    /// first controller read.
    fn controller_registry() -> Arc<ControllerRegistry> {
        let mut key = tempfile::NamedTempFile::new().expect("create api key file");
        std::io::Write::write_all(&mut key, b"dummy-api-key\n").expect("write api key");
        std::io::Write::flush(&mut key).expect("flush api key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key.path(), std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }
        let key_path = key.into_temp_path().keep().expect("persist api key file");

        let mut controllers = tempfile::NamedTempFile::new().expect("create controllers file");
        let body = format!(
            r#"{{"version":1,"devices":{{"home":{{"endpoint":"https://unifi.example.org","site":"default","api_key_file":"{}","allow_private_api":true}}}}}}"#,
            key_path.display()
        );
        std::io::Write::write_all(&mut controllers, body.as_bytes())
            .expect("write controllers file");
        std::io::Write::flush(&mut controllers).expect("flush controllers file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(controllers.path(), std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }

        Arc::new(ControllerRegistry::load(controllers.path()).expect("load controllers"))
    }

    /// A `Planned` record carrying a `device` update -- the same shape
    /// `unifi_stage_change` already refuses to create, which is exactly why
    /// this cannot be built through the tool API. It stands in for a plan
    /// staged before this check existed, or built by an older binary and
    /// loaded back from `--state-file`.
    fn device_update_record(owner: &str, controller: &str, ttl: u64) -> ChangeSetRecord {
        let record = ChangeSetRecord {
            id: crate::changeset_state::new_change_set_id(),
            owner: owner.to_owned(),
            device: controller.to_owned(),
            expected_candidate_fingerprint: String::new(),
            actions: Vec::new(),
            digest: String::new(),
            state: ChangeSetState::Planned,
            approver: None,
            approval: None,
            expires_at_unix: unix_seconds_now().saturating_add(ttl),
            operation_id: None,
            policy_signature: String::new(),
            targets: Vec::new(),
            preview: None,
            task_id: None,
            apply_without_handle: false,
            owner_subject: None,
        };
        let staged = vec![StagedMutation::update(
            "device",
            "abc123",
            serde_json::json!({ "name": "renamed-ap" }),
        )];
        UnifiServer::with_plan(
            record,
            &staged,
            &Preimage::from_resources(Vec::new()),
            "test",
        )
        .map_err(|_| "with_plan refused a device-update record")
        .expect("with_plan plans a mutation check_writable_fields will separately refuse")
    }

    /// Drive one tool call over an in-process transport, the way a real MCP
    /// client would.
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
                rmcp::model::CallToolRequestParams::new(tool.to_owned())
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

    /// Staging and `unifi_validate_change_set` both refuse a `device`
    /// mutation, which is exactly why a plan carrying one can only reach
    /// `Approved` by being seeded directly -- the scenario `--state-file`
    /// makes real. `unifi_apply_change_set` must refuse it too, settle the
    /// record to `Failed` rather than leave it stuck `Applying`, and refuse
    /// it *before* the controller is ever contacted: the controller endpoint
    /// here is a placeholder no test in this module can reach, so any
    /// outcome other than the writable-field refusal below would mean the
    /// check ran too late.
    #[tokio::test]
    async fn apply_refuses_a_seeded_device_update_with_no_controller_call() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let coordinator = coordinator_at(None);
        let record = device_update_record("alice", "home", 300);
        let (id, digest) = (record.id.clone(), record.digest.clone());
        coordinator.insert_change_set(record).await.expect("insert");
        coordinator
            .approve_change_set(
                id.clone(),
                "home".to_owned(),
                &human_approver("bob"),
                digest,
            )
            .await
            .expect("a second principal approves");

        let server = UnifiServer::new(
            controller_registry(),
            true,
            coordinator.clone(),
            None,
            mecmcp_audit::DirectCommitPolicy::new(false),
        )
        .expect("server");

        let refused = call(
            server,
            "unifi_apply_change_set",
            serde_json::json!({"controller": "home", "change_set_id": id}),
        )
        .await;
        let error = refused.expect_err("a device write has no verified route");
        assert!(error.contains("device"), "{error}");

        let settled = coordinator
            .change_set(&id, "home")
            .await
            .expect("the record must still be readable");
        assert_eq!(
            settled.state,
            ChangeSetState::Failed,
            "a claim that never wrote anything must not be left Applying"
        );
    }
}
