//! `rustunifimcp` — enterprise MCP server for UniFi Network.

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use mecmcp_audit::AuditFileSink;
use mecmcp_auth::ScopeSet;
use mecmcp_runtime::cli::{Command, TokenAction};
use mecmcp_secret::validate::{CredentialFileRole, CredentialFileSpec, validate_credential_files};
use mecmcp_transport::serve_router;
use rmcp::ServiceExt;
use rustunifimcp::cli::{TokenCli, TokenCommand, UnifiCli};
use rustunifimcp::grant::UnifiGrant;
use rustunifimcp::http_transport::build_http_router;
use rustunifimcp::server::UnifiServer;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// The two tools whose combination on one token defeats two-person control:
/// a token holding both could stage and approve the same change set.
///
/// Refused here at issuance. `UnifiServer::holds_combined_two_person_control_scope`
/// re-checks the same combination at call time, because a token store loaded
/// from a hand-edited file never went through this check at all.
const TWO_PERSON_CONTROL_TOOLS: (&str, &str) = ("unifi_stage_change", "unifi_approve_change_set");

/// Refuse minting or widening a token whose tool scope would combine both
/// change-set control tools.
///
/// # Errors
/// Returns an error naming both tools if `tools` contains both.
fn reject_combined_two_person_control_scope(tools: &[String]) -> Result<()> {
    let (stage, approve) = TWO_PERSON_CONTROL_TOOLS;
    let has = |name: &str| tools.iter().any(|t| t == name);
    if has(stage) && has(approve) {
        bail!(
            "refusing to grant a token both `{stage}` and `{approve}`: two-person control \
             requires the staging and approving tokens to differ. Issue separate tokens."
        );
    }
    Ok(())
}

/// Refuse a token command that would mint or widen a token combining both
/// change-set control scopes.
///
/// This is the single point `run_inner` calls before dispatching a `token`
/// subcommand, so a test driving it through [`TokenCli::parse_from`] exercises
/// exactly the check that stands between argv and the token store -- including
/// clap's comma-splitting of `--tools` -- rather than the helper function in
/// isolation.
///
/// # Errors
/// As [`reject_combined_two_person_control_scope`].
fn validate_token_command(command: &TokenCommand) -> Result<()> {
    match command {
        TokenCommand::Add {
            allow_self_approval: true,
            ..
        }
        | TokenCommand::SetScope {
            allow_self_approval: true,
            ..
        } => Ok(()),
        TokenCommand::Add { tools, .. } => reject_combined_two_person_control_scope(tools),
        TokenCommand::SetScope {
            tools: Some(tools), ..
        } => reject_combined_two_person_control_scope(tools),
        _ => Ok(()),
    }
}

/// Parse `--sites` into a [`UnifiGrant`].
///
/// A single `*` means every site (`ScopeSet::Wildcard`); anything else is an
/// exact allowlist. Mirrors `mecmcp_runtime::token_cmd`'s private
/// `parse_scope`, which this crate cannot call directly because it is not
/// exported -- the two must be kept in agreement by hand.
///
/// # Errors
/// Returns an error if `values` is empty, or mixes `*` with exact names.
fn parse_sites(values: Vec<String>) -> Result<UnifiGrant> {
    if values.is_empty() {
        bail!("--sites requires at least one site identifier or '*'");
    }
    if values.iter().any(|v| v == "*") {
        if values.len() != 1 {
            bail!("--sites '*' cannot be mixed with exact site identifiers");
        }
        return Ok(UnifiGrant {
            sites: ScopeSet::Wildcard,
        });
    }
    Ok(UnifiGrant {
        sites: ScopeSet::Allowlist(values),
    })
}

/// Convert `TokenCommand` to `TokenAction`, building a [`UnifiGrant`] from
/// `--sites` when the command carries one.
///
/// `--sites` is omitted on `revoke`, `list`, and `rotate` -- those never mint
/// or widen a grant, so there is nothing to parse. Omitting it on `add` or
/// `set-scope` yields `None`: a grantless new token (unrestricted by site,
/// the pre-MEC-508 default) or, on `set-scope`, no change to the token's
/// existing grant (`TokenStoreFile::set_scopes` keeps a `None` grant as "no
/// change", never as "clear").
///
/// # Errors
/// Returns an error if `--sites` fails to parse (see [`parse_sites`]).
fn token_command_to_action(command: TokenCommand) -> Result<(TokenAction, Option<UnifiGrant>)> {
    match command {
        TokenCommand::Add {
            tokens_file,
            name,
            devices,
            tools,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            oidc_issuer,
            oidc_subject,
            allow_self_approval: _,
            sites,
            server_pid,
        } => {
            let grant = sites.map(parse_sites).transpose()?;
            Ok((
                TokenAction::Add {
                    tokens_file,
                    name,
                    devices,
                    tools,
                    provider,
                    provider_tier,
                    on_behalf_of,
                    actor_type,
                    oidc_issuer,
                    oidc_subject,
                    server_pid,
                },
                grant,
            ))
        }
        TokenCommand::Revoke {
            tokens_file,
            name,
            server_pid,
        } => Ok((
            TokenAction::Revoke {
                tokens_file,
                name,
                server_pid,
            },
            None,
        )),
        TokenCommand::List { tokens_file } => Ok((TokenAction::List { tokens_file }, None)),
        TokenCommand::Rotate {
            tokens_file,
            name,
            server_pid,
        } => Ok((
            TokenAction::Rotate {
                tokens_file,
                name,
                server_pid,
            },
            None,
        )),
        TokenCommand::SetScope {
            tokens_file,
            name,
            devices,
            tools,
            yes,
            allow_self_approval: _,
            sites,
            server_pid,
        } => {
            let grant = sites.map(parse_sites).transpose()?;
            Ok((
                TokenAction::SetScopes {
                    tokens_file,
                    name,
                    devices,
                    tools,
                    yes,
                    server_pid,
                },
                grant,
            ))
        }
    }
}

/// Install a minimal audit subscriber for token operations.
///
/// Token commands are dispatched before the server's full `init_audit`, so
/// without a subscriber every token mutation — a mint, a revoke, a privilege
/// widening — is written to disk having left no record. A pre-existing
/// subscriber already installed is not an error worth refusing a token
/// operation over.
fn init_token_audit() {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::{EnvFilter, filter::filter_fn, fmt};

    // Two layers, each with its own filter, because the audit record must not
    // be reachable by RUST_LOG at all.
    //
    // Adding `audit=info` to the env filter is not enough: `EnvFilter` picks
    // the most specific matching directive, so a field-specific value such as
    // `audit[{tool}]=off` still wins over a target-only one. Measured — the
    // widening applied and stderr stayed empty:
    //
    //     RUST_LOG=audit=off            audit lines: 1
    //     RUST_LOG=audit[{tool}]=off    audit lines: 0   <- silent widening
    //
    // So the audit layer carries a plain predicate instead, which no
    // environment variable participates in.
    let audit_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(filter_fn(|metadata| metadata.target() == "audit"));

    // Everything else follows RUST_LOG as usual, minus the audit target so a
    // permissive filter cannot print the record twice.
    let general_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_filter(filter_fn(|metadata| metadata.target() != "audit"));

    let _ = tracing_subscriber::registry()
        .with(audit_layer)
        .with(general_layer)
        .try_init();
}

/// Pre-provision the audit HMAC key file at `path` if it is absent or empty,
/// mirroring `packaging/lxc/install.sh`'s own key-generation step so every
/// entry point -- LXC install, systemd start, or a container's first run --
/// converges on the same keyed-audit posture instead of only the LXC path
/// doing it (mecmcp#376 / MEC-978). `--audit-redact` still defaults to empty
/// (redaction stays opt-in), so this alone does not turn redaction on; it
/// just means the key is already there the moment an operator flips
/// `--audit-redact ...=hmac` on, instead of failing on that first restart.
///
/// A zero-byte key file is indistinguishable from "never generated" and
/// would make every HMAC output constant, so rewriting it here is a repair,
/// not data loss. A non-empty file is never rotated -- that would silently
/// break verification of every audit record signed under the old key.
fn ensure_audit_hmac_key(path: &std::path::Path) -> Result<()> {
    if std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        return Ok(());
    }

    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| {
        anyhow::anyhow!("generating audit HMAC key: OS entropy source unavailable: {e}")
    })?;
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating audit HMAC key file {}", path.display()))?;
        use std::io::Write as _;
        file.write_all(hex_key.as_bytes())
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &hex_key)
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }

    Ok(())
}

/// Install the server's audit subscriber: stderr, an optional audit-file
/// sink, and optional journald — configured from the shared `--audit-*`
/// flags, the same way every sibling mecmcp server wires them.
///
/// The returned `AuditFileSink` can be used to reopen the file on SIGHUP
/// for log rotation.
///
/// # Errors
///
/// Returns an error when `--audit-redact` does not parse, or when
/// `mecmcp_audit::init_tracing` could not open a configured audit file or
/// construct the journald layer. Both are propagated with `?` rather than
/// logged and ignored, because a server that starts anyway is a server that
/// runs with no audit trail while believing -- and telling nobody -- that it
/// has one.
fn init_audit(
    args: &mecmcp_runtime::cli::Cli,
) -> Result<Option<Arc<AuditFileSink>>, anyhow::Error> {
    if let Some(key_path) = args.audit_hmac_key_file.as_deref() {
        ensure_audit_hmac_key(key_path).context("pre-provisioning audit HMAC key file")?;
    }

    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    // This binary does not build mecmcp-audit's `otel` feature, so exporting
    // is not possible; fail startup rather than hardcoding `otel: None` below
    // and silently dropping the operator's requested export.
    if args.otel_endpoint.is_some() {
        anyhow::bail!(
            "--otel-endpoint requires a build of rustunifimcp with mecmcp-audit's `otel` \
             feature, which this binary does not enable"
        );
    }
    let audit_config = mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
        otel: None,
    };

    match mecmcp_audit::init_tracing(&audit_config) {
        Ok(Some(sink)) => Ok(Some(Arc::new(sink))),
        Ok(None) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("initializing audit tracing: {e}")),
    }
}

/// Load `--approval-digest-key-file`, if set.
///
/// `None` keeps the change-set coordinator on the unkeyed v5 approval
/// digest. A load error is a hard startup failure, not a fallback to
/// unkeyed.
fn load_approval_digest_key(
    path: Option<&std::path::Path>,
) -> Result<Option<mecmcp_changeset::ApprovalDigestKey>> {
    path.map(|path| {
        mecmcp_changeset::ApprovalDigestKey::load_from_file(path)
            .with_context(|| format!("loading --approval-digest-key-file {}", path.display()))
    })
    .transpose()
}

/// Token store the HTTP listener will load.
///
/// Stdio does not consult `--tokens-file`. The container entrypoint bakes
/// that flag in, and a stdio start must not fail because the bearer store
/// is absent.
fn listener_tokens(cli: &UnifiCli) -> Option<&Path> {
    match cli.common.transport {
        mecmcp_runtime::cli::Transport::Stdio => None,
        mecmcp_runtime::cli::Transport::StreamableHttp => cli.common.tokens_file.as_deref(),
    }
}

/// Files whose mode is checked together, before any of them is loaded.
///
/// A startup that checks one file and exits reports the next bad mode only
/// on the next restart. [`validate_startup_credentials`] asks `mecmcp-secret`
/// to report every offender in this list at once.
struct StartupCredentialFiles<'a> {
    /// Controller inventory. Required. Checked as owner-only, the same
    /// ceiling the inventory loader enforces.
    controllers: &'a Path,
    /// Bearer-token store this process will load. Required when set. Never
    /// resolved through an `/etc` fallback: this server shipped the
    /// `/var/lib` path only.
    tokens: Option<&'a Path>,
    /// Audit HMAC key. Required when set; the caller creates a missing key first.
    audit_hmac_key: Option<&'a Path>,
    /// Approval digest key from `--approval-digest-key-file`. Required when set.
    approval_digest_key: Option<&'a Path>,
}

/// Check every credential-adjacent file in one pass.
///
/// On-disk paths are unchanged. The inventory path is whatever
/// `--controllers-file` names, each API key path is the one that inventory
/// names, and the token path is `--tokens-file` exactly, with no second
/// location.
///
/// # Errors
/// Returns an error naming every file whose mode, owner, or presence failed
/// its role. A missing API key file is not an error.
fn validate_startup_credentials(files: &StartupCredentialFiles<'_>) -> Result<()> {
    let inspected = inspect_controllers(files.controllers);
    let mut specs = Vec::with_capacity(4 + inspected.api_key_files.len());
    specs.push(CredentialFileSpec {
        path: files.controllers,
        role: CredentialFileRole::Secret,
        description: "controller inventory",
        required: true,
    });
    for path in &inspected.api_key_files {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "UniFi API key",
            required: false,
        });
    }
    if let Some(path) = files.tokens {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "bearer token store",
            required: true,
        });
    }
    if let Some(path) = files.audit_hmac_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "audit HMAC key",
            required: true,
        });
    }
    if let Some(path) = files.approval_digest_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "approval digest key",
            required: true,
        });
    }

    validate_credential_files(&specs)?;
    Ok(())
}

/// API-key paths read from one inventory file.
struct InspectedControllers {
    api_key_files: Vec<PathBuf>,
}

/// Collect the API key paths `controllers.json` names.
///
/// A missing, unreadable, oversized, or unparseable file yields no paths.
/// The inventory itself is still checked as owner-only by the caller.
fn inspect_controllers(path: &Path) -> InspectedControllers {
    let limit = mecmcp_secret::FileLimits::default().max_bytes;
    let bytes = match std::fs::metadata(path) {
        Ok(metadata) if metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX) => {
            return InspectedControllers {
                api_key_files: Vec::new(),
            };
        }
        Ok(_) => match std::fs::read(path) {
            Ok(bytes) if bytes.len() <= limit => bytes,
            _ => {
                return InspectedControllers {
                    api_key_files: Vec::new(),
                };
            }
        },
        Err(_) => {
            return InspectedControllers {
                api_key_files: Vec::new(),
            };
        }
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return InspectedControllers {
            api_key_files: Vec::new(),
        };
    };
    let mut api_key_files = Vec::new();
    collect_api_key_files(&value, &mut api_key_files);
    InspectedControllers { api_key_files }
}

fn collect_api_key_files(value: &serde_json::Value, found: &mut Vec<PathBuf>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                if key.eq_ignore_ascii_case("api_key_file") {
                    push_unique_path(found, child);
                }
                collect_api_key_files(child, found);
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                collect_api_key_files(child, found);
            }
        }
        _ => {}
    }
}

fn push_unique_path(found: &mut Vec<PathBuf>, value: &serde_json::Value) {
    let Some(path) = value.as_str() else {
        return;
    };
    if path.is_empty() {
        return;
    }
    let path = PathBuf::from(path);
    if !found.iter().any(|existing| existing == &path) {
        found.push(path);
    }
}

/// A token-mutation audit record, built before the mutation and emitted after.
///
/// The scope has to be captured up front because [`TokenAction`] is consumed by
/// the runtime call, but the record must not be written until the outcome is
/// known. Emitting on the way in produced audit lines asserting a credential
/// had been minted when the store write had in fact failed.
struct PendingTokenAudit {
    /// Stable operation identifier, e.g. `token_add`.
    operation: &'static str,
    /// Audit name of the token acted on.
    token_name: String,
    /// Requested controller scope, where the action carries one.
    devices: Option<Vec<String>>,
    /// Requested tool scope, where the action carries one.
    tools: Option<Vec<String>>,
    /// Whether the named token was in the store beforehand.
    ///
    /// `None` where the question does not apply (a mint). For the operations
    /// that address an existing token, this is what separates a real change
    /// from a no-op: the runtime returns `Ok(())` either way and reports the
    /// no-op only on stderr, so without this the audit trail would record a
    /// revocation of a token that was never there.
    target_existed: Option<bool>,
}

/// The outcome word for a token mutation that returned `Ok`.
///
/// `Ok` alone does not mean the store changed: revoking a name that is not
/// present succeeds and reports the no-op only on stderr. `target_existed` is
/// `None` where presence is not the question (a mint) or could not be read, and
/// those are reported as succeeded rather than silently downgraded.
fn success_outcome_word(target_existed: Option<bool>) -> &'static str {
    match target_existed {
        Some(false) => "no_op",
        _ => "succeeded",
    }
}

/// Whether `name` is present in the token store at `path`.
///
/// Reads only the `name` field of each entry; digests and secrets are never
/// touched. Returns `None` when the store cannot be read or parsed, so an
/// unreadable store is reported as unknown rather than as absence.
fn token_name_present(path: &std::path::Path, name: &str) -> Option<bool> {
    let raw = std::fs::read_to_string(path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let entries = parsed.get("tokens")?.as_array()?;
    Some(
        entries
            .iter()
            .any(|entry| entry.get("name").and_then(serde_json::Value::as_str) == Some(name)),
    )
}

impl PendingTokenAudit {
    /// Describe a mutating token action, or `None` for read-only ones.
    fn describe(action: &TokenAction) -> Option<Self> {
        match action {
            TokenAction::Add {
                name,
                devices,
                tools,
                ..
            } => Some(Self {
                operation: "token_add",
                token_name: name.clone(),
                devices: Some(devices.clone()),
                tools: Some(tools.clone()),
                target_existed: None,
            }),
            TokenAction::Revoke {
                name, tokens_file, ..
            } => Some(Self {
                operation: "token_revoke",
                token_name: name.clone(),
                devices: None,
                tools: None,
                target_existed: token_name_present(tokens_file, name),
            }),
            TokenAction::Rotate {
                name, tokens_file, ..
            } => Some(Self {
                operation: "token_rotate",
                token_name: name.clone(),
                devices: None,
                tools: None,
                target_existed: token_name_present(tokens_file, name),
            }),
            TokenAction::SetScopes {
                name,
                devices,
                tools,
                tokens_file,
                ..
            } => Some(Self {
                operation: "token_set_scope",
                token_name: name.clone(),
                devices: devices.clone(),
                tools: tools.clone(),
                target_existed: token_name_present(tokens_file, name),
            }),
            TokenAction::SetProvenance {
                name, tokens_file, ..
            } => Some(Self {
                operation: "token_set_provenance",
                token_name: name.clone(),
                devices: None,
                tools: None,
                target_existed: token_name_present(tokens_file, name),
            }),
            // Read-only: nothing changes, so there is nothing to attest to.
            TokenAction::List { .. } => None,
        }
    }

    /// Emit the record, carrying whether the mutation actually took effect.
    ///
    /// The failure branch records the error text so an auditor can tell a
    /// rejected mint from one that never reached the store. Scope fields are
    /// emitted only for the operations that carry scope, so a revoke does not
    /// render an empty device list that reads like a scope of nothing.
    fn emit<T, E: std::fmt::Display>(&self, outcome: Result<&T, &E>) {
        let (operation, token_name) = (self.operation, self.token_name.as_str());
        let applied = success_outcome_word(self.target_existed);
        let message = if applied == "no_op" {
            "token mutation matched no token"
        } else {
            "token mutation applied"
        };
        match (outcome, self.devices.as_deref(), self.tools.as_deref()) {
            (Ok(_), Some(devices), Some(tools)) => tracing::info!(
                target: "audit",
                operation,
                token_name,
                devices = ?devices,
                tools = ?tools,
                outcome = applied,
                message
            ),
            (Ok(_), _, _) => tracing::info!(
                target: "audit",
                operation,
                token_name,
                outcome = applied,
                message
            ),
            (Err(error), Some(devices), Some(tools)) => tracing::warn!(
                target: "audit",
                operation,
                token_name,
                devices = ?devices,
                tools = ?tools,
                outcome = "failed",
                error = %error,
                "token mutation failed"
            ),
            (Err(error), _, _) => tracing::warn!(
                target: "audit",
                operation,
                token_name,
                outcome = "failed",
                error = %error,
                "token mutation failed"
            ),
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Fatal: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    run_inner().await.map_err(Into::into)
}

async fn run_inner() -> Result<()> {
    // Install crypto provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    // Dispatch token commands before parsing UnifiCli.
    //
    // This keeps grant-specific flags (--devices, --tools) off the server's help
    // and allows them to appear after the subcommand where they belong. The
    // flattened Cli still declares its own `token` subcommand, but TokenCli owns
    // the complete token surface including --help when argv names `token`.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("token") {
        // Build args for TokenCli: [program_name, add/revoke/list/rotate, ...]
        // Skip "token" at index 1 since TokenCli expects the subcommand directly.
        let token_args = std::iter::once(args[0].clone())
            .chain(args.iter().skip(2).cloned())
            .collect::<Vec<_>>();
        let token_cli = TokenCli::parse_from(token_args);

        validate_token_command(&token_cli.command)?;

        // Install a subscriber before dispatching. `run_with_grant` emits the
        // scope change as a `target: "audit"` event, and this path returns
        // long before the server's normal tracing init, so without one every token
        // mutation — a mint, a revoke, a privilege widening — is written to
        // disk having left no record that it happened.
        //
        // Deliberately minimal: the token CLI carries no audit flags, so there
        // is no log file, journald sink, or redaction policy to honour. The
        // operator running the command is the audience, and stderr is where
        // they are looking.
        init_token_audit();

        let (action, grant) = token_command_to_action(token_cli.command)?;

        // Describe the mutation now, emit the record after it runs.
        //
        // These records are the forensic trail for credential issuance. Emitting
        // them before execution logged "token minted" in the past tense for
        // mints that then failed -- an observed case wrote that line while the
        // store write returned ENOENT, leaving the audit trail asserting a
        // credential that does not exist. The scope is captured up front
        // because the action is consumed by the call; the outcome is attached
        // afterwards.
        let pending = PendingTokenAudit::describe(&action);

        let outcome = mecmcp_runtime::token_cmd::run_with_grant::<UnifiGrant>(
            action,
            &[],
            rustunifimcp_core::tools::TOOL_NAMES,
            grant,
        )
        .map_err(|error| anyhow::anyhow!("{error}"));

        if let Some(pending) = pending {
            pending.emit(outcome.as_ref());
        }

        return outcome;
    }

    let mut cli = UnifiCli::parse();

    if let Some(Command::Token { .. }) = cli.common.command.take() {
        // This path fires when a server flag precedes the subcommand
        // (e.g., `--controllers-file X token add ...`). The early dispatch at argv[1]
        // does not intercept it, so TokenCli's grant-specific flags (--devices,
        // --tools) are unavailable. Refuse rather than silently minting a
        // grantless token.
        bail!(
            "token subcommand must appear before server flags; use: \
             rustunifimcp token add [options]"
        );
    }

    // Validate the listener arguments before anything reads a file.
    //
    // This server used to skip the shared validator entirely. The listener
    // still refused the bind -- `mecmcp_transport::serve_router` owns that
    // check -- but the refusal surfaced as `Fatal: failed to serve HTTP
    // router`, with the reason discarded. An operator had no path from that
    // string to "add --allowed-origin".
    //
    // Position matters as much as the call. Every other file this binary opens
    // is read below, so validating here means an argument mistake is reported
    // as an argument mistake. Previously the controllers file and the token
    // file were both parsed first, so a wrong file mode or a malformed token
    // store masked the CLI error entirely -- the opposite order from the rest
    // of the family. See mecmcp#358.
    mecmcp_runtime::cli_validate::validate(&cli.common)
        .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;

    // The systemd unit passes --audit-format/--audit-log-file/--audit-journald
    // unconditionally, and until now nothing here consumed them: the server
    // parsed the flags and ran with no audit subscriber and no audit file,
    // silently. Fail closed instead -- `init_audit` itself refuses rather
    // than starting with a configured audit file it could not open, and `?`
    // here means this server does the same rather than swallowing that error
    // and running unaudited.
    let audit_sink = init_audit(&cli.common)?;

    if cli.lab_mode() {
        tracing::warn!(
            target: "audit",
            "Running in lab mode — two-person control disabled"
        );
    }

    // Direct-commit tools (unifi_device_action's `restart`, unifi_client_action's
    // `block`/`unblock`/`reconnect`) mutate a device or client in one call with no
    // change-set approval. Refused by default; logging here mirrors the lab-mode
    // banner above.
    let direct_commit = mecmcp_audit::DirectCommitPolicy::new(cli.allow_direct_commit);
    direct_commit.log_startup("rustunifimcp");
    if !cli.allow_direct_commit {
        tracing::info!(
            "direct-commit tools disabled: unifi_device_action's restart and \
             unifi_client_action's block/unblock/reconnect are refused on stdio and HTTP \
             alike. Use --allow-direct-commit to enable them."
        );
    }

    // Warn if --state-file is not provided.
    if cli.state_file.is_none() {
        tracing::warn!(
            target: "audit",
            "No --state-file provided; change sets will live in memory only. \
             Every approval, preview, and in-flight apply will be lost on restart. \
             Pass --state-file to persist change-set state across restarts."
        );
    }

    // One pass over every credential-adjacent file. `init_audit` has already
    // created a missing HMAC key, so this sees the file the process will use.
    // Stdio does not consult `--tokens-file`: the image entrypoint always
    // passes it, and a stdio start must still succeed when that path is
    // absent. Tokens stay at the shipped `/var/lib/unifimcp/tokens.json`
    // path; this server has no `/etc` token store.
    validate_startup_credentials(&StartupCredentialFiles {
        controllers: &cli.controllers_file,
        tokens: listener_tokens(&cli),
        audit_hmac_key: cli.common.audit_hmac_key_file.as_deref(),
        approval_digest_key: cli.common.approval_digest_key_file.as_deref(),
    })
    .context("credential file validation")?;

    // Load registry.
    let registry = Arc::new(rustunifimcp_core::inventory::ControllerRegistry::load(
        &cli.controllers_file,
    )?);

    // Built before serving, and started eagerly, so a misconfigured pipeline
    // stops the server here rather than at the first change.
    let evidence = match cli.common.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            // aws-lc-rs, not ring: this workspace's rustls is built with that
            // provider, and the fleet is genuinely split.
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let transport = Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    cli.common.evidence.ca_file(),
                    provider,
                )
                .map_err(|e| anyhow::anyhow!("building the SSDF evidence transport: {e}"))?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(config, transport)
                    .map_err(|e| anyhow::anyhow!("starting the SSDF evidence pipeline: {e}"))?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };
    let recorder = evidence
        .as_ref()
        .map(mecmcp_audit::EvidenceService::recorder);
    // `recorder` is cloned into the server; the coordinator holds its own.
    let recorder_for_coordinator = recorder.clone();

    // Build the change-set coordinator.
    let approval_digest_key =
        load_approval_digest_key(cli.common.approval_digest_key_file.as_deref())?;
    let coordinator = rustunifimcp::changeset_state::build_coordinator(
        cli.state_file.as_deref(),
        std::time::Duration::from_secs(cli.approval_timeout_secs),
        cli.lab_mode(),
        recorder_for_coordinator,
        approval_digest_key,
    )
    .map_err(|e| anyhow::anyhow!("failed to initialize the change-set coordinator: {e}"))?;

    // Build server.
    let server = UnifiServer::new(
        Arc::clone(&registry),
        cli.lab_mode(),
        coordinator,
        recorder,
        direct_commit,
    )?;

    // Determine transport.
    let served = match cli.common.transport {
        mecmcp_runtime::cli::Transport::Stdio => {
            // SIGHUP reloads the inventory and rebuilds clients.
            // Clone the server for the reload handler; serve_stdio consumes the original.
            install_sighup_reload(registry, Some(server.clone()), None, audit_sink)?;
            serve_stdio(server).await
        }
        mecmcp_runtime::cli::Transport::StreamableHttp => {
            serve_http(server, &cli, registry, audit_sink).await
        }
    };

    // Dropping the service stops its worker but deliberately does not flush:
    // a `Drop` that performs network I/O turns an ordinary teardown into an
    // unpredictable stall. Only `shutdown` closes and spools what the recorder
    // still holds, and only `apply_intent` and `result_receipt` flush on their
    // own -- so without this a proposal or an approval not followed by an apply
    // is lost at exit. Runs on the error path too, and the serving result is
    // what is returned either way.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

/// Load TLS configuration for the listener.
///
/// # Errors
///
/// Returns an error when:
/// - Only one of cert or key is provided (both or neither required)
/// - Certificate or key file cannot be read
/// - Certificate or key PEM is malformed
/// - Certificate and key are not a matching pair
fn load_listener_tls(args: &mecmcp_runtime::cli::Cli) -> Result<Option<Arc<rustls::ServerConfig>>> {
    // Validate that both or neither are provided.
    match (&args.tls_cert, &args.tls_key) {
        (Some(_), None) => bail!("--tls-cert provided without --tls-key"),
        (None, Some(_)) => bail!("--tls-key provided without --tls-cert"),
        (None, None) => Ok(None),
        (Some(cert), Some(key)) => {
            // The process-global provider is installed in `main`; do not install again —
            // `install_default` returns Err when one is already set, and treating that
            // as fatal would break every TLS start.
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            mecmcp_transport::load_tls(cert, key, Arc::new(provider))
                .context("loading listener TLS")
                .map(Some)
        }
    }
}

/// Install a SIGHUP handler that reloads configuration.
///
/// On SIGHUP:
/// - Controller inventory is reloaded from disk
/// - HTTP clients are rebuilt from the new inventory
/// - Token store is reloaded (HTTP mode only)
/// - Audit file is reopened if configured (for log rotation)
///
/// A reload failure logs at `warn` and retains the previous configuration rather
/// than terminating the running server.
///
/// # Errors
///
/// Returns error if the signal handler could not be registered.
/// One SIGHUP reload pass: reload the inventory, rebuild clients on success,
/// reload the token store, and reopen the audit file. Pulled out of the
/// closure `install_sighup_reload` hands to the signal handler so the
/// reopen branch is reachable without going through signal delivery.
fn perform_sighup_reload(
    registry: &rustunifimcp_core::inventory::ControllerRegistry,
    server: Option<&UnifiServer>,
    token_store: Option<&mecmcp_auth::TokenStoreFile<UnifiGrant>>,
    audit_sink: Option<&AuditFileSink>,
) {
    // Reload controller inventory.
    let registry_reloaded = match registry.reload() {
        Ok(count) => {
            tracing::info!(
                target: "audit",
                controllers = count,
                "controller inventory reloaded"
            );
            true
        }
        Err(error) => {
            tracing::warn!(
                target: "audit",
                %error,
                "controller inventory reload failed; retaining previous snapshot"
            );
            false
        }
    };

    // Rebuild clients if inventory reload succeeded.
    if registry_reloaded && let Some(srv) = server {
        match srv.rebuild_clients() {
            Ok(count) => {
                tracing::info!(
                    target: "audit",
                    clients = count,
                    "HTTP clients rebuilt from reloaded inventory"
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "audit",
                    %error,
                    "client rebuild failed; retaining previous clients"
                );
            }
        }
    }

    // Reload token store if present (HTTP mode only).
    if let Some(store) = token_store {
        match store.reload() {
            Ok(()) => {
                let count = store.store().len();
                tracing::info!(
                    target: "audit",
                    tokens = count,
                    "token store reloaded"
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "audit",
                    %error,
                    "token store reload failed; retaining previous snapshot"
                );
            }
        }
    }

    // Reopen audit file if configured (for lossless log rotation).
    if let Some(sink) = audit_sink {
        match sink.reopen() {
            Ok(()) => {
                tracing::info!(
                    target: "audit",
                    path = %sink.path().display(),
                    "audit file reopened"
                );
            }
            Err(error) => {
                tracing::warn!(
                    target: "audit",
                    %error,
                    path = %sink.path().display(),
                    "audit file reopen failed"
                );
            }
        }
    }
}

fn install_sighup_reload(
    registry: Arc<rustunifimcp_core::inventory::ControllerRegistry>,
    server: Option<UnifiServer>,
    token_store: Option<Arc<mecmcp_auth::TokenStoreFile<UnifiGrant>>>,
    audit_sink: Option<Arc<AuditFileSink>>,
) -> std::io::Result<()> {
    mecmcp_runtime::signals::install_hup_handler(move || {
        perform_sighup_reload(
            &registry,
            server.as_ref(),
            token_store.as_deref(),
            audit_sink.as_deref(),
        );
    })
}

async fn serve_stdio(handler: UnifiServer) -> Result<()> {
    tracing::info!("Starting MCP stdio service");

    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;

    service.waiting().await?;
    Ok(())
}

async fn serve_http(
    handler: UnifiServer,
    cli: &UnifiCli,
    registry: Arc<rustunifimcp_core::inventory::ControllerRegistry>,
    audit_sink: Option<Arc<AuditFileSink>>,
) -> Result<()> {
    // Load token store if provided.
    let token_store = if let Some(ref path) = cli.common.tokens_file {
        Some(Arc::new(mecmcp_auth::TokenStoreFile::load(path)?))
    } else {
        None
    };

    // Install SIGHUP handler that reloads inventory, rebuilds clients, and reloads token store.
    // Clone the handler for the reload callback; build_http_router consumes the original.
    install_sighup_reload(
        registry,
        Some(handler.clone()),
        token_store.clone(),
        audit_sink,
    )?;

    let limits = cli.limits.to_limits_config();
    limits
        .validate()
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    let shutdown = CancellationToken::new();
    let router = build_http_router(
        handler,
        token_store,
        cli.common.allowed_host.clone(),
        cli.common.allowed_origin.clone(),
        limits,
        cli.enable_metrics,
        cli.common.allow_insecure_bind,
        shutdown.clone(),
    )?;

    let bind_addr = format!("{}:{}", cli.common.host, cli.common.port).parse()?;

    // Load TLS config if provided.
    let tls_config = load_listener_tls(&cli.common).context("TLS configuration failed")?;

    // Remember whether TLS is enabled before moving tls_config.
    let is_tls = tls_config.is_some();

    // Attempt to bind and serve. Log intent first, then outcome after successful bind.
    if is_tls {
        tracing::info!(
            target: "audit",
            "attempting to bind HTTPS listener on {bind_addr}"
        );
    } else {
        tracing::info!(
            target: "audit",
            "attempting to bind plain HTTP listener on {bind_addr}"
        );
    }

    serve_router(
        router,
        bind_addr,
        tls_config,
        std::time::Duration::from_secs(30),
    )
    .await
    .context("failed to serve HTTP router")?;

    // This is reached only on graceful shutdown.
    if is_tls {
        tracing::info!(
            target: "audit",
            "HTTPS listener on {bind_addr} shut down"
        );
    } else {
        tracing::info!(
            target: "audit",
            "plain HTTP listener on {bind_addr} shut down"
        );
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_runtime::cli::Cli;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::NamedTempFile;

    /// Helper to generate a self-signed cert and key for testing.
    fn generate_test_cert() -> (String, String) {
        use rcgen::{CertificateParams, KeyPair};
        let key_pair = KeyPair::generate().unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.pem(), key_pair.serialize_pem())
    }

    /// Helper to write content to a temporary file and return its path.
    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    /// Helper to create a minimal Cli with optional TLS paths.
    fn make_cli(tls_cert: Option<PathBuf>, tls_key: Option<PathBuf>) -> Cli {
        use clap::Parser;

        let mut args: Vec<String> = vec![
            "rustunifimcp".to_string(),
            "--transport".to_string(),
            "streamable-http".to_string(),
            "--host".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "0".to_string(),
        ];

        if let Some(cert) = tls_cert {
            args.push("--tls-cert".to_string());
            args.push(cert.to_string_lossy().to_string());
        }
        if let Some(key) = tls_key {
            args.push("--tls-key".to_string());
            args.push(key.to_string_lossy().to_string());
        }

        Cli::try_parse_from(args).unwrap()
    }

    #[test]
    fn tls_cert_without_key_fails() {
        let (cert_pem, _) = generate_test_cert();
        let cert_file = write_temp_file(&cert_pem);

        let cli = make_cli(Some(cert_file.path().to_path_buf()), None);

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("--tls-cert provided without --tls-key")
        );
    }

    #[test]
    fn tls_key_without_cert_fails() {
        let (_, key_pem) = generate_test_cert();
        let key_file = write_temp_file(&key_pem);

        let cli = make_cli(None, Some(key_file.path().to_path_buf()));

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("--tls-key provided without --tls-cert")
        );
    }

    #[test]
    fn no_tls_args_returns_none() {
        let cli = make_cli(None, None);
        let result = load_listener_tls(&cli).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn valid_tls_cert_and_key_succeed() {
        let (cert_pem, key_pem) = generate_test_cert();
        let cert_file = write_temp_file(&cert_pem);
        let key_file = write_temp_file(&key_pem);

        let cli = make_cli(
            Some(cert_file.path().to_path_buf()),
            Some(key_file.path().to_path_buf()),
        );

        let result = load_listener_tls(&cli);
        assert!(result.is_ok());
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn malformed_cert_fails() {
        let key_pem = generate_test_cert().1;
        let cert_file = write_temp_file("not a valid PEM");
        let key_file = write_temp_file(&key_pem);

        let cli = make_cli(
            Some(cert_file.path().to_path_buf()),
            Some(key_file.path().to_path_buf()),
        );

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
    }

    /// No `--approval-digest-key-file` keeps the coordinator unkeyed, same as
    /// today.
    #[test]
    fn no_approval_digest_key_file_is_fine() {
        assert!(
            load_approval_digest_key(None)
                .expect("no path is not an error")
                .is_none()
        );
    }

    /// A valid key file is loaded and passed through to the coordinator,
    /// producing the current keyed approval digest rather than the unkeyed
    /// v5 one.
    #[test]
    fn a_valid_approval_digest_key_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"a-sufficiently-long-test-key-value").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let key = load_approval_digest_key(Some(&path))
            .expect("a valid key file must load")
            .expect("Some(path) must produce Some(key)");
        assert_eq!(&*key, b"a-sufficiently-long-test-key-value");
    }

    /// A key file that fails `mecmcp-changeset`'s checks (here: too short)
    /// must fail startup rather than falling back to running unkeyed.
    #[test]
    fn a_too_short_approval_digest_key_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"short").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let error = load_approval_digest_key(Some(&path))
            .expect_err("a too-short key file must be refused, not silently skipped");
        assert!(
            error.to_string().contains("approval-digest-key-file"),
            "{error}"
        );
    }

    /// A missing key file must fail startup rather than starting unkeyed.
    #[test]
    fn a_missing_approval_digest_key_file_fails_closed() {
        let error = load_approval_digest_key(Some(std::path::Path::new(
            "/nonexistent/does-not-exist/key",
        )))
        .expect_err("a missing key file must be refused, not silently skipped");
        assert!(
            error.to_string().contains("approval-digest-key-file"),
            "{error}"
        );
    }

    /// `--otel-endpoint` must refuse startup, since this binary does not
    /// support sending an OTel export.
    #[test]
    fn otel_endpoint_set_refuses_to_start() {
        let mut args = make_cli(None, None);
        args.otel_endpoint = Some("http://127.0.0.1:4318".to_owned());

        let error = init_audit(&args).expect_err("--otel-endpoint must be refused by this binary");
        assert!(error.to_string().contains("--otel-endpoint"), "{error}");
    }

    /// No `--otel-endpoint` keeps today's behaviour: audit initializes with
    /// `otel: None`.
    #[test]
    fn no_otel_endpoint_starts_normally() {
        let args = make_cli(None, None);
        init_audit(&args).expect("no --otel-endpoint must not be refused");
    }

    #[test]
    fn malformed_key_fails() {
        let cert_pem = generate_test_cert().0;
        let cert_file = write_temp_file(&cert_pem);
        let key_file = write_temp_file("not a valid PEM");

        let cli = make_cli(
            Some(cert_file.path().to_path_buf()),
            Some(key_file.path().to_path_buf()),
        );

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
    }

    #[test]
    fn mismatched_cert_and_key_fail() {
        let (cert_pem1, _) = generate_test_cert();
        let (_, key_pem2) = generate_test_cert();
        let cert_file = write_temp_file(&cert_pem1);
        let key_file = write_temp_file(&key_pem2);

        let cli = make_cli(
            Some(cert_file.path().to_path_buf()),
            Some(key_file.path().to_path_buf()),
        );

        let result = load_listener_tls(&cli);
        assert!(result.is_err());
    }

    #[test]
    fn token_command_to_action_add() {
        use std::path::PathBuf;
        let command = TokenCommand::Add {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            devices: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: None,
            oidc_issuer: None,
            oidc_subject: None,
            allow_self_approval: false,
            sites: None,
            server_pid: None,
        };

        let (action, grant) = token_command_to_action(command).expect("converts");
        assert!(grant.is_none());
        match action {
            TokenAction::Add {
                name,
                oidc_issuer,
                oidc_subject,
                ..
            } => {
                assert_eq!(name, "test");
                assert!(oidc_issuer.is_none());
                assert!(oidc_subject.is_none());
            }
            _ => panic!("expected TokenAction::Add"),
        }
    }

    /// `--sites` on `token add` must produce a grant restricting the new
    /// token to exactly the named sites -- the regression this issue exists
    /// for: a token scoped to one site must not be indistinguishable from an
    /// unrestricted one.
    #[test]
    fn token_command_to_action_add_with_sites_builds_a_grant() {
        use std::path::PathBuf;
        let command = TokenCommand::Add {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            devices: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: None,
            oidc_issuer: None,
            oidc_subject: None,
            allow_self_approval: false,
            sites: Some(vec!["site-a".to_string(), "site-b".to_string()]),
            server_pid: None,
        };

        let (_, grant) = token_command_to_action(command).expect("converts");
        let grant = grant.expect("--sites must produce a grant");
        assert_eq!(
            grant.sites,
            mecmcp_auth::ScopeSet::Allowlist(vec!["site-a".to_string(), "site-b".to_string()])
        );
    }

    /// `--sites '*'` mints a grant that permits every site -- distinct from
    /// omitting the flag (which mints a grantless token), but authorizing
    /// identically.
    #[test]
    fn token_command_to_action_add_with_wildcard_sites_builds_a_wildcard_grant() {
        use std::path::PathBuf;
        let command = TokenCommand::Add {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            devices: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: None,
            oidc_issuer: None,
            oidc_subject: None,
            allow_self_approval: false,
            sites: Some(vec!["*".to_string()]),
            server_pid: None,
        };

        let (_, grant) = token_command_to_action(command).expect("converts");
        let grant = grant.expect("--sites must produce a grant");
        assert_eq!(grant.sites, mecmcp_auth::ScopeSet::Wildcard);
    }

    /// `*` mixed with exact site names is refused -- the same rule
    /// `mecmcp_runtime::token_cmd`'s `parse_scope` enforces for devices/tools,
    /// kept consistent here by hand since that function is not exported.
    #[test]
    fn token_command_to_action_add_rejects_wildcard_mixed_with_exact_sites() {
        use std::path::PathBuf;
        let command = TokenCommand::Add {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            devices: vec!["*".to_string()],
            tools: vec!["*".to_string()],
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: None,
            oidc_issuer: None,
            oidc_subject: None,
            allow_self_approval: false,
            sites: Some(vec!["*".to_string(), "site-a".to_string()]),
            server_pid: None,
        };

        assert!(token_command_to_action(command).is_err());
    }

    /// A token minted with both `unifi_stage_change` and
    /// `unifi_approve_change_set` in its tool scope could stage and approve
    /// the same change set alone, defeating two-person control. Issuance
    /// must refuse it rather than depend on the operational convention in
    /// CLAUDE.md that nothing enforced.
    #[test]
    fn minting_a_token_with_both_changeset_control_scopes_is_refused() {
        let error = reject_combined_two_person_control_scope(&[
            "unifi_stage_change".to_string(),
            "unifi_approve_change_set".to_string(),
        ])
        .expect_err("both scopes on one token must be refused");
        let message = error.to_string();
        assert!(message.contains("unifi_stage_change"), "{message}");
        assert!(message.contains("unifi_approve_change_set"), "{message}");
    }

    /// Holding only one of the two scopes -- the normal case -- must not be
    /// refused, and neither must an unrelated tool list.
    #[test]
    fn minting_a_token_with_only_one_changeset_control_scope_is_allowed() {
        reject_combined_two_person_control_scope(&["unifi_stage_change".to_string()])
            .expect("staging alone must be permitted");
        reject_combined_two_person_control_scope(&["unifi_approve_change_set".to_string()])
            .expect("approving alone must be permitted");
        reject_combined_two_person_control_scope(&["unifi_get_change_set".to_string()])
            .expect("an unrelated tool must be permitted");
    }

    /// Drives the refusal through the same entry point `run_inner` calls --
    /// `TokenCli::parse_from` followed by `validate_token_command` -- rather
    /// than calling `reject_combined_two_person_control_scope` directly. That
    /// distinction matters: this is the only test that would notice if
    /// `run_inner` ever stopped calling `validate_token_command`, or if clap's
    /// `--tools` comma-splitting ever changed shape.
    #[test]
    fn token_add_cli_with_both_changeset_control_scopes_in_one_tools_flag_is_refused() {
        let cli = TokenCli::parse_from([
            "rustunifimcp",
            "add",
            "--tokens-file",
            "/tmp/tokens.json",
            "--name",
            "test",
            "--devices",
            "*",
            "--tools",
            "unifi_stage_change,unifi_approve_change_set",
        ]);
        let error = validate_token_command(&cli.command)
            .expect_err("both scopes on one token must be refused");
        let message = error.to_string();
        assert!(message.contains("unifi_stage_change"), "{message}");
        assert!(message.contains("unifi_approve_change_set"), "{message}");
    }

    /// The same refusal must apply when widening an existing token's scope
    /// with `set-scope --tools`, not just at initial `add` time.
    #[test]
    fn token_set_scope_cli_with_both_changeset_control_scopes_is_refused() {
        let cli = TokenCli::parse_from([
            "rustunifimcp",
            "set-scope",
            "--tokens-file",
            "/tmp/tokens.json",
            "--name",
            "test",
            "--tools",
            "unifi_stage_change,unifi_approve_change_set",
            "--yes",
        ]);
        validate_token_command(&cli.command)
            .expect_err("widening a token to both scopes must be refused");
    }

    /// `set-scope` with `--tools` omitted (leaving the existing scope
    /// unchanged) must not be refused -- there is nothing to check.
    #[test]
    fn token_set_scope_cli_without_tools_is_allowed() {
        let cli = TokenCli::parse_from([
            "rustunifimcp",
            "set-scope",
            "--tokens-file",
            "/tmp/tokens.json",
            "--name",
            "test",
            "--devices",
            "*",
            "--yes",
        ]);
        validate_token_command(&cli.command).expect("no --tools means nothing to validate");
    }

    #[test]
    fn token_command_to_action_revoke() {
        use std::path::PathBuf;
        let command = TokenCommand::Revoke {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            server_pid: None,
        };

        let (action, grant) = token_command_to_action(command).expect("converts");
        assert!(grant.is_none());
        match action {
            TokenAction::Revoke { name, .. } => assert_eq!(name, "test"),
            _ => panic!("expected TokenAction::Revoke"),
        }
    }

    #[test]
    fn token_command_to_action_list() {
        use std::path::PathBuf;
        let command = TokenCommand::List {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
        };

        let (action, grant) = token_command_to_action(command).expect("converts");
        assert!(grant.is_none());
        assert!(matches!(action, TokenAction::List { .. }));
    }

    #[test]
    fn token_command_to_action_rotate() {
        use std::path::PathBuf;
        let command = TokenCommand::Rotate {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            server_pid: None,
        };

        let (action, grant) = token_command_to_action(command).expect("converts");
        assert!(grant.is_none());
        match action {
            TokenAction::Rotate { name, .. } => assert_eq!(name, "test"),
            _ => panic!("expected TokenAction::Rotate"),
        }
    }

    #[test]
    fn token_command_to_action_set_scope() {
        use std::path::PathBuf;
        let command = TokenCommand::SetScope {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            devices: Some(vec!["*".to_string()]),
            tools: Some(vec!["*".to_string()]),
            yes: false,
            allow_self_approval: false,
            sites: None,
            server_pid: None,
        };

        let (action, grant) = token_command_to_action(command).expect("converts");
        assert!(grant.is_none());
        match action {
            TokenAction::SetScopes { name, .. } => assert_eq!(name, "test"),
            _ => panic!("expected TokenAction::SetScopes"),
        }
    }

    /// `--sites` on `set-scope` must build a replacement grant, the same as
    /// `add` -- this is how an existing token gets narrowed (or widened) to a
    /// site scope after issuance.
    #[test]
    fn token_command_to_action_set_scope_with_sites_builds_a_grant() {
        use std::path::PathBuf;
        let command = TokenCommand::SetScope {
            tokens_file: PathBuf::from("/tmp/tokens.json"),
            name: "test".to_string(),
            devices: None,
            tools: None,
            yes: true,
            allow_self_approval: false,
            sites: Some(vec!["site-a".to_string()]),
            server_pid: None,
        };

        let (_, grant) = token_command_to_action(command).expect("converts");
        let grant = grant.expect("--sites must produce a grant");
        assert_eq!(
            grant.sites,
            mecmcp_auth::ScopeSet::Allowlist(vec!["site-a".to_string()])
        );
    }

    #[tokio::test]
    async fn sighup_handler_installs_without_token_store() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a minimal valid controllers.json
        let mut controllers_file = NamedTempFile::new().unwrap();
        writeln!(controllers_file, "{{}}").unwrap();
        controllers_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(controllers_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(controllers_file.path(), perms).unwrap();
        }

        let registry = Arc::new(
            rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
                .unwrap(),
        );

        let coordinator = rustunifimcp::changeset_state::build_coordinator(
            None,
            std::time::Duration::from_secs(300),
            false,
            None,
            None,
        )
        .unwrap();

        // Build a server for the reload handler.
        let server = UnifiServer::new(
            Arc::clone(&registry),
            false,
            coordinator,
            None,
            mecmcp_audit::DirectCommitPolicy::new(false),
        )
        .unwrap();

        // Should install successfully without a token store.
        let result = install_sighup_reload(registry, Some(server), None, None);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn sighup_handler_installs_with_token_store() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a minimal valid controllers.json
        let mut controllers_file = NamedTempFile::new().unwrap();
        writeln!(controllers_file, "{{}}").unwrap();
        controllers_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(controllers_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(controllers_file.path(), perms).unwrap();
        }

        // Create a minimal valid tokens.json
        let mut tokens_file = NamedTempFile::new().unwrap();
        writeln!(tokens_file, r#"{{"version": 1, "tokens": []}}"#).unwrap();
        tokens_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(tokens_file.path()).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(tokens_file.path(), perms).unwrap();
        }

        let registry = Arc::new(
            rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
                .unwrap(),
        );

        let coordinator = rustunifimcp::changeset_state::build_coordinator(
            None,
            std::time::Duration::from_secs(300),
            false,
            None,
            None,
        )
        .unwrap();
        let server = UnifiServer::new(
            Arc::clone(&registry),
            false,
            coordinator,
            None,
            mecmcp_audit::DirectCommitPolicy::new(false),
        )
        .unwrap();

        let token_store = Arc::new(mecmcp_auth::TokenStoreFile::load(tokens_file.path()).unwrap());

        // Should install successfully with a token store.
        let result = install_sighup_reload(registry, Some(server), Some(token_store), None);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn malformed_inventory_reload_retains_previous_config() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create initial valid controllers.json
        let mut controllers_file = NamedTempFile::new().unwrap();
        writeln!(controllers_file, "{{}}").unwrap();
        controllers_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(controllers_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(controllers_file.path(), perms).unwrap();
        }

        let registry = Arc::new(
            rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
                .unwrap(),
        );

        // Verify initial load worked
        assert_eq!(registry.names().len(), 0);

        // Now corrupt the file
        std::fs::write(controllers_file.path(), "not valid json").unwrap();

        // Reload should fail but not panic
        let result = registry.reload();
        assert!(result.is_err());

        // The registry should still be usable with the previous config
        assert_eq!(registry.names().len(), 0);
    }

    /// `serve_http` loads `cli.common.tokens_file` via
    /// `mecmcp_auth::TokenStoreFile::load` with no fallback: unlike its five
    /// sibling servers, `rustunifimcp` shipped `/var/lib`-only from its first
    /// release and never had an `/etc` token store to migrate away from, so
    /// there is no canonical/legacy resolver to test here. What must hold
    /// instead is that a missing token file fails startup outright, naming
    /// the exact path, rather than silently proceeding unauthenticated or
    /// with an empty store — the fail-loud half of MEC-988 (mecmcp#356).
    #[test]
    fn a_missing_tokens_file_fails_loudly_and_names_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("tokens.json");

        let error = mecmcp_auth::TokenStoreFile::<UnifiGrant>::load(&missing)
            .expect_err("a missing token file must not load as an empty store");

        let message = error.to_string();
        assert!(
            message.contains(&missing.display().to_string()),
            "error must name the missing path so a bad drop-in restore is \
             diagnosable at startup, got: {message}"
        );
    }

    #[tokio::test]
    async fn client_rebuild_after_reload() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create initial valid controllers.json with no controllers
        let mut controllers_file = NamedTempFile::new().unwrap();
        writeln!(controllers_file, "{{}}").unwrap();
        controllers_file.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(controllers_file.path())
                .unwrap()
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(controllers_file.path(), perms).unwrap();
        }

        let registry = Arc::new(
            rustunifimcp_core::inventory::ControllerRegistry::load(controllers_file.path())
                .unwrap(),
        );

        let coordinator = rustunifimcp::changeset_state::build_coordinator(
            None,
            std::time::Duration::from_secs(300),
            false,
            None,
            None,
        )
        .unwrap();
        let server = UnifiServer::new(
            Arc::clone(&registry),
            false,
            coordinator,
            None,
            mecmcp_audit::DirectCommitPolicy::new(false),
        )
        .unwrap();

        // Initial state: no controllers, no clients
        assert_eq!(registry.names().len(), 0);

        // Reload should succeed with empty config
        let result = registry.reload();
        assert!(result.is_ok());

        // Rebuild clients should succeed
        let rebuild_result = server.rebuild_clients();
        assert!(rebuild_result.is_ok());
        assert_eq!(rebuild_result.unwrap(), 0);
    }
}

#[cfg(test)]
mod audit_tests {
    use super::*;
    use std::io::Write;

    fn store_with(names: &[&str]) -> tempfile::NamedTempFile {
        let entries: Vec<_> = names
            .iter()
            .map(|name| serde_json::json!({ "name": name, "digest": "x", "devices": [], "tools": [] }))
            .collect();
        let body = serde_json::json!({ "version": 1, "tokens": entries });
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        write!(file, "{body}").expect("write store");
        file
    }

    #[test]
    fn a_revoke_that_matches_nothing_is_not_reported_as_a_change() {
        // The runtime returns Ok whether or not the name was there, so this is
        // the only thing standing between the audit trail and a recorded
        // revocation of a token that never existed.
        assert_eq!(success_outcome_word(Some(false)), "no_op");
        assert_eq!(success_outcome_word(Some(true)), "succeeded");
    }

    #[test]
    fn an_unreadable_store_does_not_masquerade_as_an_absent_token() {
        // Unknown must not collapse into "absent" -- that would report a real
        // revocation as a no-op and hide it from the trail.
        assert_eq!(success_outcome_word(None), "succeeded");
    }

    #[test]
    fn presence_is_read_from_the_store_by_name() {
        let store = store_with(&["alpha", "beta"]);
        assert_eq!(token_name_present(store.path(), "alpha"), Some(true));
        assert_eq!(token_name_present(store.path(), "gamma"), Some(false));
    }

    #[test]
    fn a_missing_or_malformed_store_reads_as_unknown_not_absent() {
        assert_eq!(
            token_name_present(std::path::Path::new("/nonexistent/t.json"), "a"),
            None
        );
        let mut bad = tempfile::NamedTempFile::new().expect("temp file");
        write!(bad, "not json").expect("write");
        assert_eq!(token_name_present(bad.path(), "a"), None);
    }

    #[test]
    fn describing_a_revoke_records_whether_the_target_was_there() {
        let store = store_with(&["present"]);
        let describe = |name: &str| {
            PendingTokenAudit::describe(&TokenAction::Revoke {
                tokens_file: store.path().to_path_buf(),
                name: name.to_owned(),
                server_pid: None,
            })
            .expect("revoke is a mutating action")
            .target_existed
        };
        assert_eq!(describe("present"), Some(true));
        assert_eq!(describe("absent"), Some(false));
    }

    #[test]
    fn listing_tokens_produces_no_audit_record() {
        let store = store_with(&["a"]);
        assert!(
            PendingTokenAudit::describe(&TokenAction::List {
                tokens_file: store.path().to_path_buf(),
            })
            .is_none(),
            "a read-only list must not write a mutation record"
        );
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod startup_credential_tests {
    use super::{StartupCredentialFiles, listener_tokens, validate_startup_credentials};
    use clap::Parser;
    use rustunifimcp::cli::UnifiCli;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    fn write_file(dir: &std::path::Path, name: &str, body: &[u8], mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn no_secret_inventory(api_key_file: &std::path::Path) -> String {
        format!(
            r#"{{"version":1,"devices":{{"home":{{"endpoint":"https://unifi.example.org","site":"default","api_key_file":"{}"}}}}}}"#,
            api_key_file.display()
        )
    }

    /// Two loose modes must come back together. The failure this guards is a
    /// startup that names the first file, exits, and only names the second
    /// after that restart.
    #[test]
    fn one_pass_reports_every_bad_mode() {
        let dir = tempfile::tempdir().unwrap();
        let controllers = write_file(dir.path(), "controllers.json", b"{}\n", 0o644);
        let tokens = write_file(dir.path(), "tokens.json", b"{}\n", 0o640);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            controllers: &controllers,
            tokens: Some(&tokens),
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("both files are looser than their role allows");

        let message = error.to_string();
        assert!(
            message.contains("2 credential file"),
            "expected both failures in one error, got {message}"
        );
        assert!(message.contains("controllers.json"), "{message}");
        assert!(message.contains("tokens.json"), "{message}");
        assert!(message.contains("0644"), "{message}");
        assert!(message.contains("0640"), "{message}");
    }

    /// An owner-only inventory, an owner-only token store, and an owner-only
    /// API key file must pass together.
    #[test]
    fn acceptable_modes_pass_in_one_pass() {
        let dir = tempfile::tempdir().unwrap();
        let api_key = write_file(dir.path(), "api.key", b"key\n", 0o600);
        let inventory = no_secret_inventory(&api_key);
        let controllers = write_file(dir.path(), "controllers.json", inventory.as_bytes(), 0o600);
        let tokens = write_file(dir.path(), "tokens.json", b"{}\n", 0o600);

        validate_startup_credentials(&StartupCredentialFiles {
            controllers: &controllers,
            tokens: Some(&tokens),
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect("0600 inventory, api key, and tokens are acceptable modes");
    }

    /// A group-readable inventory is the same failure as a group-readable
    /// token store. Both must be named in one error.
    #[test]
    fn group_readable_inventory_and_tokens_fail_together() {
        let dir = tempfile::tempdir().unwrap();
        let api_key = write_file(dir.path(), "api.key", b"key\n", 0o600);
        let inventory = no_secret_inventory(&api_key);
        let controllers = write_file(dir.path(), "controllers.json", inventory.as_bytes(), 0o640);
        let tokens = write_file(dir.path(), "tokens.json", b"{}\n", 0o640);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            controllers: &controllers,
            tokens: Some(&tokens),
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("0640 is too loose for the inventory and the token store");

        let message = error.to_string();
        assert!(
            message.contains("2 credential file"),
            "expected both failures in one error, got {message}"
        );
        assert!(message.contains("controllers.json"), "{message}");
        assert!(message.contains("tokens.json"), "{message}");
        assert!(message.contains("0640"), "{message}");
        assert!(
            !message.contains("api.key"),
            "an owner-only API key must not be named, got {message}"
        );
    }

    /// An owner-only inventory passes. A missing optional API key file is
    /// not a failure.
    #[test]
    fn owner_only_inventory_and_missing_optional_file_pass() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("api.key");
        let inventory = no_secret_inventory(&missing);
        let controllers = write_file(dir.path(), "controllers.json", inventory.as_bytes(), 0o600);

        validate_startup_credentials(&StartupCredentialFiles {
            controllers: &controllers,
            tokens: None,
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect("0600 inventory and an absent optional API key file must pass");
    }

    /// The API key file holds the credential, so group-read is a failure
    /// even when the inventory next to it is owner-only.
    #[test]
    fn loose_api_key_is_a_secret() {
        let dir = tempfile::tempdir().unwrap();
        let api_key = write_file(dir.path(), "api.key", b"key\n", 0o640);
        let inventory = no_secret_inventory(&api_key);
        let controllers = write_file(dir.path(), "controllers.json", inventory.as_bytes(), 0o600);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            controllers: &controllers,
            tokens: None,
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("0640 is too loose for the API key");

        let message = error.to_string();
        assert!(message.contains("api.key"), "{message}");
        assert!(message.contains("0600"), "{message}");
        assert!(
            !message.contains("controllers.json"),
            "an owner-only inventory must not be named, got {message}"
        );
    }

    /// A required token path that is missing is named. No second path is tried.
    #[test]
    fn missing_required_tokens_file_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let controllers = write_file(dir.path(), "controllers.json", b"{}\n", 0o600);
        let tokens = dir.path().join("tokens.json");

        let error = validate_startup_credentials(&StartupCredentialFiles {
            controllers: &controllers,
            tokens: Some(&tokens),
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("a missing required token store must fail");

        let message = error.to_string();
        assert!(message.contains("tokens.json"), "{message}");
        assert!(
            !message.contains("/etc/unifimcp/tokens.json"),
            "this server has no /etc token store, got {message}"
        );
    }

    #[test]
    fn stdio_does_not_require_the_token_store() {
        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--transport",
            "stdio",
            "--tokens-file",
            "/var/lib/unifimcp/tokens.json",
        ])
        .unwrap();
        assert!(listener_tokens(&cli).is_none());
    }

    #[test]
    fn http_checks_the_configured_token_path() {
        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--transport",
            "streamable-http",
            "--tokens-file",
            "/var/lib/unifimcp/tokens.json",
        ])
        .unwrap();
        assert_eq!(
            listener_tokens(&cli).map(std::path::Path::to_path_buf),
            Some(std::path::PathBuf::from("/var/lib/unifimcp/tokens.json"))
        );
    }
}
