//! Command-line surface.
//!
//! `mecmcp_runtime::cli::Cli` is flattened rather than reimplemented, so every
//! shared flag — transport, bind, TLS, allowed hosts, audit — behaves exactly as
//! it does on the sibling servers.
//!
//! Token management is intercepted before parsing to prevent grant flags
//! (`--sites`, `--actions`) from appearing in the server's help. See
//! [`TokenCli`] and the dispatch logic in `main.rs`.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Default controller inventory.
///
/// Derived from `ServerNaming` for the deployed UniFi short name. The
/// on-disk path stays `/etc/unifimcp/controllers.json`.
#[must_use]
pub fn default_controllers_file() -> PathBuf {
    mecmcp_secret::naming::ServerNaming::derive(mecmcp_secret::naming::known::UNIFI)
        .config_dir
        .join("controllers.json")
}

/// `rustunifimcp` command line.
#[derive(Debug, Parser)]
#[command(name = "rustunifimcp", version)]
pub struct UnifiCli {
    /// Flags shared with the rest of the mechub MCP family.
    ///
    /// Carries the SSDF evidence flag group (`--ssdf-audit-*`), which this
    /// server advertised and never consumed: `mecmcp-audit` was a declared
    /// dependency imported nowhere, so the flags parsed and did nothing.
    #[command(flatten)]
    pub common: mecmcp_runtime::cli::Cli,

    /// Controller inventory. Must be mode 0600 and owned by the service user.
    #[arg(long, default_value_os_t = default_controllers_file())]
    pub controllers_file: PathBuf,

    /// Run without two-person control for destructive operations.
    ///
    /// For a single-operator lab. No approver is invented: a waived change set
    /// records `approver: null` with a lab-mode waiver, so it stays
    /// distinguishable from one a second person reviewed.
    ///
    /// Spelled identically on every mecmcp server.
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Allow direct-commit tools that mutate a device or client in one call
    /// with no change-set approval.
    ///
    /// `unifi_device_action`'s `restart` and `unifi_client_action`'s `block`,
    /// `unblock`, and `reconnect` act on the controller immediately -- there
    /// is no change-set flow to route an operational command like "restart
    /// this device" through. By default this server refuses those specific
    /// actions rather than let a model decide a firewall action alone.
    ///
    /// This applies identically over stdio and HTTP: stdio carries no caller
    /// context at all, so it is refused on exactly the same terms as an
    /// authenticated HTTP session.
    ///
    /// **Residual risk**: an operator can set this flag. Doing so is logged
    /// loudly at startup and every direct-commit call is recorded in the audit
    /// trail (`direct_commit_allowed=true`), but no second-principal review
    /// happens.
    ///
    /// Defaults to false (refuse). Spelled identically on every mecmcp server.
    #[arg(long = "allow-direct-commit")]
    pub allow_direct_commit: bool,

    /// Absolute path to the change-set and operation state file.
    ///
    /// Spelled `--state-file` on every mecmcp server, per
    /// `mecmcp/docs/PACKAGING.md`. **Without it the coordinator keeps change
    /// sets in memory only**: every approval, preview and in-flight apply is
    /// lost on restart.
    ///
    /// Left optional rather than defaulted so an existing deployment does not
    /// silently start writing a file its unit never provisioned; the packaged
    /// unit passes `$STATE_DIRECTORY/changeset-state.json`, and startup warns
    /// loudly when it is unset.
    #[arg(long = "state-file")]
    pub state_file: Option<PathBuf>,

    /// How long a change set stays usable, in seconds.
    ///
    /// Spelled `--approval-timeout-secs` on every mecmcp server, and it
    /// configures the change-set coordinator's approval TTL -- which is what
    /// actually expires an approval, rather than a window this server measured
    /// itself.
    ///
    /// The window runs from the moment something is **staged**, not from
    /// approval. So the default 300 seconds bounds the review-and-apply round,
    /// and it bounds the age of the pre-image the plan was built against, which
    /// is the point: a pre-image captured half an hour ago is not evidence
    /// about the controller now. Raise it if a review takes longer than the
    /// round it gates.
    #[arg(long = "approval-timeout-secs", default_value = "300")]
    pub approval_timeout_secs: u64,

    /// Expose the `/metrics` (Prometheus) endpoint (streamable-http only). OFF
    /// by default: `/metrics` carries no MCP bearer auth of its own, so
    /// turning it on is an operator decision, not a default. As of
    /// `mecmcp-transport` 0.24.0, `/metrics` is restricted to loopback callers
    /// by `metrics_access_middleware`, independent of this flag.
    #[arg(long = "enable-metrics")]
    pub enable_metrics: bool,

    /// HTTP resource limits (streamable-http only). Defaults match
    /// `mecmcp_transport::LimitsConfig::default()` so an upgrade with no flags
    /// passed behaves exactly as before.
    #[command(flatten)]
    pub limits: LimitsArgs,
}

impl UnifiCli {
    /// Whether lab mode is enabled.
    #[must_use]
    pub fn lab_mode(&self) -> bool {
        self.lab_mode
    }
}

/// CLI-configurable mirror of `mecmcp_transport::LimitsConfig`.
///
/// Flattened into [`UnifiCli`] rather than left hardcoded so an operator can
/// tune per-deployment resource limits without a fork. Every default below is
/// copied from `LimitsConfig::default()` — changing one here without changing
/// the other silently drifts a documented default out of sync with the
/// enforced one (see `limits_defaults_match_transport_defaults` below).
#[derive(Debug, clap::Args)]
pub struct LimitsArgs {
    /// Max request body bytes before HTTP 413. 0 = unlimited.
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    pub max_request_body_bytes: usize,

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_inflight_requests_per_token: usize,

    /// Max requests per second per source IP address. Set together with
    /// `--max-request-burst-per-ip`; `0`/`0` disables per-IP rate limiting.
    #[arg(long, default_value_t = 50)]
    pub max_requests_per_second_per_ip: u64,

    /// Max immediate request burst per source IP address. Set together with
    /// `--max-requests-per-second-per-ip`; `0`/`0` disables per-IP rate limiting.
    #[arg(long, default_value_t = 100)]
    pub max_request_burst_per_ip: u64,

    /// Max requests per second per bearer token. Set together with
    /// `--max-request-burst-per-token`; `0`/`0` disables per-token rate limiting.
    #[arg(long, default_value_t = 20)]
    pub max_requests_per_second_per_token: u64,

    /// Max immediate request burst per bearer token. Set together with
    /// `--max-requests-per-second-per-token`; `0`/`0` disables per-token rate limiting.
    #[arg(long, default_value_t = 40)]
    pub max_request_burst_per_token: u64,

    /// Max concurrent in-flight requests per target controller. 0 = unlimited.
    #[arg(long, default_value_t = 4)]
    pub max_inflight_requests_per_controller: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, default_value_t = 128)]
    pub max_sessions: usize,

    /// Max concurrent MCP sessions per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_sessions_per_token: usize,

    /// Session idle timeout in seconds. 0 = disabled.
    #[arg(long, default_value_t = 300)]
    pub session_idle_timeout_secs: u64,

    /// Session max lifetime in seconds. 0 = disabled.
    #[arg(long, default_value_t = 3600)]
    pub session_max_lifetime_secs: u64,
}

impl LimitsArgs {
    /// Build the transport's `LimitsConfig` from the parsed flags.
    #[must_use]
    pub fn to_limits_config(&self) -> mecmcp_transport::LimitsConfig {
        mecmcp_transport::LimitsConfig {
            max_request_body_bytes: self.max_request_body_bytes,
            max_inflight_requests: self.max_inflight_requests,
            max_inflight_requests_per_token: self.max_inflight_requests_per_token,
            max_requests_per_second_per_ip: self.max_requests_per_second_per_ip,
            max_request_burst_per_ip: self.max_request_burst_per_ip,
            max_requests_per_second_per_token: self.max_requests_per_second_per_token,
            max_request_burst_per_token: self.max_request_burst_per_token,
            max_inflight_requests_per_device: self.max_inflight_requests_per_controller,
            // No flag exposes this yet, so `X-Forwarded-For` stays untrusted
            // from every peer -- the same behavior as before this field
            // existed, not an opt-in to trusting a reverse proxy.
            trusted_proxies: Vec::new(),
            max_sessions: self.max_sessions,
            max_sessions_per_token: self.max_sessions_per_token,
            session_idle_timeout_secs: self.session_idle_timeout_secs,
            session_max_lifetime_secs: self.session_max_lifetime_secs,
        }
    }
}

/// Token management CLI, parsed only when argv starts with `token`.
///
/// This is dispatched before `UnifiCli` to keep grant-specific flags
/// (`--sites`, `--actions`) off the server's help text.
#[derive(Debug, Parser)]
#[command(name = "rustunifimcp", version)]
pub struct TokenCli {
    /// Token subcommand (add, revoke, list, rotate, set-scope).
    #[command(subcommand)]
    pub command: TokenCommand,
}

/// Token subcommands.
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Mint a new token and append to the file.
    Add {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Stable audit name for the token.
        #[arg(long)]
        name: String,
        /// Comma-separated controller names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        devices: Vec<String>,
        /// Comma-separated tool names, or '*' for read-only tools only.
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Provider name (e.g., "anthropic", "ollama"). Optional.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Required if provider is set.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Optional.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Optional.
        #[arg(long)]
        actor_type: Option<String>,
        /// IdP issuer URL this token is bound to. Optional. Set together with
        /// `--oidc-subject`, or omit both.
        #[arg(long)]
        oidc_issuer: Option<String>,
        /// IdP subject this token is bound to. Optional. Set together with
        /// `--oidc-issuer`, or omit both.
        #[arg(long)]
        oidc_subject: Option<String>,
        /// Allow one token to hold both `unifi_stage_change` and
        /// `unifi_approve_change_set`. Only meaningful for a server run with
        /// `--lab-mode`; without it the server refuses such a token at call time.
        #[arg(long)]
        allow_self_approval: bool,
        /// Comma-separated site identifiers this token may write to, or '*'
        /// for every site. Omit for the pre-MEC-508 default: unrestricted by
        /// site (the token may write to any site named in a call, exactly as
        /// it could before per-site scoping existed).
        #[arg(long, value_delimiter = ',')]
        sites: Option<Vec<String>>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Revoke a token by name.
    Revoke {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token name to revoke.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List all tokens in the store.
    List {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Rotate a token's secret, preserving its grant.
    Rotate {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token name to rotate.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Change an existing token's scopes without reissuing its secret.
    SetScope {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Replacement device scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Replacement tool scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// Apply a widening without the interactive confirmation.
        #[arg(long)]
        yes: bool,
        /// As for `token add`: allow the new tool scope to combine both
        /// change-set control tools (lab-mode single operator only).
        #[arg(long)]
        allow_self_approval: bool,
        /// Replacement site scope: comma-separated site identifiers, or '*'
        /// for every site. Omit to leave the token's existing site grant
        /// unchanged.
        #[arg(long, value_delimiter = ',')]
        sites: Option<Vec<String>>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

/// Validate configuration without starting the server.
#[derive(Debug, Parser)]
#[command(name = "rustunifimcp", version)]
pub struct ValidateConfigCli {
    /// Controller inventory to validate.
    #[arg(long)]
    pub controllers_file: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// --lab-mode is CLI-only and must never be readable from a config file.
    /// mecmcp#267 decided this: a relaxed security control should be visible
    /// where someone will see it, and a boolean in a product config file is
    /// strictly less visible than a flag in a unit file, not more.
    #[test]
    fn lab_mode_is_a_flag_and_defaults_off() {
        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
        ])
        .expect("parses");
        assert!(!cli.lab_mode());

        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
            "--lab-mode",
        ])
        .expect("parses");
        assert!(cli.lab_mode());
    }

    /// There must be no way to ask for unverified TLS. If this test ever needs
    /// changing, the deployment is wrong, not the test.
    #[test]
    fn there_is_no_insecure_tls_flag() {
        for flag in [
            "--insecure",
            "--no-verify-tls",
            "--insecure-skip-verify",
            "--tls-no-verify",
        ] {
            let parsed = UnifiCli::try_parse_from([
                "rustunifimcp",
                "--controllers-file",
                "/etc/unifimcp/controllers.json",
                flag,
            ]);
            assert!(parsed.is_err(), "{flag} must not be accepted");
        }
    }

    /// MEC-504: a fresh install must not silently run unrate-limited.
    #[test]
    fn fresh_install_gets_nonzero_rate_limits_without_operator_action() {
        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
        ])
        .expect("parses");
        assert!(cli.limits.max_requests_per_second_per_ip > 0);
        assert!(cli.limits.max_request_burst_per_ip > 0);
        assert!(cli.limits.max_requests_per_second_per_token > 0);
        assert!(cli.limits.max_request_burst_per_token > 0);
    }

    /// Every `LimitsArgs` default must match `LimitsConfig::default()` byte
    /// for byte: a mismatch here means the documented default and the
    /// enforced one have drifted, exactly the gap MEC-504 closes.
    #[test]
    fn limits_defaults_match_transport_defaults() {
        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
        ])
        .expect("parses");
        let got = cli.limits.to_limits_config();
        let want = mecmcp_transport::LimitsConfig::default();
        assert_eq!(got.max_request_body_bytes, want.max_request_body_bytes);
        assert_eq!(got.max_inflight_requests, want.max_inflight_requests);
        assert_eq!(
            got.max_inflight_requests_per_token,
            want.max_inflight_requests_per_token
        );
        assert_eq!(
            got.max_requests_per_second_per_ip,
            want.max_requests_per_second_per_ip
        );
        assert_eq!(got.max_request_burst_per_ip, want.max_request_burst_per_ip);
        assert_eq!(
            got.max_requests_per_second_per_token,
            want.max_requests_per_second_per_token
        );
        assert_eq!(
            got.max_request_burst_per_token,
            want.max_request_burst_per_token
        );
        assert_eq!(
            got.max_inflight_requests_per_device,
            want.max_inflight_requests_per_device
        );
        assert_eq!(got.max_sessions, want.max_sessions);
        assert_eq!(got.max_sessions_per_token, want.max_sessions_per_token);
        assert_eq!(
            got.session_idle_timeout_secs,
            want.session_idle_timeout_secs
        );
        assert_eq!(
            got.session_max_lifetime_secs,
            want.session_max_lifetime_secs
        );
    }

    #[test]
    fn rate_limits_are_operator_configurable() {
        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
            "--max-requests-per-second-per-ip",
            "5",
            "--max-request-burst-per-ip",
            "10",
            "--max-requests-per-second-per-token",
            "2",
            "--max-request-burst-per-token",
            "4",
        ])
        .expect("parses");
        let limits = cli.limits.to_limits_config();
        assert_eq!(limits.max_requests_per_second_per_ip, 5);
        assert_eq!(limits.max_request_burst_per_ip, 10);
        assert_eq!(limits.max_requests_per_second_per_token, 2);
        assert_eq!(limits.max_request_burst_per_token, 4);
    }

    #[test]
    fn metrics_are_off_by_default_but_operator_configurable() {
        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
        ])
        .expect("parses");
        assert!(!cli.enable_metrics);

        let cli = UnifiCli::try_parse_from([
            "rustunifimcp",
            "--controllers-file",
            "/etc/unifimcp/controllers.json",
            "--enable-metrics",
        ])
        .expect("parses");
        assert!(cli.enable_metrics);
    }

    /// The shipped inventory path comes from the shared layout, and the
    /// token store stays under `/var/lib`. This server never had an `/etc`
    /// token path.
    #[test]
    fn controllers_default_follows_the_unifi_layout() {
        use mecmcp_secret::naming::{ServerNaming, known};

        let naming = ServerNaming::derive(known::UNIFI);
        let controllers = naming.config_dir.join("controllers.json");
        let tokens = naming.state_dir.join("tokens.json");

        assert_eq!(default_controllers_file(), controllers);
        assert_eq!(controllers, PathBuf::from("/etc/unifimcp/controllers.json"));
        assert_eq!(tokens, PathBuf::from("/var/lib/unifimcp/tokens.json"));
        assert_ne!(tokens, naming.config_dir.join("tokens.json"));

        let cli = UnifiCli::try_parse_from(["rustunifimcp"]).expect("parses");
        assert_eq!(cli.controllers_file, controllers);
    }
}
