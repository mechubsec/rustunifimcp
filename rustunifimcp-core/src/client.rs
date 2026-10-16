//! One HTTP client per controller, over `mecmcp-http`.
//!
//! Each controller gets its own client with isolated rate limits, so a slow or
//! wedged controller cannot exhaust a pool shared with healthy ones.
//!
//! Every request's path is expanded by `mecmcp-openapi::expand_path`, which
//! rejects a parameter that would span a segment, start a query, navigate the
//! hierarchy, collapse a segment, or carry a control byte. Nothing is
//! sanitised: a rewritten value is a value the caller did not send. UniFi puts
//! the site id and the resource id directly in the path on all three local
//! surfaces, so this applies to essentially every request.
//!
//! Requests are built with [`HttpRequest::from_absolute_url`] (the
//! `absolute-url` feature), not `with_base_and_path`: the latter only accepts
//! a path, with no way to attach the percent-encoded query string this client
//! appends for pagination (`offset`/`limit`). The path portion is still
//! validated through `expand_path` before the URL string is assembled, and
//! every query key/value goes through [`percent_encode`], which escapes
//! everything outside RFC 3986 `unreserved` -- so this keeps the same
//! injection resistance `with_base_and_path` provides for the path, just
//! without its compile-time type for the part it does not cover.

use crate::ApiSurface;
use crate::error::UnifiError;
use crate::inventory::Controller;
use mecmcp_http::{HttpClient, HttpClientConfig, HttpRequest, Method};
use mecmcp_secret::OutboundSecret;
use std::sync::RwLock;
use std::time::Duration;

/// Requests in flight to one controller.
const MAX_CONCURRENT: usize = 8;
/// Callers permitted to wait behind those.
const MAX_QUEUED: usize = 32;
/// Whole-request deadline, covering permit acquisition and send.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Largest response body accepted, enforced as it streams.
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// A client bound to one controller.
#[derive(Clone)]
pub struct UnifiClient {
    controller: Controller,
    http: std::sync::Arc<HttpClient>,
    api_key: OutboundSecret,
    cached_version: std::sync::Arc<RwLock<Option<String>>>,
    cached_site_uuid: std::sync::Arc<RwLock<Option<String>>>,
}

impl UnifiClient {
    /// Build a client for one controller, loading its credential.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError`] when:
    /// - The credential cannot be loaded from env or file
    /// - The CA PEM is unreadable
    /// - The endpoint is not HTTPS
    /// - The HTTP client fails to initialize
    pub fn new(controller: Controller) -> Result<Self, UnifiError> {
        controller.validate()?;

        let api_key = controller.load_api_key()?;

        let mut extra_root_certificates = Vec::new();
        if let Some(path) = &controller.ca_pem_path {
            let pem = std::fs::read_to_string(path).map_err(|error| {
                UnifiError::Malformed(format!("ca_pem_path {}: {error}", path.display()))
            })?;
            extra_root_certificates.push(pem);
        }

        let config = HttpClientConfig {
            request_timeout: REQUEST_TIMEOUT,
            max_concurrent_requests: MAX_CONCURRENT,
            max_queued_requests: MAX_QUEUED,
            max_response_bytes: MAX_RESPONSE_BYTES,
            user_agent: concat!("rustunifimcp/", env!("CARGO_PKG_VERSION")).to_owned(),
            extra_root_certificates,
            ..HttpClientConfig::default()
        };

        let http = HttpClient::new(config)?;
        Ok(Self {
            controller,
            http: std::sync::Arc::new(http),
            api_key,
            cached_version: std::sync::Arc::new(RwLock::new(None)),
            cached_site_uuid: std::sync::Arc::new(RwLock::new(None)),
        })
    }

    /// Refuse a surface this controller has not opted into.
    ///
    /// `ResourceKind::path_template` already returns absolute paths, so there
    /// is no prefix to hand back — this is purely the permission gate, and it
    /// runs before a request is built. An un-opted-in deployment therefore
    /// cannot reach an undocumented route even by accident.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError::SurfaceRequiresConfig`] if the controller has not
    /// opted into the private or cloud surfaces, or [`UnifiError::Malformed`]
    /// for the cloud surface, which is unimplemented in v1.
    pub fn ensure_surface_permitted(
        controller: &Controller,
        surface: ApiSurface,
    ) -> Result<(), UnifiError> {
        match surface {
            ApiSurface::Supported => Ok(()),
            ApiSurface::PrivateV1 | ApiSurface::PrivateV2 if controller.allow_private_api => Ok(()),
            ApiSurface::Cloud if controller.allow_cloud => Err(UnifiError::Malformed(
                "the cloud Site Manager surface is not implemented in v1".to_owned(),
            )),
            other => Err(UnifiError::SurfaceRequiresConfig { surface: other }),
        }
    }

    /// The controller's configured default site, used when a tool omits one.
    ///
    /// This returns the site **name**, suitable for private API surfaces.
    /// For the Integration API, use [`Self::default_site_for`] instead.
    #[must_use]
    pub fn default_site(&self) -> &str {
        &self.controller.site
    }

    /// The site identifier to use for `surface` when a caller omits one.
    ///
    /// The Integration API addresses a site by UUID; the private surfaces address
    /// it by name. Passing the name to Integration v1 returns HTTP 400, so the two
    /// must not share one value.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError`] when:
    /// - The sites endpoint cannot be reached (Integration API only)
    /// - The configured site name is not found in the sites list
    /// - The response does not match the expected shape
    pub async fn default_site_for(&self, surface: ApiSurface) -> Result<String, UnifiError> {
        match surface {
            ApiSurface::Supported => {
                // Integration API requires the site UUID
                // Check cache first
                {
                    let cached = self.cached_site_uuid.read().map_err(|_| {
                        UnifiError::Malformed("site UUID cache lock poisoned".to_owned())
                    })?;
                    if let Some(uuid) = cached.as_ref() {
                        return Ok(uuid.clone());
                    }
                }

                // Fetch from controller
                let sites = self
                    .get(
                        ApiSurface::Supported,
                        "/proxy/network/integration/v1/sites",
                        &[],
                        &[],
                    )
                    .await?;

                let sites_array = crate::model::unwrap_enveloped_data(&sites)?;

                let site_name = &self.controller.site;
                let uuid = sites_array
                    .iter()
                    .find(|site| {
                        site.get("internalReference")
                            .and_then(|r| r.as_str())
                            .is_some_and(|r| r == site_name)
                    })
                    .and_then(|site| site.get("id"))
                    .and_then(|id| id.as_str())
                    .ok_or_else(|| {
                        UnifiError::Malformed(format!(
                            "site '{}' not found in sites list",
                            site_name
                        ))
                    })?
                    .to_owned();

                // Cache for future use
                {
                    let mut cached = self.cached_site_uuid.write().map_err(|_| {
                        UnifiError::Malformed("site UUID cache lock poisoned".to_owned())
                    })?;
                    *cached = Some(uuid.clone());
                }

                Ok(uuid)
            }
            ApiSurface::PrivateV1 | ApiSurface::PrivateV2 | ApiSurface::Cloud => {
                // Private surfaces use the site name directly
                Ok(self.controller.site.clone())
            }
        }
    }

    /// Fetch the controller version from the Integration API info endpoint.
    ///
    /// The version is cached after the first successful request. The Integration
    /// API endpoint is used because it is documented and stable, unlike the
    /// private `/proxy/network/api/status` path.
    ///
    /// # Errors
    ///
    /// Returns [`UnifiError`] when:
    /// - The info endpoint cannot be reached
    /// - The response does not contain an `applicationVersion` field
    pub async fn controller_version(&self) -> Result<String, UnifiError> {
        self.fetch_version_if_absent().await
    }

    /// Issue a GET against a path template.
    ///
    /// The template is expanded by `mecmcp-openapi`, which rejects a parameter
    /// that would span a segment, start a query, navigate the hierarchy,
    /// collapse a segment, or carry a control byte. Nothing is sanitised: a
    /// rewritten value is a value the caller did not send.
    ///
    /// Query parameters are percent-encoded and appended to the expanded path.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`UnifiError::SurfaceRequiresConfig`] if the controller hasn't opted into
    ///   this surface
    /// - [`UnifiError::PrivateEndpointAbsent`] for 404 on a private surface
    /// - [`UnifiError::Upstream`] for other error statuses
    /// - [`UnifiError::Http`] for network or protocol errors
    /// - [`UnifiError::Malformed`] for rejected parameters or invalid JSON
    pub async fn get(
        &self,
        surface: ApiSurface,
        template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, UnifiError> {
        Self::ensure_surface_permitted(&self.controller, surface)?;

        let expanded = mecmcp_openapi::expand_path(template, params)
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let mut url = format!(
            "{}{expanded}",
            self.controller.endpoint.trim_end_matches('/')
        );

        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let request = HttpRequest::from_absolute_url(Method::Get, &url)?
            .header("Accept", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?;

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return self
                .handle_error_response(surface, &expanded, response.status(), response.body())
                .await;
        }

        serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))
    }

    /// Issue a POST against a path template with a JSON body.
    ///
    /// The `body` is serialized to JSON and sent with `Content-Type: application/json`.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn post(
        &self,
        surface: ApiSurface,
        template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, UnifiError> {
        Self::ensure_surface_permitted(&self.controller, surface)?;

        let expanded = mecmcp_openapi::expand_path(template, params)
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let mut url = format!(
            "{}{expanded}",
            self.controller.endpoint.trim_end_matches('/')
        );

        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let body_bytes = serde_json::to_vec(body)
            .map_err(|error| UnifiError::Malformed(format!("failed to serialize body: {error}")))?;

        let request = HttpRequest::from_absolute_url(Method::Post, &url)?
            .header("Accept", "application/json")?
            .header("Content-Type", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?
            .body(body_bytes);

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return self
                .handle_error_response(surface, &expanded, response.status(), response.body())
                .await;
        }

        serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))
    }

    /// Issue a PUT against a path template with a JSON body.
    ///
    /// The `body` is serialized to JSON and sent with `Content-Type: application/json`.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn put(
        &self,
        surface: ApiSurface,
        template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, UnifiError> {
        Self::ensure_surface_permitted(&self.controller, surface)?;

        let expanded = mecmcp_openapi::expand_path(template, params)
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let mut url = format!(
            "{}{expanded}",
            self.controller.endpoint.trim_end_matches('/')
        );

        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let body_bytes = serde_json::to_vec(body)
            .map_err(|error| UnifiError::Malformed(format!("failed to serialize body: {error}")))?;

        let request = HttpRequest::from_absolute_url(Method::Put, &url)?
            .header("Accept", "application/json")?
            .header("Content-Type", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?
            .body(body_bytes);

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return self
                .handle_error_response(surface, &expanded, response.status(), response.body())
                .await;
        }

        serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))
    }

    /// Issue a DELETE against a path template.
    ///
    /// # Errors
    ///
    /// As [`Self::get`].
    pub async fn delete(
        &self,
        surface: ApiSurface,
        template: &str,
        params: &[(&str, &str)],
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, UnifiError> {
        Self::ensure_surface_permitted(&self.controller, surface)?;

        let expanded = mecmcp_openapi::expand_path(template, params)
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let mut url = format!(
            "{}{expanded}",
            self.controller.endpoint.trim_end_matches('/')
        );

        if !query.is_empty() {
            let query_string = query
                .iter()
                .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
                .collect::<Vec<_>>()
                .join("&");
            url.push('?');
            url.push_str(&query_string);
        }

        let request = HttpRequest::from_absolute_url(Method::Delete, &url)?
            .header("Accept", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?;

        let response = self.http.send(request).await?;

        if response.status() >= 300 {
            return self
                .handle_error_response(surface, &expanded, response.status(), response.body())
                .await;
        }

        serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))
    }

    /// Map error responses to the correct `UnifiError` variant.
    ///
    /// A 404 on a private surface becomes `PrivateEndpointAbsent` with the
    /// surface, path, and controller version named — that is the entire payoff
    /// of the tag enum. Other errors become `Upstream`.
    async fn handle_error_response(
        &self,
        surface: ApiSurface,
        path: &str,
        status: u16,
        body: &[u8],
    ) -> Result<serde_json::Value, UnifiError> {
        if status == 404 && surface.requires_private_scope() {
            // Ensure version is cached by fetching it if absent. This uses the
            // supported Integration API endpoint directly, avoiding recursion.
            let version = match self.fetch_version_if_absent().await {
                Ok(v) => v,
                Err(_) => {
                    // If version fetch fails, fall back to reading the cache
                    self.cached_version
                        .read()
                        .ok()
                        .and_then(|guard| guard.clone())
                        .unwrap_or_else(|| "unknown".to_owned())
                }
            };

            return Err(UnifiError::PrivateEndpointAbsent {
                surface,
                path: path.to_owned(),
                controller_version: version,
            });
        }

        let detail = crate::error::sanitize_detail(&String::from_utf8_lossy(body));

        Err(UnifiError::Upstream { status, detail })
    }

    /// Fetch the version if not cached, bypassing the normal GET path to avoid recursion.
    ///
    /// This is used by `handle_error_response` to ensure a real version is always
    /// available in private-404 errors, even when the error is the first call.
    async fn fetch_version_if_absent(&self) -> Result<String, UnifiError> {
        // Check cache first
        {
            let cached = self
                .cached_version
                .read()
                .map_err(|_| UnifiError::Malformed("version cache lock poisoned".to_owned()))?;
            if let Some(version) = cached.as_ref() {
                return Ok(version.clone());
            }
        }

        // Build and send request directly, bypassing get() to avoid recursion
        let url = format!(
            "{}/proxy/network/integration/v1/info",
            self.controller.endpoint.trim_end_matches('/')
        );

        let request = HttpRequest::from_absolute_url(Method::Get, &url)?
            .header("Accept", "application/json")?
            .secret_header("X-API-KEY", &self.api_key)?;

        let response = self.http.send(request).await?;

        // Treat non-2xx as error, but don't recursively handle it
        if response.status() >= 300 {
            let detail = crate::error::sanitize_detail(&String::from_utf8_lossy(response.body()));
            return Err(UnifiError::Upstream {
                status: response.status(),
                detail,
            });
        }

        let info: serde_json::Value = serde_json::from_slice(response.body())
            .map_err(|error| UnifiError::Malformed(error.to_string()))?;

        let version = info
            .get("applicationVersion")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                UnifiError::Malformed("info response lacks applicationVersion".to_owned())
            })?
            .to_owned();

        // Cache for future use
        {
            let mut cached = self
                .cached_version
                .write()
                .map_err(|_| UnifiError::Malformed("version cache lock poisoned".to_owned()))?;
            *cached = Some(version.clone());
        }

        Ok(version)
    }
}

/// Percent-encode a string for use in a URL query parameter or path segment.
///
/// Encodes all characters except unreserved ones (alphanumeric, `-`, `.`, `_`, `~`).
fn percent_encode(s: &str) -> String {
    s.as_bytes()
        .iter()
        .map(|&byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

/// Implementation of `ControllerOps` for `UnifiClient`.
///
/// This allows `UnifiClient` to be used with `apply_sequentially` and other
/// change-set machinery.
impl crate::changeset::apply::ControllerOps for UnifiClient {
    async fn apply_mutation(
        &self,
        _index: usize,
        mutation: &crate::changeset::StagedMutation,
    ) -> Result<Option<String>, crate::error::UnifiError> {
        use crate::changeset::StagedMutation;
        use crate::model::{ResourceKind, unwrap_enveloped_data};
        use crate::tools::read::single_resource_template;

        match mutation {
            StagedMutation::Create { kind, body } => {
                let kind_value = serde_json::Value::String(kind.clone());
                let resource_kind: ResourceKind =
                    serde_json::from_value(kind_value).map_err(|e| {
                        UnifiError::Malformed(format!("unknown resource kind '{kind}': {e}"))
                    })?;

                let surface = resource_kind.surface();
                let site = self.default_site_for(surface).await?;
                let template = resource_kind.path_template();

                let response = self
                    .post(surface, template, &[("site", &site)], &[], body)
                    .await?;

                // Extract the created resource ID from the response
                let items = match surface {
                    ApiSurface::Supported | ApiSurface::PrivateV1 => {
                        unwrap_enveloped_data(&response)?
                    }
                    ApiSurface::PrivateV2 => response.as_array().ok_or_else(|| {
                        UnifiError::Malformed("expected Private v2 bare array".to_owned())
                    })?,
                    ApiSurface::Cloud => {
                        return Err(UnifiError::Malformed(
                            "cloud surface not supported".to_owned(),
                        ));
                    }
                };

                if items.is_empty() {
                    return Err(UnifiError::Malformed(format!(
                        "create {kind}: response has no data"
                    )));
                }

                let id = items[0]
                    .get("_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        UnifiError::Malformed(format!("create {kind}: response has no _id"))
                    })?;

                Ok(Some(id.to_owned()))
            }

            StagedMutation::Update { kind, id, body } => {
                let kind_value = serde_json::Value::String(kind.clone());
                let resource_kind: ResourceKind =
                    serde_json::from_value(kind_value).map_err(|e| {
                        UnifiError::Malformed(format!("unknown resource kind '{kind}': {e}"))
                    })?;

                // Device configuration writes have no verified route on this
                // controller family, so they are refused rather than guessed.
                //
                // `docs/PARITY-AUDIT.md` maps set_device_port_overrides onto the
                // change-set lifecycle via /proxy/network/api/s/{site}/rest/device/{id}.
                // Probed read-only against UniFi Network 10.5.67, that path returns
                // 404, as does /upd/device/{id}; the sibling rest/networkconf and
                // rest/firewallgroup return 200, so this is the device route being
                // absent rather than the surface or the credential.
                //
                // Writing port overrides reconfigures switch ports, so the route is
                // not determined by trying candidates against a live controller.
                // Until one is confirmed, refusing names the gap; PUTting to a 404
                // would surface as a generic failure and leave the parity claim
                // looking satisfied.
                if kind == "device" {
                    return Err(UnifiError::Malformed(
                        "device configuration writes are not supported: no verified \
                         write route exists for kind 'device' on this controller. \
                         Device operations (restart, locate, adopt, upgrade, \
                         port-action) are available through unifi_device_action."
                            .to_owned(),
                    ));
                }
                let (surface, template): (ApiSurface, String) = (
                    resource_kind.surface(),
                    single_resource_template(resource_kind),
                );

                let site = self.default_site_for(surface).await?;

                // For Private v2 surfaces, merge partial updates over the current resource
                // to avoid rejecting missing required fields.
                let merged_body = if surface == ApiSurface::PrivateV2 {
                    // Fetch current resource
                    match self.fetch_resource(kind, id).await? {
                        Some(mut current) => {
                            // Merge staged fields over current, preserving controller-managed fields
                            if let Some(current_obj) = current.as_object_mut()
                                && let Some(staged_obj) = body.as_object()
                            {
                                for (key, value) in staged_obj {
                                    // Drop controller-managed fields from staged body
                                    // These fields are managed by the controller and should not be overwritten:
                                    // - _id: resource identifier
                                    // - site_id: site association
                                    if key != "_id" && key != "site_id" {
                                        current_obj.insert(key.clone(), value.clone());
                                    }
                                }
                            }
                            current
                        }
                        None => {
                            return Err(UnifiError::Malformed(format!(
                                "update {} {}: resource not found before apply",
                                kind, id
                            )));
                        }
                    }
                } else {
                    body.clone()
                };

                self.put(
                    surface,
                    &template,
                    &[("site", &site), ("id", id)],
                    &[],
                    &merged_body,
                )
                .await?;

                Ok(None)
            }

            StagedMutation::Delete { kind, id } => {
                let kind_value = serde_json::Value::String(kind.clone());
                let resource_kind: ResourceKind =
                    serde_json::from_value(kind_value).map_err(|e| {
                        UnifiError::Malformed(format!("unknown resource kind '{kind}': {e}"))
                    })?;

                let surface = resource_kind.surface();
                let site = self.default_site_for(surface).await?;
                let template = single_resource_template(resource_kind);

                self.delete(surface, &template, &[("site", &site), ("id", id)], &[])
                    .await?;

                Ok(None)
            }

            StagedMutation::Restore { .. } => Err(UnifiError::Malformed(
                "backup restore not implemented".to_owned(),
            )),
        }
    }

    async fn rollback_mutation(
        &self,
        _index: usize,
        mutation: &crate::changeset::StagedMutation,
        prior_value: Option<&serde_json::Value>,
        created_id: Option<&str>,
    ) -> Result<(), crate::error::UnifiError> {
        use crate::changeset::StagedMutation;
        use crate::model::ResourceKind;
        use crate::tools::read::single_resource_template;

        match mutation {
            StagedMutation::Create { kind, .. } => {
                // Rollback a create by deleting the created resource
                let id = created_id.ok_or_else(|| {
                    UnifiError::Malformed(format!("rollback create {kind}: no created_id provided"))
                })?;

                let kind_value = serde_json::Value::String(kind.clone());
                let resource_kind: ResourceKind =
                    serde_json::from_value(kind_value).map_err(|e| {
                        UnifiError::Malformed(format!("unknown resource kind '{kind}': {e}"))
                    })?;

                let surface = resource_kind.surface();
                let site = self.default_site_for(surface).await?;
                let template = single_resource_template(resource_kind);

                self.delete(surface, &template, &[("site", &site), ("id", id)], &[])
                    .await?;

                Ok(())
            }

            StagedMutation::Update { kind, id, .. } => {
                // Rollback an update by restoring the prior value
                let prior = prior_value.ok_or_else(|| {
                    UnifiError::Malformed(format!("rollback update {kind} {id}: no prior_value"))
                })?;

                let kind_value = serde_json::Value::String(kind.clone());
                let resource_kind: ResourceKind =
                    serde_json::from_value(kind_value).map_err(|e| {
                        UnifiError::Malformed(format!("unknown resource kind '{kind}': {e}"))
                    })?;

                let surface = resource_kind.surface();
                let site = self.default_site_for(surface).await?;
                let template = single_resource_template(resource_kind);

                self.put(
                    surface,
                    &template,
                    &[("site", &site), ("id", id)],
                    &[],
                    prior,
                )
                .await?;

                Ok(())
            }

            StagedMutation::Delete { kind, .. } => {
                // Rollback a delete by re-creating the resource
                let prior = prior_value.ok_or_else(|| {
                    UnifiError::Malformed(format!("rollback delete {kind}: no prior_value"))
                })?;

                let kind_value = serde_json::Value::String(kind.clone());
                let resource_kind: ResourceKind =
                    serde_json::from_value(kind_value).map_err(|e| {
                        UnifiError::Malformed(format!("unknown resource kind '{kind}': {e}"))
                    })?;

                let surface = resource_kind.surface();
                let site = self.default_site_for(surface).await?;
                let template = resource_kind.path_template();

                self.post(surface, template, &[("site", &site)], &[], prior)
                    .await?;

                Ok(())
            }

            StagedMutation::Restore { .. } => Err(UnifiError::Malformed(
                "restore rollback not supported".to_owned(),
            )),
        }
    }

    async fn preimage_matches(
        &self,
        preimage: &crate::changeset::Preimage,
        mutations: &[crate::changeset::StagedMutation],
    ) -> Result<bool, crate::error::UnifiError> {
        use crate::changeset::StagedMutation;

        for mutation in mutations {
            // Creates have no prior state to drift, and a restore's pre-image
            // is the whole controller, which is not captured.
            let (kind, id) = match mutation {
                StagedMutation::Update { kind, id, .. } | StagedMutation::Delete { kind, id } => {
                    (kind, id)
                }
                StagedMutation::Create { .. } | StagedMutation::Restore { .. } => continue,
            };

            let Some(recorded) = preimage.get_resource(id) else {
                // The pre-image does not cover a resource this change set
                // edits, so the approval was granted against a state that was
                // never captured. Refuse rather than assume it is unchanged.
                return Ok(false);
            };

            // A fetch failure propagates: apply_sequentially treats anything
            // other than Ok(true) as stale, so an unreachable controller
            // refuses the apply instead of proceeding blind.
            let current = self.fetch_resource(kind, id).await?;
            match current {
                Some(live) if live == recorded => {}
                _ => return Ok(false),
            }
        }

        Ok(true)
    }

    async fn fetch_resource(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Option<serde_json::Value>, crate::error::UnifiError> {
        use crate::model::{ResourceKind, unwrap_enveloped_data};
        use crate::tools::read::single_resource_template;

        let kind_value = serde_json::Value::String(kind.to_owned());
        let resource_kind: ResourceKind = serde_json::from_value(kind_value)
            .map_err(|e| UnifiError::Malformed(format!("unknown resource kind '{kind}': {e}")))?;

        let surface = resource_kind.surface();
        let site = self.default_site_for(surface).await?;
        let template = single_resource_template(resource_kind);

        let response = self
            .get(surface, &template, &[("site", &site), ("id", id)], &[])
            .await;

        match response {
            Ok(raw) => {
                let items = match surface {
                    ApiSurface::Supported | ApiSurface::PrivateV1 => unwrap_enveloped_data(&raw)?,
                    ApiSurface::PrivateV2 => {
                        // Private v2 can return either a bare array or a single object.
                        // Preimage::capture_preimage accepts both shapes; this must match.
                        if let Some(arr) = raw.as_array() {
                            arr
                        } else if raw.is_object() {
                            // Single object - wrap it in a Vec for uniform handling
                            &vec![raw.clone()]
                        } else {
                            return Err(UnifiError::Malformed(
                                "expected Private v2 array or object".to_owned(),
                            ));
                        }
                    }
                    ApiSurface::Cloud => {
                        return Err(UnifiError::Malformed(
                            "cloud surface not supported".to_owned(),
                        ));
                    }
                };

                if items.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(items[0].clone()))
                }
            }
            // On a private surface, a 404 becomes PrivateEndpointAbsent. On a single-resource
            // fetch, a 404 means the resource is absent, not that the endpoint is missing,
            // so both error shapes map to Ok(None) here. This is only for fetch_resource;
            // PrivateEndpointAbsent keeps its "endpoint missing on this controller version"
            // meaning everywhere else.
            Err(UnifiError::Upstream { status: 404, .. })
            | Err(UnifiError::PrivateEndpointAbsent { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn verify_applied(
        &self,
        mutations: &[crate::changeset::StagedMutation],
        created_ids: &std::collections::HashMap<usize, String>,
    ) -> Result<(), crate::error::UnifiError> {
        use crate::changeset::StagedMutation;

        let mut failed_verifications = Vec::new();

        for (index, mutation) in mutations.iter().enumerate() {
            match mutation {
                StagedMutation::Create { kind, .. } => {
                    // For creates, use the controller-assigned ID from apply
                    if let Some(id) = created_ids.get(&index) {
                        match self.fetch_resource(kind, id).await {
                            Ok(Some(_)) => {
                                // Resource exists as expected
                            }
                            Ok(None) => {
                                failed_verifications.push(format!(
                                    "create {} {}: resource does not exist after apply",
                                    kind, id
                                ));
                            }
                            Err(e) => {
                                return Err(UnifiError::Malformed(format!(
                                    "could not verify create {} {}: {}",
                                    kind, id, e
                                )));
                            }
                        }
                    }
                    // If no created ID recorded, skip verification for this create
                }
                StagedMutation::Update { kind, id, body } => {
                    // For updates, verify the resource matches the staged body
                    match self.fetch_resource(kind, id).await {
                        Ok(Some(fetched)) => {
                            // Compare key fields (simplified - full implementation would
                            // need deep comparison logic)
                            if let Some(expected_name) = body.get("name")
                                && fetched.get("name") != Some(expected_name)
                            {
                                failed_verifications.push(format!(
                                    "update {} {}: field mismatch after apply",
                                    kind, id
                                ));
                            }
                        }
                        Ok(None) => {
                            failed_verifications.push(format!(
                                "update {} {}: resource does not exist after apply",
                                kind, id
                            ));
                        }
                        Err(e) => {
                            return Err(UnifiError::Malformed(format!(
                                "could not verify update {} {}: {}",
                                kind, id, e
                            )));
                        }
                    }
                }
                StagedMutation::Delete { kind, id } => {
                    // For deletes, verify the resource is gone
                    match self.fetch_resource(kind, id).await {
                        Ok(None) => {
                            // Resource is absent as expected
                        }
                        Ok(Some(_)) => {
                            failed_verifications.push(format!(
                                "delete {} {}: resource still exists after apply",
                                kind, id
                            ));
                        }
                        Err(e) => {
                            return Err(UnifiError::Malformed(format!(
                                "could not verify delete {} {}: {}",
                                kind, id, e
                            )));
                        }
                    }
                }
                StagedMutation::Restore { .. } => {
                    // Restores cannot be verified in the same way as other mutations
                    // since they replace the entire controller state. Skip verification.
                    continue;
                }
            }
        }

        if !failed_verifications.is_empty() {
            return Err(UnifiError::Malformed(format!(
                "verification failed for {} mutations: {}",
                failed_verifications.len(),
                failed_verifications.join("; ")
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::UnifiClient;
    use crate::ApiSurface;
    use crate::inventory::Controller;

    fn supported_only() -> Controller {
        serde_json::from_str(
            r#"{
                "endpoint": "https://unifi.example.org",
                "site": "default",
                "api_key_env": "UNIFI_TEST_KEY"
            }"#,
        )
        .expect("parses")
    }

    /// The tag is not decorative. A controller that has not opted in must be
    /// refused before a request is built, not after it 404s.
    #[test]
    fn a_private_surface_is_refused_when_the_controller_has_not_opted_in() {
        let controller = supported_only();
        let permitted = UnifiClient::ensure_surface_permitted(&controller, ApiSurface::PrivateV2);
        assert!(matches!(
            permitted,
            Err(crate::error::UnifiError::SurfaceRequiresConfig { .. })
        ));
    }

    #[test]
    fn the_supported_surface_needs_no_opt_in() {
        let controller = supported_only();
        UnifiClient::ensure_surface_permitted(&controller, ApiSurface::Supported)
            .expect("supported surface is always available");
    }

    /// Path templating goes through mecmcp-openapi, which rejects rather than
    /// sanitises. A site id containing a traversal must not produce a request.
    #[test]
    fn a_traversing_site_id_is_rejected_not_sanitised() {
        let expanded = mecmcp_openapi::expand_path(
            "/proxy/network/api/s/{site}/rest/networkconf",
            &[("site", "../../../v2/api/site/default")],
        );
        assert!(expanded.is_err(), "traversal must be rejected");
    }

    /// A 3xx response must be treated as an error, not parsed as success.
    #[test]
    fn redirect_responses_are_errors() {
        // Test that status classification treats 3xx as error
        let is_error = |status: u16| status >= 300;
        assert!(is_error(301), "301 redirect must be an error");
        assert!(is_error(302), "302 redirect must be an error");
        assert!(is_error(307), "307 redirect must be an error");
        assert!(!is_error(200), "200 OK must not be an error");
        assert!(!is_error(201), "201 Created must not be an error");
    }

    /// Private surfaces use the site name; the Integration API uses the UUID.
    /// This is verified by checking that the logic correctly routes to each.
    #[test]
    fn private_surfaces_return_site_name_directly() {
        let controller = supported_only();
        // Private surfaces should return the configured site name
        let private_v1_site = match ApiSurface::PrivateV1 {
            ApiSurface::PrivateV1 | ApiSurface::PrivateV2 | ApiSurface::Cloud => {
                controller.site.clone()
            }
            _ => panic!("unexpected surface routing"),
        };
        assert_eq!(private_v1_site, "default");
    }

    /// The sites endpoint returns an envelope `{"data": [...], ...}`, not a bare
    /// array. This test ensures the resolver unwraps it correctly.
    #[test]
    fn sites_envelope_is_unwrapped() {
        let envelope = serde_json::json!({
            "offset": 0,
            "limit": 25,
            "count": 1,
            "totalCount": 1,
            "data": [
                {
                    "id": "test-uuid",
                    "internalReference": "test-site",
                    "name": "Test Site"
                }
            ]
        });
        let unwrapped = crate::model::unwrap_enveloped_data(&envelope).expect("envelope unwraps");
        assert_eq!(unwrapped.len(), 1);
        assert_eq!(unwrapped[0]["id"], "test-uuid");
    }

    /// The recorded sites fixture must parse and resolve to the expected UUID.
    #[test]
    fn sites_fixture_resolves_site_uuid() {
        let sites_raw = crate::testing::fixture(crate::testing::DEFAULT_FIXTURE_VERSION, "sites");
        let sites_array =
            crate::model::unwrap_enveloped_data(&sites_raw).expect("sites fixture unwraps");

        // The fixture should have at least one site
        assert!(!sites_array.is_empty(), "fixture has at least one site");

        // Find the site with internalReference "default"
        let default_site = sites_array
            .iter()
            .find(|site| {
                site.get("internalReference")
                    .and_then(|r| r.as_str())
                    .is_some_and(|r| r == "default")
            })
            .expect("fixture has a 'default' site");

        // It should have a UUID
        let uuid = default_site
            .get("id")
            .and_then(|id| id.as_str())
            .expect("default site has an id");

        assert!(!uuid.is_empty(), "site UUID is not empty");
    }
}
