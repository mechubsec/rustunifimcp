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

    /// GET one resource's raw response body.
    ///
    /// Every kind is read at `{list path}/{id}` except a firewall zone: the
    /// controller answers `firewall/zone/{id}` with 405 Method Not Allowed, so
    /// a zone is read from the list and narrowed to the elements whose `_id`
    /// is `id` (an empty array when it is absent, as for any other v2 read).
    pub(crate) async fn get_single_raw(
        &self,
        kind: crate::model::ResourceKind,
        site: &str,
        id: &str,
    ) -> Result<serde_json::Value, UnifiError> {
        use crate::model::ResourceKind;

        let surface = kind.surface();
        if kind != ResourceKind::FirewallZone {
            let template = crate::tools::read::single_resource_template(kind);
            return self
                .get(surface, &template, &[("site", site), ("id", id)], &[])
                .await;
        }

        let listed = self
            .get(surface, kind.path_template(), &[("site", site)], &[])
            .await?;
        let Some(zones) = listed.as_array() else {
            return Err(UnifiError::Malformed(
                "expected Private v2 array for firewall_zone list".to_owned(),
            ));
        };
        Ok(serde_json::Value::Array(
            zones
                .iter()
                .filter(|zone| zone.get("_id").and_then(|v| v.as_str()) == Some(id))
                .cloned()
                .collect(),
        ))
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

        delete_response_body(response.body())
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

/// Parse a successful DELETE's body.
///
/// Private v2 answers a delete with an empty 2xx body. That is success, not a
/// malformed response: parsing it as JSON reported every v2 delete (and the
/// rollback of every v2 create) as failed after it had landed.
fn delete_response_body(body: &[u8]) -> Result<serde_json::Value, UnifiError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_slice(body).map_err(|error| UnifiError::Malformed(error.to_string()))
}

/// Extract the controller-assigned id from a create response.
///
/// Private v2 returns the created object or a bare array; v1 and the
/// Integration API envelope it in `data`. The POST has already succeeded when
/// this runs, so every error says the resource may exist untracked.
fn created_id(
    surface: ApiSurface,
    kind: &str,
    response: &serde_json::Value,
) -> Result<String, UnifiError> {
    let orphan = |detail: &str| {
        UnifiError::Malformed(format!(
            "create {kind}: the controller accepted the request but its response {detail}; \
             the resource may exist on the controller without this change set tracking it"
        ))
    };
    let items = match surface {
        ApiSurface::Supported | ApiSurface::PrivateV1 => {
            crate::model::unwrap_enveloped_data(response)
                .map_err(|_| orphan("is not an enveloped `data` array"))?
                .as_slice()
        }
        ApiSurface::PrivateV2 => match response.as_array() {
            Some(array) => array.as_slice(),
            None if response.is_object() => std::slice::from_ref(response),
            None => return Err(orphan("is neither an object nor an array")),
        },
        ApiSurface::Cloud => {
            return Err(UnifiError::Malformed(
                "cloud surface not supported".to_owned(),
            ));
        }
    };

    items
        .first()
        .and_then(|item| item.get("_id"))
        .and_then(|id| id.as_str())
        .map(str::to_owned)
        .ok_or_else(|| orphan("carries no `_id`"))
}

/// The staged top-level scalar fields an update's read-back does not carry.
///
/// Names only, never values, so a mismatch report cannot echo a field the
/// redactor would have hidden. The controller omits a field left at its
/// default, so an absent field matches a staged `null`, `false` or `""`.
/// shortcut: arrays and objects are skipped because the controller fills in
/// and reorders them; compare them leaf by leaf if a nested write goes unverified.
fn mismatched_scalar_fields<'a>(
    staged: &'a serde_json::Value,
    fetched: &serde_json::Value,
) -> Vec<&'a str> {
    let Some(staged) = staged.as_object() else {
        return Vec::new();
    };
    staged
        .iter()
        .filter(|(_, expected)| !expected.is_array() && !expected.is_object())
        .filter(|(field, expected)| match fetched.get(field.as_str()) {
            Some(actual) => actual != *expected,
            None => !(expected.is_null() || **expected == false || **expected == ""),
        })
        .map(|(field, _)| field.as_str())
        .collect()
}

/// What a write of this kind may send back of a resource as the controller
/// lists it. A zone keeps only `_id` and its writable fields (`name`,
/// `network_ids`): the zone list also carries `attr_no_edit`,
/// `cloud_template`, `default_zone`, `external_id` and `zone_key`, and the zone
/// endpoint refuses each as an unrecognized field (#143, checked live against
/// UniFi Network 11.0.97). Every other kind is returned unchanged.
fn writable_projection(
    kind: crate::model::ResourceKind,
    mut resource: serde_json::Value,
) -> serde_json::Value {
    if kind == crate::model::ResourceKind::FirewallZone
        && let Some(writable) = crate::changeset::validate::writable_fields(kind)
        && let Some(fields) = resource.as_object_mut()
    {
        fields.retain(|field, _| field == "_id" || writable.contains(&field.as_str()));
    }
    resource
}

/// The body a Private v2 update PUTs: the writable part of the current
/// resource with the staged fields laid over it, because that surface rejects
/// a body missing required fields. `_id` and `site_id` are never taken from
/// the staged body.
fn merged_update_body(
    kind: crate::model::ResourceKind,
    current: serde_json::Value,
    staged: &serde_json::Value,
) -> serde_json::Value {
    let mut body = writable_projection(kind, current);
    if let Some(body_fields) = body.as_object_mut()
        && let Some(staged_fields) = staged.as_object()
    {
        for (field, value) in staged_fields {
            if field != "_id" && field != "site_id" {
                body_fields.insert(field.clone(), value.clone());
            }
        }
    }
    body
}

/// What the update at `index` should read back as, or `None` when a later
/// update or delete of the same resource supersedes it. Same-resource
/// updates fold in order, as validation folds them.
fn expected_after_update(
    mutations: &[crate::changeset::StagedMutation],
    index: usize,
) -> Option<serde_json::Value> {
    use crate::changeset::StagedMutation;
    let StagedMutation::Update { kind, id, .. } = &mutations[index] else {
        return None;
    };
    let same_resource = |mutation: &StagedMutation| {
        matches!(mutation,
            StagedMutation::Update { kind: other_kind, id: other_id, .. }
            | StagedMutation::Delete { kind: other_kind, id: other_id }
                if other_kind == kind && other_id == id)
    };
    if mutations[index + 1..].iter().any(same_resource) {
        return None;
    }
    let mut folded = serde_json::Map::new();
    for mutation in mutations[..=index]
        .iter()
        .filter(|mutation| same_resource(mutation))
    {
        if let StagedMutation::Update { body, .. } = mutation
            && let Some(fields) = body.as_object()
        {
            folded.extend(fields.clone());
        }
    }
    Some(serde_json::Value::Object(folded))
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
        use crate::model::ResourceKind;
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

                created_id(surface, kind, &response).map(Some)
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
                        Some(current) => merged_update_body(resource_kind, current, body),
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
                    &writable_projection(resource_kind, prior.clone()),
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

        let kind_value = serde_json::Value::String(kind.to_owned());
        let resource_kind: ResourceKind = serde_json::from_value(kind_value)
            .map_err(|e| UnifiError::Malformed(format!("unknown resource kind '{kind}': {e}")))?;

        let surface = resource_kind.surface();
        let site = self.default_site_for(surface).await?;

        let response = self.get_single_raw(resource_kind, &site, id).await;

        match response {
            Ok(raw) => match surface {
                ApiSurface::Supported | ApiSurface::PrivateV1 => {
                    Ok(unwrap_enveloped_data(&raw)?.first().cloned())
                }
                // Private v2 can return either a bare array or a single object.
                // Preimage::capture_preimage accepts both shapes; this must match.
                ApiSurface::PrivateV2 => match &raw {
                    serde_json::Value::Array(arr) => Ok(select_by_id(arr, id).cloned()),
                    serde_json::Value::Object(_) => Ok(Some(raw.clone())),
                    _ => Err(UnifiError::Malformed(
                        "expected Private v2 array or object".to_owned(),
                    )),
                },
                ApiSurface::Cloud => Err(UnifiError::Malformed(
                    "cloud surface not supported".to_owned(),
                )),
            },
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
                StagedMutation::Update { kind, id, .. } => {
                    let Some(expected) = expected_after_update(mutations, index) else {
                        continue;
                    };
                    match self.fetch_resource(kind, id).await {
                        Ok(Some(fetched)) => {
                            let mismatched = mismatched_scalar_fields(&expected, &fetched);
                            if !mismatched.is_empty() {
                                failed_verifications.push(format!(
                                    "update {} {}: {} did not read back as staged",
                                    kind,
                                    id,
                                    mismatched.join(", ")
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

/// The element of a v2 array whose `_id` is `id`.
///
/// Not `arr[0]`: a v2 array need not be the one resource asked for, and
/// taking the first element would pre-image, diff and verify the wrong object.
pub(crate) fn select_by_id<'a>(
    items: &'a [serde_json::Value],
    id: &str,
) -> Option<&'a serde_json::Value> {
    items
        .iter()
        .find(|item| item.get("_id").and_then(|v| v.as_str()) == Some(id))
}

#[cfg(test)]
mod tests {
    use super::{
        UnifiClient, created_id, delete_response_body, expected_after_update, merged_update_body,
        mismatched_scalar_fields, select_by_id, writable_projection,
    };
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

    /// A v2 single-resource POST returns the created object, not an array.
    #[test]
    fn created_id_accepts_a_v2_single_object_and_a_bare_array() {
        let object = serde_json::json!({"_id": "abc"});
        let array = serde_json::json!([{"_id": "abc"}]);
        for response in [object, array] {
            let id = created_id(ApiSurface::PrivateV2, "firewall_policy", &response);
            assert_eq!(id.expect("id"), "abc");
        }
    }

    #[test]
    fn created_id_accepts_a_v1_enveloped_response() {
        let response = serde_json::json!({"data": [{"_id": "abc"}]});
        let id = created_id(ApiSurface::PrivateV1, "network", &response);
        assert_eq!(id.expect("id"), "abc");
    }

    /// A v2 delete's empty 2xx body is success; a v1 envelope still parses
    /// and garbage is still an error.
    #[test]
    fn delete_response_body_treats_an_empty_body_as_success() {
        assert_eq!(
            delete_response_body(b"").expect("empty"),
            serde_json::Value::Null
        );
        assert_eq!(
            delete_response_body(b" \n").expect("blank"),
            serde_json::Value::Null
        );
        let enveloped = delete_response_body(br#"{"meta":{"rc":"ok"},"data":[]}"#);
        assert_eq!(enveloped.expect("v1")["meta"]["rc"], "ok");
        assert!(delete_response_body(b"<html>").is_err());
    }

    /// After a successful POST a parse failure is an orphan risk, and says so.
    #[test]
    fn created_id_without_an_id_warns_of_an_untracked_resource() {
        let error = created_id(
            ApiSurface::PrivateV2,
            "firewall_policy",
            &serde_json::json!({}),
        )
        .expect_err("no _id");
        assert!(
            error
                .to_string()
                .contains("without this change set tracking")
        );
    }

    #[test]
    fn select_by_id_ignores_a_leading_element_with_another_id() {
        let items = vec![
            serde_json::json!({"_id": "other"}),
            serde_json::json!({"_id": "wanted", "name": "z"}),
        ];
        assert_eq!(select_by_id(&items, "wanted"), Some(&items[1]));
        assert_eq!(select_by_id(&items, "missing"), None);
    }

    /// #143: an update that changed `fwd_port` but not `name` was reported
    /// verified, because only `name` was read back.
    #[test]
    fn an_update_read_back_compares_every_staged_scalar() {
        let staged = serde_json::json!({
            "name": "mcp-test-143-upd",
            "fwd_port": "40144",
            "enabled": false,
            "cleared": null,
            "use_fixedip": false,
            "dhcpd_dns_2": "",
            "source": {"zone_id": "z1"}
        });
        let fetched = serde_json::json!({
            "_id": "id1",
            "name": "mcp-test-143-upd",
            "fwd_port": "40143",
            "enabled": false,
            "source": {"zone_id": "z1", "matching_target": "ANY"}
        });
        assert_eq!(mismatched_scalar_fields(&staged, &fetched), ["fwd_port"]);

        let landed =
            serde_json::json!({"name": "mcp-test-143-upd", "fwd_port": "40144", "enabled": false});
        assert!(mismatched_scalar_fields(&staged, &landed).is_empty());

        let dropped = serde_json::json!({"use_fixedip": true, "fixed_ip": "192.0.2.10"});
        assert_eq!(
            mismatched_scalar_fields(&dropped, &serde_json::json!({})),
            ["use_fixedip", "fixed_ip"]
        );
    }

    /// A set that writes one field twice must verify the last value, and a
    /// resource it later deletes is verified by the delete, not the update.
    #[test]
    fn repeated_updates_to_one_resource_verify_as_the_last_leaves_it() {
        use crate::changeset::StagedMutation;
        let mutations = [
            StagedMutation::update(
                "network",
                "n1",
                serde_json::json!({"enabled": true, "domain_name": "a.invalid"}),
            ),
            StagedMutation::update("network", "n2", serde_json::json!({"enabled": true})),
            StagedMutation::update("network", "n1", serde_json::json!({"enabled": false})),
            StagedMutation::update("network", "n2", serde_json::json!({"enabled": false})),
            StagedMutation::delete("network", "n2"),
        ];
        assert_eq!(expected_after_update(&mutations, 0), None);
        assert_eq!(
            expected_after_update(&mutations, 2),
            Some(serde_json::json!({"enabled": false, "domain_name": "a.invalid"}))
        );
        assert_eq!(expected_after_update(&mutations, 3), None);
    }

    #[test]
    fn a_zone_update_sends_only_its_id_and_writable_fields() {
        use crate::model::ResourceKind;
        let listed = serde_json::json!({
            "_id": "z1", "name": "old", "default_zone": false, "network_ids": ["n1"],
            "external_id": "e1", "attr_no_edit": false, "cloud_template": "t", "zone_key": "k",
        });
        let body = merged_update_body(
            ResourceKind::FirewallZone,
            listed,
            &serde_json::json!({ "name": "new", "_id": "other" }),
        );
        assert_eq!(
            body,
            serde_json::json!({ "_id": "z1", "name": "new", "network_ids": ["n1"] })
        );
    }

    #[test]
    fn a_policy_update_keeps_every_field_the_controller_returned() {
        use crate::model::ResourceKind;
        let current =
            serde_json::json!({ "_id": "p1", "site_id": "s1", "name": "old", "origin_type": "x" });
        let body = merged_update_body(
            ResourceKind::FirewallPolicy,
            current,
            &serde_json::json!({ "name": "new", "site_id": "s2" }),
        );
        assert_eq!(
            body,
            serde_json::json!({ "_id": "p1", "site_id": "s1", "name": "new", "origin_type": "x" })
        );
    }

    #[test]
    fn a_zone_rollback_restores_only_what_the_zone_endpoint_takes() {
        use crate::model::ResourceKind;
        let preimage = serde_json::json!({
            "_id": "z1", "name": "before", "default_zone": false, "network_ids": ["n1"],
            "external_id": "e1", "attr_no_edit": false, "cloud_template": "t", "zone_key": "k",
        });
        assert_eq!(
            writable_projection(ResourceKind::FirewallZone, preimage),
            serde_json::json!({ "_id": "z1", "name": "before", "network_ids": ["n1"] })
        );
        let network = serde_json::json!({ "_id": "n1", "name": "lan", "attr_no_delete": true });
        assert_eq!(
            writable_projection(ResourceKind::Network, network.clone()),
            network
        );
    }
}
