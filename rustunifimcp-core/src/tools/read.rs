//! The five read primitives.
//!
//! `unifi_list_resources` and `unifi_get_resource` are where the collapsed
//! surface lives: roughly 130 of the legacy server's tools were `list_x` /
//! `get_x` pairs differing only in the resource addressed, and they are variants
//! of `ResourceKind` here behind one documented envelope.

use crate::ApiSurface;
use crate::client::UnifiClient;
use crate::error::UnifiError;
use crate::model::ResourceKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Arguments to `unifi_list_resources`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListResourcesArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Which kind of resource to list.
    pub kind: ResourceKind,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Maximum items to return. Defaults to 200.
    ///
    /// A response holding exactly this many items may not be the whole
    /// collection — advance `offset` by `limit` to read the next page.
    #[serde(default)]
    pub limit: Option<u32>,
    /// Offset into the result set. Defaults to 0.
    #[serde(default)]
    pub offset: Option<u64>,
}

/// Arguments to `unifi_get_resource`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetResourceArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Which kind of resource to fetch.
    pub kind: ResourceKind,
    /// The resource identifier.
    pub id: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Subject for statistics queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StatsSubject {
    /// Site-wide statistics.
    Site,
    /// Per-device statistics.
    Device,
    /// Per-station (client) statistics.
    Station,
    /// Per-WLAN statistics.
    Wlan,
    /// Per-flow statistics.
    Flow,
    /// The controller event log.
    Event,
}

/// Arguments to `unifi_query_stats`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryStatsArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// What to query statistics for.
    pub subject: StatsSubject,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Start of the time window (Unix timestamp in seconds).
    #[serde(default)]
    pub start: Option<i64>,
    /// End of the time window (Unix timestamp in seconds).
    #[serde(default)]
    pub end: Option<i64>,
    /// Offset into the result set. Defaults to 0.
    ///
    /// The private stats surface returns its whole collection regardless of
    /// what is asked for, so the window named here is applied locally, after
    /// the fetch. A response holding exactly `limit` items may not be the
    /// whole collection -- advance `offset` by `limit` to read the next page.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Maximum items to return. Defaults to 200.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments to `unifi_search`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Free text query.
    pub query: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Maximum items to return per resource type.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments to `unifi_list_sites`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListSitesArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
}

/// Parses a raw resource response through the appropriate model parser.
///
/// This is where raw controller JSON becomes typed, filtered resources. Each
/// `ResourceKind` that has a parser is routed through it; kinds without one
/// return the raw payload.
fn parse_resource_list(
    kind: ResourceKind,
    raw: &serde_json::Value,
) -> Result<serde_json::Value, UnifiError> {
    use crate::model::device::parse_devices;
    use crate::model::firewall::{
        parse_firewall_groups, parse_firewall_policies, parse_firewall_rules, parse_firewall_zones,
    };
    use crate::model::network::{
        parse_dhcp_reservations, parse_networks, parse_port_profiles, parse_radius_profiles,
        parse_wlans,
    };
    use crate::model::portforward::parse_port_forwards;
    use crate::model::routing::{parse_routes, parse_traffic_routes};
    use crate::model::station::parse_stations;

    match kind {
        ResourceKind::Station => {
            let parsed = parse_stations(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::Device => {
            let parsed = parse_devices(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::Network => {
            let parsed = parse_networks(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::Wlan => {
            let parsed = parse_wlans(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::PortProfile => {
            let parsed = parse_port_profiles(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::DhcpReservation => {
            let parsed = parse_dhcp_reservations(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::FirewallPolicy => {
            let parsed = parse_firewall_policies(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::FirewallZone => {
            let parsed = parse_firewall_zones(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::FirewallGroup => {
            let parsed = parse_firewall_groups(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::TrafficRoute => {
            let parsed = parse_traffic_routes(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::RadiusProfile => {
            let parsed = parse_radius_profiles(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::FirewallRule => {
            let parsed = parse_firewall_rules(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::PortForward => {
            let parsed = parse_port_forwards(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        ResourceKind::StaticRoute => {
            let parsed = parse_routes(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
    }
}

/// List resources of one kind.
///
/// # Errors
///
/// Returns [`UnifiError::SurfaceRequiresConfig`] if the kind lives on a private
/// surface the controller has not opted into, or [`UnifiError::PrivateEndpointAbsent`]
/// if a private route has been removed by a controller upgrade.
pub async fn list_resources(
    client: &UnifiClient,
    args: &ListResourcesArgs,
) -> Result<serde_json::Value, UnifiError> {
    let page = mecmcp_openapi::page(
        args.offset.unwrap_or(0),
        u64::from(args.limit.unwrap_or(200)),
        mecmcp_openapi::PageLimits::default(),
    )
    .map_err(|error| UnifiError::Malformed(error.to_string()))?;

    let surface = args.kind.surface();
    let site = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        &client.default_site_for(surface).await?
    };

    let raw = client
        .get(
            surface,
            args.kind.path_template(),
            &[("site", site)],
            &[
                ("offset", &page.from.to_string()),
                ("limit", &page.size.to_string()),
            ],
        )
        .await?;

    let parsed = parse_resource_list(args.kind, &raw)?;
    let paged = apply_page_if_upstream_ignored_it(surface, &page, parsed);

    // Every resource kind is projected through its declared allowlist before
    // it reaches the model, in addition to (not instead of) the narrowing the
    // typed model parser already did. This is the explicit, testable
    // guarantee: see `crate::redact`.
    Ok(crate::redact::project_resource_list(args.kind, &paged))
}

/// Applies `offset`/`limit` locally on the surfaces that discard them.
///
/// `offset` and `limit` are sent as query parameters, but only the Integration
/// API acts on them. The two private surfaces accept the pair and return the
/// whole collection, so `limit` read as "maximum items to return" while
/// returning 230 firewall policies for `limit=1` — 226 KB, enough to overflow
/// an MCP client's tool-result budget with the very call made to avoid doing
/// so. See rustunifimcp#36.
///
/// The surface check is not defensive coding; it is required. `Supported` has
/// been verified to honour both parameters — `kind=device, limit=1` returns one
/// device, and adding `offset=1` returns a *different* one — so slicing its
/// response again would skip `offset` items on every call and silently drop
/// real results. Paging is applied here only where the controller did not
/// already do it.
///
/// A non-array response is returned untouched: it is either an error shape or a
/// parser result this function has no business reinterpreting.
fn apply_page_if_upstream_ignored_it(
    surface: ApiSurface,
    page: &mecmcp_openapi::Page,
    parsed: serde_json::Value,
) -> serde_json::Value {
    if surface == ApiSurface::Supported {
        return parsed;
    }
    let serde_json::Value::Array(items) = parsed else {
        return parsed;
    };
    let from = usize::try_from(page.from).unwrap_or(usize::MAX);
    let size = usize::try_from(page.size).unwrap_or(usize::MAX);
    serde_json::Value::Array(items.into_iter().skip(from).take(size).collect())
}

/// Parses a single-resource response through the appropriate model parser.
///
/// Controllers may return a single object or an enveloped object; this function
/// handles both by normalizing to the parsed model type.
fn parse_single_resource(
    kind: ResourceKind,
    raw: &serde_json::Value,
) -> Result<serde_json::Value, UnifiError> {
    use crate::model::device::parse_devices;
    use crate::model::firewall::{
        parse_firewall_groups, parse_firewall_policies, parse_firewall_rules, parse_firewall_zones,
    };
    use crate::model::network::{
        parse_dhcp_reservations, parse_networks, parse_port_profiles, parse_radius_profiles,
        parse_wlans,
    };
    use crate::model::portforward::parse_port_forwards;
    use crate::model::routing::{parse_routes, parse_traffic_routes};
    use crate::model::station::parse_stations;

    // A single-resource GET does not always answer in the collection's shape.
    // The Integration API returns the object itself, so `kind=device` and
    // `kind=station` reached the collection parsers as a bare object and failed
    // with "expected an envelope object" -- a message that reads like a
    // controller fault rather than a shape we never normalised. Normalise once
    // here instead of teaching every parser two shapes.
    let normalised;
    let raw = match raw.get("data") {
        // Already the collection shape.
        Some(data) if data.is_array() => raw,
        // The Integration API answers a single-resource GET with the object
        // under `data`, not a one-element array. Without this the parser
        // reports "invalid type: map, expected a sequence".
        Some(data) => {
            normalised = serde_json::json!({ "data": [data] });
            &normalised
        }
        None if raw.is_array() => raw,
        // A bare object, which is how the private surfaces answer.
        None => {
            normalised = match kind.surface() {
                ApiSurface::PrivateV2 => serde_json::json!([raw]),
                _ => serde_json::json!({ "data": [raw] }),
            };
            &normalised
        }
    };

    // Wrap in an envelope if needed, parse, then extract the single item
    let parsed_vec = match kind {
        ResourceKind::Station => {
            let parsed = parse_stations(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::Device => {
            let parsed = parse_devices(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::Network => {
            let parsed = parse_networks(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::Wlan => {
            let parsed = parse_wlans(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::PortProfile => {
            let parsed = parse_port_profiles(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::DhcpReservation => {
            let parsed = parse_dhcp_reservations(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::FirewallPolicy => {
            let parsed = parse_firewall_policies(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::FirewallZone => {
            let parsed = parse_firewall_zones(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::FirewallGroup => {
            let parsed = parse_firewall_groups(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::TrafficRoute => {
            let parsed = parse_traffic_routes(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::RadiusProfile => {
            let parsed = parse_radius_profiles(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::FirewallRule => {
            let parsed = parse_firewall_rules(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::PortForward => {
            let parsed = parse_port_forwards(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
        ResourceKind::StaticRoute => {
            let parsed = parse_routes(raw)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?
        }
    };

    // If parsing returned an array with one item, return that item; otherwise return as-is
    if let Some(arr) = parsed_vec.as_array()
        && arr.len() == 1
    {
        return Ok(arr[0].clone());
    }
    Ok(parsed_vec)
}

/// Get a single resource by ID.
///
/// # Errors
///
/// Returns [`UnifiError::SurfaceRequiresConfig`] if the kind lives on a private
/// surface the controller has not opted into, or [`UnifiError::PrivateEndpointAbsent`]
/// The path template addressing one resource of `kind` by id.
///
/// `{id}`, never `{}`: [`mecmcp_openapi::expand_path`] matches placeholders by
/// name, so an anonymous brace pair can never be supplied and the request fails
/// before it reaches the controller. This is a function rather than an inline
/// `format!` so the test exercises the same construction the request does.
#[must_use]
pub fn single_resource_template(kind: ResourceKind) -> String {
    format!("{}/{{id}}", kind.path_template())
}

/// if a private route has been removed by a controller upgrade.
pub async fn get_resource(
    client: &UnifiClient,
    args: &GetResourceArgs,
) -> Result<serde_json::Value, UnifiError> {
    let surface = args.kind.surface();
    let site = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        &client.default_site_for(surface).await?
    };

    let template = single_resource_template(args.kind);

    let raw = client
        .get(surface, &template, &[("site", site), ("id", &args.id)], &[])
        .await?;

    let parsed = parse_single_resource(args.kind, &raw)?;
    // `project_resource_list` rather than `project_resource`: `parsed` is
    // normally a single object, but `parse_single_resource` falls back to
    // returning an unreduced array for a shape it could not collapse to one
    // item, and `project_many` handles both without dropping the array to
    // `Null` the way a plain single-object projection would.
    Ok(crate::redact::project_resource_list(args.kind, &parsed))
}

/// Query statistics for a subject.
///
/// Statistics are served from the Private v1 API surface, which returns its
/// whole collection regardless of `offset`/`limit`, so the page named in
/// `args` is applied locally, after the fetch -- see
/// [`crate::tools::pagination`].
///
/// # Errors
///
/// Returns [`UnifiError::SurfaceRequiresConfig`] if the controller has not
/// opted into private API access, or [`UnifiError::Malformed`] if `offset`/
/// `limit` are invalid.
pub async fn query_stats(
    client: &UnifiClient,
    args: &QueryStatsArgs,
) -> Result<serde_json::Value, UnifiError> {
    let site = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        &client.default_site_for(ApiSurface::PrivateV1).await?
    };

    let endpoint = match args.subject {
        StatsSubject::Site => "/proxy/network/api/s/{site}/stat/sites",
        StatsSubject::Device => "/proxy/network/api/s/{site}/stat/device",
        StatsSubject::Station => "/proxy/network/api/s/{site}/stat/sta",
        StatsSubject::Wlan => "/proxy/network/api/s/{site}/stat/wlan",
        StatsSubject::Flow => "/proxy/network/api/s/{site}/stat/flow",
        StatsSubject::Event => "/proxy/network/api/s/{site}/stat/event",
    };

    let mut query = Vec::new();
    if let Some(start) = args.start {
        query.push(("start", start.to_string()));
    }
    if let Some(end) = args.end {
        query.push(("end", end.to_string()));
    }

    let query_refs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();

    let raw = client
        .get(
            ApiSurface::PrivateV1,
            endpoint,
            &[("site", site)],
            &query_refs,
        )
        .await?;

    let data = crate::model::unwrap_enveloped_data(&raw)?.clone();
    let page = crate::tools::pagination::paginate(data, args.offset, args.limit)?;
    let projected = project_stats(args.subject, &page.items)?;

    Ok(serde_json::json!({
        "data": projected,
        "offset": page.offset,
        "limit": page.limit,
        "total": page.total,
    }))
}

/// Items scanned per leg before `search` gives up and returns what it has.
///
/// Bounded so a search against a huge site cannot turn into an unbounded
/// scan; generous enough that a real UniFi deployment -- at most a few
/// thousand clients or devices per site -- is scanned in full.
const SEARCH_SCAN_CAP: usize = 5000;

/// Page size used when scanning a leg for search matches.
const SEARCH_PAGE_SIZE: u32 = 200;

/// One page of a collection `search` scans.
///
/// Exists so the scan-and-filter loop in [`scan_and_filter`] is testable
/// against a canned in-memory collection instead of a live controller. The
/// defect this fixes -- `unifi_search` matching only the first `limit` items
/// on the whole site -- was invisible to any test that fed [`filter_by_query`]
/// an already-truncated slice, because that function has always filtered
/// correctly over whatever it is given. The bug was in how much it was given.
trait PagedSource {
    /// Fetch one page, in the same "asked for `limit`, may return fewer"
    /// contract the Integration API honours.
    async fn fetch_page(
        &self,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<serde_json::Value>, UnifiError>;
}

/// A `PagedSource` over one Integration API collection endpoint.
struct IntegrationLeg<'a> {
    client: &'a UnifiClient,
    path: &'a str,
    site_uuid: &'a str,
}

impl PagedSource for IntegrationLeg<'_> {
    async fn fetch_page(
        &self,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<serde_json::Value>, UnifiError> {
        let raw = self
            .client
            .get(
                ApiSurface::Supported,
                self.path,
                &[("site", self.site_uuid)],
                &[
                    ("offset", &offset.to_string()),
                    ("limit", &limit.to_string()),
                ],
            )
            .await?;
        Ok(crate::model::unwrap_enveloped_data(&raw)?.clone())
    }
}

/// The result of scanning one leg: the matches found, and whether
/// [`SEARCH_SCAN_CAP`] cut the scan short before the whole collection was
/// seen.
struct ScanResult {
    /// Matches found within the items actually scanned.
    items: Vec<serde_json::Value>,
    /// `true` if the scan stopped at [`SEARCH_SCAN_CAP`] rather than running
    /// out of pages -- meaning items past the cap were never looked at, and a
    /// caller cannot conclude their query has no more matches on this leg.
    capped: bool,
}

/// Scan a whole collection, page by page, and filter it by `query`.
///
/// Scans the whole collection -- bounded by [`SEARCH_SCAN_CAP`] -- before
/// filtering, rather than filtering only the first page and calling it a
/// search. A caller looking for a client past the first [`SEARCH_PAGE_SIZE`]
/// clients on a large site must get a match, not a silent empty leg: the
/// Integration API honours `offset`/`limit` itself, so a search that sent
/// `limit=10` upstream and filtered only that page was searching the first
/// ten clients on the site, not the site.
async fn scan_and_filter<S: PagedSource>(
    source: &S,
    query: &str,
    limit: usize,
) -> Result<ScanResult, UnifiError> {
    let mut all = Vec::new();
    let mut offset = 0u64;
    let mut capped = false;
    loop {
        let page = source.fetch_page(offset, SEARCH_PAGE_SIZE).await?;
        let page_len = page.len();
        all.extend(page);
        if all.len() >= SEARCH_SCAN_CAP {
            capped = page_len >= SEARCH_PAGE_SIZE as usize;
            break;
        }
        if page_len < SEARCH_PAGE_SIZE as usize {
            break;
        }
        offset += u64::from(SEARCH_PAGE_SIZE);
    }
    Ok(ScanResult {
        items: filter_by_query(&all, query, limit),
        capped,
    })
}

/// Narrow a page of stats items to the fields the model may see.
///
/// `Device`, `Station`, and `Event` route through the typed models in
/// `model::stats` -- an allowlist by construction, since a struct with no
/// catch-all field silently drops anything it does not name. All three
/// parsers expect an enveloped `{"data": [...]}` shape, so `items` (already
/// sliced to the requested page by [`query_stats`]) is re-wrapped before
/// parsing. `Event` in particular could not use the shared crate's
/// denylist-and-shape scan the way `Site`/`Flow` below do: a UniFi event's
/// type discriminator lives in a field literally named `key`
/// (`"EVT_WU_Connected"`), which the scan denylists as an exact match to
/// catch WireGuard/API keys named plainly elsewhere -- it would have stripped
/// the one field that says what kind of event this is, on every event. The
/// typed model instead renames it to `event_type` on the way out (see
/// `model::stats::Event`), sidestepping the collision.
///
/// `Wlan` has no typed stats model, but `stat/wlan` answers with the same
/// shape as the `wlanconf` resource merged with runtime counters, so it
/// routes through `redact::project_resource_list(ResourceKind::Wlan, ..)` --
/// the same allowlist the config read path uses -- rather than the
/// denylist-and-shape scan: the scan alone cannot catch `x_iapp_key` (see the
/// allowlist's doc comment), and this endpoint carries that field in every
/// real response. Neither `Site` nor `Flow` has a comparable typed shape to
/// project through (their fields are aggregate counters that vary by
/// controller version), so those fall back to the shared crate's
/// denylist-and-shape scan, the defensive net rather than the strong
/// allowlist guarantee.
fn project_stats(
    subject: StatsSubject,
    items: &[serde_json::Value],
) -> Result<serde_json::Value, UnifiError> {
    use crate::model::stats::{parse_device_stats, parse_events, parse_station_stats};

    match subject {
        StatsSubject::Device => {
            let envelope = serde_json::json!({ "data": items });
            let parsed = parse_device_stats(&envelope)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        StatsSubject::Station => {
            let envelope = serde_json::json!({ "data": items });
            let parsed = parse_station_stats(&envelope)?;
            serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
        }
        StatsSubject::Event => {
            let envelope = serde_json::json!({ "data": items });
            let parsed = parse_events(&envelope)?;
            let mut projected =
                serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))?;
            // `msg` is unbounded controller free text (admin usernames,
            // source IPs, client hostnames, SSIDs) that the typed model
            // cannot narrow further without losing the description itself,
            // so run it through the denylist-and-shape scan as defence in
            // depth -- see `model::stats::Event`'s doc comment for why this
            // kind cannot use the scan for its `key`/`event_type` field
            // instead.
            crate::redact::redact_in_place(&mut projected);
            Ok(projected)
        }
        StatsSubject::Wlan => Ok(crate::redact::project_resource_list(
            crate::model::ResourceKind::Wlan,
            &serde_json::Value::Array(items.to_vec()),
        )),
        StatsSubject::Site | StatsSubject::Flow => Ok(crate::redact::redact_owned(
            &serde_json::Value::Array(items.to_vec()),
        )),
    }
}

/// Search across stations, devices, and sites.
///
/// Merges results from the Integration API's client and device endpoints and
/// the Private v1 site endpoint. If a leg is refused for surface-permission
/// reasons, the result carries `partial: true` and an `omitted` array naming
/// what was skipped. A smaller answer, clearly labelled, beats a wrong one.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was searched)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn search(
    client: &UnifiClient,
    args: &SearchArgs,
) -> Result<serde_json::Value, UnifiError> {
    let limit = args.limit.unwrap_or(10);

    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;

    let mut omitted = Vec::new();
    // Legs refused outright (permission/config), not merely capped. A capped
    // leg still searched (and matched over) thousands of items, so it must
    // not count toward "nothing was searched" below.
    let mut refused_legs = 0u8;
    let mut stations_results = Vec::new();
    let mut devices_results = Vec::new();
    let mut sites_results = Vec::new();

    // Search stations (clients) via Integration API, scanning the whole
    // collection rather than only the first page.
    match scan_and_filter(
        &IntegrationLeg {
            client,
            path: "/proxy/network/integration/v1/sites/{site}/clients",
            site_uuid: &site_uuid,
        },
        &args.query,
        limit as usize,
    )
    .await
    {
        Ok(result) => {
            let envelope = serde_json::json!({ "data": result.items });
            let parsed = crate::model::station::parse_stations(&envelope)?;
            stations_results = to_value_vec(&parsed)?;
            if result.capped {
                omitted.push(format!(
                    "stations: scanned first {SEARCH_SCAN_CAP} of \u{2265}{SEARCH_SCAN_CAP}; \
                     refine the query"
                ));
            }
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("stations: controller has Integration API disabled".to_owned());
            refused_legs += 1;
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("stations: token lacks required scope".to_owned());
            refused_legs += 1;
        }
        Err(e) => return Err(e),
    }

    // Search devices via Integration API, scanning the whole collection
    // rather than only the first page.
    match scan_and_filter(
        &IntegrationLeg {
            client,
            path: "/proxy/network/integration/v1/sites/{site}/devices",
            site_uuid: &site_uuid,
        },
        &args.query,
        limit as usize,
    )
    .await
    {
        Ok(result) => {
            let envelope = serde_json::json!({ "data": result.items });
            let parsed = crate::model::device::parse_devices(&envelope)?;
            devices_results = to_value_vec(&parsed)?;
            if result.capped {
                omitted.push(format!(
                    "devices: scanned first {SEARCH_SCAN_CAP} of \u{2265}{SEARCH_SCAN_CAP}; \
                     refine the query"
                ));
            }
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("devices: controller has Integration API disabled".to_owned());
            refused_legs += 1;
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("devices: token lacks required scope".to_owned());
            refused_legs += 1;
        }
        Err(e) => return Err(e),
    }

    // Search sites via the Integration API list `unifi_list_sites` reads.
    // Private v1 `/self` describes the logged-in admin, not the sites, and
    // never parsed as a `Site`.
    match client
        .get(
            ApiSurface::Supported,
            "/proxy/network/integration/v1/sites",
            &[],
            &[],
        )
        .await
    {
        Ok(sites) => {
            let parsed = crate::model::site::parse_sites(&sites)?;
            let values = to_value_vec(&parsed)?;
            sites_results = filter_by_query(&values, &args.query, limit as usize);
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("sites: controller has Integration API disabled".to_owned());
            refused_legs += 1;
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("sites: token lacks required scope".to_owned());
            refused_legs += 1;
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error. A capped leg is not a
    // refusal -- it searched (and matched over) thousands of items -- so it
    // must not count here.
    if refused_legs == 3 {
        return Err(UnifiError::Malformed(
            "all search legs refused: nothing was searched".to_owned(),
        ));
    }

    let partial = !omitted.is_empty();
    let results = serde_json::json!({
        "stations": stations_results,
        "devices": devices_results,
        "sites": sites_results,
        "partial": partial,
        "omitted": omitted,
    });

    Ok(results)
}

/// Serialize a `Vec<T>` of parsed, typed resources to a `Vec<Value>`.
///
/// `unifi_search` filters on the JSON rendering of each item, and it must
/// filter on the same narrowed shape `unifi_list_resources` returns -- the
/// typed model, not the raw controller payload it was fetched from -- or a
/// search result carries fields the equivalent list call would have dropped.
fn to_value_vec<T: serde::Serialize>(items: &[T]) -> Result<Vec<serde_json::Value>, UnifiError> {
    items
        .iter()
        .map(|item| serde_json::to_value(item).map_err(|e| UnifiError::Malformed(e.to_string())))
        .collect()
}

/// Filter results by a query string.
fn filter_by_query(
    items: &[serde_json::Value],
    query: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    let query_lower = query.to_lowercase();
    items
        .iter()
        .filter(|item| {
            let json_str = item.to_string().to_lowercase();
            json_str.contains(&query_lower)
        })
        .take(limit)
        .cloned()
        .collect()
}

/// List sites visible to this controller.
///
/// # Errors
///
/// Returns [`UnifiError`] when the sites endpoint cannot be reached or returns
/// an unexpected shape.
pub async fn list_sites(
    client: &UnifiClient,
    _args: &ListSitesArgs,
) -> Result<serde_json::Value, UnifiError> {
    let raw = client
        .get(
            ApiSurface::Supported,
            "/proxy/network/integration/v1/sites",
            &[],
            &[],
        )
        .await?;

    // Routed through the typed `Site` model rather than returned as the raw
    // controller payload: `Site` names only `id`, `internalReference`, and
    // `name`, which is itself an allowlist by construction.
    let parsed = crate::model::site::parse_sites(&raw)?;
    serde_json::to_value(parsed).map_err(|e| UnifiError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {

    /// No path in the crate may carry an anonymous `{}` placeholder.
    ///
    /// The first fix of this defect corrected `get_resource` and missed an
    /// identical construction in `changeset/preimage.rs`, which kept every
    /// pre-image capture failing -- and with it every change set that touches
    /// an existing resource. Fixing one occurrence of a defect is not the same
    /// as fixing the defect, so this sweeps the sources rather than trusting
    /// that the known sites are all of them.
    #[test]
    fn no_source_file_builds_a_path_with_an_anonymous_placeholder() {
        // Assembled at runtime so this assertion cannot match itself.
        let needle = format!("{}/{}{}\"", "format!(\"{}", "{", "{}}");
        for (name, source) in [
            ("tools/read.rs", include_str!("read.rs")),
            (
                "changeset/preimage.rs",
                include_str!("../changeset/preimage.rs"),
            ),
            ("changeset/apply.rs", include_str!("../changeset/apply.rs")),
            (
                "changeset/rollback.rs",
                include_str!("../changeset/rollback.rs"),
            ),
            ("client.rs", include_str!("../client.rs")),
        ] {
            assert!(
                !source.contains(&needle),
                "{name} builds a path with an anonymous placeholder, which \
                 expand_path can never fill"
            );
        }
    }

    /// Every single-resource GET path must actually expand.
    ///
    /// `get_resource` builds its path by appending an id segment to the kind's
    /// list template. That concatenation is invisible to the path-provenance
    /// test, which checks the constants only -- so an anonymous `{}` shipped
    /// here and made `unifi_get_resource` fail for every kind, on every
    /// controller, while the fixture tests stayed green. This expands the real
    /// template through the real expander, for all of `ResourceKind::ALL`.
    #[test]
    fn every_kind_expands_to_a_usable_single_resource_path() {
        for &kind in crate::model::ResourceKind::ALL {
            let template = super::single_resource_template(kind);
            let expanded =
                mecmcp_openapi::expand_path(&template, &[("site", "default"), ("id", "abc123")])
                    .unwrap_or_else(|error| {
                        panic!("{kind:?} single-resource path does not expand: {error}")
                    });
            assert!(
                expanded.ends_with("/abc123"),
                "{kind:?} expanded to {expanded}, which does not address the id"
            );
            assert!(
                !expanded.contains('{') && !expanded.contains('}'),
                "{kind:?} left an unexpanded placeholder: {expanded}"
            );
        }
    }

    use super::{GetResourceArgs, ListResourcesArgs, SearchArgs};
    use crate::error::UnifiError;
    use crate::model::ResourceKind;

    /// Unknown fields must be refused, not dropped. rust-proxmoxmcp shipped
    /// this as a fix (its "refuse unknown fields instead of silently dropping
    /// them" commit): a caller who misspells a filter should be told, not
    /// silently given unfiltered results.
    #[test]
    fn unknown_arguments_are_refused_not_dropped() {
        let raw = r#"{"controller":"home","kind":"network","limitt":5}"#;
        let parsed: Result<ListResourcesArgs, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "a misspelled argument must be an error");
    }

    #[test]
    fn every_resource_kind_round_trips_through_the_args_schema() {
        for kind in ResourceKind::ALL {
            let json = serde_json::to_string(kind).expect("serializes");
            let raw = format!(r#"{{"controller":"home","kind":{json}}}"#);
            let parsed: ListResourcesArgs =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
            assert_eq!(parsed.kind, *kind);
        }
    }

    #[test]
    fn get_resource_requires_an_id() {
        let raw = r#"{"controller":"home","kind":"network"}"#;
        let parsed: Result<GetResourceArgs, _> = serde_json::from_str(raw);
        assert!(parsed.is_err(), "get_resource without an id must not parse");
    }

    /// Verify SearchArgs structure for completeness.
    #[test]
    fn search_args_parses_all_fields() {
        let raw = r#"{"controller":"home","query":"test","site":"default","limit":5}"#;
        let parsed: SearchArgs = serde_json::from_str(raw).expect("valid SearchArgs");
        assert_eq!(parsed.controller, "home");
        assert_eq!(parsed.query, "test");
        assert_eq!(parsed.site, Some("default".to_owned()));
        assert_eq!(parsed.limit, Some(5));
    }

    /// `unifi_query_stats` must accept the pagination cursor it documents.
    #[test]
    fn query_stats_args_parses_the_pagination_cursor() {
        let raw = r#"{"controller":"home","subject":"device","offset":40,"limit":20}"#;
        let parsed: super::QueryStatsArgs = serde_json::from_str(raw).expect("valid args");
        assert_eq!(parsed.offset, Some(40));
        assert_eq!(parsed.limit, Some(20));
    }

    /// `unifi_query_stats(subject=event)` reaches the controller event log.
    #[test]
    fn query_stats_args_accepts_the_event_subject() {
        let raw = r#"{"controller":"home","subject":"event"}"#;
        let parsed: super::QueryStatsArgs = serde_json::from_str(raw).expect("valid args");
        assert_eq!(parsed.subject, super::StatsSubject::Event);
    }

    /// The controller event log must reach the model through the typed
    /// `model::stats::Event` parser, which renames the controller's `key`
    /// field to `event_type` -- a field literally named `key` would be
    /// redacted by the shared crate's denylist scan (see that struct's doc
    /// comment), so a bare pass-through here would silently drop the one
    /// field that says what kind of event this is.
    #[test]
    fn event_stats_survive_projection_with_the_key_field_renamed() {
        use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

        let raw = fixture(DEFAULT_FIXTURE_VERSION, "stat_event");
        let data = crate::model::unwrap_enveloped_data(&raw)
            .expect("envelope")
            .clone();

        let projected =
            super::project_stats(super::StatsSubject::Event, &data).expect("project events");
        let rendered = projected.to_string();
        assert!(
            rendered.contains("EVT_WU_Connected"),
            "the event's type must survive projection"
        );
        assert_eq!(
            projected[0]["event_type"], "EXAMPLE-EVT_WU_Connected",
            "the controller's `key` field must be renamed to `event_type`"
        );
        assert!(
            projected[0].get("key").is_none(),
            "the output must not carry a field literally named `key`"
        );
    }

    /// `msg` is unbounded controller free text the typed `Event` model
    /// cannot narrow further, so it must still go through the
    /// denylist-and-shape scan as defence in depth (Percy's F3): a
    /// secret-shaped value embedded in the message must not survive.
    #[test]
    fn event_msg_is_scanned_for_secret_shaped_content() {
        use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

        let raw = fixture(DEFAULT_FIXTURE_VERSION, "stat_event");
        let data = crate::model::unwrap_enveloped_data(&raw)
            .expect("envelope")
            .clone();

        let projected =
            super::project_stats(super::StatsSubject::Event, &data).expect("project events");
        let rendered = projected.to_string();
        assert!(
            !rendered.contains("EXAMPLE-event-secret-fake1-AQ=="),
            "a secret-shaped value in `msg` leaked through unscanned: {rendered}"
        );
    }

    /// Search result shape must include partial and omitted fields.
    #[test]
    fn search_result_carries_partial_metadata() {
        // Simulated partial result as search would return
        let partial_result = serde_json::json!({
            "stations": [],
            "devices": [],
            "sites": [],
            "partial": true,
            "omitted": ["sites: controller has Integration API disabled"]
        });

        assert_eq!(
            partial_result.get("partial").and_then(|v| v.as_bool()),
            Some(true)
        );
        let omitted = partial_result.get("omitted").and_then(|v| v.as_array());
        assert!(omitted.is_some(), "omitted field must be present");
        if let Some(arr) = omitted {
            assert_eq!(arr.len(), 1);
        }
    }

    /// A fake [`super::PagedSource`] over an in-memory collection, paging it
    /// the way the Integration API does: honours `offset`/`limit` for real,
    /// so it can stand in for a live controller in [`scan_and_filter`] tests.
    struct FakeSource {
        items: Vec<serde_json::Value>,
    }

    impl super::PagedSource for FakeSource {
        async fn fetch_page(
            &self,
            offset: u64,
            limit: u32,
        ) -> Result<Vec<serde_json::Value>, UnifiError> {
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(self.items.len());
            let end = start.saturating_add(limit as usize).min(self.items.len());
            Ok(self.items[start..end].to_vec())
        }
    }

    /// The reported defect: `unifi_search` matched only the first page of a
    /// leg's collection, so a match past item 10 -- or past
    /// `super::SEARCH_PAGE_SIZE` on a large site -- was never found.
    ///
    /// The fixture holds more items than one page, with every match sitting
    /// in the second page, so this fails against the old code (which asked
    /// upstream for exactly `limit` items and filtered only those) and passes
    /// against `scan_and_filter`, which scans the whole collection first.
    #[tokio::test]
    async fn search_finds_matches_past_the_first_page() {
        let page_size = super::SEARCH_PAGE_SIZE as usize;
        let total = page_size * 2 + 50;

        let items: Vec<serde_json::Value> = (0..total)
            .map(|i| {
                // Every match lives in the second page or later, well past
                // where the old, unpaginated fetch ever looked.
                let name = if i >= page_size {
                    format!("special-widget-{i}")
                } else {
                    format!("ordinary-device-{i}")
                };
                serde_json::json!({ "name": name })
            })
            .collect();
        let matching_count = total - page_size;

        let source = FakeSource { items };

        // limit above the number of matches: every match must come back.
        let scan = super::scan_and_filter(&source, "special-widget", matching_count + 10)
            .await
            .expect("scan succeeds");
        assert_eq!(
            scan.items.len(),
            matching_count,
            "not every match past the first page was found"
        );
        assert!(!scan.capped, "the whole collection fit under the cap");

        // limit below the number of matches: capped, but not empty.
        let limited = super::scan_and_filter(&source, "special-widget", 10)
            .await
            .expect("scan succeeds");
        assert_eq!(limited.items.len(), 10, "limit must still bound the output");
        for item in &limited.items {
            assert!(
                item["name"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("special-widget"),
                "a non-matching item leaked through the filter"
            );
        }
    }

    /// A leg with nothing beyond one page must not scan forever, and must
    /// still find matches within that single page.
    #[tokio::test]
    async fn search_stops_after_one_short_page() {
        let items: Vec<serde_json::Value> = (0..5)
            .map(|i| serde_json::json!({ "name": format!("widget-{i}") }))
            .collect();
        let source = FakeSource { items };

        let scan = super::scan_and_filter(&source, "widget", 100)
            .await
            .expect("scan succeeds");
        assert_eq!(scan.items.len(), 5);
        assert!(
            !scan.capped,
            "a short final page means the collection is exhausted"
        );
    }

    /// Percy review F3 (MEC-549): hitting `SEARCH_SCAN_CAP` used to be silent
    /// -- `search` reported `partial: false` on a site with more items than
    /// the cap, even though it never looked at the rest. A leg whose scan
    /// stops at the cap on a still-full page must say so.
    #[tokio::test]
    async fn a_scan_that_hits_the_cap_reports_itself_as_capped() {
        let total = super::SEARCH_SCAN_CAP + 1;
        let items: Vec<serde_json::Value> = (0..total)
            .map(|i| serde_json::json!({ "name": format!("widget-{i}") }))
            .collect();
        let source = FakeSource { items };

        let scan = super::scan_and_filter(&source, "widget", total)
            .await
            .expect("scan succeeds");
        assert!(
            scan.capped,
            "a collection larger than SEARCH_SCAN_CAP must report itself as capped"
        );
        assert!(
            scan.items.len() <= super::SEARCH_SCAN_CAP,
            "the scan must not exceed the cap"
        );
    }

    /// A collection whose scan ends on a short final page is not capped even
    /// when there happen to be more matches than the caller's `limit`: the
    /// source ran out of items on its own, distinct from the scan giving up
    /// at [`super::SEARCH_SCAN_CAP`].
    #[tokio::test]
    async fn ending_on_a_short_page_below_the_cap_is_not_capped() {
        let total = super::SEARCH_SCAN_CAP - 1;
        let items: Vec<serde_json::Value> = (0..total)
            .map(|i| serde_json::json!({ "name": format!("widget-{i}") }))
            .collect();
        let source = FakeSource { items };

        let scan = super::scan_and_filter(&source, "widget", total)
            .await
            .expect("scan succeeds");
        assert!(
            !scan.capped,
            "the collection was exhausted below the cap via a short final page"
        );
    }

    /// The all-legs-refused error message must be recognizable.
    #[test]
    fn search_all_legs_refused_error_is_descriptive() {
        let error =
            UnifiError::Malformed("all search legs refused: nothing was searched".to_owned());
        let error_text = error.to_string();
        assert!(
            error_text.contains("all search legs refused"),
            "error must clearly state nothing was searched: {error_text}"
        );
    }

    /// Every ResourceKind must route through a model parser.
    ///
    /// This is the coverage test that would have caught the DHCP reservation
    /// bypass: every kind must have a parser wired in parse_resource_list, or
    /// appear in an explicit commented list of kinds with no parser yet (there
    /// are none currently — all kinds have parsers).
    ///
    /// Runs over every fixture set present: the committed synthetic one, so CI
    /// exercises it, plus any recorded controller versions, so a developer
    /// holding a live capture still exercises the parsers against real data.
    ///
    /// A recorded version may legitimately have no fixture for a kind: the
    /// capture script writes an `.absent` marker instead when the route 404s,
    /// which is how the version matrix asserts drift as a fact. Those pairs
    /// are skipped. The synthetic set carries every kind and is never absent,
    /// so a missing synthetic fixture still fails here.
    #[test]
    fn every_resource_kind_has_a_parser_wired() {
        use crate::model::ResourceKind;
        use crate::testing::{SYNTHETIC_FIXTURE_VERSION, fixture, fixture_versions, is_absent};

        for version in fixture_versions() {
            for kind in ResourceKind::ALL {
                let fixture_name = match kind {
                    ResourceKind::Station => "clients",
                    ResourceKind::Device => "devices",
                    ResourceKind::Network => "networkconf",
                    ResourceKind::Wlan => "wlanconf",
                    ResourceKind::PortProfile => "portconf",
                    ResourceKind::DhcpReservation => "user",
                    ResourceKind::FirewallGroup => "firewallgroup",
                    ResourceKind::RadiusProfile => "radiusprofile",
                    ResourceKind::FirewallPolicy => "policies",
                    ResourceKind::FirewallZone => "zones",
                    ResourceKind::TrafficRoute => "traffic_routes",
                    ResourceKind::FirewallRule => "firewallrule",
                    ResourceKind::PortForward => "portforward",
                    ResourceKind::StaticRoute => "routing",
                };

                if is_absent(&version, fixture_name) {
                    assert_ne!(
                        version, SYNTHETIC_FIXTURE_VERSION,
                        "the synthetic set records no endpoint as absent"
                    );
                    continue;
                }

                let raw = fixture(&version, fixture_name);
                super::parse_resource_list(*kind, &raw).unwrap_or_else(|e| {
                    panic!("{kind:?} parser not wired or failed on {version}: {e}")
                });
            }
        }
    }

    /// DHCP reservations must return strictly fewer rows than the raw /rest/user payload.
    ///
    /// This is the regression test for the architectural gap: parse_dhcp_reservations
    /// filters to `use_fixedip: true`, but list_resources was bypassing the parser,
    /// so callers got all 260 user records instead of the 46 actual reservations.
    #[test]
    fn dhcp_reservation_list_is_filtered() {
        use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

        let raw = fixture(DEFAULT_FIXTURE_VERSION, "user");
        let total_users = crate::model::unwrap_enveloped_data(&raw)
            .expect("envelope")
            .len();

        let parsed = super::parse_resource_list(ResourceKind::DhcpReservation, &raw)
            .expect("parse dhcp reservations");
        let parsed_count = parsed.as_array().expect("parsed result is an array").len();

        assert!(
            parsed_count < total_users,
            "parse_dhcp_reservations must filter: got {parsed_count}, expected < {total_users}"
        );

        // And the filter must not swallow everything: a reservation list that
        // is empty because the filter is wrong would also satisfy the check
        // above.
        assert!(
            parsed_count > 0,
            "the fixture has reservations; a zero count means the filter is wrong"
        );
    }

    use super::apply_page_if_upstream_ignored_it;
    use crate::ApiSurface;

    /// Builds a page the way `list_resources` does.
    fn page(from: u64, size: u64) -> mecmcp_openapi::Page {
        mecmcp_openapi::page(from, size, mecmcp_openapi::PageLimits::default()).expect("valid page")
    }

    fn array(n: usize) -> serde_json::Value {
        serde_json::Value::Array(
            (0..n)
                .map(|i| serde_json::json!({ "n": i }))
                .collect::<Vec<_>>(),
        )
    }

    fn ids(value: &serde_json::Value) -> Vec<u64> {
        value
            .as_array()
            .expect("array")
            .iter()
            .map(|item| item["n"].as_u64().expect("n"))
            .collect()
    }

    /// The reported defect: 230 firewall policies came back for `limit=1`.
    ///
    /// The fixture must be LARGER than the limit. A fixture that already fits
    /// under it would pass without the truncation ever running, which is how a
    /// paging bug survives a green test suite.
    #[test]
    fn private_v2_collection_is_truncated_to_the_limit() {
        let out = apply_page_if_upstream_ignored_it(ApiSurface::PrivateV2, &page(0, 1), array(230));
        assert_eq!(ids(&out), vec![0], "limit=1 must yield exactly one item");
    }

    #[test]
    fn private_v1_collection_is_truncated_to_the_limit() {
        let out = apply_page_if_upstream_ignored_it(ApiSurface::PrivateV1, &page(0, 5), array(31));
        assert_eq!(ids(&out), vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn offset_selects_a_later_window() {
        let out = apply_page_if_upstream_ignored_it(ApiSurface::PrivateV1, &page(3, 2), array(10));
        assert_eq!(ids(&out), vec![3, 4], "offset must skip, not just truncate");
    }

    /// The guard against double-applying the page.
    ///
    /// The Integration API honours `offset` and `limit` itself — verified
    /// against a live controller: `kind=device, limit=1` returns one device and
    /// `offset=1` returns a different one. Its response is therefore ALREADY
    /// the requested window. Slicing it again with the same offset would skip
    /// `offset` items that were never there and return nothing, turning a
    /// correct page into an empty result.
    #[test]
    fn supported_surface_is_never_re_paged() {
        let already_paged = array(1);
        let out = apply_page_if_upstream_ignored_it(
            ApiSurface::Supported,
            &page(1, 1),
            already_paged.clone(),
        );
        assert_eq!(
            out, already_paged,
            "the Integration API already applied the page; re-slicing drops real results"
        );
    }

    #[test]
    fn a_short_collection_is_returned_whole() {
        let out = apply_page_if_upstream_ignored_it(ApiSurface::PrivateV1, &page(0, 200), array(3));
        assert_eq!(ids(&out), vec![0, 1, 2]);
    }

    #[test]
    fn a_non_array_payload_is_passed_through_untouched() {
        let object = serde_json::json!({ "error": "not a collection" });
        let out =
            apply_page_if_upstream_ignored_it(ApiSurface::PrivateV2, &page(0, 1), object.clone());
        assert_eq!(out, object);
    }
}
