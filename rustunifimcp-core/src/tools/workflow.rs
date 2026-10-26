//! Workflow tools that join multiple data sources.
//!
//! These three reports answer in one call what the legacy server needed a dozen
//! for, with the join done server-side rather than orchestrated by a model one
//! tool call at a time.

use crate::ApiSurface;
use crate::client::UnifiClient;
use crate::error::UnifiError;
use crate::model::ResourceKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Arguments to `unifi_site_health_report`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SiteHealthReportArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Offset into `devices`. Defaults to 0.
    ///
    /// The report joins several surfaces before it has a device list to page,
    /// so this is applied to the joined result, not to any one upstream
    /// call. A response holding exactly `limit` devices may not be the whole
    /// site -- advance `offset` by `limit` to read the next page.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Maximum devices to return. Defaults to 200.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Site health report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct SiteHealthReport {
    /// Device health entries.
    pub devices: Vec<serde_json::Value>,
    /// Site-wide health metrics.
    pub health: serde_json::Value,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
    /// Offset `devices` was windowed from.
    pub offset: u64,
    /// The page size actually applied to `devices`.
    pub limit: u32,
    /// The number of devices in the site, before paging.
    pub total: usize,
}

/// Arguments to `unifi_topology_report`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TopologyReportArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Offset into `devices`. Defaults to 0.
    ///
    /// Applied to the joined result: a response holding exactly `limit`
    /// devices may not be the whole site -- advance `offset` by `limit` to
    /// read the next page. `edges` and `networks` are not paged; on a large
    /// site, expect them to dominate the response size.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Maximum devices to return. Defaults to 200.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Topology report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct TopologyReport {
    /// Network topology edges.
    pub edges: Vec<serde_json::Value>,
    /// Devices enriched with connection state.
    pub devices: Vec<serde_json::Value>,
    /// Networks referenced in the topology.
    pub networks: Vec<serde_json::Value>,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
    /// Offset `devices` was windowed from.
    pub offset: u64,
    /// The page size actually applied to `devices`.
    pub limit: u32,
    /// The number of devices in the site, before paging.
    pub total: usize,
}

/// Arguments to `unifi_traffic_flow_report`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrafficFlowReportArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
    /// Start of the time window (Unix timestamp in seconds).
    #[serde(default)]
    pub start: Option<i64>,
    /// End of the time window (Unix timestamp in seconds).
    #[serde(default)]
    pub end: Option<i64>,
    /// Offset into `clients`. Defaults to 0.
    ///
    /// Applied to the joined result: a response holding exactly `limit`
    /// clients may not be the whole site -- advance `offset` by `limit` to
    /// read the next page. `top_applications` is not paged; it is already
    /// bounded to the top 10.
    #[serde(default)]
    pub offset: Option<u64>,
    /// Maximum clients to return. Defaults to 200.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Traffic flow report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct TrafficFlowReport {
    /// Active clients with flow statistics.
    pub clients: Vec<serde_json::Value>,
    /// Top applications by traffic.
    pub top_applications: Vec<serde_json::Value>,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
    /// Offset `clients` was windowed from.
    pub offset: u64,
    /// The page size actually applied to `clients`.
    pub limit: u32,
    /// The number of clients in the site, before paging.
    pub total: usize,
}

/// Arguments to `unifi_client_troubleshoot`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClientTroubleshootArgs {
    /// Which controller, by its name in `controllers.json`.
    pub controller: String,
    /// Client MAC address.
    pub mac: String,
    /// Site identifier; defaults to the controller's configured site.
    #[serde(default)]
    pub site: Option<String>,
}

/// Client troubleshoot report response.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ClientTroubleshootReport {
    /// Client MAC address.
    pub mac: String,
    /// Association data from the station record.
    pub association: Option<serde_json::Value>,
    /// Uplink device the client is connected to.
    pub uplink_device: Option<serde_json::Value>,
    /// Applied firewall policies.
    pub applied_policies: Vec<serde_json::Value>,
    /// Whether this report is missing data it would normally include.
    pub partial: bool,
    /// What was omitted and why, one entry per omission.
    pub omitted: Vec<String>,
}

/// Generate a site health report.
///
/// Joins device inventory, health metrics, and device statistics into a single
/// view of site health. If a leg is refused for surface-permission reasons, the
/// result carries `partial: true` and an `omitted` array naming what was skipped.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn site_health_report(
    client: &UnifiClient,
    args: &SiteHealthReportArgs,
) -> Result<SiteHealthReport, UnifiError> {
    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut devices_result = Vec::new();
    let mut health_result = serde_json::Value::Null;
    let mut stats_result = Vec::new();

    // Fetch devices via Integration API
    match client
        .get(
            ApiSurface::Supported,
            ResourceKind::Device.path_template(),
            &[("site", &site_uuid)],
            &[],
        )
        .await
    {
        Ok(devices) => {
            let devices_data = crate::model::unwrap_enveloped_data(&devices)?;
            // Raw Integration API devices, not the typed model this crate's
            // read path parses through -- projected here through the same
            // per-kind allowlist so this workflow join carries the same
            // guarantee `unifi_list_resources` does.
            devices_result = devices_data
                .iter()
                .map(|d| crate::redact::project_resource(ResourceKind::Device, d))
                .collect();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("devices: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("devices: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch health via Private v1 API
    // Note: stat/health has no ResourceKind entry; path verified in capture-fixtures.sh
    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/health",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(health) => {
            let health_data = crate::model::unwrap_enveloped_data(&health)?;
            // `stat/health` has no `ResourceKind` and so no allowlist; run it
            // through the shared crate's denylist-and-shape scan as the
            // defensive net instead.
            health_result =
                crate::redact::redact_owned(&serde_json::Value::Array(health_data.to_vec()));
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("health: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("health: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch device statistics via Private v1 API
    // Note: stat/device has no ResourceKind entry; path verified in capture-fixtures.sh
    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/device",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(stats) => {
            let stats_data = crate::model::unwrap_enveloped_data(&stats)?;
            stats_result = stats_data.to_vec();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("device_stats: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("device_stats: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 3 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    // Join devices with stats by MAC address
    let devices = if !devices_result.is_empty() {
        join_devices_with_stats(&devices_result, &stats_result)
    } else {
        devices_result
    };

    let page = crate::tools::pagination::paginate(devices, args.offset, args.limit)?;

    let partial = !omitted.is_empty();
    Ok(SiteHealthReport {
        devices: page.items,
        health: health_result,
        partial,
        omitted,
        offset: page.offset,
        limit: page.limit,
        total: page.total,
    })
}

/// Generate a topology report.
///
/// Joins network topology with device inventory and network configurations.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn topology_report(
    client: &UnifiClient,
    args: &TopologyReportArgs,
) -> Result<TopologyReport, UnifiError> {
    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut edges_result = Vec::new();
    let mut devices_result = Vec::new();
    let mut networks_result = Vec::new();

    // Fetch topology edges via Private v2 API
    // Note: topology has no ResourceKind entry; path verified in capture-fixtures.sh
    match client
        .get(
            ApiSurface::PrivateV2,
            "/proxy/network/v2/api/site/{site}/topology",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(topology) => {
            if let Some(edges_array) = topology.get("edges").and_then(|v| v.as_array()) {
                edges_result = edges_array.clone();
            }
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("topology: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("topology: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch devices via Integration API
    match client
        .get(
            ApiSurface::Supported,
            ResourceKind::Device.path_template(),
            &[("site", &site_uuid)],
            &[],
        )
        .await
    {
        Ok(devices) => {
            let devices_data = crate::model::unwrap_enveloped_data(&devices)?;
            devices_result = devices_data
                .iter()
                .map(|d| crate::redact::project_resource(ResourceKind::Device, d))
                .collect();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("devices: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("devices: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch networks via Private v1 API
    match client
        .get(
            ApiSurface::PrivateV1,
            ResourceKind::Network.path_template(),
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(networks) => {
            let networks_data = crate::model::unwrap_enveloped_data(&networks)?;
            // Networks carry `x_secret`, WireGuard private keys, and PPPoE
            // passwords in this exact raw shape -- projected through the
            // network allowlist before it becomes part of the report.
            networks_result = networks_data
                .iter()
                .map(|n| crate::redact::project_resource(ResourceKind::Network, n))
                .collect();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("networks: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("networks: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 3 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    let page = crate::tools::pagination::paginate(devices_result, args.offset, args.limit)?;

    let partial = !omitted.is_empty();
    Ok(TopologyReport {
        edges: edges_result,
        devices: page.items,
        networks: networks_result,
        partial,
        omitted,
        offset: page.offset,
        limit: page.limit,
        total: page.total,
    })
}

/// Generate a traffic flow report.
///
/// Joins client statistics with flow data and application metrics.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn traffic_flow_report(
    client: &UnifiClient,
    args: &TrafficFlowReportArgs,
) -> Result<TrafficFlowReport, UnifiError> {
    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut clients_result = Vec::new();
    let mut top_apps_result = Vec::new();

    // Fetch clients via Integration API
    match client
        .get(
            ApiSurface::Supported,
            ResourceKind::Station.path_template(),
            &[("site", &site_uuid)],
            &[],
        )
        .await
    {
        Ok(clients) => {
            let clients_data = crate::model::unwrap_enveloped_data(&clients)?;
            // Projected here (not only in `join_clients_with_stats`, which is
            // never reached when the stats leg below is refused) so a
            // partial report carries the same guarantee a complete one does.
            clients_result = clients_data
                .iter()
                .map(|c| crate::redact::project_resource(ResourceKind::Station, c))
                .collect();
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("clients: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("clients: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch station statistics via Private v1 API
    // Note: stat/sta has no ResourceKind entry; path verified in capture-fixtures.sh
    let mut query = Vec::new();
    if let Some(start) = args.start {
        query.push(("start", start.to_string()));
    }
    if let Some(end) = args.end {
        query.push(("end", end.to_string()));
    }
    let query_refs: Vec<(&str, &str)> = query.iter().map(|(k, v)| (*k, v.as_str())).collect();

    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/sta",
            &[("site", site_name)],
            &query_refs,
        )
        .await
    {
        Ok(stats) => {
            let stats_data = crate::model::unwrap_enveloped_data(&stats)?;
            // Join clients with their flow stats
            if !clients_result.is_empty() {
                clients_result = join_clients_with_stats(&clients_result, stats_data);
            }
            // Extract top applications from the stats
            top_apps_result = extract_top_applications(stats_data);
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("station_stats: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("station_stats: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 2 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    let page = crate::tools::pagination::paginate(clients_result, args.offset, args.limit)?;

    let partial = !omitted.is_empty();
    Ok(TrafficFlowReport {
        clients: page.items,
        top_applications: top_apps_result,
        partial,
        omitted,
        offset: page.offset,
        limit: page.limit,
        total: page.total,
    })
}

/// Generate a client troubleshoot report.
///
/// Correlates a station's association history, signal, DHCP lease, applied
/// firewall policy, and recent flows. If correlation cannot be built, it is
/// reported in `omitted` rather than silently degrading to a station lookup.
///
/// # Errors
///
/// Returns [`UnifiError`] when:
/// - All legs are refused for surface permission reasons (nothing was gathered)
/// - Any leg fails with a real transport/protocol error (not a permission refusal)
pub async fn client_troubleshoot(
    client: &UnifiClient,
    args: &ClientTroubleshootArgs,
) -> Result<ClientTroubleshootReport, UnifiError> {
    let site_uuid = client.default_site_for(ApiSurface::Supported).await?;
    let site_name = if let Some(ref s) = args.site {
        s.as_str()
    } else {
        client.default_site()
    };

    let mut omitted = Vec::new();
    let mut stations_result = serde_json::Value::Null;
    let mut devices_result = serde_json::Value::Null;
    let mut policies_result = serde_json::Value::Null;
    let mut zones_result = serde_json::Value::Null;

    // Fetch station statistics via Private v1 API
    match client
        .get(
            ApiSurface::PrivateV1,
            "/proxy/network/api/s/{site}/stat/sta",
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(stations) => {
            stations_result = stations;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("stations: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("stations: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch devices via Integration API
    match client
        .get(
            ApiSurface::Supported,
            ResourceKind::Device.path_template(),
            &[("site", &site_uuid)],
            &[],
        )
        .await
    {
        Ok(devices) => {
            devices_result = devices;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("devices: controller has Integration API disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("devices: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch firewall policies via Private v2 API
    match client
        .get(
            ApiSurface::PrivateV2,
            ResourceKind::FirewallPolicy.path_template(),
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(policies) => {
            policies_result = policies;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("policies: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("policies: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // Fetch firewall zones via Private v2 API
    match client
        .get(
            ApiSurface::PrivateV2,
            ResourceKind::FirewallZone.path_template(),
            &[("site", site_name)],
            &[],
        )
        .await
    {
        Ok(zones) => {
            zones_result = zones;
        }
        Err(UnifiError::SurfaceRequiresConfig { .. }) => {
            omitted.push("zones: controller has allow_private_api disabled".to_owned());
        }
        Err(UnifiError::SurfaceRequiresScope { .. }) => {
            omitted.push("zones: token lacks required scope".to_owned());
        }
        Err(e) => return Err(e),
    }

    // If all legs were refused, that's an error
    if omitted.len() == 4 {
        return Err(UnifiError::Malformed(
            "all data sources refused: nothing was gathered".to_owned(),
        ));
    }

    build_client_troubleshoot(
        &args.mac,
        args.site.as_deref().unwrap_or(site_name),
        &stations_result,
        &devices_result,
        &policies_result,
        &zones_result,
    )
    .map(|mut report| {
        report.partial = !omitted.is_empty();
        report.omitted = omitted;
        report
    })
}

/// Build a client troubleshoot report from stations, devices, policies, and zones.
///
/// # Errors
///
/// Returns an error if:
/// - The station MAC is not found on the site
/// - Data cannot be parsed
pub fn build_client_troubleshoot(
    mac: &str,
    site: &str,
    stations: &serde_json::Value,
    devices: &serde_json::Value,
    policies: &serde_json::Value,
    zones: &serde_json::Value,
) -> Result<ClientTroubleshootReport, UnifiError> {
    let stations_data = crate::model::unwrap_enveloped_data(stations)?;
    let devices_data = crate::model::unwrap_enveloped_data(devices)?;

    // Policies and zones can be bare arrays or enveloped
    let policies_array = policies
        .as_array()
        .or_else(|| policies.get("data").and_then(|d| d.as_array()));
    let zones_array = zones
        .as_array()
        .or_else(|| zones.get("data").and_then(|d| d.as_array()));

    // Find the station by MAC - if not found, this is an error
    let station = stations_data
        .iter()
        .find(|s| s.get("mac").and_then(|v| v.as_str()) == Some(mac))
        .ok_or_else(|| UnifiError::Malformed(format!("station {mac} not found on site {site}")))?;

    let association = Some(crate::redact::project_resource(
        ResourceKind::Station,
        station,
    ));

    // Find the uplink device by matching the station's last_uplink_mac
    let uplink_device =
        if let Some(uplink_mac) = station.get("last_uplink_mac").and_then(|v| v.as_str()) {
            devices_data
                .iter()
                .find(|d| d.get("macAddress").and_then(|v| v.as_str()) == Some(uplink_mac))
                .map(|d| crate::redact::project_resource(ResourceKind::Device, d))
        } else {
            None
        };

    // Build the real correlation: network_id -> zone_id -> policies
    let mut omitted = Vec::new();
    let applied_policies = if let Some(network_id) =
        station.get("network_id").and_then(|v| v.as_str())
    {
        if let (Some(zones_arr), Some(policies_arr)) = (zones_array, policies_array) {
            // Find zones that contain this network_id
            let matching_zone_ids: Vec<&str> = zones_arr
                .iter()
                .filter_map(|zone| {
                    if let Some(network_ids) = zone.get("network_ids").and_then(|v| v.as_array()) {
                        if network_ids
                            .iter()
                            .any(|nid| nid.as_str() == Some(network_id))
                        {
                            zone.get("_id").and_then(|v| v.as_str())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            if matching_zone_ids.is_empty() {
                omitted.push(format!("network {network_id} not found in any zone"));
            }

            // Find policies that reference these zones
            let matching_policies: Vec<serde_json::Value> = policies_arr
                .iter()
                .filter(|p| {
                    if !p.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false) {
                        return false;
                    }

                    // Check if policy references any of the matching zones
                    let source_zone = p
                        .get("source")
                        .and_then(|s| s.get("zone_id"))
                        .and_then(|v| v.as_str());
                    let dest_zone = p
                        .get("destination")
                        .and_then(|d| d.get("zone_id"))
                        .and_then(|v| v.as_str());

                    matching_zone_ids
                        .iter()
                        .any(|&zone_id| Some(zone_id) == source_zone || Some(zone_id) == dest_zone)
                })
                // A firewall policy's open field set is redacted, not
                // allowlisted (see `crate::redact`'s module doc): a policy
                // this server does not control the shape of can still carry
                // a secret-named field in an operator's custom rule.
                .map(|p| crate::redact::project_resource(ResourceKind::FirewallPolicy, p))
                .collect();

            matching_policies
        } else {
            if zones_array.is_none() {
                omitted.push("zones unavailable for correlation".to_owned());
            }
            if policies_array.is_none() {
                omitted.push("policies unavailable for correlation".to_owned());
            }
            Vec::new()
        }
    } else {
        omitted.push("station has no network_id for correlation".to_owned());
        Vec::new()
    };

    let partial = !omitted.is_empty();
    Ok(ClientTroubleshootReport {
        mac: mac.to_owned(),
        association,
        uplink_device,
        applied_policies,
        partial,
        omitted,
    })
}

/// Extract the first station MAC from fixture data for testing.
pub fn first_station_mac(stations: &serde_json::Value) -> Option<String> {
    crate::model::unwrap_enveloped_data(stations)
        .ok()
        .and_then(|data| data.first())
        .and_then(|station| station.get("mac"))
        .and_then(|v| v.as_str())
        .map(String::from)
}

/// Join devices with their statistics by MAC address.
///
/// `devices` is projected through the [`ResourceKind::Device`] allowlist
/// before the join, and the joined `stats` blob -- the raw `stat/device`
/// record, inform/auth keys included -- through
/// [`crate::redact::project_device_stats`], so neither side of the join can
/// reintroduce a field the read path would have dropped.
fn join_devices_with_stats(
    devices: &[serde_json::Value],
    stats: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    devices
        .iter()
        .map(|device| {
            let mut enriched = crate::redact::project_resource(ResourceKind::Device, device);
            if let Some(mac) = device.get("macAddress").and_then(|v| v.as_str())
                && let Some(stat) = stats
                    .iter()
                    .find(|s| s.get("mac").and_then(|v| v.as_str()) == Some(mac))
                && let Some(obj) = enriched.as_object_mut()
            {
                obj.insert(
                    "stats".to_owned(),
                    crate::redact::project_device_stats(stat),
                );
            }
            enriched
        })
        .collect()
}

/// Join clients with their statistics by MAC address.
///
/// Same treatment as [`join_devices_with_stats`]: `clients` is projected
/// through the [`ResourceKind::Station`] allowlist before the join, and the
/// joined `flowStats` blob goes through the denylist-and-shape scan.
fn join_clients_with_stats(
    clients: &[serde_json::Value],
    stats: &[serde_json::Value],
) -> Vec<serde_json::Value> {
    clients
        .iter()
        .map(|client| {
            let mut enriched = crate::redact::project_resource(ResourceKind::Station, client);
            if let Some(mac) = client.get("macAddress").and_then(|v| v.as_str())
                && let Some(stat) = stats
                    .iter()
                    .find(|s| s.get("mac").and_then(|v| v.as_str()) == Some(mac))
                && let Some(obj) = enriched.as_object_mut()
            {
                obj.insert("flowStats".to_owned(), crate::redact::redact_owned(stat));
            }
            enriched
        })
        .collect()
}

/// Extract top applications from station statistics.
fn extract_top_applications(stats: &[serde_json::Value]) -> Vec<serde_json::Value> {
    use std::collections::HashMap;

    let mut app_bytes: HashMap<String, u64> = HashMap::new();

    for stat in stats {
        if let Some(by_app) = stat.get("by_app").and_then(|v| v.as_array()) {
            for app in by_app {
                if let (Some(app_name), Some(tx), Some(rx)) = (
                    app.get("app").and_then(|v| v.as_str()),
                    app.get("tx_bytes").and_then(|v| v.as_u64()),
                    app.get("rx_bytes").and_then(|v| v.as_u64()),
                ) {
                    *app_bytes.entry(app_name.to_owned()).or_insert(0) += tx + rx;
                }
            }
        }
    }

    let mut apps: Vec<_> = app_bytes
        .into_iter()
        .map(|(name, bytes)| {
            serde_json::json!({
                "application": name,
                "totalBytes": bytes,
            })
        })
        .collect();

    apps.sort_by(|a, b| {
        let a_bytes = a.get("totalBytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let b_bytes = b.get("totalBytes").and_then(|v| v.as_u64()).unwrap_or(0);
        b_bytes.cmp(&a_bytes)
    });

    apps.into_iter().take(10).collect()
}

#[cfg(test)]
mod tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// Build a site health report from fixtures.
    ///
    /// This is a helper for tests that need a complete report from recorded data.
    fn build_site_health(
        devices: &serde_json::Value,
        health: &serde_json::Value,
        stats: &serde_json::Value,
    ) -> Result<super::SiteHealthReport, String> {
        let devices_data = crate::model::unwrap_enveloped_data(devices)
            .map_err(|e| format!("unwrapping devices: {e}"))?;
        let health_data = crate::model::unwrap_enveloped_data(health)
            .map_err(|e| format!("unwrapping health: {e}"))?;
        let stats_data = crate::model::unwrap_enveloped_data(stats)
            .map_err(|e| format!("unwrapping stats: {e}"))?;

        let devices = super::join_devices_with_stats(devices_data, stats_data);
        let total = devices.len();

        Ok(super::SiteHealthReport {
            devices,
            health: serde_json::Value::Array(health_data.to_vec()),
            partial: false,
            omitted: Vec::new(),
            offset: 0,
            limit: crate::tools::pagination::DEFAULT_PAGE_SIZE,
            total,
        })
    }

    /// Build a partial site health report without private surfaces.
    ///
    /// This simulates a supported-only deployment.
    fn build_site_health_without_private(
        devices: &serde_json::Value,
    ) -> Result<super::SiteHealthReport, String> {
        let devices_data = crate::model::unwrap_enveloped_data(devices)
            .map_err(|e| format!("unwrapping devices: {e}"))?;
        let total = devices_data.len();

        Ok(super::SiteHealthReport {
            devices: devices_data.to_vec(),
            health: serde_json::Value::Null,
            partial: true,
            omitted: vec![
                "health: controller has allow_private_api disabled".to_owned(),
                "device_stats: controller has allow_private_api disabled".to_owned(),
            ],
            offset: 0,
            limit: crate::tools::pagination::DEFAULT_PAGE_SIZE,
            total,
        })
    }

    /// The report is a join, and a join that silently drops one side is worse
    /// than no report. Every device in the inventory must appear.
    #[test]
    fn the_health_report_accounts_for_every_device() {
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let health = fixture(DEFAULT_FIXTURE_VERSION, "health");
        let stats = fixture(DEFAULT_FIXTURE_VERSION, "stat_device");

        let report = build_site_health(&devices, &health, &stats)
            .expect("report builds from recorded fixtures");

        let device_count = devices["data"].as_array().map_or(0, Vec::len);
        assert_eq!(
            report.devices.len(),
            device_count,
            "the join dropped devices"
        );
    }

    /// GHSA-7fmh-fgch-xwqf: the joined `stats` is the controller's raw
    /// `stat/device` record. No secret-named field may survive the join, and
    /// the gateway WAN fields dual-WAN monitoring reads must.
    #[test]
    fn health_report_stats_drop_device_secrets_and_keep_wan_fields() {
        let device = serde_json::json!({ "macAddress": "02:00:00:01:01:fe", "name": "Gateway" });
        let stat = serde_json::json!({
            "mac": "02:00:00:01:01:fe",
            "x_authkey": "EXAMPLE",
            "x_inform_authkey": "EXAMPLE",
            "syslog_key": "EXAMPLE",
            "guest_token": "EXAMPLE",
            "x_ssh_hostkey_fingerprint": "EXAMPLE",
            "x_aes_gcm": true,
            "ssh_session_table": [{ "user": "EXAMPLE" }],
            "last_wan_interfaces": { "WAN": { "alive": true, "ip": "192.0.2.8" } },
            "last_wan_status": { "WAN": "online", "WAN2": "offline" },
            "uplink": { "comment": "WAN", "ip": "192.0.2.8", "up": true },
            "wan1": { "ip": "192.0.2.8", "up": true, "status": "online",
                      "mac_table": [{ "mac": "02:00:00:00:01:01" }] },
            "wan2": { "ip": "192.0.2.4", "up": false, "status": "offline" },
        });

        let joined = super::join_devices_with_stats(&[device], &[stat]);
        let stats = &joined[0]["stats"];

        fn walk(value: &serde_json::Value, path: &str) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, child) in map {
                        let lower = key.to_ascii_lowercase();
                        assert!(
                            !lower.starts_with("x_")
                                && !lower.contains("key")
                                && !lower.contains("token")
                                && lower != "ssh_session_table",
                            "secret-named field survived: {path}.{key}"
                        );
                        walk(child, &format!("{path}.{key}"));
                    }
                }
                serde_json::Value::Array(items) => items.iter().for_each(|i| walk(i, path)),
                _ => {}
            }
        }
        walk(stats, "stats");

        assert_eq!(stats["last_wan_interfaces"]["WAN"]["ip"], "192.0.2.8");
        assert_eq!(stats["last_wan_status"]["WAN2"], "offline");
        assert_eq!(stats["uplink"]["comment"], "WAN");
        assert_eq!(
            stats["wan1"],
            serde_json::json!({ "ip": "192.0.2.8", "up": true, "status": "online" })
        );
        assert_eq!(
            stats["wan2"],
            serde_json::json!({ "ip": "192.0.2.4", "up": false, "status": "offline" })
        );
    }

    /// The report's device list must actually page: a caller asking for
    /// fewer devices than the site has must get exactly that many, plus the
    /// true site-wide total, not the whole joined list truncated for display
    /// only.
    ///
    /// Uses a synthetic device list rather than the committed fixture, which
    /// holds only one device -- too few to page over.
    #[test]
    fn the_health_report_pages_its_device_list() {
        let full_count = 5;
        let joined: Vec<serde_json::Value> = (0..full_count)
            .map(|i| serde_json::json!({ "id": format!("device-{i}") }))
            .collect();

        let page =
            crate::tools::pagination::paginate(joined, Some(0), Some(1)).expect("valid page");
        let report = super::SiteHealthReport {
            devices: page.items,
            health: serde_json::Value::Null,
            partial: false,
            omitted: Vec::new(),
            offset: page.offset,
            limit: page.limit,
            total: page.total,
        };

        assert_eq!(
            report.devices.len(),
            1,
            "limit=1 must yield exactly one device"
        );
        assert_eq!(
            report.total, full_count,
            "total must report the whole site, not the page"
        );
    }

    /// A workflow that needs a private surface must say so rather than
    /// returning a partial answer that looks complete.
    #[test]
    fn a_report_missing_a_private_surface_is_marked_partial() {
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let report = build_site_health_without_private(&devices).expect("builds");
        assert!(
            report.partial,
            "a report built without the private surfaces must declare itself partial"
        );
        assert!(!report.omitted.is_empty(), "and must name what it omitted");
    }

    /// Topology report must account for all devices.
    #[test]
    fn the_topology_report_includes_all_devices() {
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let topology = fixture(DEFAULT_FIXTURE_VERSION, "topology");

        let devices_data = crate::model::unwrap_enveloped_data(&devices).expect("devices unwrap");
        let edges = topology
            .get("edges")
            .and_then(|v| v.as_array())
            .expect("topology has edges");

        let report = super::TopologyReport {
            devices: devices_data.to_vec(),
            edges: edges.clone(),
            networks: Vec::new(),
            partial: false,
            omitted: Vec::new(),
            offset: 0,
            limit: crate::tools::pagination::DEFAULT_PAGE_SIZE,
            total: devices_data.len(),
        };

        let device_count = devices["data"].as_array().map_or(0, Vec::len);
        assert_eq!(
            report.devices.len(),
            device_count,
            "topology report dropped devices"
        );
    }

    /// Traffic flow report must include clients.
    #[test]
    fn the_traffic_flow_report_includes_clients() {
        let clients = fixture(DEFAULT_FIXTURE_VERSION, "clients");
        let stats = fixture(DEFAULT_FIXTURE_VERSION, "stat_sta");

        let clients_data = crate::model::unwrap_enveloped_data(&clients).expect("clients unwrap");
        let stats_data = crate::model::unwrap_enveloped_data(&stats).expect("stats unwrap");

        let joined = super::join_clients_with_stats(clients_data, stats_data);
        let top_apps = super::extract_top_applications(stats_data);

        let report = super::TrafficFlowReport {
            clients: joined.clone(),
            top_applications: top_apps,
            partial: false,
            omitted: Vec::new(),
            offset: 0,
            limit: crate::tools::pagination::DEFAULT_PAGE_SIZE,
            total: joined.len(),
        };

        let client_count = clients["data"].as_array().map_or(0, Vec::len);
        assert_eq!(
            report.clients.len(),
            client_count,
            "traffic flow report dropped clients"
        );
    }
}

#[cfg(test)]
mod troubleshoot_tests {
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// The whole point is the correlation. A troubleshoot result that answers
    /// only from the station record is the legacy get_client_details with more
    /// steps.
    #[test]
    fn troubleshoot_correlates_every_source_it_claims_to() {
        let stations = fixture(DEFAULT_FIXTURE_VERSION, "stat_sta");
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let policies = fixture(DEFAULT_FIXTURE_VERSION, "policies");
        let zones = fixture(DEFAULT_FIXTURE_VERSION, "zones");

        let mac = crate::tools::workflow::first_station_mac(&stations)
            .expect("the fixture has at least one station");

        let result = crate::tools::workflow::build_client_troubleshoot(
            &mac, "default", &stations, &devices, &policies, &zones,
        )
        .expect("builds");

        assert!(result.association.is_some(), "no association data");
        assert!(result.uplink_device.is_some(), "station not tied to its AP");
        assert!(!result.applied_policies.is_empty(), "no policy correlation");

        // The correlation is real: policies reference zones that contain the station's network
        let station = result.association.as_ref().expect("association present");
        let network_id = station
            .get("network_id")
            .and_then(|v| v.as_str())
            .expect("station has network_id");

        // Find zones containing this network
        let zones_data = zones.as_array().expect("zones is array");
        let zone_ids: Vec<&str> = zones_data
            .iter()
            .filter_map(|z| {
                if z.get("network_ids")
                    .and_then(|nids| nids.as_array())
                    .is_some_and(|arr| arr.iter().any(|n| n.as_str() == Some(network_id)))
                {
                    z.get("_id").and_then(|v| v.as_str())
                } else {
                    None
                }
            })
            .collect();

        assert!(!zone_ids.is_empty(), "station's network not in any zone");

        // Verify all returned policies reference at least one of these zones
        for policy in &result.applied_policies {
            let source_zone = policy
                .get("source")
                .and_then(|s| s.get("zone_id"))
                .and_then(|v| v.as_str());
            let dest_zone = policy
                .get("destination")
                .and_then(|d| d.get("zone_id"))
                .and_then(|v| v.as_str());

            let references_zone = zone_ids
                .iter()
                .any(|&zid| Some(zid) == source_zone || Some(zid) == dest_zone);

            assert!(references_zone, "policy does not reference station's zones");
        }
    }

    /// A missing station is an error, not an empty success.
    #[test]
    fn missing_station_is_an_error() {
        let stations = fixture(DEFAULT_FIXTURE_VERSION, "stat_sta");
        let devices = fixture(DEFAULT_FIXTURE_VERSION, "devices");
        let policies = fixture(DEFAULT_FIXTURE_VERSION, "policies");
        let zones = fixture(DEFAULT_FIXTURE_VERSION, "zones");

        let result = crate::tools::workflow::build_client_troubleshoot(
            "02:00:00:00:00:ff",
            "default",
            &stations,
            &devices,
            &policies,
            &zones,
        );

        assert!(result.is_err(), "missing station returned Ok");
        let err_msg = result.expect_err("result is error").to_string();
        assert!(
            err_msg.contains("02:00:00:00:00:ff"),
            "error doesn't name the MAC"
        );
        assert!(
            err_msg.contains("not found"),
            "error doesn't say 'not found'"
        );
    }
}
