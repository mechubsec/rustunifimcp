//! UniFi network resource model.

use crate::error::UnifiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A configured network / VLAN.
///
/// This includes WAN connections — entries with `purpose: "wan"` carry WAN DNS
/// fields (`wan_dns1`, `wan_dns2`, `wan_ipv6_dns1`, `wan_ipv6_dns2`).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Network {
    /// Network ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Network name.
    pub name: String,
    /// Network purpose (e.g., `"corporate"`, `"vlan-only"`, `"wan"`, `"remote-user-vpn"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// IP subnet in CIDR notation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_subnet: Option<String>,
    /// VLAN ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan: Option<u16>,
    /// Whether DHCP is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_enabled: Option<bool>,
    /// DHCP start address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_start: Option<String>,
    /// DHCP stop address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_stop: Option<String>,
    /// Primary WAN DNS server (for WAN networks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_dns1: Option<String>,
    /// Secondary WAN DNS server (for WAN networks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_dns2: Option<String>,
    /// Primary WAN IPv6 DNS server (for WAN networks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_ipv6_dns1: Option<String>,
    /// Secondary WAN IPv6 DNS server (for WAN networks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_ipv6_dns2: Option<String>,
    /// Firewall zone the network belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_zone_id: Option<String>,
    /// DNS domain name handed out to clients.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    /// Whether VLAN tagging is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_enabled: Option<bool>,
    /// Network group (e.g., `"LAN"`, `"WAN"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networkgroup: Option<String>,
    /// Whether the network is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Whether IGMP snooping is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub igmp_snooping: Option<bool>,
    /// Whether the network has internet access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internet_access_enabled: Option<bool>,
    /// Whether the network is isolated from other networks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_isolation_enabled: Option<bool>,
    /// Whether DHCP hands out custom DNS servers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_dns_enabled: Option<bool>,
    /// First custom DHCP DNS server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_dns_1: Option<String>,
    /// Second custom DHCP DNS server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_dns_2: Option<String>,
    /// Third custom DHCP DNS server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_dns_3: Option<String>,
    /// Fourth custom DHCP DNS server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_dns_4: Option<String>,
    /// DHCP lease time in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcpd_leasetime: Option<u64>,
    /// Whether the controller refuses to delete this network (built-in default).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attr_no_delete: Option<bool>,
    /// WAN connection type (for WAN networks, e.g., `"dhcp"`, `"pppoe"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wan_type: Option<String>,
}

/// A wireless network (WLAN).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Wlan {
    /// WLAN ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// WLAN name / SSID.
    pub name: String,
    /// Whether the WLAN is enabled.
    pub enabled: bool,
    /// Security mode (e.g., `"wpapsk"`, `"open"`).
    pub security: String,
    /// WLAN band (e.g., `"5g"`, `"2.4g"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wlan_band: Option<String>,
    /// Whether this is a guest network.
    #[serde(default)]
    pub is_guest: bool,
}

/// A switch port profile.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct PortProfile {
    /// Port profile ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Profile name.
    pub name: String,
    /// Forwarding mode (e.g., `"customize"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward: Option<String>,
    /// Native network ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_networkconf_id: Option<String>,
}

/// A static DHCP reservation (user).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct DhcpReservation {
    /// User/client ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Client MAC address.
    pub mac: String,
    /// Last seen IP address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_ip: Option<String>,
    /// Fixed IP address when `use_fixedip` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_ip: Option<String>,
    /// Hostname.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Whether the client has a fixed-IP reservation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_fixedip: Option<bool>,
    /// ID of the network the reservation belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,
}

/// A RADIUS profile.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RadiusProfile {
    /// RADIUS profile ID.
    #[serde(rename = "_id")]
    pub id: String,
    /// Profile name.
    pub name: String,
    /// External ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

/// Parses networks from the Private v1 API response.
pub fn parse_networks(val: &serde_json::Value) -> Result<Vec<Network>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("network parse failed: {e}")))
        })
        .collect()
}

/// Parses WLANs from the Private v1 API response.
pub fn parse_wlans(val: &serde_json::Value) -> Result<Vec<Wlan>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("wlan parse failed: {e}")))
        })
        .collect()
}

/// Parses port profiles from the Private v1 API response.
pub fn parse_port_profiles(val: &serde_json::Value) -> Result<Vec<PortProfile>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("port profile parse failed: {e}")))
        })
        .collect()
}

/// Parses DHCP reservations from the Private v1 API response.
///
/// The `/rest/user` endpoint returns every known client, not only those with
/// a fixed-IP assignment. A reservation is marked by `use_fixedip: true` in
/// the record; this function filters to only actual reservations.
pub fn parse_dhcp_reservations(
    val: &serde_json::Value,
) -> Result<Vec<DhcpReservation>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .filter(|item| {
            item.get("use_fixedip")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("dhcp reservation parse failed: {e}")))
        })
        .collect()
}

/// Parses RADIUS profiles from the Private v1 API response.
pub fn parse_radius_profiles(val: &serde_json::Value) -> Result<Vec<RadiusProfile>, UnifiError> {
    let data = super::unwrap_enveloped_data(val)?;
    data.iter()
        .map(|item| {
            serde_json::from_value(item.clone())
                .map_err(|e| UnifiError::Malformed(format!("radius profile parse failed: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_dhcp_reservations;
    use crate::testing::{DEFAULT_FIXTURE_VERSION, fixture};

    /// The `/rest/user` endpoint returns all known clients, not only those
    /// with a fixed-IP reservation. Verify that the parser filters to actual
    /// reservations (marked by `use_fixedip: true`).
    #[test]
    fn dhcp_reservations_are_filtered_from_all_users() {
        let raw = fixture(DEFAULT_FIXTURE_VERSION, "user");
        let reservations = parse_dhcp_reservations(&raw).expect("parse");

        // Asserted as a relationship rather than a count. The count was
        // pinned to the 10.5.67 capture, which meant the committed synthetic
        // set had to carry 46 reservations to satisfy a test that is really
        // about the filter being active at all.
        let total_users = raw
            .get("data")
            .and_then(|d| d.as_array())
            .map(|arr| arr.len())
            .expect("envelope");

        assert!(
            reservations.len() < total_users,
            "parsed {}, total {}: filter did not reduce the set",
            reservations.len(),
            total_users
        );

        // And not zero: a filter that matched nothing would also be
        // strictly fewer than the total.
        assert!(
            !reservations.is_empty(),
            "the fixture has reservations; an empty result means the filter is wrong"
        );
    }
}
