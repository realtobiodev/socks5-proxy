//! Network inspection and high-level VPN/traffic-flow modelling.

use proxy_core::{ProxyEndpoint, ResolvedProfile, RoutingMode};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::platform;
use crate::types::{ConnectionState, NetworkSnapshot, RuntimeState, TrafficFlow, VpnStatus};
use crate::util::current_unix_timestamp;

pub fn inspect_network_for_profile(profile: &ResolvedProfile) -> NetworkSnapshot {
    if !matches!(profile.routing_mode, RoutingMode::Tun) {
        return NetworkSnapshot::default();
    }

    let route_target = resolve_route_target(&profile.endpoint);
    let default_route_interface = platform::default_route_interface().ok().flatten();
    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut active_vpn_interface = platform::active_vpn_interface(default_route_interface.clone())
        .ok()
        .flatten();
    #[cfg(target_os = "windows")]
    if active_vpn_interface.is_none() {
        let mullvad = proxy_platform_windows::mullvad_status();
        if mullvad
            .state
            .as_deref()
            .map(|state| state.to_ascii_lowercase().starts_with("connected"))
            .unwrap_or(false)
        {
            active_vpn_interface = mullvad.tunnel_interface;
        }
    }
    let proxy_uplink_interface = route_target
        .as_deref()
        .and_then(|target| platform::route_interface_to(target).ok().flatten());

    let last_reason = match (&active_vpn_interface, &proxy_uplink_interface) {
        (Some(vpn), Some(proxy_iface)) if vpn == proxy_iface => {
            Some("Proxy uplink uses the active VPN".to_string())
        }
        (Some(_), Some(_)) => {
            Some("Proxy uplink is not the currently active VPN interface".to_string())
        }
        (Some(_), None) => Some("Could not resolve the proxy uplink interface".to_string()),
        (None, _) => Some("No active VPN uplink detected".to_string()),
    };

    NetworkSnapshot {
        default_route_interface,
        active_vpn_interface,
        proxy_uplink_interface,
        last_reason,
    }
}

pub fn resolve_route_target(endpoint: &ProxyEndpoint) -> Option<String> {
    let target = resolve_socket_addrs_with_timeout(
        endpoint.host.clone(),
        endpoint.port,
        Duration::from_secs(3),
    )
    .ok()?
    .into_iter()
    .next()?;
    Some(match target.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_string(),
    })
}

fn resolve_socket_addrs_with_timeout(
    host: String,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, String> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let result = (host.as_str(), port)
            .to_socket_addrs()
            .map(|addrs| addrs.collect::<Vec<_>>())
            .map_err(|error| error.to_string());
        let _ = tx.send(result);
    });

    rx.recv_timeout(timeout).map_err(|_| {
        format!(
            "timed out resolving proxy host after {}s",
            timeout.as_secs()
        )
    })?
}

#[allow(dead_code)]
pub fn apply_network_snapshot(
    runtime: &mut RuntimeState,
    profile: &ResolvedProfile,
    snapshot: &NetworkSnapshot,
) {
    runtime.vpn_status = build_vpn_status(profile, snapshot, runtime.connection_state);
    runtime.traffic_flow =
        build_traffic_flow(Some(profile), &runtime.vpn_status, runtime.connection_state);
}

pub fn build_vpn_status(
    profile: &ResolvedProfile,
    snapshot: &NetworkSnapshot,
    connection_state: ConnectionState,
) -> VpnStatus {
    let (state, reason) = if !matches!(profile.routing_mode, RoutingMode::Tun) {
        ("inactive".to_string(), None)
    } else if connection_state == ConnectionState::Rebinding {
        (
            "vpn_changed".to_string(),
            Some("Rebinding after VPN change".to_string()),
        )
    } else if snapshot.valid_vpn_uplink() {
        (
            "vpn_detected".to_string(),
            Some("Using active VPN uplink".to_string()),
        )
    } else if snapshot.active_vpn_interface.is_none() {
        (
            "no_vpn".to_string(),
            Some("No VPN active; proxy egress is direct".to_string()),
        )
    } else {
        (
            "vpn_bypassed".to_string(),
            Some("Proxy uplink is not routed through the active VPN".to_string()),
        )
    };

    VpnStatus {
        state,
        vpn_interface: snapshot.active_vpn_interface.clone(),
        default_route_interface: snapshot.default_route_interface.clone(),
        proxy_uplink_interface: snapshot.proxy_uplink_interface.clone(),
        last_reason: snapshot.last_reason.clone().or(reason),
        last_change_unix: Some(current_unix_timestamp()),
    }
}

pub fn build_traffic_flow(
    profile: Option<&ResolvedProfile>,
    vpn_status: &VpnStatus,
    connection_state: ConnectionState,
) -> TrafficFlow {
    let Some(profile) = profile else {
        return TrafficFlow::default_disconnected();
    };

    match profile.routing_mode {
        RoutingMode::System => TrafficFlow {
            nodes: vec![
                "Apps".into(),
                "System Proxy".into(),
                "SOCKS5 Proxy".into(),
                "WAN".into(),
            ],
            status_line:
                "System proxy mode applies best-effort app-level routing and may not tunnel DNS."
                    .into(),
        },
        RoutingMode::Tun => {
            let mut nodes = vec!["Apps".into(), "TUN".into(), "SOCKS5 Proxy".into()];

            if connection_state == ConnectionState::Blocked {
                nodes.push("Blocked".into());
            } else if vpn_status.proxy_uplink_interface.is_some()
                && vpn_status.vpn_interface.is_some()
                && vpn_status.proxy_uplink_interface == vpn_status.vpn_interface
            {
                nodes.push("VPN".into());
                nodes.push("WAN".into());
            } else {
                nodes.push("WAN".into());
            }

            let status_line = match connection_state {
                ConnectionState::Connected => vpn_status
                    .last_reason
                    .clone()
                    .unwrap_or_else(|| "TUN routing active".into()),
                ConnectionState::Blocked => vpn_status
                    .last_reason
                    .clone()
                    .unwrap_or_else(|| "Blocked".into()),
                ConnectionState::Rebinding => "Rebinding after VPN change".into(),
                ConnectionState::Error => "TUN session failed".into(),
                ConnectionState::Stopped => "No active routing session.".into(),
            };

            TrafficFlow { nodes, status_line }
        }
    }
}
