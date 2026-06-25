//! Shared data types used across the runtime/network/tray modules.

use proxy_core::local_socks::LocalSocksServer;
use proxy_core::system_proxy::SystemProxySnapshot;
use proxy_core::{
    ImportedProxyEntry, PinnedProxyRouteStatus, ResolvedProfile, RoutingMode, WfpFilterStatus,
};
use serde::{Deserialize, Serialize};
use std::process::Child;
use std::sync::{mpsc, Arc, Mutex};

pub type SharedRuntimeState = Arc<Mutex<RuntimeState>>;

pub struct RuntimeState {
    pub connection_state: ConnectionState,
    pub active_profile: Option<ResolvedProfile>,
    pub last_profile_name: Option<String>,
    pub child: Option<Child>,
    pub system_snapshot: Option<SystemProxySnapshot>,
    pub local_system_proxy: Option<LocalSystemProxyRuntime>,
    pub exit_poll_stop: Option<mpsc::Sender<()>>,
    pub network_watch_stop: Option<mpsc::Sender<()>>,
    pub generation: u64,
    /// Incremented while a stop-then-start sequence is in progress so concurrent
    /// watcher threads do not race in a second Start.
    #[allow(dead_code)]
    pub restart_lock: u64,
    pub last_error: Option<String>,
    pub exit_status: ExitStatus,
    pub vpn_status: VpnStatus,
    pub traffic_flow: TrafficFlow,
    pub runtime_artifacts: Option<RuntimeArtifacts>,
    pub current_session_id: Option<String>,
    #[cfg(target_os = "windows")]
    pub windows_recovery_watchdog: Option<crate::windows_recovery::TunRecoveryWatchdog>,
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self {
            connection_state: ConnectionState::Stopped,
            active_profile: None,
            last_profile_name: None,
            child: None,
            system_snapshot: None,
            local_system_proxy: None,
            exit_poll_stop: None,
            network_watch_stop: None,
            generation: 0,
            restart_lock: 0,
            last_error: None,
            exit_status: ExitStatus::default(),
            vpn_status: VpnStatus::default(),
            traffic_flow: TrafficFlow::default_disconnected(),
            runtime_artifacts: None,
            current_session_id: None,
            #[cfg(target_os = "windows")]
            windows_recovery_watchdog: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    #[default]
    Stopped,
    Connected,
    Blocked,
    Rebinding,
    Error,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ExitStatus {
    pub exit_ip: Option<String>,
    pub country_code: Option<String>,
    pub country_flag: Option<String>,
    pub tray_text: Option<String>,
    pub lookup_error: Option<String>,
    pub last_checked_unix: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VpnStatus {
    pub state: String,
    pub vpn_interface: Option<String>,
    pub default_route_interface: Option<String>,
    pub proxy_uplink_interface: Option<String>,
    pub last_reason: Option<String>,
    pub last_change_unix: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrafficFlow {
    pub nodes: Vec<String>,
    pub status_line: String,
}

impl TrafficFlow {
    pub fn default_disconnected() -> Self {
        Self {
            nodes: vec!["Apps".into(), "SOCKS5 Proxy".into(), "WAN".into()],
            status_line: "No active routing session.".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub enabled: bool,
    pub selected_profile_id: Option<String>,
    pub active_profile_id: Option<String>,
    pub active_profile_name: Option<String>,
    pub routing_mode: String,
    pub connection_state: ConnectionState,
    pub last_error: Option<String>,
    pub local_system_proxy_port: Option<u16>,
    pub exit_status: ExitStatus,
    pub vpn_status: VpnStatus,
    pub traffic_flow: TrafficFlow,
}

#[derive(Clone, Debug, Serialize)]
pub struct RawImportPreview {
    pub entries: Vec<ImportedProxyEntry>,
    pub canonical_text: String,
}

#[derive(Clone, Debug)]
pub struct RuntimeArtifacts {
    pub session_id: String,
    pub tun_device: String,
    pub tun_marker: String,
    pub route_marker: String,
    pub proxy_pid: Option<u32>,
    pub pinned_proxy_routes: Vec<PinnedProxyRouteStatus>,
    pub wfp_filters: Vec<WfpFilterStatus>,
    #[allow(dead_code)]
    pub created_unix: u64,
    pub bound_vpn_interface: Option<String>,
}

pub struct LocalSystemProxyRuntime {
    pub port: u16,
    pub handle: LocalSocksServer,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistentRuntimeState {
    pub session_id: String,
    pub profile_id: String,
    pub tun_device: String,
    pub tun_marker: String,
    pub route_marker: String,
    pub proxy_pid: Option<u32>,
    #[serde(default)]
    pub pinned_proxy_routes: Vec<PinnedProxyRouteStatus>,
    #[serde(default)]
    pub wfp_filters: Vec<WfpFilterStatus>,
    pub created_unix: u64,
}

#[derive(Clone, Debug, Default)]
pub struct NetworkSnapshot {
    pub default_route_interface: Option<String>,
    pub active_vpn_interface: Option<String>,
    pub proxy_uplink_interface: Option<String>,
    pub last_reason: Option<String>,
}

impl NetworkSnapshot {
    #[allow(dead_code)]
    pub fn signature(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.default_route_interface.as_deref().unwrap_or("none"),
            self.active_vpn_interface.as_deref().unwrap_or("none"),
            self.proxy_uplink_interface.as_deref().unwrap_or("none"),
            self.last_reason.as_deref().unwrap_or("none")
        )
    }

    pub fn valid_vpn_uplink(&self) -> bool {
        match (&self.active_vpn_interface, &self.proxy_uplink_interface) {
            (Some(vpn), Some(proxy)) => vpn == proxy,
            _ => false,
        }
    }
}

#[derive(Clone, Copy)]
pub enum TrayConnectionState {
    Disconnected,
    Connected,
    Blocked,
    Error,
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum TUNAction {
    Start,
    Restart,
    Block,
}

#[derive(Clone, Debug)]
pub struct RuntimeSnapshot {
    pub connection_state: ConnectionState,
    pub active_profile_name: Option<String>,
    pub last_profile_name: Option<String>,
    pub routing_mode: Option<RoutingMode>,
    pub last_error: Option<String>,
    pub local_system_proxy_port: Option<u16>,
    pub exit_status: ExitStatus,
    pub vpn_status: VpnStatus,
}

impl From<&RuntimeState> for RuntimeSnapshot {
    fn from(value: &RuntimeState) -> Self {
        Self {
            connection_state: value.connection_state,
            active_profile_name: value.active_profile.as_ref().map(|p| p.name.clone()),
            last_profile_name: value.last_profile_name.clone(),
            routing_mode: value
                .active_profile
                .as_ref()
                .map(|p| p.routing_mode.clone()),
            last_error: value.last_error.clone(),
            local_system_proxy_port: value.local_system_proxy.as_ref().map(|proxy| proxy.port),
            exit_status: value.exit_status.clone(),
            vpn_status: value.vpn_status.clone(),
        }
    }
}

#[derive(Clone)]
pub struct TrayHandles {
    pub status_item: tauri::menu::MenuItem<tauri::Wry>,
    pub exit_item: tauri::menu::MenuItem<tauri::Wry>,
    pub action_item: tauri::menu::MenuItem<tauri::Wry>,
}

// ---- tunable constants -----------------------------------------------------
pub mod consts {
    use std::time::Duration;

    pub const TRAY_ID: &str = "main";
    pub const MENU_STATUS_ID: &str = "status";
    pub const MENU_EXIT_ID: &str = "exit";
    pub const MENU_ACTION_ID: &str = "action";
    pub const MENU_OPEN_ID: &str = "open_settings";
    pub const MENU_QUIT_ID: &str = "quit";

    /// Minimum interval between network polls when state is changing rapidly.
    #[allow(dead_code)]
    pub const WATCH_INTERVAL_MIN: Duration = Duration::from_secs(4);
    /// Cap for the adaptive backoff when state has been stable.
    #[allow(dead_code)]
    pub const WATCH_INTERVAL_MAX: Duration = Duration::from_secs(30);
    /// Poll interval for the spawned tun2proxy child process.
    #[allow(dead_code)]
    pub const CHILD_WATCH_INTERVAL: Duration = Duration::from_millis(500);
    /// Number of consecutive identical observations required before reacting.
    #[allow(dead_code)]
    pub const VPN_STABILITY_POLLS: u8 = 2;

    pub const HTTP_TIMEOUT: Duration = Duration::from_secs(12);
    #[cfg(target_os = "linux")]
    pub const KILL_GRACE_MS: u64 = 300;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_runtime_state_defaults_missing_wfp_filters() {
        let text = r#"
session_id = "session-1"
profile_id = "profile-1"
tun_device = "s5ptest"
tun_marker = "C:\\tmp\\tun.marker"
route_marker = "C:\\tmp\\route.marker"
proxy_pid = 1234
created_unix = 42
"#;

        let state: PersistentRuntimeState = toml::from_str(text).expect("runtime state");
        assert!(state.pinned_proxy_routes.is_empty());
        assert!(state.wfp_filters.is_empty());
    }

    #[test]
    fn persistent_runtime_state_roundtrips_wfp_filters() {
        let state = PersistentRuntimeState {
            session_id: "session-1".to_string(),
            profile_id: "profile-1".to_string(),
            tun_device: "s5ptest".to_string(),
            tun_marker: "C:\\tmp\\tun.marker".to_string(),
            route_marker: "C:\\tmp\\route.marker".to_string(),
            proxy_pid: Some(1234),
            pinned_proxy_routes: Vec::new(),
            wfp_filters: vec![WfpFilterStatus {
                filter_id: "{11111111-1111-1111-1111-111111111111}".to_string(),
                layer: "FWPM_LAYER_ALE_AUTH_CONNECT_V4".to_string(),
                display_name: "socks5proxy-z4 allow tun2proxy".to_string(),
                session_tag: "socks5proxy-z4".to_string(),
            }],
            created_unix: 42,
        };

        let text = toml::to_string(&state).expect("serialize runtime state");
        let parsed: PersistentRuntimeState = toml::from_str(&text).expect("parse runtime state");
        assert_eq!(parsed.wfp_filters, state.wfp_filters);
    }
}
