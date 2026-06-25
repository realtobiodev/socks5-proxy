use serde::{Deserialize, Serialize};
#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::{ProxyEndpoint, ProxyError, ResolvedProfile};

pub const DEFAULT_DAEMON_SOCKET_PATH: &str = "/run/socks5proxyd.sock";

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamespaceSessionStatus {
    pub state: String,
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub proxy_host: Option<String>,
    pub proxy_ip: Option<String>,
    pub tun2proxy_pid: Option<u32>,
    pub host_vpn_interface: Option<String>,
    pub proxy_uplink_interface: Option<String>,
    #[serde(default)]
    pub owner_uid: Option<u32>,
    #[serde(default)]
    pub launched_apps: Vec<LaunchedAppStatus>,
    #[serde(default)]
    pub pinned_proxy_routes: Vec<PinnedProxyRouteStatus>,
    #[serde(default)]
    pub wfp_filters: Vec<WfpFilterStatus>,
    pub last_error: Option<String>,
    pub last_reason: Option<String>,
}

impl NamespaceSessionStatus {
    pub fn stopped() -> Self {
        Self {
            state: "stopped".to_string(),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DaemonRequest {
    StartTunSession { profile: ResolvedProfile },
    StopTunSession,
    GetTunStatus,
    RecoverState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonResponse {
    pub ok: bool,
    pub status: NamespaceSessionStatus,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LaunchedAppStatus {
    pub launcher_id: String,
    pub label: String,
    pub pid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PinnedProxyRouteStatus {
    pub destination_prefix: String,
    pub interface_index: u32,
    pub next_hop: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WfpFilterStatus {
    pub filter_id: String,
    pub layer: String,
    pub display_name: String,
    pub session_tag: String,
}

pub fn daemon_socket_path() -> PathBuf {
    std::env::var_os("SOCKS5PROXYD_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DAEMON_SOCKET_PATH))
}

#[cfg(unix)]
pub fn daemon_request(request: &DaemonRequest) -> crate::Result<DaemonResponse> {
    use std::os::unix::net::UnixStream;

    let socket = daemon_socket_path();
    let mut stream = UnixStream::connect(&socket).map_err(|error| {
        ProxyError::Command(format!(
            "failed to connect to socks5proxyd at {}: {error}",
            socket.display()
        ))
    })?;
    // Bound the request so a busy or wedged daemon can never block the caller
    // indefinitely. The desktop polls status frequently; an unbounded read here would
    // otherwise hang whichever thread issued the request.
    let timeout = std::time::Duration::from_secs(10);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let payload = serde_json::to_string(request)?;
    stream.write_all(payload.as_bytes())?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err(ProxyError::Command(
            "socks5proxyd closed the connection without a response; restart socks5proxyd so the daemon matches this GUI version".to_string(),
        ));
    }
    let response = serde_json::from_str::<DaemonResponse>(&line)?;
    Ok(response)
}

#[cfg(not(unix))]
pub fn daemon_request(_request: &DaemonRequest) -> crate::Result<DaemonResponse> {
    Err(ProxyError::Command(
        "socks5proxyd is only supported on Linux".to_string(),
    ))
}

pub fn daemon_tun_start(profile: ResolvedProfile) -> crate::Result<NamespaceSessionStatus> {
    let response = daemon_request(&DaemonRequest::StartTunSession { profile })?;
    if response.ok {
        Ok(response.status)
    } else {
        Err(ProxyError::Command(response.error.unwrap_or_else(|| {
            "socks5proxyd TUN start failed".to_string()
        })))
    }
}

pub fn daemon_tun_stop() -> crate::Result<NamespaceSessionStatus> {
    let response = daemon_request(&DaemonRequest::StopTunSession)?;
    if response.ok {
        Ok(response.status)
    } else {
        Err(ProxyError::Command(response.error.unwrap_or_else(|| {
            "socks5proxyd TUN stop failed".to_string()
        })))
    }
}

pub fn daemon_tun_status() -> crate::Result<NamespaceSessionStatus> {
    let response = daemon_request(&DaemonRequest::GetTunStatus)?;
    if response.ok {
        Ok(response.status)
    } else {
        Err(ProxyError::Command(response.error.unwrap_or_else(|| {
            "socks5proxyd TUN status failed".to_string()
        })))
    }
}

pub fn daemon_recover() -> crate::Result<NamespaceSessionStatus> {
    let response = daemon_request(&DaemonRequest::RecoverState)?;
    if response.ok {
        Ok(response.status)
    } else {
        Err(ProxyError::Command(response.error.unwrap_or_else(|| {
            "socks5proxyd recover failed".to_string()
        })))
    }
}

pub fn endpoint_display(endpoint: &ProxyEndpoint) -> String {
    format!("{}:{}", endpoint.host, endpoint.port)
}
