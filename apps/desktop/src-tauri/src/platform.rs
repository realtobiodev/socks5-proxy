//! Platform-specific helpers (route inspection, process control, TUN cleanup).

use proxy_core::validate::{validate_ip_literal, validate_tun_device};
use proxy_core::PinnedProxyRouteStatus;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use crate::types::consts::KILL_GRACE_MS;

pub fn default_route_interface() -> Result<Option<String>, String> {
    default_route_interface_impl()
}

pub fn active_vpn_interface(
    default_route_interface: Option<String>,
) -> Result<Option<String>, String> {
    active_vpn_interface_impl(default_route_interface)
}

pub fn route_interface_to(target: &str) -> Result<Option<String>, String> {
    validate_ip_literal(target).map_err(|e| e.to_string())?;
    route_interface_to_impl(target)
}

pub fn cleanup_tun_device(tun_device: &str) -> Result<(), String> {
    validate_tun_device(tun_device).map_err(|e| e.to_string())?;
    cleanup_tun_device_impl(tun_device)
}

pub fn cleanup_pinned_proxy_routes(routes: &[PinnedProxyRouteStatus]) -> Result<(), String> {
    cleanup_pinned_proxy_routes_impl(routes)
}

pub fn process_exists(pid: u32) -> Result<bool, String> {
    process_exists_impl(pid)
}

pub fn kill_process(pid: u32) -> Result<(), String> {
    kill_process_impl(pid)
}

/// Kill an orphaned tun2proxy-bin process via the privileged `tun2proxy-stop` helper.
///
/// Uses `sudo -n` (NOPASSWD) so it never blocks. Silently succeeds if the helper
/// is not installed or sudo is not configured — the normal `child.kill()` path
/// already handles the non-sudo case.
pub fn kill_tun_orphan(tun_device: &str) {
    if let Err(e) = validate_tun_device(tun_device) {
        tracing::warn!(
            "kill_tun_orphan: invalid device name '{}': {}",
            tun_device,
            e
        );
        return;
    }
    kill_tun_orphan_impl(tun_device);
}

pub(crate) fn vpn_like(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "tun",
        "tap",
        "wg",
        "vpn",
        "ppp",
        "utun",
        "tailscale",
        "nordlynx",
        "warp",
        "zt",
        "proton",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix) || lower.contains(prefix))
}

#[cfg(target_os = "linux")]
fn default_route_interface_impl() -> Result<Option<String>, String> {
    parse_route_dev(command_output(
        Command::new("ip").args(["route", "show", "default"]),
    )?)
}

#[cfg(target_os = "linux")]
fn active_vpn_interface_impl(
    default_route_interface: Option<String>,
) -> Result<Option<String>, String> {
    if let Some(interface) = default_route_interface {
        if vpn_like(&interface) {
            return Ok(Some(interface));
        }
    }

    let output = command_output(Command::new("ip").args(["-o", "link", "show", "up"]))?;
    for line in output.lines() {
        let mut parts = line.split(':');
        let _index = parts.next();
        let name = parts.next().map(str::trim);
        if let Some(name) = name {
            if vpn_like(name) {
                return Ok(Some(name.to_string()));
            }
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn route_interface_to_impl(target: &str) -> Result<Option<String>, String> {
    parse_route_dev(command_output(
        Command::new("ip").args(["route", "get", target]),
    )?)
}

#[cfg(target_os = "linux")]
fn cleanup_tun_device_impl(tun_device: &str) -> Result<(), String> {
    let status = Command::new("ip")
        .args(["link", "show", "dev", tun_device])
        .status()
        .map_err(|error| format!("failed to inspect tun device '{tun_device}': {error}"))?;
    if !status.success() {
        return Ok(());
    }

    let delete_status = Command::new("ip")
        .args(["link", "delete", "dev", tun_device])
        .status()
        .map_err(|error| format!("failed to delete tun device '{tun_device}': {error}"))?;
    if delete_status.success() {
        return Ok(());
    }

    // Interfaces created by pkexec/sudo-backed tun2proxy sessions can outlive
    // the unprivileged desktop process. Fall back to the narrow stop helper so
    // cleanup still works after child crashes or partial startup failures.
    kill_tun_orphan_impl(tun_device);

    let final_status = Command::new("ip")
        .args(["link", "show", "dev", tun_device])
        .status()
        .map_err(|error| format!("failed to re-check tun device '{tun_device}': {error}"))?;
    if !final_status.success() {
        Ok(())
    } else {
        Err(format!(
            "failed to delete tun device '{tun_device}': ip exited with status {delete_status}"
        ))
    }
}

#[cfg(target_os = "linux")]
fn process_exists_impl(pid: u32) -> Result<bool, String> {
    let status = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .map_err(|error| format!("failed to probe pid {pid}: {error}"))?;
    if status.success() {
        return Ok(true);
    }

    // `kill -0` returns EPERM for processes we are not allowed to signal, which
    // is expected for pkexec/sudo-rooted tun2proxy instances. Fall back to /proc.
    Ok(Path::new(&format!("/proc/{pid}")).exists())
}

#[cfg(target_os = "linux")]
fn kill_tun_orphan_impl(tun_device: &str) {
    let status = Command::new("sudo")
        .args(["-n", "/usr/local/bin/tun2proxy-stop", tun_device])
        .status();
    match status {
        Ok(s) if s.success() => {
            tracing::info!("tun2proxy-stop: cleaned up device '{tun_device}'");
        }
        Ok(s) => {
            tracing::warn!("tun2proxy-stop exited with {s} for device '{tun_device}'");
        }
        Err(e) => {
            tracing::warn!("tun2proxy-stop: failed to run: {e}");
        }
    }
}

#[cfg(target_os = "linux")]
fn kill_process_impl(pid: u32) -> Result<(), String> {
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .map_err(|error| format!("failed to terminate pid {pid}: {error}"))?;
    thread::sleep(Duration::from_millis(KILL_GRACE_MS));
    if process_exists_impl(pid)? {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .map_err(|error| format!("failed to kill pid {pid}: {error}"))?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn default_route_interface_impl() -> Result<Option<String>, String> {
    let output = command_output(crate::util::console_hidden_command("powershell").args([
        "-NoProfile",
        "-Command",
        "(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, ifMetric | Select-Object -First 1 | ForEach-Object { (Get-NetAdapter -InterfaceIndex $_.ifIndex).Name })",
    ]))?;
    Ok(non_empty(output))
}

#[cfg(target_os = "windows")]
fn active_vpn_interface_impl(
    default_route_interface: Option<String>,
) -> Result<Option<String>, String> {
    if let Some(interface) = default_route_interface {
        if vpn_like(&interface) {
            return Ok(Some(interface));
        }
    }

    let output = command_output(crate::util::console_hidden_command("powershell").args([
        "-NoProfile",
        "-Command",
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name",
    ]))?;
    for line in output.lines() {
        let name = line.trim();
        if vpn_like(name) {
            return Ok(Some(name.to_string()));
        }
    }
    Ok(None)
}

#[cfg(target_os = "windows")]
fn route_interface_to_impl(target: &str) -> Result<Option<String>, String> {
    let command = format!(
        "$route = Find-NetRoute -RemoteIPAddress {target} -ErrorAction SilentlyContinue | Select-Object -First 1; if ($route) {{ (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex).Name }}"
    );
    let output =
        command_output(crate::util::console_hidden_command("powershell").args(["-NoProfile", "-Command", &command]))?;
    Ok(non_empty(output))
}

#[cfg(target_os = "windows")]
fn kill_tun_orphan_impl(tun_device: &str) {
    let status = crate::util::console_hidden_command("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &windows_kill_tun_orphan_script(tun_device),
        ])
        .status();
    match status {
        Ok(s) if s.success() => {
            tracing::info!("Windows tun2proxy orphan cleanup attempted for '{tun_device}'");
        }
        Ok(s) => {
            tracing::warn!("Windows tun2proxy orphan cleanup exited with {s} for '{tun_device}'");
        }
        Err(e) => {
            tracing::warn!("Windows tun2proxy orphan cleanup failed for '{tun_device}': {e}");
        }
    }
}

#[cfg(target_os = "windows")]
fn cleanup_tun_device_impl(tun_device: &str) -> Result<(), String> {
    let status = crate::util::console_hidden_command("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &windows_cleanup_tun_device_script(tun_device),
        ])
        .status()
        .map_err(|error| format!("failed to clean tun device '{tun_device}': {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "failed to clean tun device '{tun_device}': powershell exited with {status}"
        ))
    }
}

#[cfg(target_os = "windows")]
fn cleanup_pinned_proxy_routes_impl(routes: &[PinnedProxyRouteStatus]) -> Result<(), String> {
    if routes.is_empty() {
        return Ok(());
    }
    let status = crate::util::console_hidden_command("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &windows_cleanup_pinned_proxy_routes_script(routes),
        ])
        .status()
        .map_err(|error| format!("failed to clean pinned proxy routes: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "failed to clean pinned proxy routes: powershell exited with {status}"
        ))
    }
}

#[cfg(target_os = "windows")]
fn process_exists_impl(pid: u32) -> Result<bool, String> {
    let output = command_output(crate::util::console_hidden_command("powershell").args([
        "-NoProfile",
        "-Command",
        &format!("$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; if ($p) {{ 'yes' }}"),
    ]))?;
    Ok(output.trim() == "yes")
}

#[cfg(target_os = "windows")]
fn kill_process_impl(pid: u32) -> Result<(), String> {
    crate::util::console_hidden_command("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status()
        .map_err(|error| format!("failed to terminate pid {pid}: {error}"))?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn default_route_interface_impl() -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn active_vpn_interface_impl(
    _default_route_interface: Option<String>,
) -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn route_interface_to_impl(_target: &str) -> Result<Option<String>, String> {
    Ok(None)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn kill_tun_orphan_impl(_tun_device: &str) {}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn cleanup_tun_device_impl(_tun_device: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn cleanup_pinned_proxy_routes_impl(_routes: &[PinnedProxyRouteStatus]) -> Result<(), String> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn process_exists_impl(_pid: u32) -> Result<bool, String> {
    Ok(false)
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn kill_process_impl(_pid: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_route_dev(text: String) -> Result<Option<String>, String> {
    for line in text.lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if let Some(index) = parts.iter().position(|part| *part == "dev") {
            if let Some(name) = parts.get(index + 1) {
                return Ok(Some((*name).to_string()));
            }
        }
    }
    Ok(None)
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn command_output(command: &mut Command) -> Result<String, String> {
    let output = command
        .output()
        .map_err(|error| format!("failed to run command: {error}"))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "windows")]
fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "windows")]
fn windows_kill_tun_orphan_script(tun_device: &str) -> String {
    format!(
        "$tun = '{tun_device}'; \
         Get-CimInstance Win32_Process | \
         Where-Object {{ ($_.Name -eq 'tun2proxy-bin.exe' -or $_.Name -eq 'tun2proxy.exe') -and $_.CommandLine -like \"*--tun*$tun*\" }} | \
         ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }}"
    )
}

#[cfg(target_os = "windows")]
fn windows_cleanup_tun_device_script(tun_device: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Continue'; \
         $tun = '{tun_device}'; \
         $adapter = Get-NetAdapter -Name $tun -ErrorAction SilentlyContinue; \
         if ($adapter) {{ \
           Get-NetRoute -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue | \
             ForEach-Object {{ try {{ Remove-NetRoute -AddressFamily IPv4 -DestinationPrefix $_.DestinationPrefix -InterfaceIndex $_.InterfaceIndex -NextHop $_.NextHop -Confirm:$false -ErrorAction Stop }} catch {{ Write-Verbose $_ }} }}; \
           try {{ Disable-NetAdapter -Name $tun -Confirm:$false -ErrorAction Stop | Out-Null }} catch {{ Write-Verbose $_ }} \
         }}; \
         exit 0"
    )
}

#[cfg(target_os = "windows")]
fn windows_cleanup_pinned_proxy_routes_script(routes: &[PinnedProxyRouteStatus]) -> String {
    let cleanup = routes
        .iter()
        .map(|route| {
            format!(
                "try {{ Remove-NetRoute -DestinationPrefix '{}' -InterfaceIndex {} -NextHop '{}' -Confirm:$false -ErrorAction Stop }} catch {{ Write-Verbose $_ }}",
                ps_single_quote(&route.destination_prefix),
                route.interface_index,
                ps_single_quote(&route.next_hop)
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    format!("$ErrorActionPreference = 'Continue'; {cleanup}; exit 0")
}

#[cfg(target_os = "windows")]
fn ps_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_route_dev_linux_default() {
        let text = "default via 192.168.1.1 dev wlp3s0 proto dhcp metric 600".to_string();
        assert_eq!(parse_route_dev(text).unwrap().as_deref(), Some("wlp3s0"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_route_dev_empty() {
        assert_eq!(parse_route_dev(String::new()).unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_route_dev_multiline_picks_first() {
        let text = "1.2.3.4 dev eth0 src 5.6.7.8\nfallback".to_string();
        assert_eq!(parse_route_dev(text).unwrap().as_deref(), Some("eth0"));
    }

    #[test]
    fn vpn_like_matches_prefixes_and_substrings() {
        assert!(vpn_like("tun0"));
        assert!(vpn_like("wg0"));
        assert!(vpn_like("Tailscale"));
        assert!(vpn_like("protonvpn-tun0"));
        assert!(!vpn_like("eth0"));
        assert!(!vpn_like("wlp3s0"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_cleanup_scripts_are_scoped_to_tun_device() {
        let kill = windows_kill_tun_orphan_script("s5pabc123");
        assert!(kill.contains("tun2proxy-bin.exe"));
        assert!(kill.contains("*--tun*$tun*"));
        assert!(kill.contains("Stop-Process"));

        let cleanup = windows_cleanup_tun_device_script("s5pabc123");
        assert!(cleanup.contains("Get-NetAdapter -Name $tun"));
        assert!(cleanup.contains("Remove-NetRoute"));
        assert!(cleanup.contains("Disable-NetAdapter"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_pinned_route_cleanup_script_is_scoped() {
        let routes = vec![PinnedProxyRouteStatus {
            destination_prefix: "198.51.100.10/32".to_string(),
            interface_index: 42,
            next_hop: "0.0.0.0".to_string(),
        }];
        let script = windows_cleanup_pinned_proxy_routes_script(&routes);
        assert!(script.contains("Remove-NetRoute"));
        assert!(script.contains("-DestinationPrefix '198.51.100.10/32'"));
        assert!(script.contains("-InterfaceIndex 42"));
        assert!(script.contains("-NextHop '0.0.0.0'"));
        assert!(script.contains("-Confirm:$false"));
    }
}
