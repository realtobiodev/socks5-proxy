//! Windows-specific platform support for socks5proxy.
//!
//! This crate is the isolated home for everything that is Windows-only and does
//! not belong in the cross-platform `proxy-core`: host-wide TUN routing via
//! Wintun + tun2proxy, UAC elevation, and Windows firewall/route handling. It is
//! the Windows counterpart to the Linux-only `proxy-daemon` crate.

use proxy_core::daemon::{NamespaceSessionStatus, PinnedProxyRouteStatus, WfpFilterStatus};
use proxy_core::tun::{effective_tun_profile, tun2proxy_args, tun_device_name};
use proxy_core::{ProxyError, ResolvedProfile};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const TUN2PROXY_CANDIDATES: &[&str] = &["tun2proxy-bin.exe", "tun2proxy.exe"];
const MULLVAD_CLI_NAMES: &[&str] = &["mullvad.exe", "mullvad"];
const WIREGUARD_CLI_NAMES: &[&str] = &["wg.exe", "wg"];
const WINDOWS_TUN_DNS_SERVER: &str = "10.0.0.1";
const WINDOWS_BLOCKED_IPV4_DNS_SERVER: &str = "127.0.0.1";
const WINDOWS_BLOCKED_IPV6_DNS_SERVER: &str = "::1";
/// tun2proxy's Wintun gateway address (the on-link next hop for traffic captured
/// into the proxy TUN). Used as the next hop for the host-wide capture split below.
const WINDOWS_TUN_GATEWAY: &str = "10.0.0.1";
/// Route metric for the proxy-server pin through the VPN. tun2proxy installs its own
/// proxy-bypass host route via the *physical* uplink at metric 1; we install ours at 0
/// so it deterministically wins even if tun2proxy's route reappears after a race.
const PROXY_VPN_ROUTE_METRIC: u32 = 0;
/// The two more-specific halves that capture all host traffic into the proxy TUN.
/// tun2proxy only installs a `0.0.0.0/0` default, which ties with Mullvad's own `/0`
/// (both metric 0) and then loses on interface metric, so app traffic escapes via the
/// VPN instead of the proxy. A `/1` pair is strictly more specific than any `/0`.
const WINDOWS_TUN_CAPTURE_PREFIXES: &[&str] = &["0.0.0.0/1", "128.0.0.0/1"];
const ALLOW_EXPERIMENTAL_MULLVAD_TUN_ENV: &str = "SOCKS5PROXY_ALLOW_EXPERIMENTAL_MULLVAD_TUN";
pub const ENABLE_WFP_MUTATION_ENV: &str = "SOCKS5PROXY_ENABLE_WFP_MUTATION";
/// Mullvad's always-on kill-switch (`BlockAll`) lives in its WFP *baseline
/// sublayer*, whose weight is `MAXUINT16` (0xFFFF) — the maximum a UINT16
/// sublayer weight can hold. WFP evaluates sublayers from highest weight to
/// lowest and a BLOCK in a higher-weighted sublayer is terminating, so a PERMIT
/// in *any* separate sublayer we could create (weight < 0xFFFF) is never even
/// reached. The only way to let Z4 proxy/TUN egress survive the kill-switch
/// (CHAIN-4) is to install our PERMIT filters *into Mullvad's own baseline
/// sublayer* at a higher filter weight than their block — exactly how Mullvad
/// itself permits its relay endpoint (`PermitEndpoint`, WeightClass::Medium).
///
/// This GUID is only a last-resort fallback: the sublayer key differs between
/// Mullvad versions (the source-tree GUID `{21e068a2-…}` is not present on
/// shipped builds — e.g. this machine uses `{c78056ff-…}`), so at apply time we
/// resolve the real key at runtime by enumerating sublayers and matching name +
/// weight 0xFFFF (`resolve_mullvad_baseline_sublayer`). Only if enumeration
/// finds nothing do we fall back to this constant.
const MULLVAD_BASELINE_SUBLAYER_GUID: &str = "{c78056ff-2bc1-4211-aadd-7f358def202d}";
/// Raw 64-bit filter weight for our permits. Must outrank Mullvad's `BlockAll`
/// (installed at WeightClass::Min) within the shared baseline sublayer. Kept
/// just below the reserved top of the range to avoid auto-weight collisions.
const SOCKS5PROXY_PERMIT_FILTER_WEIGHT: u64 = 0xF000_0000_0000_0000;
const FWP_E_FILTER_NOT_FOUND_CODE: u32 = 0x8032_0003;
const FWP_E_PROVIDER_NOT_FOUND_CODE: u32 = 0x8032_0005;
const FWP_E_SUBLAYER_NOT_FOUND_CODE: u32 = 0x8032_0007;
const FWP_E_NOT_FOUND_CODE: u32 = 0x8032_0008;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsTunPreflight {
    pub elevated: bool,
    pub tun2proxy_path: Option<PathBuf>,
    pub wintun_path: Option<PathBuf>,
    pub missing_reasons: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsMullvadStatus {
    pub cli_path: Option<PathBuf>,
    pub state: Option<String>,
    pub visible_location: Option<String>,
    pub visible_ipv4: Option<String>,
    pub visible_ipv6: Option<String>,
    pub mullvad_exit_ip: Option<bool>,
    pub locked_down: Option<bool>,
    pub endpoint_address: Option<String>,
    pub endpoint_ip: Option<String>,
    pub endpoint_port: Option<u16>,
    pub endpoint_protocol: Option<String>,
    pub tunnel_interface: Option<String>,
    pub relay_hostname: Option<String>,
    pub relay_ipv4: Option<String>,
    pub relay_ipv6: Option<String>,
    pub entry_hostname: Option<String>,
    pub entry_ipv4: Option<String>,
    pub entry_ipv6: Option<String>,
    pub bridge_hostname: Option<String>,
    pub obfuscator_hostname: Option<String>,
    pub tunnel_protocol: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWireGuardStatus {
    pub cli_path: Option<PathBuf>,
    pub interfaces: Vec<String>,
    pub endpoint_ips: Vec<String>,
    pub locked_down: Option<bool>,
    pub lockdown_reason: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsFirewallPreflight {
    pub elevated: bool,
    pub firewall_profiles_count: Option<u32>,
    pub matching_firewall_rule_count: Option<u32>,
    pub wfp_state_available: bool,
    pub wfp_state_error: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpExceptionPlan {
    pub required: bool,
    pub ready: bool,
    pub status: String,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub app_path: Option<PathBuf>,
    pub tun2proxy_path: Option<PathBuf>,
    pub mullvad_tunnel_interface: Option<String>,
    pub mullvad_endpoint_ip: Option<String>,
    pub planned_allows: Vec<String>,
    pub planned_cleanup: Vec<String>,
    pub planned_filter_identities: Vec<WindowsWfpRuleId>,
    pub session_tag: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpRuleId {
    pub role: String,
    pub key: String,
    pub display_name: String,
    pub layer: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpOperationPlan {
    pub required: bool,
    pub ready: bool,
    pub status: String,
    pub blockers: Vec<String>,
    pub session_tag: String,
    pub cleanup_before_apply: Vec<WindowsWfpOperation>,
    pub apply_operations: Vec<WindowsWfpOperation>,
    pub rollback_operations: Vec<WindowsWfpOperation>,
    pub expected_runtime_filters: Vec<WfpFilterStatus>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpOperation {
    pub action: String,
    pub role: String,
    pub key: String,
    pub layer: String,
    pub display_name: String,
    pub scope: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpApplyReadiness {
    pub required: bool,
    pub ready: bool,
    pub status: String,
    pub context: WindowsWfpApplyContext,
    pub blockers: Vec<String>,
    pub role_specs: Vec<WindowsWfpApplyRoleSpec>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpApplyContext {
    pub app_path: Option<PathBuf>,
    pub tun2proxy_path: Option<PathBuf>,
    pub proxy_ip: Option<String>,
    pub proxy_ip_error: Option<String>,
    pub mullvad_tunnel_interface: Option<String>,
    pub mullvad_tunnel_interface_index: Option<u32>,
    pub mullvad_tunnel_interface_index_error: Option<String>,
    pub mullvad_endpoint_ip: Option<String>,
    pub mullvad_endpoint_ip_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpApplyRoleSpec {
    pub role: String,
    pub key: String,
    pub layer: String,
    pub display_name: String,
    pub ready: bool,
    pub conditions: Vec<String>,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsWfpMutationReport {
    pub attempted: bool,
    pub status: String,
    pub blockers: Vec<String>,
    pub applied: Vec<WfpFilterStatus>,
    pub deleted: Vec<WfpFilterStatus>,
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsProxyRoutePlan {
    pub proxy_ip: String,
    pub destination_prefix: String,
    pub vpn_interface: String,
    pub vpn_interface_index: u32,
    pub next_hop: String,
    pub add_command: String,
    pub remove_command: String,
}

impl WindowsProxyRoutePlan {
    fn status(&self) -> PinnedProxyRouteStatus {
        PinnedProxyRouteStatus {
            destination_prefix: self.destination_prefix.clone(),
            interface_index: self.vpn_interface_index,
            next_hop: self.next_hop.clone(),
        }
    }
}

struct WindowsTunSession {
    profile: ResolvedProfile,
    effective_profile: ResolvedProfile,
    route_snapshot: WindowsRouteSnapshot,
    pinned_proxy_routes: Vec<WindowsProxyRoutePlan>,
    dns_snapshot: Option<WindowsDnsSnapshot>,
    wfp_filters: Vec<WfpFilterStatus>,
    wfp_operation_plan: Option<WindowsWfpOperationPlan>,
    child: Child,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct WindowsDnsSnapshot {
    entries: Vec<WindowsDnsServerEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WindowsDnsServerEntry {
    interface_index: u32,
    interface_alias: String,
    address_family: String,
    server_addresses: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct WindowsRouteSnapshot {
    active_vpn_interface: Option<String>,
    proxy_uplink_interface: Option<String>,
    last_reason: Option<String>,
}

static SESSION: OnceLock<Mutex<Option<WindowsTunSession>>> = OnceLock::new();

fn session_slot() -> &'static Mutex<Option<WindowsTunSession>> {
    SESSION.get_or_init(|| Mutex::new(None))
}

/// Build a `Command` that does NOT pop up a console window on Windows.
///
/// The desktop app is a GUI-subsystem binary in release (no console), so every
/// child CLI process (powershell/netsh/net/ipconfig/mullvad/tun2proxy) would
/// otherwise allocate its own console window and flash on screen — continuously,
/// because route/VPN status is polled on a timer. CREATE_NO_WINDOW suppresses that.
/// On non-Windows this is a plain `Command::new`.
fn console_hidden_command<S: AsRef<std::ffi::OsStr>>(program: S) -> Command {
    let mut command = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

/// Start host-wide TUN routing for `profile` on Windows.
pub fn start_tun_session(profile: &ResolvedProfile) -> Result<NamespaceSessionStatus, ProxyError> {
    require_admin()?;
    let binary = resolve_tun2proxy_binary().ok_or_else(|| {
        ProxyError::Command(
            "tun2proxy-bin.exe was not found. Install or bundle tun2proxy before starting Windows TUN routing.".to_string(),
        )
    })?;
    require_wintun_next_to(&binary)?;

    let effective_profile = resolve_windows_tun_profile(profile)?;
    let (mut wfp_filters, wfp_operation_plan) =
        prepare_mullvad_wfp_for_tun(&effective_profile.endpoint.host, &binary)?;
    if effective_profile.proxy_dns {
        flush_dns_cache()?;
    }
    let mut pinned_proxy_routes = Vec::new();
    if let Some(plan) = proxy_vpn_route_plan(&effective_profile.endpoint.host)? {
        apply_proxy_route_plan(&plan)?;
        pinned_proxy_routes.push(plan);
    }
    let args = tun2proxy_args(&effective_profile);
    let mut command = console_hidden_command(&binary);
    command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = binary.parent() {
        command.current_dir(dir);
    }
    let mut child = command.spawn().map_err(|error| {
        remove_proxy_route_plans(&pinned_proxy_routes);
        rollback_wfp_if_needed(wfp_operation_plan.as_ref());
        ProxyError::Command(format!("failed to start {}: {error}", binary.display()))
    })?;

    std::thread::sleep(Duration::from_millis(500));
    if let Some(status) = child.try_wait().map_err(|error| {
        ProxyError::Command(format!(
            "failed to inspect spawned tun2proxy process: {error}"
        ))
    })? {
        remove_proxy_route_plans(&pinned_proxy_routes);
        rollback_wfp_if_needed(wfp_operation_plan.as_ref());
        return Err(ProxyError::Command(format!(
            "tun2proxy exited immediately with status {status}. Windows TUN routing was not established."
        )));
    }
    let dns_snapshot = match harden_dns_for_tun(&effective_profile) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            remove_proxy_route_plans(&pinned_proxy_routes);
            rollback_wfp_if_needed(wfp_operation_plan.as_ref());
            return Err(error);
        }
    };
    // CHAIN-4 phase 2: tun2proxy has now created the Wintun adapter, so its LUID
    // is resolvable. Permit app traffic that gets routed into the proxy TUN;
    // without this, Mullvad's kill-switch blocks every user connect() on the
    // Wintun interface even though phase-1 permitted tun2proxy/controller/proxy.
    // Only runs when phase-1 actually applied WFP (Mullvad connected + gate on).
    if wfp_operation_plan.is_some() {
        let session_tag = wfp_operation_plan
            .as_ref()
            .map(|plan| plan.session_tag.clone())
            .unwrap_or_default();
        let tun_device = tun_device_name(&effective_profile.id);
        // Resolve the Wintun LUID once; both phase-2 permits (general egress and the
        // DNS-sublayer hole) bind to it. Any failure here tears the session down.
        let outcome = interface_luid(&tun_device).and_then(|luid| {
            let (egress_status, _rollback) = apply_wintun_egress_permit(&session_tag, luid)?;
            // Phase 2b: only punch the DNS hole when we actually route DNS through the
            // proxy (proxy_dns). Without it, Mullvad's DNS-leak block kills queries to
            // the virtual resolver and name resolution dies even though TCP works.
            let dns_status = if effective_profile.proxy_dns {
                Some(apply_wintun_dns_permit(&session_tag, luid)?.0)
            } else {
                None
            };
            Ok((egress_status, dns_status))
        });
        match outcome {
            Ok((egress_status, dns_status)) => {
                // The delete ops for these filters are already part of the operation
                // plan's rollback_operations (built with the stable session tag), so
                // teardown removes them by key — no need to splice them in here.
                wfp_filters.push(egress_status);
                if let Some(dns_status) = dns_status {
                    wfp_filters.push(dns_status);
                }
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                restore_dns_if_needed(dns_snapshot.as_ref());
                remove_proxy_route_plans(&pinned_proxy_routes);
                rollback_wfp_if_needed(wfp_operation_plan.as_ref());
                return Err(error);
            }
        }
    }
    // CHAIN-3 (post-spawn): tun2proxy has now installed its own routes. Repair the
    // proxy-server VPN pin (BUG #1) and add the host-wide capture split (BUG #2)
    // before the kill-switch guard and connectivity probe evaluate the route table.
    if let Err(error) = enforce_tun_capture_routes(
        &effective_profile.endpoint.host,
        &tun_device_name(&effective_profile.id),
        &mut pinned_proxy_routes,
    ) {
        let _ = child.kill();
        let _ = child.wait();
        restore_dns_if_needed(dns_snapshot.as_ref());
        remove_proxy_route_plans(&pinned_proxy_routes);
        rollback_wfp_if_needed(wfp_operation_plan.as_ref());
        return Err(error);
    }
    let route_snapshot = inspect_windows_routes(&effective_profile.endpoint.host);
    if let Some(reason) = vpn_chain_block_reason(&route_snapshot) {
        let _ = child.kill();
        let _ = child.wait();
        restore_dns_if_needed(dns_snapshot.as_ref());
        remove_proxy_route_plans(&pinned_proxy_routes);
        rollback_wfp_if_needed(wfp_operation_plan.as_ref());
        return Err(ProxyError::Command(format!(
            "Windows TUN routing did not become active after start: {reason}"
        )));
    }
    if let Err(error) = probe_tun_connectivity() {
        let _ = child.kill();
        let _ = child.wait();
        restore_dns_if_needed(dns_snapshot.as_ref());
        remove_proxy_route_plans(&pinned_proxy_routes);
        rollback_wfp_if_needed(wfp_operation_plan.as_ref());
        return Err(error);
    }

    let status = connected_status(
        profile,
        &effective_profile,
        &route_snapshot,
        &pinned_proxy_routes,
        &wfp_filters,
        child.id(),
    );
    let mut slot = match session_slot().lock() {
        Ok(slot) => slot,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            restore_dns_if_needed(dns_snapshot.as_ref());
            remove_proxy_route_plans(&pinned_proxy_routes);
            rollback_wfp_if_needed(wfp_operation_plan.as_ref());
            return Err(ProxyError::Command(
                "Windows TUN session lock poisoned".to_string(),
            ));
        }
    };
    if let Some(mut previous) = slot.take() {
        let _ = previous.child.kill();
        let _ = previous.child.wait();
        restore_dns_if_needed(previous.dns_snapshot.as_ref());
        remove_proxy_route_plans(&previous.pinned_proxy_routes);
        rollback_wfp_if_needed(previous.wfp_operation_plan.as_ref());
    }
    *slot = Some(WindowsTunSession {
        profile: profile.clone(),
        effective_profile,
        route_snapshot,
        pinned_proxy_routes,
        dns_snapshot,
        wfp_filters,
        wfp_operation_plan,
        child,
    });

    Ok(status)
}

/// Tear down the active Windows TUN session.
pub fn stop_tun_session() -> Result<NamespaceSessionStatus, ProxyError> {
    let mut slot = session_slot()
        .lock()
        .map_err(|_| ProxyError::Command("Windows TUN session lock poisoned".to_string()))?;
    if let Some(mut session) = slot.take() {
        let _ = session.child.kill();
        let _ = session.child.wait();
        restore_dns_if_needed(session.dns_snapshot.as_ref());
        remove_proxy_route_plans(&session.pinned_proxy_routes);
        rollback_wfp_if_needed(session.wfp_operation_plan.as_ref());
    }
    Ok(NamespaceSessionStatus::stopped())
}

/// Return the active Windows TUN status.
pub fn tun_status() -> Result<NamespaceSessionStatus, ProxyError> {
    let mut slot = session_slot()
        .lock()
        .map_err(|_| ProxyError::Command("Windows TUN session lock poisoned".to_string()))?;
    let Some(session) = slot.as_mut() else {
        return Ok(NamespaceSessionStatus::stopped());
    };

    match session.child.try_wait() {
        Ok(Some(status)) => {
            let mut out = error_status(
                &session.profile,
                &session.effective_profile,
                format!("tun2proxy exited with status {status}"),
            );
            out.tun2proxy_pid = Some(session.child.id());
            restore_dns_if_needed(session.dns_snapshot.as_ref());
            remove_proxy_route_plans(&session.pinned_proxy_routes);
            rollback_wfp_if_needed(session.wfp_operation_plan.as_ref());
            *slot = None;
            Ok(out)
        }
        Ok(None) => {
            reconcile_proxy_vpn_route(session);
            if let Some(reason) = vpn_chain_block_reason(&session.route_snapshot) {
                return Ok(blocked_status(
                    &session.profile,
                    &session.effective_profile,
                    &session.route_snapshot,
                    &session.pinned_proxy_routes,
                    &session.wfp_filters,
                    session.child.id(),
                    reason,
                ));
            }
            Ok(connected_status(
                &session.profile,
                &session.effective_profile,
                &session.route_snapshot,
                &session.pinned_proxy_routes,
                &session.wfp_filters,
                session.child.id(),
            ))
        }
        Err(error) => Ok(error_status(
            &session.profile,
            &session.effective_profile,
            format!("failed to inspect tun2proxy process: {error}"),
        )),
    }
}

/// Best-effort cleanup after a previous app crash.
pub fn recover_tun_state() -> Result<NamespaceSessionStatus, ProxyError> {
    stop_tun_session()
}

pub fn preflight() -> WindowsTunPreflight {
    let elevated = require_admin().is_ok();
    let tun2proxy_path = resolve_tun2proxy_binary();
    let wintun_path = tun2proxy_path
        .as_deref()
        .and_then(|path| path.parent())
        .map(|dir| dir.join("wintun.dll"))
        .filter(|path| path.is_file());
    let mut missing_reasons = Vec::new();
    if !elevated {
        missing_reasons.push("Windows administrator rights are required.".to_string());
    }
    if tun2proxy_path.is_none() {
        missing_reasons.push("tun2proxy-bin.exe was not found.".to_string());
    }
    if wintun_path.is_none() {
        missing_reasons.push("wintun.dll was not found next to tun2proxy-bin.exe.".to_string());
    }
    WindowsTunPreflight {
        elevated,
        tun2proxy_path,
        wintun_path,
        missing_reasons,
    }
}

pub fn mullvad_status() -> WindowsMullvadStatus {
    let cli_path = resolve_mullvad_cli();
    let Some(path) = cli_path.clone() else {
        return WindowsMullvadStatus {
            cli_path: None,
            state: None,
            visible_location: None,
            visible_ipv4: None,
            visible_ipv6: None,
            mullvad_exit_ip: None,
            locked_down: None,
            endpoint_address: None,
            endpoint_ip: None,
            endpoint_port: None,
            endpoint_protocol: None,
            tunnel_interface: None,
            relay_hostname: None,
            relay_ipv4: None,
            relay_ipv6: None,
            entry_hostname: None,
            entry_ipv4: None,
            entry_ipv6: None,
            bridge_hostname: None,
            obfuscator_hostname: None,
            tunnel_protocol: None,
            error: Some("mullvad.exe was not found.".to_string()),
        };
    };

    let tunnel_protocol = mullvad_relay_tunnel_protocol(&path);
    match console_hidden_command(&path).args(["status", "--json"]).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            let mut parsed = parse_mullvad_status_json(&text).unwrap_or_else(|| {
                let (state, visible_location) = parse_mullvad_status_output(&text);
                WindowsMullvadStatus {
                    cli_path: Some(path.clone()),
                    state,
                    visible_location,
                    visible_ipv4: None,
                    visible_ipv6: None,
                    mullvad_exit_ip: None,
                    locked_down: None,
                    endpoint_address: None,
                    endpoint_ip: None,
                    endpoint_port: None,
                    endpoint_protocol: None,
                    tunnel_interface: None,
                    relay_hostname: None,
                    relay_ipv4: None,
                    relay_ipv6: None,
                    entry_hostname: None,
                    entry_ipv4: None,
                    entry_ipv6: None,
                    bridge_hostname: None,
                    obfuscator_hostname: None,
                    tunnel_protocol: None,
                    error: None,
                }
            });
            parsed.cli_path = Some(path);
            parsed.tunnel_protocol = tunnel_protocol;
            enrich_mullvad_relay_ips(&mut parsed);
            parsed
        }
        Ok(output) => {
            let status_error = format!(
                "mullvad status exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
            let fallback = console_hidden_command(&path).arg("status").output().ok();
            let (state, visible_location) = fallback
                .as_ref()
                .filter(|output| output.status.success())
                .map(|output| parse_mullvad_status_output(&String::from_utf8_lossy(&output.stdout)))
                .unwrap_or((None, None));
            WindowsMullvadStatus {
                cli_path: Some(path),
                state,
                visible_location,
                visible_ipv4: None,
                visible_ipv6: None,
                mullvad_exit_ip: None,
                locked_down: None,
                endpoint_address: None,
                endpoint_ip: None,
                endpoint_port: None,
                endpoint_protocol: None,
                tunnel_interface: None,
                relay_hostname: None,
                relay_ipv4: None,
                relay_ipv6: None,
                entry_hostname: None,
                entry_ipv4: None,
                entry_ipv6: None,
                bridge_hostname: None,
                obfuscator_hostname: None,
                tunnel_protocol,
                error: Some(status_error),
            }
        }
        Err(error) => WindowsMullvadStatus {
            cli_path: Some(path),
            state: None,
            visible_location: None,
            visible_ipv4: None,
            visible_ipv6: None,
            mullvad_exit_ip: None,
            locked_down: None,
            endpoint_address: None,
            endpoint_ip: None,
            endpoint_port: None,
            endpoint_protocol: None,
            tunnel_interface: None,
            relay_hostname: None,
            relay_ipv4: None,
            relay_ipv6: None,
            entry_hostname: None,
            entry_ipv4: None,
            entry_ipv6: None,
            bridge_hostname: None,
            obfuscator_hostname: None,
            tunnel_protocol,
            error: Some(format!("failed to run mullvad status: {error}")),
        },
    }
}

pub fn wireguard_status() -> WindowsWireGuardStatus {
    let cli_path = resolve_wireguard_cli();
    let Some(path) = cli_path.clone() else {
        return WindowsWireGuardStatus {
            cli_path: None,
            interfaces: Vec::new(),
            endpoint_ips: Vec::new(),
            locked_down: None,
            lockdown_reason: None,
            error: Some("wg.exe was not found.".to_string()),
        };
    };

    let interfaces_output = match console_hidden_command(&path).args(["show", "interfaces"]).output() {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
                return WindowsWireGuardStatus {
                    cli_path: Some(path),
                    interfaces: Vec::new(),
                    endpoint_ips: Vec::new(),
                    locked_down: None,
                    lockdown_reason: None,
                    error: Some(format!(
                    "wg show interfaces exited with {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )),
            };
        }
        Err(error) => {
            return WindowsWireGuardStatus {
                cli_path: Some(path),
                interfaces: Vec::new(),
                endpoint_ips: Vec::new(),
                locked_down: None,
                lockdown_reason: None,
                error: Some(format!("failed to run wg show interfaces: {error}")),
            };
        }
    };

    let interfaces =
        parse_wireguard_interfaces(&String::from_utf8_lossy(&interfaces_output.stdout));
    let mut endpoint_ips = BTreeSet::new();
    for interface in &interfaces {
        if let Ok(output) = console_hidden_command(&path)
            .args(["show", interface, "endpoints"])
            .output()
        {
            if output.status.success() {
                for ip in parse_wireguard_endpoint_ips(&String::from_utf8_lossy(&output.stdout)) {
                    endpoint_ips.insert(ip);
                }
            }
        }
    }

    WindowsWireGuardStatus {
        cli_path: Some(path),
        interfaces,
        endpoint_ips: endpoint_ips.into_iter().collect(),
        locked_down: Some(wireguard_firewall_lockdown_active()),
        lockdown_reason: wireguard_firewall_lockdown_reason(),
        error: None,
    }
}

fn wireguard_firewall_lockdown_active() -> bool {
    wireguard_firewall_lockdown_reason().is_some()
}

fn wireguard_firewall_lockdown_reason() -> Option<String> {
    let script = r#"
$rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
  Where-Object {
    ($_.DisplayName -match 'WireGuard' -or $_.Group -match 'WireGuard') -and
    $_.Action -eq 'Block' -and
    $_.Enabled -eq 'True'
  } |
  Select-Object -First 5 -ExpandProperty DisplayName)
if ($rules.Count -gt 0) { $rules -join '; ' }
"#;

    let output = console_hidden_command("powershell.exe")
        .args(["-NoProfile", "-Command", script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let rules = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if rules.is_empty() {
        None
    } else {
        Some(format!("WireGuard firewall block rule(s) active: {rules}"))
    }
}

pub fn firewall_preflight() -> WindowsFirewallPreflight {
    let elevated = require_admin().is_ok();
    let mut errors = Vec::new();
    let firewall_profiles_count =
        match powershell_count("(Get-NetFirewallProfile -ErrorAction Stop | Measure-Object).Count")
        {
            Ok(count) => Some(count),
            Err(error) => {
                errors.push(format!(
                    "failed to inspect Windows Firewall profiles: {error}"
                ));
                None
            }
        };
    let matching_firewall_rule_count = match powershell_count(
        "(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_.DisplayName -match 'Mullvad|WireGuard|socks5proxy|tun2proxy' -or $_.Group -match 'Mullvad|WireGuard|socks5proxy|tun2proxy' } | Measure-Object).Count",
    ) {
        Ok(count) => Some(count),
        Err(error) => {
            errors.push(format!("failed to inspect Windows Firewall rules: {error}"));
            None
        }
    };
    let (wfp_state_available, wfp_state_error) = netsh_wfp_state_available();

    WindowsFirewallPreflight {
        elevated,
        firewall_profiles_count,
        matching_firewall_rule_count,
        wfp_state_available,
        wfp_state_error,
        error: if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        },
    }
}

pub fn wfp_exception_plan(
    mullvad: &WindowsMullvadStatus,
    firewall: &WindowsFirewallPreflight,
) -> WindowsWfpExceptionPlan {
    let required = mullvad_connected(mullvad);
    let app_path = env::current_exe().ok();
    let tun2proxy_path = resolve_tun2proxy_binary();
    let mut blockers = Vec::new();
    let mut warnings = Vec::new();

    if required {
        if !firewall.elevated {
            blockers.push(
                "Administrator rights are required to inspect and install WFP filters.".to_string(),
            );
        }
        if !firewall.wfp_state_available {
            blockers.push(match firewall.wfp_state_error.as_deref() {
                Some(error) => format!("WFP state is not readable in this session: {error}"),
                None => "WFP state is not readable in this session.".to_string(),
            });
        }
        if app_path.is_none() {
            blockers.push(
                "The running desktop executable path could not be resolved for WFP scoping."
                    .to_string(),
            );
        }
        if tun2proxy_path.is_none() {
            blockers.push(
                "tun2proxy-bin.exe could not be resolved for WFP process scoping.".to_string(),
            );
        }
        if mullvad.tunnel_interface.as_deref().is_none() {
            blockers.push("Mullvad tunnel interface is unknown.".to_string());
        }
        if mullvad.endpoint_ip.as_deref().is_none() {
            blockers.push("Mullvad transport endpoint IP is unknown.".to_string());
        }
        if firewall.matching_firewall_rule_count == Some(0) {
            warnings.push(
                "No high-level Windows Firewall rules matching Mullvad/WireGuard/socks5proxy/tun2proxy were visible; the effective policy is likely in lower WFP layers.".to_string(),
            );
        }
    }

    let planned_allows = if required {
        vec![
            "Allow the managed tun2proxy process to exchange packets with the Wintun adapter while Mullvad is connected.".to_string(),
            "Allow the socks5proxy desktop controller to manage the TUN session and local SOCKS bridge without opening unrelated outbound traffic.".to_string(),
            "Keep the proxy server host route pinned through the Mullvad tunnel; do not allow proxy traffic to bypass Mullvad.".to_string(),
            "Keep Mullvad relay/transport traffic outside the proxy TUN so VPN keepalives and rekeys cannot loop back into tun2proxy.".to_string(),
        ]
    } else {
        Vec::new()
    };
    let planned_cleanup = if required {
        vec![
            "Remove all socks5proxy-scoped WFP filters when the TUN session stops, fails to start, or is recovered after a crash.".to_string(),
            "Remove stale socks5proxy-scoped WFP filters before installing a replacement session after Mullvad reconnects or changes relay.".to_string(),
        ]
    } else {
        Vec::new()
    };
    let planned_filter_identities = if required {
        wfp_rule_identities("socks5proxy-z4")
    } else {
        Vec::new()
    };
    let ready = required && blockers.is_empty();
    let status = if !required {
        "not_required"
    } else if ready {
        "ready"
    } else {
        "blocked"
    }
    .to_string();

    WindowsWfpExceptionPlan {
        required,
        ready,
        status,
        blockers,
        warnings,
        app_path,
        tun2proxy_path,
        mullvad_tunnel_interface: mullvad.tunnel_interface.clone(),
        mullvad_endpoint_ip: mullvad.endpoint_ip.clone(),
        planned_allows,
        planned_cleanup,
        planned_filter_identities,
        session_tag: "socks5proxy-z4".to_string(),
    }
}

pub fn wfp_operation_plan(exception_plan: &WindowsWfpExceptionPlan) -> WindowsWfpOperationPlan {
    if !exception_plan.required {
        return WindowsWfpOperationPlan {
            required: false,
            ready: false,
            status: "not_required".to_string(),
            blockers: Vec::new(),
            session_tag: exception_plan.session_tag.clone(),
            cleanup_before_apply: Vec::new(),
            apply_operations: Vec::new(),
            rollback_operations: Vec::new(),
            expected_runtime_filters: Vec::new(),
        };
    }

    let identities = &exception_plan.planned_filter_identities;
    // The phase-2 Wintun-egress permit is applied dynamically (after tun2proxy spawns),
    // so it is not among the planned identities — but it is owned by our provider and
    // lives in Mullvad's sublayer. Always purge it FIRST (before the provider) on both
    // cleanup and rollback so a leaked copy from a crashed session cannot pin the
    // provider with FWP_E_IN_USE during teardown or a fresh apply.
    let wintun_egress_cleanup = {
        let mut op = wintun_egress_rollback_operation(&exception_plan.session_tag);
        op.action = "delete_stale".to_string();
        op.scope = "session identity cleanup".to_string();
        op
    };
    // The phase-2b DNS permit (Mullvad DNS sublayer) is also dynamic and owned by
    // our provider, so it must be purged FIRST alongside the egress permit.
    let wintun_dns_cleanup = {
        let mut op = wintun_dns_rollback_operation(&exception_plan.session_tag);
        op.action = "delete_stale".to_string();
        op.scope = "session identity cleanup".to_string();
        op
    };
    let mut cleanup_before_apply = vec![wintun_egress_cleanup, wintun_dns_cleanup];
    cleanup_before_apply.extend(
        identities
            .iter()
            .rev()
            .map(|identity| wfp_operation("delete_stale", identity, "session identity cleanup")),
    );
    let apply_operations = identities
        .iter()
        .map(|identity| wfp_operation("add", identity, wfp_operation_scope(identity)))
        .collect::<Vec<_>>();
    let mut rollback_operations = vec![
        wintun_egress_rollback_operation(&exception_plan.session_tag),
        wintun_dns_rollback_operation(&exception_plan.session_tag),
    ];
    rollback_operations.extend(
        identities
            .iter()
            .rev()
            .map(|identity| wfp_operation("delete", identity, "session rollback")),
    );
    let expected_runtime_filters = identities
        .iter()
        .filter(|identity| identity.layer.starts_with("FWPM_LAYER_"))
        .map(|identity| WfpFilterStatus {
            filter_id: identity.key.clone(),
            layer: identity.layer.clone(),
            display_name: identity.display_name.clone(),
            session_tag: exception_plan.session_tag.clone(),
        })
        .collect::<Vec<_>>();

    WindowsWfpOperationPlan {
        required: true,
        ready: exception_plan.ready,
        status: if exception_plan.ready {
            "ready"
        } else {
            "blocked"
        }
        .to_string(),
        blockers: exception_plan.blockers.clone(),
        session_tag: exception_plan.session_tag.clone(),
        cleanup_before_apply,
        apply_operations,
        rollback_operations,
        expected_runtime_filters,
    }
}

pub fn rollback_wfp_operation_plan(
    operation_plan: &WindowsWfpOperationPlan,
) -> Result<WindowsWfpMutationReport, ProxyError> {
    if !operation_plan.required {
        return Ok(WindowsWfpMutationReport {
            attempted: false,
            status: "not_required".to_string(),
            blockers: Vec::new(),
            applied: Vec::new(),
            deleted: Vec::new(),
            errors: Vec::new(),
        });
    }

    if !wfp_mutation_enabled() {
        return Ok(WindowsWfpMutationReport {
            attempted: false,
            status: "blocked".to_string(),
            blockers: vec![format!(
                "WFP mutation is disabled. Set {ENABLE_WFP_MUTATION_ENV}=1 only for an elevated guarded live rollback."
            )],
            applied: Vec::new(),
            deleted: Vec::new(),
            errors: Vec::new(),
        });
    }

    rollback_wfp_operation_plan_inner(operation_plan)
}

fn rollback_applied_wfp_operation_plan(
    operation_plan: &WindowsWfpOperationPlan,
) -> Result<WindowsWfpMutationReport, ProxyError> {
    if !operation_plan.required {
        return Ok(WindowsWfpMutationReport {
            attempted: false,
            status: "not_required".to_string(),
            blockers: Vec::new(),
            applied: Vec::new(),
            deleted: Vec::new(),
            errors: Vec::new(),
        });
    }

    rollback_wfp_operation_plan_inner(operation_plan)
}

pub fn cleanup_persisted_wfp_filters(
    filters: &[WfpFilterStatus],
) -> Result<WindowsWfpMutationReport, ProxyError> {
    if filters.is_empty() {
        return Ok(WindowsWfpMutationReport {
            attempted: false,
            status: "not_required".to_string(),
            blockers: Vec::new(),
            applied: Vec::new(),
            deleted: Vec::new(),
            errors: Vec::new(),
        });
    }

    let session_tag = filters
        .first()
        .map(|filter| filter.session_tag.clone())
        .unwrap_or_else(|| "socks5proxy-z4".to_string());
    let rollback_operations = filters
        .iter()
        .map(|filter| WindowsWfpOperation {
            action: "delete".to_string(),
            role: "filter".to_string(),
            scope: "runtime".to_string(),
            key: filter.filter_id.clone(),
            layer: filter.layer.clone(),
            display_name: filter.display_name.clone(),
        })
        .collect();

    rollback_wfp_operation_plan(&WindowsWfpOperationPlan {
        required: true,
        ready: true,
        status: "ready".to_string(),
        blockers: Vec::new(),
        session_tag,
        cleanup_before_apply: Vec::new(),
        apply_operations: Vec::new(),
        rollback_operations,
        expected_runtime_filters: filters.to_vec(),
    })
}

pub fn apply_wfp_operation_plan(
    operation_plan: &WindowsWfpOperationPlan,
    readiness: &WindowsWfpApplyReadiness,
) -> Result<WindowsWfpMutationReport, ProxyError> {
    if !operation_plan.required {
        return Ok(WindowsWfpMutationReport {
            attempted: false,
            status: "not_required".to_string(),
            blockers: Vec::new(),
            applied: Vec::new(),
            deleted: Vec::new(),
            errors: Vec::new(),
        });
    }

    if !readiness.ready {
        return Ok(WindowsWfpMutationReport {
            attempted: false,
            status: "blocked".to_string(),
            blockers: readiness.blockers.clone(),
            applied: Vec::new(),
            deleted: Vec::new(),
            errors: Vec::new(),
        });
    }

    if !wfp_mutation_enabled() {
        return Ok(WindowsWfpMutationReport {
            attempted: false,
            status: "blocked".to_string(),
            blockers: vec![format!(
                "WFP mutation is disabled. Set {ENABLE_WFP_MUTATION_ENV}=1 only for an elevated guarded live apply."
            )],
            applied: Vec::new(),
            deleted: Vec::new(),
            errors: Vec::new(),
        });
    }

    apply_wfp_operation_plan_inner(operation_plan, readiness)
}

pub fn wfp_apply_readiness(
    exception_plan: &WindowsWfpExceptionPlan,
    operation_plan: &WindowsWfpOperationPlan,
) -> WindowsWfpApplyReadiness {
    let context = wfp_apply_context_from_exception_plan(None, exception_plan);
    wfp_apply_readiness_with_context(exception_plan, operation_plan, &context)
}

pub fn wfp_apply_readiness_with_context(
    exception_plan: &WindowsWfpExceptionPlan,
    operation_plan: &WindowsWfpOperationPlan,
    context: &WindowsWfpApplyContext,
) -> WindowsWfpApplyReadiness {
    if !operation_plan.required {
        return WindowsWfpApplyReadiness {
            required: false,
            ready: false,
            status: "not_required".to_string(),
            context: context.clone(),
            blockers: Vec::new(),
            role_specs: Vec::new(),
        };
    }

    let role_specs = operation_plan
        .apply_operations
        .iter()
        .map(|operation| wfp_apply_role_spec(exception_plan, operation, context))
        .collect::<Vec<_>>();
    let mut blockers = exception_plan.blockers.clone();
    for spec in &role_specs {
        for blocker in &spec.blockers {
            blockers.push(format!("{}: {blocker}", spec.role));
        }
    }
    let ready =
        exception_plan.ready && blockers.is_empty() && role_specs.iter().all(|spec| spec.ready);
    WindowsWfpApplyReadiness {
        required: true,
        ready,
        status: if ready { "ready" } else { "blocked" }.to_string(),
        context: context.clone(),
        blockers,
        role_specs,
    }
}

pub fn wfp_apply_context_from_exception_plan(
    proxy_ip: Option<&str>,
    exception_plan: &WindowsWfpExceptionPlan,
) -> WindowsWfpApplyContext {
    wfp_apply_context(
        proxy_ip,
        exception_plan.app_path.clone(),
        exception_plan.tun2proxy_path.clone(),
        exception_plan.mullvad_tunnel_interface.as_deref(),
        None,
        None,
        exception_plan.mullvad_endpoint_ip.as_deref(),
    )
}

pub fn wfp_apply_context_for_mullvad(
    proxy_ip: Option<&str>,
    mullvad: &WindowsMullvadStatus,
) -> WindowsWfpApplyContext {
    wfp_apply_context_for_mullvad_with_paths(proxy_ip, mullvad, None, None)
}

pub fn wfp_apply_context_for_mullvad_with_paths(
    proxy_ip: Option<&str>,
    mullvad: &WindowsMullvadStatus,
    app_path: Option<PathBuf>,
    tun2proxy_path: Option<PathBuf>,
) -> WindowsWfpApplyContext {
    let (interface_index, interface_index_error) = match mullvad.tunnel_interface.as_deref() {
        Some(interface) => match interface_index(interface) {
            Ok(index) => (Some(index), None),
            Err(error) => (None, Some(error.to_string())),
        },
        None => (None, None),
    };
    wfp_apply_context(
        proxy_ip,
        app_path,
        tun2proxy_path,
        mullvad.tunnel_interface.as_deref(),
        interface_index,
        interface_index_error,
        mullvad.endpoint_ip.as_deref(),
    )
}

pub fn wfp_apply_context(
    proxy_ip: Option<&str>,
    app_path: Option<PathBuf>,
    tun2proxy_path: Option<PathBuf>,
    mullvad_tunnel_interface: Option<&str>,
    mullvad_tunnel_interface_index: Option<u32>,
    mullvad_tunnel_interface_index_error: Option<String>,
    mullvad_endpoint_ip: Option<&str>,
) -> WindowsWfpApplyContext {
    let (proxy_ip, proxy_ip_error) = validate_optional_ip("proxy server IP", proxy_ip);
    let (mullvad_endpoint_ip, mullvad_endpoint_ip_error) =
        validate_optional_ip("Mullvad endpoint IP", mullvad_endpoint_ip);
    WindowsWfpApplyContext {
        app_path,
        tun2proxy_path,
        proxy_ip,
        proxy_ip_error,
        mullvad_tunnel_interface: mullvad_tunnel_interface
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        mullvad_tunnel_interface_index,
        mullvad_tunnel_interface_index_error,
        mullvad_endpoint_ip,
        mullvad_endpoint_ip_error,
    }
}

fn validate_optional_ip(label: &str, value: Option<&str>) -> (Option<String>, Option<String>) {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some(value) => match value.parse::<IpAddr>() {
            Ok(ip) => (Some(ip.to_string()), None),
            Err(error) => (
                None,
                Some(format!(
                    "{label} must be an IP literal, got {value:?}: {error}"
                )),
            ),
        },
        None => (None, None),
    }
}

fn wfp_apply_role_spec(
    exception_plan: &WindowsWfpExceptionPlan,
    operation: &WindowsWfpOperation,
    context: &WindowsWfpApplyContext,
) -> WindowsWfpApplyRoleSpec {
    let mut conditions = Vec::new();
    let mut blockers = Vec::new();
    match operation.role.as_str() {
        "provider" => conditions.push("FWPM_PROVIDER0 with deterministic provider key".to_string()),
        "sublayer" => conditions.push("FWPM_SUBLAYER0 owned by socks5proxy provider".to_string()),
        "allow_tun2proxy" => {
            conditions
                .push("FWPM_CONDITION_ALE_APP_ID equals tun2proxy-bin.exe app id".to_string());
            if exception_plan.tun2proxy_path.is_none() {
                blockers.push("tun2proxy-bin.exe path is required for app-id scoping".to_string());
            }
        }
        "allow_controller" => {
            conditions.push(
                "FWPM_CONDITION_ALE_APP_ID equals socks5proxy-desktop.exe app id".to_string(),
            );
            if exception_plan.app_path.is_none() {
                blockers.push("desktop executable path is required for app-id scoping".to_string());
            }
        }
        "enforce_proxy_vpn_route" => {
            if let Some(proxy_ip) = &context.proxy_ip {
                conditions.push(format!(
                    "FWPM_CONDITION_IP_REMOTE_ADDRESS equals proxy server IP {proxy_ip}"
                ));
            } else {
                conditions
                    .push("FWPM_CONDITION_IP_REMOTE_ADDRESS equals proxy server IP".to_string());
                blockers.push(context.proxy_ip_error.clone().unwrap_or_else(|| {
                    "proxy server IP is required for WFP route enforcement".to_string()
                }));
            }
            match (
                context.mullvad_tunnel_interface.as_deref(),
                context.mullvad_tunnel_interface_index,
            ) {
                (Some(interface), Some(index)) => conditions.push(format!(
                    "FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX equals Mullvad interface index {index} ({interface})"
                )),
                (Some(interface), None) => {
                    conditions.push(format!(
                        "FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX equals Mullvad interface index for {interface}"
                    ));
                    blockers.push(context.mullvad_tunnel_interface_index_error.clone().unwrap_or_else(|| {
                        format!("Mullvad interface index is required for {interface}")
                    }));
                }
                (None, _) => {
                    conditions
                        .push("Mullvad tunnel interface condition is required".to_string());
                    blockers.push("Mullvad tunnel interface is required".to_string());
                }
            }
        }
        "allow_mullvad_transport" => {
            let endpoint_ip = context
                .mullvad_endpoint_ip
                .as_ref()
                .or(exception_plan.mullvad_endpoint_ip.as_ref());
            if let Some(endpoint_ip) = endpoint_ip {
                conditions.push(format!(
                    "FWPM_CONDITION_IP_REMOTE_ADDRESS equals Mullvad endpoint IP {endpoint_ip}"
                ));
            } else {
                conditions.push(
                    "FWPM_CONDITION_IP_REMOTE_ADDRESS equals Mullvad endpoint IP".to_string(),
                );
                blockers.push(
                    context
                        .mullvad_endpoint_ip_error
                        .clone()
                        .unwrap_or_else(|| "Mullvad endpoint IP is required".to_string()),
                );
            }
        }
        _ => blockers.push(format!("unknown WFP apply role {}", operation.role)),
    }

    WindowsWfpApplyRoleSpec {
        role: operation.role.clone(),
        key: operation.key.clone(),
        layer: operation.layer.clone(),
        display_name: operation.display_name.clone(),
        ready: blockers.is_empty(),
        conditions,
        blockers,
    }
}

fn wfp_mutation_enabled() -> bool {
    env::var(ENABLE_WFP_MUTATION_ENV)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(windows)]
fn rollback_wfp_operation_plan_inner(
    operation_plan: &WindowsWfpOperationPlan,
) -> Result<WindowsWfpMutationReport, ProxyError> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterDeleteByKey0, FwpmProviderDeleteByKey0,
        FwpmSubLayerDeleteByKey0,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

    unsafe {
        let mut engine: HANDLE = std::ptr::null_mut();
        let open_result = FwpmEngineOpen0(
            std::ptr::null(),
            RPC_C_AUTHN_DEFAULT as u32,
            std::ptr::null(),
            std::ptr::null(),
            &mut engine,
        );
        if open_result != 0 {
            return Err(ProxyError::Command(format!(
                "failed to open Windows Filtering Platform engine for rollback: 0x{open_result:08x}"
            )));
        }

        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        for operation in &operation_plan.rollback_operations {
            let guid = match parse_wfp_guid(&operation.key) {
                Ok(guid) => guid,
                Err(error) => {
                    errors.push(format!("{} {}: {error}", operation.action, operation.role));
                    continue;
                }
            };
            let result = match operation.role.as_str() {
                "provider" => FwpmProviderDeleteByKey0(engine, &guid),
                "sublayer" => FwpmSubLayerDeleteByKey0(engine, &guid),
                _ if operation.layer.starts_with("FWPM_LAYER_") => {
                    FwpmFilterDeleteByKey0(engine, &guid)
                }
                _ => {
                    errors.push(format!(
                        "unsupported WFP rollback role {} at layer {}",
                        operation.role, operation.layer
                    ));
                    continue;
                }
            };
            if result == 0 {
                if operation.layer.starts_with("FWPM_LAYER_") {
                    deleted.push(WfpFilterStatus {
                        filter_id: operation.key.clone(),
                        layer: operation.layer.clone(),
                        display_name: operation.display_name.clone(),
                        session_tag: operation_plan.session_tag.clone(),
                    });
                }
            } else if wfp_delete_missing_ok(&operation.role, result) {
                continue;
            } else {
                errors.push(format!(
                    "failed to delete WFP {} {} ({}): 0x{result:08x}",
                    operation.role, operation.key, operation.display_name
                ));
            }
        }

        let close_result = FwpmEngineClose0(engine);
        if close_result != 0 {
            errors.push(format!(
                "failed to close Windows Filtering Platform engine: 0x{close_result:08x}"
            ));
        }

        Ok(WindowsWfpMutationReport {
            attempted: true,
            status: if errors.is_empty() {
                "rolled_back"
            } else {
                "error"
            }
            .to_string(),
            blockers: Vec::new(),
            applied: Vec::new(),
            deleted,
            errors,
        })
    }
}

fn wfp_delete_missing_ok(role: &str, result: u32) -> bool {
    result == FWP_E_NOT_FOUND_CODE
        || match role {
            "provider" => result == FWP_E_PROVIDER_NOT_FOUND_CODE,
            "sublayer" => result == FWP_E_SUBLAYER_NOT_FOUND_CODE,
            _ => result == FWP_E_FILTER_NOT_FOUND_CODE,
        }
}

#[cfg(not(windows))]
fn rollback_wfp_operation_plan_inner(
    _operation_plan: &WindowsWfpOperationPlan,
) -> Result<WindowsWfpMutationReport, ProxyError> {
    Err(ProxyError::Command(
        "Windows Filtering Platform rollback is only available on Windows".to_string(),
    ))
}

#[cfg(windows)]
fn apply_wfp_operation_plan_inner(
    operation_plan: &WindowsWfpOperationPlan,
    readiness: &WindowsWfpApplyReadiness,
) -> Result<WindowsWfpMutationReport, ProxyError> {
    use std::ffi::c_void;
    use std::net::IpAddr;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmFreeMemory0,
        FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0,
        FwpmSubLayerDeleteByKey0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID,
        FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0, FWPM_FILTER0,
        FWPM_FILTER_CONDITION0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_PROVIDER0, FWPM_SUBLAYER0, FWP_ACTION_PERMIT, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
        FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT64, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
        FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

    struct AppIdBlob {
        ptr: *mut windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB,
    }

    struct WfpFilterConditionSet {
        conditions: Vec<FWPM_FILTER_CONDITION0>,
        v4_masks: Vec<FWP_V4_ADDR_AND_MASK>,
        v6_masks: Vec<FWP_V6_ADDR_AND_MASK>,
        _app_blobs: Vec<AppIdBlob>,
        // Which ALE_AUTH_CONNECT layer this filter must be installed on. Address
        // filters pick V4 vs V6 from the resolved IP family; app-id filters stay
        // V4 (see wfp_filter_condition_set). The apply loop reads this to choose
        // the layerKey instead of hard-coding V4.
        layer_is_v6: bool,
    }

    impl Drop for AppIdBlob {
        fn drop(&mut self) {
            if !self.ptr.is_null() {
                unsafe {
                    let mut ptr = self.ptr.cast::<c_void>();
                    FwpmFreeMemory0(&mut ptr);
                }
                self.ptr = std::ptr::null_mut();
            }
        }
    }

    unsafe {
        let mut engine: HANDLE = std::ptr::null_mut();
        let open_result = FwpmEngineOpen0(
            std::ptr::null(),
            RPC_C_AUTHN_DEFAULT as u32,
            std::ptr::null(),
            std::ptr::null(),
            &mut engine,
        );
        if open_result != 0 {
            return Err(ProxyError::Command(format!(
                "failed to open Windows Filtering Platform engine for apply: 0x{open_result:08x}"
            )));
        }

        let mut applied = Vec::new();
        let mut deleted = Vec::new();
        let mut errors = Vec::new();

        for operation in &operation_plan.cleanup_before_apply {
            let guid = match parse_wfp_guid(&operation.key) {
                Ok(guid) => guid,
                Err(error) => {
                    errors.push(format!("{} {}: {error}", operation.action, operation.role));
                    continue;
                }
            };
            let result = match operation.role.as_str() {
                "provider" => FwpmProviderDeleteByKey0(engine, &guid),
                "sublayer" => FwpmSubLayerDeleteByKey0(engine, &guid),
                _ if operation.layer.starts_with("FWPM_LAYER_") => {
                    FwpmFilterDeleteByKey0(engine, &guid)
                }
                _ => 0,
            };
            if result == 0 {
                deleted.push(WfpFilterStatus {
                    filter_id: operation.key.clone(),
                    layer: operation.layer.clone(),
                    display_name: operation.display_name.clone(),
                    session_tag: operation_plan.session_tag.clone(),
                });
            }
        }

        if errors.is_empty() {
            if let Err(error) =
                add_wfp_provider_sublayer_and_filters(engine, operation_plan, readiness)
            {
                errors.push(error.to_string());
            } else {
                applied = operation_plan.expected_runtime_filters.clone();
            }
        }

        FwpmEngineClose0(engine);
        return Ok(WindowsWfpMutationReport {
            attempted: true,
            status: if errors.is_empty() {
                "applied"
            } else {
                "error"
            }
            .to_string(),
            blockers: Vec::new(),
            applied,
            deleted,
            errors,
        });
    }

    unsafe fn add_wfp_provider_sublayer_and_filters(
        engine: HANDLE,
        operation_plan: &WindowsWfpOperationPlan,
        readiness: &WindowsWfpApplyReadiness,
    ) -> Result<(), ProxyError> {
        let provider_operation = operation_plan
            .apply_operations
            .iter()
            .find(|operation| operation.role == "provider")
            .ok_or_else(|| {
                ProxyError::Invalid("WFP apply plan has no provider role".to_string())
            })?;
        let sublayer_operation = operation_plan
            .apply_operations
            .iter()
            .find(|operation| operation.role == "sublayer")
            .ok_or_else(|| {
                ProxyError::Invalid("WFP apply plan has no sublayer role".to_string())
            })?;
        let mut provider_key = parse_wfp_guid(&provider_operation.key)?;
        let sublayer_key = parse_wfp_guid(&sublayer_operation.key)?;
        let provider_name = wide_null(&provider_operation.display_name);
        let provider_desc = wide_null("SOCKS5Proxy managed Z4 WFP provider");
        let provider = FWPM_PROVIDER0 {
            providerKey: provider_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: provider_name.as_ptr() as *mut _,
                description: provider_desc.as_ptr() as *mut _,
            },
            // Non-persistent on purpose: a persistent object would survive a
            // reboot. Combined with non-persistent filters in Mullvad's
            // kill-switch sublayer, that would leave a permanent hole in the
            // kill-switch if we ever failed to clean up. See cleanup/rollback.
            flags: 0,
            ..Default::default()
        };
        let result = FwpmProviderAdd0(engine, &provider, std::ptr::null_mut());
        if result != 0 {
            return Err(ProxyError::Command(format!(
                "failed to add WFP provider {}: 0x{result:08x}",
                provider_operation.key
            )));
        }

        let sublayer_name = wide_null(&sublayer_operation.display_name);
        let sublayer_desc = wide_null("SOCKS5Proxy managed Z4 WFP sublayer");
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: sublayer_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: sublayer_name.as_ptr() as *mut _,
                description: sublayer_desc.as_ptr() as *mut _,
            },
            providerKey: &mut provider_key,
            // Non-persistent (see provider comment). NOTE: our permit filters do
            // NOT live in this sublayer — a separate sublayer can never outrank
            // Mullvad's baseline (weight 0xFFFF). This sublayer is retained only
            // as a provider-owned anchor for diagnostics/cleanup symmetry; the
            // filters below target MULLVAD_BASELINE_SUBLAYER_GUID instead.
            flags: 0,
            weight: 0x7000,
            ..Default::default()
        };
        let result = FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut());
        if result != 0 {
            return Err(ProxyError::Command(format!(
                "failed to add WFP sublayer {}: 0x{result:08x}",
                sublayer_operation.key
            )));
        }

        // All permit filters go into Mullvad's baseline kill-switch sublayer so
        // they can actually outrank Mullvad's BlockAll. Without this they land
        // in a lower-weighted sublayer and are never reached (= "no internet").
        let mullvad_baseline_sublayer = resolve_mullvad_baseline_sublayer(engine)?;

        for operation in operation_plan
            .apply_operations
            .iter()
            .filter(|operation| operation.layer.starts_with("FWPM_LAYER_"))
        {
            let filter_key = parse_wfp_guid(&operation.key)?;
            let display_name = wide_null(&operation.display_name);
            let display_desc = wide_null(&operation.scope);
            let mut condition_set = wfp_filter_condition_set(operation, readiness)?;
            // Raw u64 weight, must outlive the FwpmFilterAdd0 call below.
            let mut filter_weight: u64 = SOCKS5PROXY_PERMIT_FILTER_WEIGHT;
            let mut filter = FWPM_FILTER0 {
                filterKey: filter_key,
                displayData: FWPM_DISPLAY_DATA0 {
                    name: display_name.as_ptr() as *mut _,
                    description: display_desc.as_ptr() as *mut _,
                },
                // Non-persistent: a crash must not leave a permanent permit in
                // Mullvad's kill-switch sublayer. These filters are torn down on
                // stop/failure and swept on next start.
                flags: 0,
                providerKey: &mut provider_key,
                // Mullvad blocks V4 and V6 separately, so a permit must sit on the
                // ALE_AUTH_CONNECT layer matching the address family it permits.
                layerKey: if condition_set.layer_is_v6 {
                    FWPM_LAYER_ALE_AUTH_CONNECT_V6
                } else {
                    FWPM_LAYER_ALE_AUTH_CONNECT_V4
                },
                subLayerKey: mullvad_baseline_sublayer,
                weight: FWP_VALUE0 {
                    r#type: FWP_UINT64,
                    Anonymous: FWP_VALUE0_0 {
                        uint64: &mut filter_weight,
                    },
                },
                numFilterConditions: condition_set.conditions.len() as u32,
                filterCondition: if condition_set.conditions.is_empty() {
                    std::ptr::null_mut()
                } else {
                    condition_set.conditions.as_mut_ptr()
                },
                action: FWPM_ACTION0 {
                    r#type: FWP_ACTION_PERMIT,
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut filter_id = 0u64;
            let result = FwpmFilterAdd0(engine, &mut filter, std::ptr::null_mut(), &mut filter_id);
            if result != 0 {
                return Err(ProxyError::Command(format!(
                    "failed to add WFP filter {} ({}): 0x{result:08x}",
                    operation.role, operation.key
                )));
            }
        }

        Ok(())
    }

    unsafe fn wfp_filter_condition_set(
        operation: &WindowsWfpOperation,
        readiness: &WindowsWfpApplyReadiness,
    ) -> Result<WfpFilterConditionSet, ProxyError> {
        let mut set = WfpFilterConditionSet {
            conditions: Vec::new(),
            v4_masks: Vec::new(),
            v6_masks: Vec::new(),
            _app_blobs: Vec::new(),
            layer_is_v6: false,
        };
        match operation.role.as_str() {
            "allow_tun2proxy" | "allow_controller" => {
                let path = match operation.role.as_str() {
                    "allow_tun2proxy" => readiness.context.tun2proxy_path.as_ref(),
                    _ => readiness.context.app_path.as_ref(),
                }
                .ok_or_else(|| {
                    ProxyError::Invalid(format!(
                        "{} path is required for WFP app-id apply",
                        operation.role
                    ))
                })?;
                set._app_blobs.push(app_id_blob(path)?);
                let blob_ptr = set._app_blobs.last_mut().expect("app blob").ptr;
                set.conditions.push(condition_app_id(blob_ptr));
                Ok(set)
            }
            "enforce_proxy_vpn_route" => {
                // Permit tun2proxy's upstream connection to the proxy server.
                // Forcing it *through* the Mullvad tunnel is a routing concern
                // (pinned host route, CHAIN-3), not a WFP one:
                // FWPM_CONDITION_NEXTHOP_INTERFACE_INDEX is not a valid field at
                // the ALE_AUTH_CONNECT layer and made FwpmFilterAdd0 fail, which
                // aborted the whole apply. Mullvad's own PermitVpnTunnel already
                // permits in-tunnel egress, so a remote-address permit suffices.
                let proxy_ip = readiness.context.proxy_ip.as_deref().ok_or_else(|| {
                    ProxyError::Invalid("proxy IP is required for WFP apply".to_string())
                })?;
                push_remote_address(&mut set, proxy_ip)?;
                Ok(set)
            }
            "allow_mullvad_transport" => {
                let endpoint_ip = readiness
                    .context
                    .mullvad_endpoint_ip
                    .as_deref()
                    .ok_or_else(|| {
                        ProxyError::Invalid(
                            "Mullvad endpoint IP is required for WFP apply".to_string(),
                        )
                    })?;
                push_remote_address(&mut set, endpoint_ip)?;
                Ok(set)
            }
            _ => Ok(set),
        }
    }

    unsafe fn app_id_blob(path: &Path) -> Result<AppIdBlob, ProxyError> {
        let wide = wide_null(&path.display().to_string());
        let mut ptr = std::ptr::null_mut();
        let result = FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut ptr);
        if result != 0 {
            return Err(ProxyError::Command(format!(
                "failed to resolve WFP app id for {}: 0x{result:08x}",
                path.display()
            )));
        }
        Ok(AppIdBlob { ptr })
    }

    fn condition_app_id(
        blob: *mut windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB,
    ) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: blob },
            },
        }
    }

    fn condition_v4_addr(
        field_key: &windows_sys::core::GUID,
        value: &mut FWP_V4_ADDR_AND_MASK,
    ) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: *field_key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V4_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: value },
            },
        }
    }

    fn condition_v6_addr(
        field_key: &windows_sys::core::GUID,
        value: &mut FWP_V6_ADDR_AND_MASK,
    ) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: *field_key,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_V6_ADDR_MASK,
                Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: value },
            },
        }
    }

    /// Add an exact remote-address condition for `value`, picking V4 vs V6 by the
    /// parsed family and flagging the set so the apply loop installs the filter on
    /// the matching ALE_AUTH_CONNECT layer. The mask/addr struct lives in the set
    /// (one element per call), so the raw pointer in the condition stays valid.
    fn push_remote_address(
        set: &mut WfpFilterConditionSet,
        value: &str,
    ) -> Result<(), ProxyError> {
        match value.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                set.v4_masks.push(FWP_V4_ADDR_AND_MASK {
                    addr: u32::from_be_bytes(ip.octets()),
                    mask: u32::MAX,
                });
                let remote = set.v4_masks.last_mut().expect("v4 mask");
                set.conditions
                    .push(condition_v4_addr(&FWPM_CONDITION_IP_REMOTE_ADDRESS, remote));
            }
            Ok(IpAddr::V6(ip)) => {
                set.v6_masks.push(FWP_V6_ADDR_AND_MASK {
                    addr: ip.octets(),
                    prefixLength: 128,
                });
                let remote = set.v6_masks.last_mut().expect("v6 mask");
                set.conditions
                    .push(condition_v6_addr(&FWPM_CONDITION_IP_REMOTE_ADDRESS, remote));
                set.layer_is_v6 = true;
            }
            Err(error) => {
                return Err(ProxyError::Invalid(format!(
                    "invalid IP address for WFP apply {value:?}: {error}"
                )));
            }
        }
        Ok(())
    }

    fn wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
fn apply_wfp_operation_plan_inner(
    _operation_plan: &WindowsWfpOperationPlan,
    _readiness: &WindowsWfpApplyReadiness,
) -> Result<WindowsWfpMutationReport, ProxyError> {
    Err(ProxyError::Command(
        "Windows Filtering Platform apply is only available on Windows".to_string(),
    ))
}

/// Role name for the deferred Wintun-egress permit (CHAIN-4 phase 2). Unlike the
/// six planned roles, this filter is applied only *after* tun2proxy creates the
/// Wintun adapter, because its condition needs the adapter's interface LUID,
/// which does not exist until the process is running.
const WFP_WINTUN_EGRESS_ROLE: &str = "allow_wintun_egress";

// Phase-2 DNS permit. Mullvad enforces DNS-leak protection with a dedicated
// "Mullvad VPN DNS" sublayer that BLOCKS all outbound port-53 traffic except to
// its own resolver — separate from its baseline kill-switch. Our baseline Wintun
// permit therefore does NOT cover DNS, so the proxy's virtual resolver (10.0.0.1,
// reached via the Wintun) is unreachable and name resolution dies. We add a permit
// for Wintun-egress DNS *into that DNS sublayer* with a weight above Mullvad's
// weight-0 block (mirroring Mullvad's own weight-7 "loopback DNS" permit). Scoped
// to the Wintun local interface, so it only frees DNS that flows into the proxy
// TUN — physical-interface DNS stays under Mullvad's leak protection.
const WFP_WINTUN_DNS_ROLE: &str = "allow_wintun_dns";
const WFP_WINTUN_DNS_DISPLAY: &str = "SOCKS5Proxy Z4 allow Wintun DNS";
const WFP_WINTUN_DNS_LAYER: &str = "FWPM_LAYER_ALE_AUTH_CONNECT_V4";
const WFP_WINTUN_DNS_SCOPE: &str =
    "allow DNS from the proxy Wintun adapter past Mullvad's DNS-leak block";
/// Fallback key for Mullvad's DNS sublayer; resolved by name at runtime because
/// the GUID is not stable across Mullvad versions (see resolver below).
const MULLVAD_DNS_SUBLAYER_GUID: &str = "{e65841b6-82f6-4d55-bde2-61f84d4508d4}";

fn wintun_dns_filter_key(session_tag: &str) -> String {
    deterministic_wfp_guid(session_tag, WFP_WINTUN_DNS_ROLE)
}

fn wintun_dns_filter_status(session_tag: &str) -> WfpFilterStatus {
    WfpFilterStatus {
        filter_id: wintun_dns_filter_key(session_tag),
        layer: WFP_WINTUN_DNS_LAYER.to_string(),
        display_name: WFP_WINTUN_DNS_DISPLAY.to_string(),
        session_tag: session_tag.to_string(),
    }
}

fn wintun_dns_rollback_operation(session_tag: &str) -> WindowsWfpOperation {
    WindowsWfpOperation {
        action: "delete".to_string(),
        role: WFP_WINTUN_DNS_ROLE.to_string(),
        key: wintun_dns_filter_key(session_tag),
        layer: WFP_WINTUN_DNS_LAYER.to_string(),
        display_name: WFP_WINTUN_DNS_DISPLAY.to_string(),
        scope: WFP_WINTUN_DNS_SCOPE.to_string(),
    }
}
const WFP_WINTUN_EGRESS_DISPLAY: &str = "SOCKS5Proxy Z4 allow Wintun egress";
const WFP_WINTUN_EGRESS_LAYER: &str = "FWPM_LAYER_ALE_AUTH_CONNECT_V4";
const WFP_WINTUN_EGRESS_SCOPE: &str = "allow app traffic routed into the proxy Wintun adapter";

/// Stable filter key for the Wintun-egress permit, derived like every other WFP
/// identity so teardown can delete it by key even across process restarts.
fn wintun_egress_filter_key(session_tag: &str) -> String {
    deterministic_wfp_guid(session_tag, WFP_WINTUN_EGRESS_ROLE)
}

/// Tracked status for the phase-2 Wintun-egress filter, appended to the live
/// session's `wfp_filters` so status reporting and persisted-filter sweeps see it.
fn wintun_egress_filter_status(session_tag: &str) -> WfpFilterStatus {
    WfpFilterStatus {
        filter_id: wintun_egress_filter_key(session_tag),
        layer: WFP_WINTUN_EGRESS_LAYER.to_string(),
        display_name: WFP_WINTUN_EGRESS_DISPLAY.to_string(),
        session_tag: session_tag.to_string(),
    }
}

/// Delete operation for the Wintun-egress permit, inserted at the front of the
/// live session's rollback list after a successful phase-2 apply so the existing
/// teardown path (`rollback_wfp_if_needed`) removes it by key before the provider.
fn wintun_egress_rollback_operation(session_tag: &str) -> WindowsWfpOperation {
    WindowsWfpOperation {
        action: "delete".to_string(),
        role: WFP_WINTUN_EGRESS_ROLE.to_string(),
        key: wintun_egress_filter_key(session_tag),
        layer: WFP_WINTUN_EGRESS_LAYER.to_string(),
        display_name: WFP_WINTUN_EGRESS_DISPLAY.to_string(),
        scope: WFP_WINTUN_EGRESS_SCOPE.to_string(),
    }
}

/// Resolve Mullvad's kill-switch ("baseline") sublayer key at runtime.
///
/// The sublayer GUID is not stable across Mullvad versions, so hard-coding it
/// breaks with `FWP_E_SUBLAYER_NOT_FOUND` whenever the installed build differs
/// from the one the constant was copied from. Instead we enumerate every sublayer
/// in the engine and pick Mullvad's baseline by its two invariant properties: the
/// display name contains "mullvad" + "baseline" and it sits at the maximum
/// sublayer weight 0xFFFF (`MAXUINT16`, where Mullvad installs its terminating
/// `BlockAll`). Returns the hard-coded constant only if nothing matches (e.g.
/// Mullvad not running), so callers still get a defined key.
#[cfg(windows)]
unsafe fn resolve_mullvad_baseline_sublayer(
    engine: windows_sys::Win32::Foundation::HANDLE,
) -> Result<windows_sys::core::GUID, ProxyError> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFreeMemory0, FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDestroyEnumHandle0,
        FwpmSubLayerEnum0, FWPM_SUBLAYER0,
    };

    unsafe fn read_wide(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }

    let mut enum_handle: HANDLE = std::ptr::null_mut();
    let create = FwpmSubLayerCreateEnumHandle0(engine, std::ptr::null(), &mut enum_handle);
    if create != 0 {
        return Err(ProxyError::Command(format!(
            "failed to enumerate WFP sublayers: 0x{create:08x}"
        )));
    }

    let mut resolved: Option<windows_sys::core::GUID> = None;
    // Highest-weight match wins, so the 0xFFFF baseline beats any decoy.
    let mut best_weight: i32 = -1;
    loop {
        let mut entries: *mut *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        let mut returned: u32 = 0;
        let result = FwpmSubLayerEnum0(engine, enum_handle, 512, &mut entries, &mut returned);
        if result != 0 {
            FwpmSubLayerDestroyEnumHandle0(engine, enum_handle);
            return Err(ProxyError::Command(format!(
                "failed to read WFP sublayer batch: 0x{result:08x}"
            )));
        }
        if returned == 0 || entries.is_null() {
            break;
        }
        for index in 0..returned as usize {
            let sublayer = *entries.add(index);
            if sublayer.is_null() {
                continue;
            }
            let name = read_wide((*sublayer).displayData.name).to_ascii_lowercase();
            let weight = (*sublayer).weight;
            if name.contains("mullvad") && name.contains("baseline") && i32::from(weight) > best_weight
            {
                best_weight = i32::from(weight);
                resolved = Some((*sublayer).subLayerKey);
            }
        }
        let mut entries_ptr = entries.cast::<std::ffi::c_void>();
        FwpmFreeMemory0(&mut entries_ptr);
        if returned < 512 {
            break;
        }
    }
    FwpmSubLayerDestroyEnumHandle0(engine, enum_handle);

    match resolved {
        Some(guid) => Ok(guid),
        // Mullvad not detected (or renamed its sublayer); fall back to the
        // documented constant so the caller still has a defined key. If the key is
        // genuinely wrong the filter add fails loudly, as before.
        None => parse_wfp_guid(MULLVAD_BASELINE_SUBLAYER_GUID),
    }
}

/// Resolve Mullvad's DNS-leak-protection sublayer ("Mullvad VPN DNS") at runtime.
///
/// Like the baseline sublayer, this GUID changes across Mullvad versions, so we
/// enumerate and match by the invariant name (contains "mullvad" + "dns"). This is
/// where Mullvad installs its weight-0 "Block outbound DNS" filter; our DNS permit
/// must live in the SAME sublayer to outrank it. Highest-weight match wins so a
/// decoy can't shadow the real one. Falls back to the documented constant.
#[cfg(windows)]
unsafe fn resolve_mullvad_dns_sublayer(
    engine: windows_sys::Win32::Foundation::HANDLE,
) -> Result<windows_sys::core::GUID, ProxyError> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmFreeMemory0, FwpmSubLayerCreateEnumHandle0, FwpmSubLayerDestroyEnumHandle0,
        FwpmSubLayerEnum0, FWPM_SUBLAYER0,
    };

    unsafe fn read_wide(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len))
    }

    let mut enum_handle: HANDLE = std::ptr::null_mut();
    let create = FwpmSubLayerCreateEnumHandle0(engine, std::ptr::null(), &mut enum_handle);
    if create != 0 {
        return Err(ProxyError::Command(format!(
            "failed to enumerate WFP sublayers: 0x{create:08x}"
        )));
    }

    let mut resolved: Option<windows_sys::core::GUID> = None;
    let mut best_weight: i32 = -1;
    loop {
        let mut entries: *mut *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        let mut returned: u32 = 0;
        let result = FwpmSubLayerEnum0(engine, enum_handle, 512, &mut entries, &mut returned);
        if result != 0 {
            FwpmSubLayerDestroyEnumHandle0(engine, enum_handle);
            return Err(ProxyError::Command(format!(
                "failed to read WFP sublayer batch: 0x{result:08x}"
            )));
        }
        if returned == 0 || entries.is_null() {
            break;
        }
        for index in 0..returned as usize {
            let sublayer = *entries.add(index);
            if sublayer.is_null() {
                continue;
            }
            let name = read_wide((*sublayer).displayData.name).to_ascii_lowercase();
            let weight = (*sublayer).weight;
            if name.contains("mullvad") && name.contains("dns") && i32::from(weight) > best_weight {
                best_weight = i32::from(weight);
                resolved = Some((*sublayer).subLayerKey);
            }
        }
        let mut entries_ptr = entries.cast::<std::ffi::c_void>();
        FwpmFreeMemory0(&mut entries_ptr);
        if returned < 512 {
            break;
        }
    }
    FwpmSubLayerDestroyEnumHandle0(engine, enum_handle);

    match resolved {
        Some(guid) => Ok(guid),
        None => parse_wfp_guid(MULLVAD_DNS_SUBLAYER_GUID),
    }
}

/// Resolve a network interface's LUID (a stable 64-bit identifier) from its
/// adapter alias. Used to bind the Wintun-egress permit to the proxy TUN device.
#[cfg(windows)]
fn interface_luid(alias: &str) -> Result<u64, ProxyError> {
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    let mut luid: NET_LUID_LH = unsafe { std::mem::zeroed() };
    let result = unsafe {
        windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid(
            wide.as_ptr(),
            &mut luid,
        )
    };
    if result != 0 {
        return Err(ProxyError::Command(format!(
            "failed to resolve interface LUID for {alias:?}: 0x{result:08x}"
        )));
    }
    Ok(unsafe { luid.Value })
}

#[cfg(not(windows))]
fn interface_luid(_alias: &str) -> Result<u64, ProxyError> {
    Err(ProxyError::Command(
        "interface LUID resolution is only available on Windows".to_string(),
    ))
}

/// Phase 2 of the Z4 WFP exception: permit outbound connections whose local
/// interface is the proxy Wintun adapter. App `connect()`s routed into the proxy
/// TUN egress on the Wintun interface (not Mullvad's tunnel), so Mullvad's
/// `BlockAll` would kill them; this permit, installed into Mullvad's baseline
/// sublayer above their block, lets them through. Mirrors Mullvad's own
/// per-interface tunnel permit. Reuses the provider created in phase 1 and is
/// non-persistent. Returns the tracked status plus the rollback delete op so the
/// caller can wire teardown.
#[cfg(windows)]
fn apply_wintun_egress_permit(
    session_tag: &str,
    wintun_luid: u64,
) -> Result<(WfpFilterStatus, WindowsWfpOperation), ProxyError> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FWPM_ACTION0,
        FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, FWP_CONDITION_VALUE0,
        FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT64, FWP_VALUE0, FWP_VALUE0_0,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

    let status = wintun_egress_filter_status(session_tag);
    let rollback = wintun_egress_rollback_operation(session_tag);
    let mut provider_key = parse_wfp_guid(&deterministic_wfp_guid(session_tag, "provider"))?;
    let filter_key = parse_wfp_guid(&status.filter_id)?;
    let display_name: Vec<u16> = WFP_WINTUN_EGRESS_DISPLAY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let display_desc: Vec<u16> = WFP_WINTUN_EGRESS_SCOPE
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut engine: HANDLE = std::ptr::null_mut();
        let open = FwpmEngineOpen0(
            std::ptr::null(),
            RPC_C_AUTHN_DEFAULT as u32,
            std::ptr::null(),
            std::ptr::null(),
            &mut engine,
        );
        if open != 0 {
            return Err(ProxyError::Command(format!(
                "failed to open WFP engine for Wintun permit: 0x{open:08x}"
            )));
        }
        let sublayer = match resolve_mullvad_baseline_sublayer(engine) {
            Ok(guid) => guid,
            Err(error) => {
                FwpmEngineClose0(engine);
                return Err(error);
            }
        };
        // luid_value/filter_weight must outlive the FwpmFilterAdd0 call: the
        // condition and weight hold raw pointers into them.
        let mut luid_value: u64 = wintun_luid;
        let mut conditions = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint64: &mut luid_value,
                },
            },
        }];
        let mut filter_weight: u64 = SOCKS5PROXY_PERMIT_FILTER_WEIGHT;
        let filter = FWPM_FILTER0 {
            filterKey: filter_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: display_name.as_ptr() as *mut _,
                description: display_desc.as_ptr() as *mut _,
            },
            // Non-persistent: must not survive a crash/reboot as a hole in the
            // kill-switch sublayer. Torn down on stop and swept on next start.
            flags: 0,
            providerKey: &mut provider_key,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: sublayer,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut filter_weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut filter_id = 0u64;
        let result = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut filter_id);
        FwpmEngineClose0(engine);
        if result != 0 {
            return Err(ProxyError::Command(format!(
                "failed to add WFP Wintun egress permit (luid 0x{wintun_luid:016x}): 0x{result:08x}"
            )));
        }
    }
    Ok((status, rollback))
}

#[cfg(not(windows))]
fn apply_wintun_egress_permit(
    _session_tag: &str,
    _wintun_luid: u64,
) -> Result<(WfpFilterStatus, WindowsWfpOperation), ProxyError> {
    Err(ProxyError::Command(
        "Windows Filtering Platform apply is only available on Windows".to_string(),
    ))
}

/// Phase 2b of the Z4 WFP exception: permit DNS that egresses on the proxy Wintun
/// adapter so the proxy's virtual resolver (10.0.0.1) is reachable past Mullvad's
/// DNS-leak block. Identical condition to the egress permit (local interface ==
/// Wintun LUID) but installed into Mullvad's *DNS* sublayer, where its weight
/// outranks Mullvad's weight-0 "Block outbound DNS". Reuses the phase-1 provider,
/// non-persistent. Returns the tracked status plus the rollback delete op.
#[cfg(windows)]
fn apply_wintun_dns_permit(
    session_tag: &str,
    wintun_luid: u64,
) -> Result<(WfpFilterStatus, WindowsWfpOperation), ProxyError> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
        FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FWPM_ACTION0,
        FWPM_CONDITION_IP_LOCAL_INTERFACE, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0,
        FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWP_ACTION_PERMIT, FWP_CONDITION_VALUE0,
        FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT64, FWP_VALUE0, FWP_VALUE0_0,
    };
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;

    let status = wintun_dns_filter_status(session_tag);
    let rollback = wintun_dns_rollback_operation(session_tag);
    let mut provider_key = parse_wfp_guid(&deterministic_wfp_guid(session_tag, "provider"))?;
    let filter_key = parse_wfp_guid(&status.filter_id)?;
    let display_name: Vec<u16> = WFP_WINTUN_DNS_DISPLAY
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let display_desc: Vec<u16> = WFP_WINTUN_DNS_SCOPE
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut engine: HANDLE = std::ptr::null_mut();
        let open = FwpmEngineOpen0(
            std::ptr::null(),
            RPC_C_AUTHN_DEFAULT as u32,
            std::ptr::null(),
            std::ptr::null(),
            &mut engine,
        );
        if open != 0 {
            return Err(ProxyError::Command(format!(
                "failed to open WFP engine for Wintun DNS permit: 0x{open:08x}"
            )));
        }
        let sublayer = match resolve_mullvad_dns_sublayer(engine) {
            Ok(guid) => guid,
            Err(error) => {
                FwpmEngineClose0(engine);
                return Err(error);
            }
        };
        // luid_value/filter_weight must outlive the FwpmFilterAdd0 call.
        let mut luid_value: u64 = wintun_luid;
        let mut conditions = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_LOCAL_INTERFACE,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    uint64: &mut luid_value,
                },
            },
        }];
        let mut filter_weight: u64 = SOCKS5PROXY_PERMIT_FILTER_WEIGHT;
        let filter = FWPM_FILTER0 {
            filterKey: filter_key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: display_name.as_ptr() as *mut _,
                description: display_desc.as_ptr() as *mut _,
            },
            flags: 0,
            providerKey: &mut provider_key,
            layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            subLayerKey: sublayer,
            weight: FWP_VALUE0 {
                r#type: FWP_UINT64,
                Anonymous: FWP_VALUE0_0 {
                    uint64: &mut filter_weight,
                },
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: FWPM_ACTION0 {
                r#type: FWP_ACTION_PERMIT,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut filter_id = 0u64;
        let result = FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut filter_id);
        FwpmEngineClose0(engine);
        if result != 0 {
            return Err(ProxyError::Command(format!(
                "failed to add WFP Wintun DNS permit (luid 0x{wintun_luid:016x}): 0x{result:08x}"
            )));
        }
    }
    Ok((status, rollback))
}

#[cfg(not(windows))]
fn apply_wintun_dns_permit(
    _session_tag: &str,
    _wintun_luid: u64,
) -> Result<(WfpFilterStatus, WindowsWfpOperation), ProxyError> {
    Err(ProxyError::Command(
        "Windows Filtering Platform apply is only available on Windows".to_string(),
    ))
}

/// Result of [`wintun_egress_permit_selftest`].
#[derive(Clone, Debug)]
pub struct WintunEgressSelftestReport {
    pub interface: String,
    pub luid: Option<u64>,
    pub luid_error: Option<String>,
    pub phase1_status: String,
    pub phase1_errors: Vec<String>,
    pub wintun_applied: bool,
    pub wintun_error: Option<String>,
    pub rollback_status: String,
    pub rollback_errors: Vec<String>,
    pub ok: bool,
}

/// Live self-test for the CHAIN-4 phase-2 Wintun-egress permit, against a real
/// interface alias instead of a running tun2proxy session. It applies phase 1
/// (provider + sublayer + the four permits), resolves the interface LUID, adds
/// the Wintun-egress permit, then rolls everything back. This exercises the
/// new FFI (`ConvertInterfaceAliasToLuid` + `FwpmFilterAdd0` with an
/// `IP_LOCAL_INTERFACE` condition) without needing a working proxy connection.
/// Requires Mullvad connected, elevation, and the WFP mutation gate.
#[cfg(windows)]
pub fn wintun_egress_permit_selftest(
    operation_plan: &WindowsWfpOperationPlan,
    readiness: &WindowsWfpApplyReadiness,
    interface: &str,
) -> WintunEgressSelftestReport {
    let mut report = WintunEgressSelftestReport {
        interface: interface.to_string(),
        luid: None,
        luid_error: None,
        phase1_status: String::new(),
        phase1_errors: Vec::new(),
        wintun_applied: false,
        wintun_error: None,
        rollback_status: String::new(),
        rollback_errors: Vec::new(),
        ok: false,
    };

    match apply_wfp_operation_plan(operation_plan, readiness) {
        Ok(result) => {
            report.phase1_status = result.status;
            report.phase1_errors = result.errors;
        }
        Err(error) => {
            report.phase1_status = "error".to_string();
            report.phase1_errors = vec![error.to_string()];
            return report;
        }
    }
    if !report.phase1_errors.is_empty() || report.phase1_status != "applied" {
        return report;
    }

    let mut rollback_plan = operation_plan.clone();
    match interface_luid(interface) {
        Ok(luid) => {
            report.luid = Some(luid);
            match apply_wintun_egress_permit(&operation_plan.session_tag, luid) {
                Ok((_status, rollback)) => {
                    report.wintun_applied = true;
                    rollback_plan.rollback_operations.insert(0, rollback);
                }
                Err(error) => report.wintun_error = Some(error.to_string()),
            }
        }
        Err(error) => report.luid_error = Some(error.to_string()),
    }

    // Always tear down — a self-test must never leave filters behind.
    match rollback_wfp_operation_plan(&rollback_plan) {
        Ok(result) => {
            report.rollback_status = result.status;
            report.rollback_errors = result.errors;
        }
        Err(error) => {
            report.rollback_status = "error".to_string();
            report.rollback_errors = vec![error.to_string()];
        }
    }

    report.ok = report.phase1_errors.is_empty()
        && report.luid_error.is_none()
        && report.wintun_applied
        && report.wintun_error.is_none()
        && report.rollback_errors.is_empty();
    report
}

#[cfg(not(windows))]
pub fn wintun_egress_permit_selftest(
    _operation_plan: &WindowsWfpOperationPlan,
    _readiness: &WindowsWfpApplyReadiness,
    interface: &str,
) -> WintunEgressSelftestReport {
    WintunEgressSelftestReport {
        interface: interface.to_string(),
        luid: None,
        luid_error: Some("Wintun egress self-test is only available on Windows".to_string()),
        phase1_status: "unsupported".to_string(),
        phase1_errors: Vec::new(),
        wintun_applied: false,
        wintun_error: None,
        rollback_status: "unsupported".to_string(),
        rollback_errors: Vec::new(),
        ok: false,
    }
}

fn parse_wfp_guid(input: &str) -> Result<windows_sys::core::GUID, ProxyError> {
    let trimmed = input.trim();
    let bare = trimmed
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(trimmed);
    let parts = bare.split('-').collect::<Vec<_>>();
    if parts.len() != 5
        || parts[0].len() != 8
        || parts[1].len() != 4
        || parts[2].len() != 4
        || parts[3].len() != 4
        || parts[4].len() != 12
    {
        return Err(ProxyError::Invalid(format!("invalid WFP GUID: {input}")));
    }

    let data1 = u32::from_str_radix(parts[0], 16)
        .map_err(|error| ProxyError::Invalid(format!("invalid WFP GUID {input}: {error}")))?;
    let data2 = u16::from_str_radix(parts[1], 16)
        .map_err(|error| ProxyError::Invalid(format!("invalid WFP GUID {input}: {error}")))?;
    let data3 = u16::from_str_radix(parts[2], 16)
        .map_err(|error| ProxyError::Invalid(format!("invalid WFP GUID {input}: {error}")))?;
    let data4_hex = format!("{}{}", parts[3], parts[4]);
    let mut data4 = [0u8; 8];
    for index in 0..8 {
        let offset = index * 2;
        data4[index] = u8::from_str_radix(&data4_hex[offset..offset + 2], 16)
            .map_err(|error| ProxyError::Invalid(format!("invalid WFP GUID {input}: {error}")))?;
    }

    Ok(windows_sys::core::GUID {
        data1,
        data2,
        data3,
        data4,
    })
}

fn wfp_operation(
    action: &str,
    identity: &WindowsWfpRuleId,
    scope: impl Into<String>,
) -> WindowsWfpOperation {
    WindowsWfpOperation {
        action: action.to_string(),
        role: identity.role.clone(),
        key: identity.key.clone(),
        layer: identity.layer.clone(),
        display_name: identity.display_name.clone(),
        scope: scope.into(),
    }
}

fn wfp_operation_scope(identity: &WindowsWfpRuleId) -> &'static str {
    match identity.role.as_str() {
        "provider" => "create socks5proxy-owned WFP provider",
        "sublayer" => "create socks5proxy-owned WFP sublayer",
        "allow_tun2proxy" => "allow managed tun2proxy process traffic",
        "allow_controller" => "allow desktop controller management traffic",
        "enforce_proxy_vpn_route" => "enforce proxy server traffic through Mullvad tunnel",
        "allow_mullvad_transport" => "allow Mullvad relay transport outside proxy TUN",
        _ => "unknown socks5proxy WFP identity",
    }
}

fn wfp_rule_identities(session_tag: &str) -> Vec<WindowsWfpRuleId> {
    [
        ("provider", "FWPM_PROVIDER", "SOCKS5Proxy Z4 WFP provider"),
        ("sublayer", "FWPM_SUBLAYER", "SOCKS5Proxy Z4 WFP sublayer"),
        (
            "allow_tun2proxy",
            "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            "SOCKS5Proxy Z4 allow tun2proxy",
        ),
        (
            "allow_controller",
            "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            "SOCKS5Proxy Z4 allow controller",
        ),
        (
            "enforce_proxy_vpn_route",
            "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            "SOCKS5Proxy Z4 enforce proxy via Mullvad",
        ),
        (
            "allow_mullvad_transport",
            "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            "SOCKS5Proxy Z4 allow Mullvad transport",
        ),
    ]
    .into_iter()
    .map(|(role, layer, display_name)| WindowsWfpRuleId {
        role: role.to_string(),
        key: deterministic_wfp_guid(session_tag, role),
        display_name: display_name.to_string(),
        layer: layer.to_string(),
    })
    .collect()
}

fn deterministic_wfp_guid(session_tag: &str, role: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"socks5proxy-windows-wfp-v1");
    digest.update(session_tag.as_bytes());
    digest.update(b":");
    digest.update(role.as_bytes());
    let hash = digest.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{{{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

pub fn proxy_vpn_route_plan(proxy_ip: &str) -> Result<Option<WindowsProxyRoutePlan>, ProxyError> {
    let snapshot = try_inspect_windows_routes(proxy_ip)?;
    let Some(vpn_interface) = snapshot.active_vpn_interface.as_deref() else {
        return Ok(None);
    };
    if snapshot.proxy_uplink_interface.as_deref() == Some(vpn_interface) {
        return Ok(None);
    }
    let vpn_interface_index = interface_index(vpn_interface)?;
    Ok(Some(build_proxy_route_plan(
        proxy_ip,
        vpn_interface,
        vpn_interface_index,
    )?))
}

pub fn resolve_tun2proxy_binary() -> Option<PathBuf> {
    env_override_candidates()
        .into_iter()
        .chain(current_exe_dir_candidates())
        .chain(project_runtime_candidates())
        .into_iter()
        .chain(path_candidates())
        .find(|path| path.is_file())
}

pub fn resolve_mullvad_cli() -> Option<PathBuf> {
    env::var_os("MULLVAD_CLI")
        .map(PathBuf::from)
        .into_iter()
        .chain(program_files_mullvad_candidates())
        .chain(path_mullvad_candidates())
        .find(|path| path.is_file())
}

pub fn resolve_wireguard_cli() -> Option<PathBuf> {
    env::var_os("WG_CLI")
        .map(PathBuf::from)
        .into_iter()
        .chain(program_files_wireguard_candidates())
        .chain(path_wireguard_candidates())
        .find(|path| path.is_file())
}

fn effective_windows_tun_profile(profile: &ResolvedProfile) -> ResolvedProfile {
    let mut effective = effective_tun_profile(profile);
    add_mullvad_transport_bypasses(&mut effective);
    add_wireguard_transport_bypasses(&mut effective);
    effective
}

/// Build the effective Windows TUN profile, ensuring the proxy endpoint host has
/// been resolved to an IP literal before we start pinning routes / WFP filters.
///
/// Route and WFP pinning require a concrete proxy IP (`enforce_proxy_vpn_route`,
/// `build_proxy_route_plan`). `effective_tun_profile` resolves the host via DNS but
/// silently leaves the hostname in place when resolution fails (it swallows the
/// `to_socket_addrs` error). A transient DNS hiccup — e.g. left over from a just
/// torn-down session — would then surface deep in the apply path as the cryptic
/// "proxy server IP must be an IP literal" error, the session never starts, and
/// Mullvad's kill-switch leaves the host with no internet. Retry a few times
/// (flushing the resolver cache between attempts to clear any poisoned negative
/// entry), then fail with a clear, actionable message instead.
fn resolve_windows_tun_profile(profile: &ResolvedProfile) -> Result<ResolvedProfile, ProxyError> {
    const RESOLVE_ATTEMPTS: usize = 4;
    let mut effective = effective_windows_tun_profile(profile);
    for attempt in 1..=RESOLVE_ATTEMPTS {
        if effective.endpoint.host.parse::<IpAddr>().is_ok() {
            return Ok(effective);
        }
        if attempt < RESOLVE_ATTEMPTS {
            let _ = flush_dns_cache();
            std::thread::sleep(Duration::from_millis(750));
            effective = effective_windows_tun_profile(profile);
        }
    }
    Err(ProxyError::Command(format!(
        "could not resolve proxy host {:?} to an IP address after {RESOLVE_ATTEMPTS} attempts. \
         Check DNS or reconnect Mullvad, then try again.",
        profile.endpoint.host
    )))
}

fn add_mullvad_transport_bypasses(profile: &mut ResolvedProfile) {
    let status = mullvad_status();
    let mut bypasses = profile.bypass.iter().cloned().collect::<BTreeSet<_>>();
    for candidate in mullvad_transport_bypasses(&status) {
        bypasses.insert(candidate);
    }
    profile.bypass = bypasses.into_iter().collect();
}

fn mullvad_transport_bypasses(status: &WindowsMullvadStatus) -> Vec<String> {
    if !mullvad_connected(status) {
        return Vec::new();
    }
    [
        status.endpoint_ip.as_ref(),
        status.relay_ipv4.as_ref(),
        status.relay_ipv6.as_ref(),
        status.entry_ipv4.as_ref(),
        status.entry_ipv6.as_ref(),
    ]
    .into_iter()
    .flatten()
    .cloned()
    .collect::<BTreeSet<_>>()
    .into_iter()
    .collect()
}

fn add_wireguard_transport_bypasses(profile: &mut ResolvedProfile) {
    let status = wireguard_status();
    let mut bypasses = profile.bypass.iter().cloned().collect::<BTreeSet<_>>();
    for candidate in wireguard_transport_bypasses(&status) {
        bypasses.insert(candidate);
    }
    profile.bypass = bypasses.into_iter().collect();
}

fn wireguard_transport_bypasses(status: &WindowsWireGuardStatus) -> Vec<String> {
    status
        .endpoint_ips
        .iter()
        .filter(|value| value.parse::<IpAddr>().is_ok())
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn mullvad_connected(status: &WindowsMullvadStatus) -> bool {
    status
        .state
        .as_deref()
        .map(|state| state.eq_ignore_ascii_case("connected") || state.starts_with("Connected"))
        .unwrap_or(false)
}

fn prepare_mullvad_wfp_for_tun(
    proxy_ip: &str,
    tun2proxy_path: &Path,
) -> Result<(Vec<WfpFilterStatus>, Option<WindowsWfpOperationPlan>), ProxyError> {
    let status = mullvad_status();
    if !mullvad_connected(&status) || experimental_mullvad_tun_allowed() {
        return Ok((Vec::new(), None));
    }

    let firewall = firewall_preflight();
    let exception_plan = wfp_exception_plan(&status, &firewall);
    let operation_plan = wfp_operation_plan(&exception_plan);
    let context = wfp_apply_context_for_mullvad_with_paths(
        Some(proxy_ip),
        &status,
        env::current_exe().ok(),
        Some(tun2proxy_path.to_path_buf()),
    );
    let readiness = wfp_apply_readiness_with_context(&exception_plan, &operation_plan, &context);
    let report = apply_wfp_operation_plan(&operation_plan, &readiness)?;
    if report.status == "applied" {
        return Ok((report.applied, Some(operation_plan)));
    }

    let state = status.state.as_deref().unwrap_or("connected");
    let endpoint = status
        .endpoint_address
        .as_deref()
        .or(status.relay_hostname.as_deref())
        .unwrap_or("unknown endpoint");
    let blockers = report
        .blockers
        .into_iter()
        .chain(report.errors)
        .collect::<Vec<_>>();
    let detail = if blockers.is_empty() {
        "WFP apply was not completed.".to_string()
    } else {
        blockers.join("; ")
    };
    Err(ProxyError::Command(format!(
        "Mullvad is {state} ({endpoint}). Windows Z4 requires the WFP kill-switch exception before starting TUN routing: {detail}"
    )))
}

fn rollback_wfp_if_needed(operation_plan: Option<&WindowsWfpOperationPlan>) {
    if let Some(operation_plan) = operation_plan {
        let _ = rollback_applied_wfp_operation_plan(operation_plan);
    }
}

fn experimental_mullvad_tun_allowed() -> bool {
    env::var(ALLOW_EXPERIMENTAL_MULLVAD_TUN_ENV)
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
fn mullvad_chain_block_reason(
    status: &WindowsMullvadStatus,
    experimental_allowed: bool,
) -> Option<String> {
    if experimental_allowed || !mullvad_connected(status) {
        return None;
    }

    let state = status.state.as_deref().unwrap_or("connected");
    let endpoint = status
        .endpoint_address
        .as_deref()
        .or(status.relay_hostname.as_deref())
        .unwrap_or("unknown endpoint");
    Some(format!(
        "Mullvad is {state} ({endpoint}). Windows Z4 requires the scoped WFP kill-switch exception before starting TUN routing. Disconnect Mullvad to run Z2, or set {ENABLE_WFP_MUTATION_ENV}=1 only for an elevated guarded Z4 live test."
    ))
}

fn probe_tun_connectivity() -> Result<(), ProxyError> {
    // tun2proxy's own connection to the upstream proxy is not always established the
    // instant routing is in place; the first probe through the chain can lose the
    // cold-start race. Retry a few times before declaring the chain dead.
    let addr = SocketAddr::from(([1, 1, 1, 1], 443));
    let mut last_error = None;
    for attempt in 0..4 {
        match TcpStream::connect_timeout(&addr, Duration::from_secs(6)) {
            Ok(_) => return Ok(()),
            Err(error) => {
                last_error = Some(error);
                if attempt < 3 {
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }
    Err(ProxyError::Command(format!(
        "Windows TUN routing started but internet connectivity probe failed: {}",
        last_error.expect("probe loop runs at least once")
    )))
}

fn connected_status(
    profile: &ResolvedProfile,
    effective_profile: &ResolvedProfile,
    route_snapshot: &WindowsRouteSnapshot,
    pinned_proxy_routes: &[WindowsProxyRoutePlan],
    wfp_filters: &[WfpFilterStatus],
    pid: u32,
) -> NamespaceSessionStatus {
    NamespaceSessionStatus {
        state: "connected".to_string(),
        profile_id: Some(profile.id.clone()),
        profile_name: Some(profile.name.clone()),
        proxy_host: Some(profile.endpoint.host.clone()),
        proxy_ip: Some(effective_profile.endpoint.host.clone()),
        tun2proxy_pid: Some(pid),
        host_vpn_interface: route_snapshot.active_vpn_interface.clone(),
        proxy_uplink_interface: route_snapshot.proxy_uplink_interface.clone(),
        owner_uid: None,
        launched_apps: Vec::new(),
        pinned_proxy_routes: pinned_proxy_routes
            .iter()
            .map(WindowsProxyRoutePlan::status)
            .collect(),
        wfp_filters: wfp_filters.to_vec(),
        last_error: None,
        last_reason: route_snapshot
            .last_reason
            .clone()
            .or_else(|| Some("Windows TUN session is managed by tun2proxy.".to_string())),
    }
}

fn error_status(
    profile: &ResolvedProfile,
    effective_profile: &ResolvedProfile,
    message: String,
) -> NamespaceSessionStatus {
    NamespaceSessionStatus {
        state: "error".to_string(),
        profile_id: Some(profile.id.clone()),
        profile_name: Some(profile.name.clone()),
        proxy_host: Some(profile.endpoint.host.clone()),
        proxy_ip: Some(effective_profile.endpoint.host.clone()),
        tun2proxy_pid: None,
        host_vpn_interface: None,
        proxy_uplink_interface: None,
        owner_uid: None,
        launched_apps: Vec::new(),
        pinned_proxy_routes: Vec::new(),
        wfp_filters: Vec::new(),
        last_error: Some(message),
        last_reason: Some("Windows TUN backend reported an error.".to_string()),
    }
}

fn blocked_status(
    profile: &ResolvedProfile,
    effective_profile: &ResolvedProfile,
    route_snapshot: &WindowsRouteSnapshot,
    pinned_proxy_routes: &[WindowsProxyRoutePlan],
    wfp_filters: &[WfpFilterStatus],
    pid: u32,
    reason: String,
) -> NamespaceSessionStatus {
    NamespaceSessionStatus {
        state: "blocked".to_string(),
        profile_id: Some(profile.id.clone()),
        profile_name: Some(profile.name.clone()),
        proxy_host: Some(profile.endpoint.host.clone()),
        proxy_ip: Some(effective_profile.endpoint.host.clone()),
        tun2proxy_pid: Some(pid),
        host_vpn_interface: route_snapshot.active_vpn_interface.clone(),
        proxy_uplink_interface: route_snapshot.proxy_uplink_interface.clone(),
        owner_uid: None,
        launched_apps: Vec::new(),
        pinned_proxy_routes: pinned_proxy_routes
            .iter()
            .map(WindowsProxyRoutePlan::status)
            .collect(),
        wfp_filters: wfp_filters.to_vec(),
        last_error: Some(reason.clone()),
        last_reason: Some(reason),
    }
}

fn inspect_windows_routes(proxy_ip: &str) -> WindowsRouteSnapshot {
    match try_inspect_windows_routes(proxy_ip) {
        Ok(snapshot) => snapshot,
        Err(error) => WindowsRouteSnapshot {
            last_reason: Some(format!("Could not inspect Windows routes: {error}")),
            ..Default::default()
        },
    }
}

fn try_inspect_windows_routes(proxy_ip: &str) -> Result<WindowsRouteSnapshot, ProxyError> {
    let default_route_interface = default_route_interface()?;
    let active_vpn_interface = active_vpn_interface(default_route_interface)?;
    let proxy_uplink_interface = route_interface_to(proxy_ip)?;
    let last_reason = route_reason(&active_vpn_interface, &proxy_uplink_interface);
    Ok(WindowsRouteSnapshot {
        active_vpn_interface,
        proxy_uplink_interface,
        last_reason,
    })
}

fn default_route_interface() -> Result<Option<String>, ProxyError> {
    let output = command_output(console_hidden_command("powershell").args([
        "-NoProfile",
        "-Command",
        "(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric, ifMetric | Select-Object -First 1 | ForEach-Object { (Get-NetAdapter -InterfaceIndex $_.ifIndex).Name })",
    ]))?;
    Ok(non_empty(output))
}

fn active_vpn_interface(
    default_route_interface: Option<String>,
) -> Result<Option<String>, ProxyError> {
    if default_route_interface
        .as_deref()
        .map(vpn_like)
        .unwrap_or(false)
    {
        return Ok(default_route_interface);
    }

    let output = command_output(console_hidden_command("powershell").args([
        "-NoProfile",
        "-Command",
        "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name",
    ]))?;
    Ok(output
        .lines()
        .map(str::trim)
        .find(|name| vpn_like(name))
        .map(ToString::to_string))
}

fn route_interface_to(target: &str) -> Result<Option<String>, ProxyError> {
    let ip = target.parse::<IpAddr>().map_err(|_| {
        ProxyError::Invalid(format!(
            "expected proxy route target to be an IP literal, got {target:?}"
        ))
    })?;
    let command = format!(
        "$route = Find-NetRoute -RemoteIPAddress '{ip}' -ErrorAction SilentlyContinue | Select-Object -First 1; if ($route) {{ (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex).Name }}"
    );
    let output =
        command_output(console_hidden_command("powershell").args(["-NoProfile", "-Command", &command]))?;
    Ok(non_empty(output))
}

fn interface_index(interface: &str) -> Result<u32, ProxyError> {
    let escaped = ps_single_quote(interface);
    let command = format!(
        "$adapter = Get-NetAdapter -Name '{escaped}' -ErrorAction Stop; [int]$adapter.ifIndex"
    );
    let output =
        command_output(console_hidden_command("powershell").args(["-NoProfile", "-Command", &command]))?;
    output.trim().parse::<u32>().map_err(|error| {
        ProxyError::Command(format!(
            "Windows route inspection returned invalid interface index for {interface}: {error}"
        ))
    })
}

fn build_proxy_route_plan(
    proxy_ip: &str,
    vpn_interface: &str,
    vpn_interface_index: u32,
) -> Result<WindowsProxyRoutePlan, ProxyError> {
    build_proxy_route_plan_with_metric(proxy_ip, vpn_interface, vpn_interface_index, 1)
}

fn build_proxy_route_plan_with_metric(
    proxy_ip: &str,
    vpn_interface: &str,
    vpn_interface_index: u32,
    metric: u32,
) -> Result<WindowsProxyRoutePlan, ProxyError> {
    let ip = proxy_ip.parse::<IpAddr>().map_err(|_| {
        ProxyError::Invalid(format!(
            "expected proxy route target to be an IP literal, got {proxy_ip:?}"
        ))
    })?;
    let destination_prefix = host_route_prefix(ip);
    let next_hop = zero_next_hop(ip).to_string();
    Ok(build_interface_route_plan(
        proxy_ip,
        &destination_prefix,
        vpn_interface,
        vpn_interface_index,
        &next_hop,
        metric,
    ))
}

/// Build an `ActiveStore` route plan pinning `destination_prefix` to a specific
/// interface. Used both for the proxy-server VPN pin and for the host-wide capture
/// split into the proxy TUN; the resulting plan is tracked in `pinned_proxy_routes`
/// so the existing teardown removes it automatically.
fn build_interface_route_plan(
    proxy_ip: &str,
    destination_prefix: &str,
    interface_alias: &str,
    interface_index: u32,
    next_hop: &str,
    metric: u32,
) -> WindowsProxyRoutePlan {
    let prefix_arg = ps_single_quote(destination_prefix);
    let next_hop_arg = ps_single_quote(next_hop);
    let add_command = format!(
        "New-NetRoute -DestinationPrefix '{prefix_arg}' -InterfaceIndex {interface_index} -NextHop '{next_hop_arg}' -RouteMetric {metric} -PolicyStore ActiveStore -ErrorAction Stop"
    );
    let remove_command = format!(
        "Remove-NetRoute -DestinationPrefix '{prefix_arg}' -InterfaceIndex {interface_index} -NextHop '{next_hop_arg}' -Confirm:$false -ErrorAction SilentlyContinue"
    );
    WindowsProxyRoutePlan {
        proxy_ip: proxy_ip.to_string(),
        destination_prefix: destination_prefix.to_string(),
        vpn_interface: interface_alias.to_string(),
        vpn_interface_index: interface_index,
        next_hop: next_hop.to_string(),
        add_command,
        remove_command,
    }
}

/// Best-effort removal of any host route for `proxy_ip` that does NOT live on
/// `keep_interface_index`. tun2proxy installs its proxy-bypass route via the physical
/// uplink, which would bypass the VPN; we drop it before pinning our own. Failure here
/// is non-fatal because our replacement route uses a strictly lower metric.
fn remove_competing_proxy_routes(proxy_ip: &str, keep_interface_index: u32) {
    let Ok(ip) = proxy_ip.parse::<IpAddr>() else {
        return;
    };
    let prefix = host_route_prefix(ip);
    let prefix_arg = ps_single_quote(&prefix);
    let command = format!(
        "Get-NetRoute -DestinationPrefix '{prefix_arg}' -ErrorAction SilentlyContinue | Where-Object {{ $_.ifIndex -ne {keep_interface_index} }} | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue"
    );
    let _ = console_hidden_command("powershell")
        .args(["-NoProfile", "-Command", &command])
        .stdin(Stdio::null())
        .status();
}

/// After tun2proxy is up, repair the two Windows routing gaps that otherwise break Z4
/// (proxy + Mullvad). Both only apply while a VPN is the active interface; with no VPN
/// (Z2) tun2proxy's own routing is already correct, so this is a no-op.
///
///  1. tun2proxy pins the proxy-server bypass route through the *physical* uplink,
///     bypassing the VPN — the kill-switch guard then refuses the session. We re-pin
///     the proxy server through the active VPN interface at a winning metric.
///  2. tun2proxy installs only a `0.0.0.0/0` default that ties with the VPN's own `/0`
///     and loses on interface metric, so app traffic escapes via the VPN instead of
///     the proxy. We add the `/1` capture split through the Wintun.
///
/// Successfully applied routes are pushed into `pinned` as they go, so the caller's
/// existing rollback (`remove_proxy_route_plans`) tears down partial work on error.
fn enforce_tun_capture_routes(
    proxy_ip: &str,
    tun_adapter: &str,
    pinned: &mut Vec<WindowsProxyRoutePlan>,
) -> Result<(), ProxyError> {
    let snapshot = try_inspect_windows_routes(proxy_ip)?;
    let Some(vpn_interface) = snapshot.active_vpn_interface else {
        return Ok(());
    };

    // (1) Proxy server must egress via the VPN, not the physical uplink.
    let vpn_index = interface_index(&vpn_interface)?;
    remove_competing_proxy_routes(proxy_ip, vpn_index);
    let proxy_plan = build_proxy_route_plan_with_metric(
        proxy_ip,
        &vpn_interface,
        vpn_index,
        PROXY_VPN_ROUTE_METRIC,
    )?;
    apply_proxy_route_plan(&proxy_plan)?;
    pinned.push(proxy_plan);

    // (2) Capture all host traffic into the proxy TUN, beating the VPN's own default.
    let tun_index = interface_index(tun_adapter)?;
    for prefix in WINDOWS_TUN_CAPTURE_PREFIXES {
        let plan = build_interface_route_plan(
            "",
            prefix,
            tun_adapter,
            tun_index,
            WINDOWS_TUN_GATEWAY,
            0,
        );
        apply_proxy_route_plan(&plan)?;
        pinned.push(plan);
    }
    Ok(())
}

fn apply_proxy_route_plan(plan: &WindowsProxyRoutePlan) -> Result<(), ProxyError> {
    let status = console_hidden_command("powershell")
        .args(["-NoProfile", "-Command", &plan.add_command])
        .stdin(Stdio::null())
        .status()
        .map_err(|error| {
            ProxyError::Command(format!(
                "failed to pin proxy route {} via {}: {error}",
                plan.destination_prefix, plan.vpn_interface
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(ProxyError::Command(format!(
            "failed to pin proxy route {} via {}: powershell exited with {status}",
            plan.destination_prefix, plan.vpn_interface
        )))
    }
}

fn remove_proxy_route_plan(plan: &WindowsProxyRoutePlan) -> Result<(), ProxyError> {
    let status = console_hidden_command("powershell")
        .args(["-NoProfile", "-Command", &plan.remove_command])
        .stdin(Stdio::null())
        .status()
        .map_err(|error| {
            ProxyError::Command(format!(
                "failed to remove pinned proxy route {} via {}: {error}",
                plan.destination_prefix, plan.vpn_interface
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(ProxyError::Command(format!(
            "failed to remove pinned proxy route {} via {}: powershell exited with {status}",
            plan.destination_prefix, plan.vpn_interface
        )))
    }
}

fn remove_proxy_route_plans(plans: &[WindowsProxyRoutePlan]) {
    for plan in plans {
        let _ = remove_proxy_route_plan(plan);
    }
}

fn harden_dns_for_tun(profile: &ResolvedProfile) -> Result<Option<WindowsDnsSnapshot>, ProxyError> {
    if !profile.proxy_dns {
        return Ok(None);
    }
    let tun_device = tun_device_name(&profile.id);
    let output = console_hidden_command("powershell")
        .args([
            "-NoProfile",
            "-Command",
            r#"
$ErrorActionPreference = 'Stop'
$tun = $env:S5P_TUN_ADAPTER
$ipv4Dns = $env:S5P_TUN_DNS
$ipv6Dns = $env:S5P_BLOCKED_IPV6_DNS
$before = @(
  foreach ($family in @('IPv4', 'IPv6')) {
    Get-DnsClientServerAddress -AddressFamily $family -ErrorAction Stop |
      Select-Object InterfaceAlias, InterfaceIndex, @{Name = 'AddressFamily'; Expression = { $family } }, ServerAddresses
  }
)
$targets = @($before | Where-Object {
  $_.InterfaceAlias -and
  -not ([string]$_.InterfaceAlias).Equals($tun, [System.StringComparison]::OrdinalIgnoreCase) -and
  -not ([string]$_.InterfaceAlias).Equals('Loopback Pseudo-Interface 1', [System.StringComparison]::OrdinalIgnoreCase) -and
  @($_.ServerAddresses | Where-Object { $_ -and ([string]$_) -notmatch '^fec0:0:0:ffff::[123]$' }).Count -gt 0
})
$targets |
  Group-Object InterfaceIndex |
  ForEach-Object {
    $families = @($_.Group | ForEach-Object { [string]$_.AddressFamily } | Select-Object -Unique)
    $servers = @()
    if ($families -contains 'IPv4') { $servers += $ipv4Dns }
    if ($families -contains 'IPv6') { $servers += $ipv6Dns }
    if ($servers.Count -gt 0) {
      Set-DnsClientServerAddress -InterfaceIndex ([int]$_.Name) -ServerAddresses @($servers) -ErrorAction Stop
    }
  }
ipconfig /flushdns | Out-Null
# Emit a SANITIZED snapshot for teardown: strip our own virtual/blocked DNS servers so
# restore never re-applies them. Without this, a session that starts while a previous
# one leaked the virtual DNS (10.0.0.1) would record it as the baseline and re-leak it,
# leaving name resolution dead after teardown. Hardening above still uses the raw values.
$strip = @($env:S5P_TUN_DNS, $env:S5P_BLOCKED_IPV4_DNS, $env:S5P_BLOCKED_IPV6_DNS) |
  Where-Object { $_ }
$snapshot = @($before | ForEach-Object {
  [PSCustomObject]@{
    InterfaceAlias  = $_.InterfaceAlias
    InterfaceIndex  = $_.InterfaceIndex
    AddressFamily   = $_.AddressFamily
    ServerAddresses = @($_.ServerAddresses | Where-Object { $_ -and ($strip -notcontains [string]$_) })
  }
})
$snapshot | ConvertTo-Json -Depth 5
"#,
        ])
        .env("S5P_TUN_ADAPTER", tun_device)
        .env("S5P_TUN_DNS", WINDOWS_TUN_DNS_SERVER)
        .env("S5P_BLOCKED_IPV4_DNS", WINDOWS_BLOCKED_IPV4_DNS_SERVER)
        .env("S5P_BLOCKED_IPV6_DNS", WINDOWS_BLOCKED_IPV6_DNS_SERVER)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            ProxyError::Command(format!("failed to harden Windows DNS for TUN: {error}"))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(ProxyError::Command(format!(
            "Windows DNS hardening exited with {}: {}{}{}",
            output.status,
            stderr,
            if stderr.is_empty() || stdout.is_empty() {
                ""
            } else {
                "; "
            },
            stdout
        )));
    }
    let text = String::from_utf8_lossy(&output.stdout);
    parse_dns_snapshot_json(&text).map(Some).map_err(|error| {
        ProxyError::Command(format!("failed to parse Windows DNS snapshot: {error}"))
    })
}

fn restore_dns_if_needed(snapshot: Option<&WindowsDnsSnapshot>) {
    if let Some(snapshot) = snapshot {
        let _ = restore_dns_snapshot(snapshot);
    }
}

fn restore_dns_snapshot(snapshot: &WindowsDnsSnapshot) -> Result<(), ProxyError> {
    let mut script = String::from("$ErrorActionPreference = 'Continue'\n");
    let mut by_interface = BTreeMap::<u32, Vec<String>>::new();
    for entry in &snapshot.entries {
        let _ = (&entry.interface_alias, &entry.address_family);
        by_interface
            .entry(entry.interface_index)
            .or_default()
            .extend(entry.server_addresses.iter().cloned());
    }
    for (interface_index, server_addresses) in by_interface {
        if server_addresses.is_empty() {
            script.push_str(&format!(
                "Set-DnsClientServerAddress -InterfaceIndex {interface_index} -ResetServerAddresses -ErrorAction SilentlyContinue\n"
            ));
        } else {
            let servers = server_addresses
                .iter()
                .map(|server| format!("'{}'", ps_single_quote(server)))
                .collect::<Vec<_>>()
                .join(", ");
            script.push_str(&format!(
                "Set-DnsClientServerAddress -InterfaceIndex {interface_index} -ServerAddresses @({servers}) -ErrorAction SilentlyContinue\n"
            ));
        }
    }
    script.push_str("ipconfig /flushdns | Out-Null\n");

    let status = console_hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .stdin(Stdio::null())
        .status()
        .map_err(|error| {
            ProxyError::Command(format!("failed to restore Windows DNS snapshot: {error}"))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(ProxyError::Command(format!(
            "Windows DNS restore exited with {status}"
        )))
    }
}

fn parse_dns_snapshot_json(text: &str) -> Result<WindowsDnsSnapshot, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(WindowsDnsSnapshot::default());
    }
    let value: serde_json::Value =
        serde_json::from_str(trimmed).map_err(|error| error.to_string())?;
    let values = match value {
        serde_json::Value::Array(values) => values,
        serde_json::Value::Object(_) => vec![value],
        serde_json::Value::Null => Vec::new(),
        other => {
            return Err(format!(
                "expected DNS snapshot object or array, got {other:?}"
            ))
        }
    };
    let mut entries = Vec::new();
    for value in values {
        let Some(interface_index) = value.get("InterfaceIndex").and_then(|value| value.as_u64())
        else {
            continue;
        };
        let interface_index = u32::try_from(interface_index)
            .map_err(|_| format!("DNS interface index {interface_index} is out of range"))?;
        let interface_alias = value
            .get("InterfaceAlias")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string();
        let address_family = value
            .get("AddressFamily")
            .and_then(|value| value.as_str())
            .unwrap_or("IPv4");
        let address_family = match address_family {
            "IPv4" | "IPv6" => address_family.to_string(),
            other => return Err(format!("invalid DNS address family {other:?}")),
        };
        // PowerShell 5.1 can serialize an empty array property as "" rather than [],
        // which would otherwise parse to a bogus empty server address; drop empties.
        let server_addresses = match value.get("ServerAddresses") {
            Some(serde_json::Value::Array(values)) => values
                .iter()
                .filter_map(|value| value.as_str().map(ToString::to_string))
                .filter(|value| !value.is_empty())
                .collect(),
            Some(serde_json::Value::String(value)) if !value.is_empty() => vec![value.clone()],
            _ => Vec::new(),
        };
        entries.push(WindowsDnsServerEntry {
            interface_index,
            interface_alias,
            address_family,
            server_addresses,
        });
    }
    Ok(WindowsDnsSnapshot { entries })
}

fn reconcile_proxy_vpn_route(session: &mut WindowsTunSession) {
    session.route_snapshot = inspect_windows_routes(&session.effective_profile.endpoint.host);
    if vpn_chain_block_reason(&session.route_snapshot).is_none() {
        return;
    }

    let plan = match proxy_vpn_route_plan(&session.effective_profile.endpoint.host) {
        Ok(Some(plan)) => plan,
        Ok(None) => return,
        Err(error) => {
            session.route_snapshot.last_reason = Some(format!(
                "Could not refresh Windows proxy-to-VPN host route: {error}"
            ));
            return;
        }
    };

    let replacing_same_route = session
        .pinned_proxy_routes
        .iter()
        .any(|existing| same_proxy_route(existing, &plan));
    let mut old_routes = if replacing_same_route {
        let old = std::mem::take(&mut session.pinned_proxy_routes);
        remove_proxy_route_plans(&old);
        Vec::new()
    } else {
        Vec::new()
    };

    if let Err(error) = apply_proxy_route_plan(&plan) {
        session.route_snapshot.last_reason = Some(format!(
            "Could not refresh Windows proxy-to-VPN host route {} via {}: {error}",
            plan.destination_prefix, plan.vpn_interface
        ));
        return;
    }

    if !replacing_same_route {
        old_routes = std::mem::replace(&mut session.pinned_proxy_routes, vec![plan.clone()]);
    } else {
        session.pinned_proxy_routes = vec![plan.clone()];
    }
    remove_proxy_route_plans(&old_routes);
    session.route_snapshot = inspect_windows_routes(&session.effective_profile.endpoint.host);
}

fn same_proxy_route(left: &WindowsProxyRoutePlan, right: &WindowsProxyRoutePlan) -> bool {
    left.destination_prefix == right.destination_prefix
        && left.vpn_interface_index == right.vpn_interface_index
        && left.next_hop == right.next_hop
}

fn host_route_prefix(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    }
}

fn zero_next_hop(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "0.0.0.0",
        IpAddr::V6(_) => "::",
    }
}

fn ps_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn command_output(command: &mut Command) -> Result<String, ProxyError> {
    let output = command.output().map_err(|error| {
        ProxyError::Command(format!("failed to run Windows route inspection: {error}"))
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(ProxyError::Command(format!(
            "Windows route inspection exited with {}: {stderr}",
            output.status
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn powershell_count(command: &str) -> Result<u32, ProxyError> {
    let output =
        command_output(console_hidden_command("powershell").args(["-NoProfile", "-Command", command]))?;
    output.trim().parse::<u32>().map_err(|error| {
        ProxyError::Command(format!(
            "Windows PowerShell count output was not numeric ({output:?}): {error}"
        ))
    })
}

fn netsh_wfp_state_available() -> (bool, Option<String>) {
    let output_path = env::temp_dir().join(format!(
        "socks5proxy-wfpstate-check-{}.xml",
        std::process::id()
    ));
    let file_arg = format!("file={}", output_path.display());
    let result = console_hidden_command("netsh")
        .args(["wfp", "show", "state", &file_arg])
        .stdin(Stdio::null())
        .output();
    let _ = std::fs::remove_file(&output_path);

    match result {
        Ok(output) if output.status.success() => (true, None),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let message = if stderr.is_empty() { stdout } else { stderr };
            (false, Some(message))
        }
        Err(error) => (
            false,
            Some(format!("failed to run netsh wfp show state: {error}")),
        ),
    }
}

fn non_empty(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn vpn_like(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "tun",
        "tap",
        "wg",
        "vpn",
        "wireguard",
        "mullvad",
        "tailscale",
        "nordlynx",
        "proton",
        "warp",
    ]
    .iter()
    .any(|needle| lower.starts_with(needle) || lower.contains(needle))
}

fn route_reason(
    active_vpn_interface: &Option<String>,
    proxy_uplink_interface: &Option<String>,
) -> Option<String> {
    match (active_vpn_interface, proxy_uplink_interface) {
        (Some(vpn), Some(proxy_iface)) if vpn == proxy_iface => {
            Some("Proxy uplink uses the active Windows VPN interface.".to_string())
        }
        (Some(vpn), Some(proxy_iface)) => Some(format!(
            "Proxy uplink uses {proxy_iface}, not active Windows VPN interface {vpn}."
        )),
        (Some(vpn), None) => Some(format!(
            "Active Windows VPN interface {vpn} was detected, but proxy uplink route could not be resolved."
        )),
        (None, Some(proxy_iface)) => Some(format!(
            "No active Windows VPN interface detected; proxy uplink uses {proxy_iface}."
        )),
        (None, None) => {
            Some("No active Windows VPN interface detected and proxy uplink route could not be resolved.".to_string())
        }
    }
}

fn vpn_chain_block_reason(route_snapshot: &WindowsRouteSnapshot) -> Option<String> {
    match (
        route_snapshot.active_vpn_interface.as_deref(),
        route_snapshot.proxy_uplink_interface.as_deref(),
    ) {
        (Some(vpn), Some(proxy_iface)) if vpn != proxy_iface => Some(format!(
            "Active Windows VPN interface {vpn} was detected, but the proxy uplink uses {proxy_iface}; stopping Windows TUN to avoid bypassing the VPN."
        )),
        (Some(vpn), None) => Some(format!(
            "Active Windows VPN interface {vpn} was detected, but the proxy uplink route could not be resolved; stopping Windows TUN to avoid bypassing the VPN."
        )),
        _ => None,
    }
}

fn require_admin() -> Result<(), ProxyError> {
    let status = console_hidden_command("net")
        .arg("session")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            ProxyError::Command(format!(
                "failed to check Windows administrator rights: {error}"
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(ProxyError::Command(
            "Windows TUN routing requires an elevated administrator session.".to_string(),
        ))
    }
}

fn require_wintun_next_to(binary: &Path) -> Result<(), ProxyError> {
    let Some(dir) = binary.parent() else {
        return Err(ProxyError::Command(
            "tun2proxy path has no parent directory".to_string(),
        ));
    };
    let dll = dir.join("wintun.dll");
    if dll.is_file() {
        Ok(())
    } else {
        Err(ProxyError::Command(format!(
            "wintun.dll was not found next to {}. Bundle Wintun with tun2proxy before starting Windows TUN routing.",
            binary.display()
        )))
    }
}

fn flush_dns_cache() -> Result<(), ProxyError> {
    let output = console_hidden_command("ipconfig")
        .arg("/flushdns")
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            ProxyError::Command(format!("failed to flush Windows DNS cache: {error}"))
        })?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Err(ProxyError::Command(format!(
            "ipconfig /flushdns exited with {}: {}{}{}",
            output.status,
            stderr,
            if stderr.is_empty() || stdout.is_empty() {
                ""
            } else {
                "; "
            },
            stdout
        )))
    }
}

fn current_exe_dir_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let dirs = [
                dir.to_path_buf(),
                dir.join("resources"),
                dir.join("resources").join("runtime").join("windows"),
                dir.join("runtime").join("windows"),
                dir.join("..").join("resources"),
                dir.join("..")
                    .join("resources")
                    .join("runtime")
                    .join("windows"),
            ];
            for base in dirs {
                for name in TUN2PROXY_CANDIDATES {
                    candidates.push(base.join(name));
                }
            }
        }
    }
    candidates
}

fn env_override_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = env::var_os("SOCKS5PROXY_TUN2PROXY") {
        candidates.push(PathBuf::from(path));
    }
    candidates
}

fn project_runtime_candidates() -> Vec<PathBuf> {
    let Ok(cwd) = env::current_dir() else {
        return Vec::new();
    };
    TUN2PROXY_CANDIDATES
        .iter()
        .map(|name| cwd.join("runtime").join("windows").join(name))
        .collect()
}

fn path_candidates() -> Vec<PathBuf> {
    let Some(path) = env::var_os("PATH") else {
        return Vec::new();
    };
    env::split_paths(&path)
        .flat_map(|dir| TUN2PROXY_CANDIDATES.iter().map(move |name| dir.join(name)))
        .collect()
}

fn program_files_mullvad_candidates() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(env::var_os)
        .map(PathBuf::from)
        .map(|base| {
            base.join("Mullvad VPN")
                .join("resources")
                .join("mullvad.exe")
        })
        .collect()
}

fn path_mullvad_candidates() -> Vec<PathBuf> {
    let Some(path) = env::var_os("PATH") else {
        return Vec::new();
    };
    env::split_paths(&path)
        .flat_map(|dir| MULLVAD_CLI_NAMES.iter().map(move |name| dir.join(name)))
        .collect()
}

fn program_files_wireguard_candidates() -> Vec<PathBuf> {
    ["ProgramFiles", "ProgramFiles(x86)"]
        .iter()
        .filter_map(env::var_os)
        .map(PathBuf::from)
        .flat_map(|base| {
            [
                base.join("WireGuard").join("wg.exe"),
                base.join("WireGuard").join("wireguard.exe"),
            ]
        })
        .collect()
}

fn path_wireguard_candidates() -> Vec<PathBuf> {
    let Some(path) = env::var_os("PATH") else {
        return Vec::new();
    };
    env::split_paths(&path)
        .flat_map(|dir| WIREGUARD_CLI_NAMES.iter().map(move |name| dir.join(name)))
        .collect()
}

fn parse_mullvad_status_output(text: &str) -> (Option<String>, Option<String>) {
    let state = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(ToString::to_string);
    let visible_location = text.lines().map(str::trim).find_map(|line| {
        line.strip_prefix("Visible location:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    });
    (state, visible_location)
}

fn parse_wireguard_interfaces(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn parse_wireguard_endpoint_ips(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(endpoint_host)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn endpoint_host(endpoint: &str) -> Option<String> {
    let candidate = if endpoint.starts_with('[') {
        endpoint
            .split_once(']')?
            .0
            .trim_start_matches('[')
            .to_string()
    } else if let Some((host, _port)) = endpoint.rsplit_once(':') {
        host.to_string()
    } else {
        endpoint.to_string()
    };
    if candidate.parse::<IpAddr>().is_ok() {
        Some(candidate)
    } else {
        None
    }
}

fn parse_mullvad_status_json(text: &str) -> Option<WindowsMullvadStatus> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let state = value
        .get("state")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let details = value.get("details")?;
    let endpoint = details.get("endpoint");
    let location = details.get("location");
    let visible_location = location.map(format_mullvad_location);
    let endpoint_address = endpoint
        .and_then(|endpoint| endpoint.get("address"))
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let (endpoint_ip, endpoint_port) = endpoint_address
        .as_deref()
        .map(parse_mullvad_endpoint_address)
        .unwrap_or((None, None));
    Some(WindowsMullvadStatus {
        cli_path: None,
        state,
        visible_location,
        visible_ipv4: location
            .and_then(|location| location.get("ipv4"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        visible_ipv6: location
            .and_then(|location| location.get("ipv6"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        mullvad_exit_ip: location
            .and_then(|location| location.get("mullvad_exit_ip"))
            .and_then(|value| value.as_bool()),
        locked_down: details.get("locked_down").and_then(|value| value.as_bool()),
        endpoint_address,
        endpoint_ip,
        endpoint_port,
        endpoint_protocol: endpoint
            .and_then(|endpoint| endpoint.get("protocol"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        tunnel_interface: endpoint
            .and_then(|endpoint| endpoint.get("tunnel_interface"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        relay_hostname: location
            .and_then(|location| location.get("hostname"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        relay_ipv4: None,
        relay_ipv6: None,
        entry_hostname: location
            .and_then(|location| location.get("entry_hostname"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        entry_ipv4: None,
        entry_ipv6: None,
        bridge_hostname: location
            .and_then(|location| location.get("bridge_hostname"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        obfuscator_hostname: location
            .and_then(|location| location.get("obfuscator_hostname"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        tunnel_protocol: None,
        error: None,
    })
}

fn parse_mullvad_endpoint_address(value: &str) -> (Option<String>, Option<u16>) {
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            let host = host.trim_matches(['[', ']']);
            if host.parse::<IpAddr>().is_ok() {
                return (Some(host.to_string()), Some(port));
            }
        }
    }
    if value.parse::<IpAddr>().is_ok() {
        return (Some(value.to_string()), None);
    }
    (None, None)
}

fn format_mullvad_location(location: &serde_json::Value) -> String {
    let mut parts = Vec::new();
    if let Some(country) = location.get("country").and_then(|value| value.as_str()) {
        parts.push(country.to_string());
    }
    if let Some(city) = location.get("city").and_then(|value| value.as_str()) {
        parts.push(city.to_string());
    }
    let mut out = parts.join(", ");
    if let Some(ipv4) = location.get("ipv4").and_then(|value| value.as_str()) {
        if !out.is_empty() {
            out.push_str(". ");
        }
        out.push_str(&format!("IPv4: {ipv4}"));
    }
    if let Some(ipv6) = location.get("ipv6").and_then(|value| value.as_str()) {
        if !out.is_empty() {
            out.push_str(". ");
        }
        out.push_str(&format!("IPv6: {ipv6}"));
    }
    out
}

fn enrich_mullvad_relay_ips(status: &mut WindowsMullvadStatus) {
    if status.relay_hostname.is_none() && status.entry_hostname.is_none() {
        return;
    }
    let Some(cli_path) = status.cli_path.as_ref() else {
        return;
    };
    let Ok(output) = console_hidden_command(cli_path).args(["relay", "list"]).output() else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    if let Some(hostname) = status.relay_hostname.as_deref() {
        if let Some((ipv4, ipv6)) = parse_mullvad_relay_list_entry(&text, hostname) {
            status.relay_ipv4 = Some(ipv4);
            status.relay_ipv6 = ipv6;
        }
    }
    if let Some(hostname) = status.entry_hostname.as_deref() {
        if let Some((ipv4, ipv6)) = parse_mullvad_relay_list_entry(&text, hostname) {
            status.entry_ipv4 = Some(ipv4);
            status.entry_ipv6 = ipv6;
        }
    }
}

fn parse_mullvad_relay_list_entry(text: &str, hostname: &str) -> Option<(String, Option<String>)> {
    let needle = format!("{hostname} (");
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with(&needle))?;
    let addresses = line
        .strip_prefix(&needle)?
        .split_once(')')?
        .0
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let ipv4 = addresses
        .iter()
        .find(|value| value.parse::<std::net::Ipv4Addr>().is_ok())?
        .to_string();
    let ipv6 = addresses
        .iter()
        .find(|value| value.parse::<std::net::Ipv6Addr>().is_ok())
        .map(|value| (*value).to_string());
    Some((ipv4, ipv6))
}

fn mullvad_relay_tunnel_protocol(path: &Path) -> Option<String> {
    let output = console_hidden_command(path).args(["relay", "get"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_mullvad_relay_tunnel_protocol(&String::from_utf8_lossy(&output.stdout))
}

fn parse_mullvad_relay_tunnel_protocol(text: &str) -> Option<String> {
    text.lines().map(str::trim).find_map(|line| {
        line.strip_prefix("Tunnel protocol:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mullvad_status_for_plan(state: &str) -> WindowsMullvadStatus {
        WindowsMullvadStatus {
            cli_path: None,
            state: Some(state.to_string()),
            visible_location: None,
            visible_ipv4: None,
            visible_ipv6: None,
            mullvad_exit_ip: None,
            locked_down: None,
            endpoint_address: Some("198.51.100.74:8978".to_string()),
            endpoint_ip: Some("198.51.100.74".to_string()),
            endpoint_port: Some(8978),
            endpoint_protocol: Some("udp".to_string()),
            tunnel_interface: Some("Mullvad".to_string()),
            relay_hostname: Some("wg-test-001".to_string()),
            relay_ipv4: Some("198.51.100.74".to_string()),
            relay_ipv6: None,
            entry_hostname: None,
            entry_ipv4: None,
            entry_ipv6: None,
            bridge_hostname: None,
            obfuscator_hostname: None,
            tunnel_protocol: Some("WireGuard".to_string()),
            error: None,
        }
    }

    fn firewall_preflight_for_plan(
        elevated: bool,
        wfp_state_available: bool,
    ) -> WindowsFirewallPreflight {
        WindowsFirewallPreflight {
            elevated,
            firewall_profiles_count: Some(3),
            matching_firewall_rule_count: Some(0),
            wfp_state_available,
            wfp_state_error: if wfp_state_available {
                None
            } else {
                Some("ERROR_ACCESS_DENIED".to_string())
            },
            error: None,
        }
    }

    fn resolved_profile_for_status() -> ResolvedProfile {
        ResolvedProfile {
            id: "profile-test".to_string(),
            name: "Test".to_string(),
            endpoint: proxy_core::ProxyEndpoint {
                host: "proxy.example.invalid".to_string(),
                port: 1080,
                username: Some("user".to_string()),
                password: Some("pass".to_string()),
            },
            routing_mode: proxy_core::RoutingMode::Tun,
            proxy_dns: true,
            startup_cleanup_enabled: true,
            bypass: Vec::new(),
        }
    }

    fn wfp_filter_for_status() -> WfpFilterStatus {
        WfpFilterStatus {
            filter_id: "{19e96ee3-f85c-5390-a16d-84c9e144a4a7}".to_string(),
            layer: "FWPM_LAYER_ALE_AUTH_CONNECT_V4".to_string(),
            display_name: "SOCKS5Proxy Z4 allow tun2proxy".to_string(),
            session_tag: "socks5proxy-z4".to_string(),
        }
    }

    #[test]
    fn status_is_stopped_without_active_session() {
        let _ = stop_tun_session();
        let status = tun_status().expect("status should be available");
        assert_eq!(status.state, "stopped");
        assert_eq!(status.tun2proxy_pid, None);
    }

    #[test]
    fn stop_is_idempotent_without_active_session() {
        let first = stop_tun_session().expect("first stop should succeed");
        let second = stop_tun_session().expect("second stop should succeed");
        assert_eq!(first.state, "stopped");
        assert_eq!(second.state, "stopped");
    }

    #[test]
    fn dns_snapshot_json_accepts_array_object_and_null() {
        let array = parse_dns_snapshot_json(
            r#"[
              {"InterfaceAlias": "Ethernet 2", "InterfaceIndex": 12, "AddressFamily": "IPv4", "ServerAddresses": ["192.168.2.100"]},
              {"InterfaceAlias": "Ethernet 2", "InterfaceIndex": 23, "AddressFamily": "IPv6", "ServerAddresses": "::1"},
              {"InterfaceAlias": "WLAN", "InterfaceIndex": 34, "AddressFamily": "IPv4", "ServerAddresses": null}
            ]"#,
        )
        .expect("array snapshot should parse");
        assert_eq!(
            array.entries,
            vec![
                WindowsDnsServerEntry {
                    interface_index: 12,
                    interface_alias: "Ethernet 2".to_string(),
                    address_family: "IPv4".to_string(),
                    server_addresses: vec!["192.168.2.100".to_string()],
                },
                WindowsDnsServerEntry {
                    interface_index: 23,
                    interface_alias: "Ethernet 2".to_string(),
                    address_family: "IPv6".to_string(),
                    server_addresses: vec!["::1".to_string()],
                },
                WindowsDnsServerEntry {
                    interface_index: 34,
                    interface_alias: "WLAN".to_string(),
                    address_family: "IPv4".to_string(),
                    server_addresses: Vec::new(),
                },
            ]
        );

        let object =
            parse_dns_snapshot_json(r#"{"InterfaceIndex": 7, "ServerAddresses": ["10.0.0.1"]}"#)
                .expect("single object snapshot should parse");
        assert_eq!(object.entries.len(), 1);
        assert_eq!(object.entries[0].interface_index, 7);

        let null = parse_dns_snapshot_json("null").expect("null snapshot should parse");
        assert!(null.entries.is_empty());
    }

    #[test]
    fn dns_snapshot_json_rejects_out_of_range_interface_index() {
        let error = parse_dns_snapshot_json(
            r#"{"InterfaceIndex": 4294967296, "ServerAddresses": ["10.0.0.1"]}"#,
        )
        .expect_err("u32 overflow should be rejected");
        assert!(error.contains("out of range"));
    }

    #[test]
    fn connected_and_blocked_status_preserve_wfp_filters() {
        let profile = resolved_profile_for_status();
        let effective = ResolvedProfile {
            endpoint: proxy_core::ProxyEndpoint {
                host: "198.51.100.10".to_string(),
                ..profile.endpoint.clone()
            },
            ..profile.clone()
        };
        let snapshot = WindowsRouteSnapshot {
            active_vpn_interface: Some("Mullvad".to_string()),
            proxy_uplink_interface: Some("Mullvad".to_string()),
            last_reason: Some("Proxy route uses active VPN".to_string()),
        };
        let filters = vec![wfp_filter_for_status()];

        let connected = connected_status(&profile, &effective, &snapshot, &[], &filters, 42);
        assert_eq!(connected.wfp_filters, filters);

        let blocked = blocked_status(
            &profile,
            &effective,
            &snapshot,
            &[],
            &connected.wfp_filters,
            42,
            "blocked for test".to_string(),
        );
        assert_eq!(blocked.wfp_filters.len(), 1);
        assert_eq!(blocked.wfp_filters[0].session_tag, "socks5proxy-z4");
    }

    #[test]
    fn vpn_like_detects_windows_vpn_names() {
        assert!(vpn_like("Mullvad"));
        assert!(vpn_like("WireGuard Tunnel"));
        assert!(vpn_like("wg-office"));
        assert!(vpn_like("My VPN Adapter"));
        assert!(!vpn_like("Ethernet"));
        assert!(!vpn_like("Wi-Fi"));
    }

    #[test]
    fn route_reason_reports_vpn_alignment() {
        assert_eq!(
            route_reason(&Some("Mullvad".into()), &Some("Mullvad".into())).as_deref(),
            Some("Proxy uplink uses the active Windows VPN interface.")
        );
        assert!(
            route_reason(&Some("Mullvad".into()), &Some("Ethernet".into()))
                .unwrap()
                .contains("not active Windows VPN interface")
        );
        assert!(route_reason(&None, &Some("Ethernet".into()))
            .unwrap()
            .contains("No active Windows VPN interface detected"));
    }

    #[test]
    fn vpn_chain_block_reason_blocks_vpn_bypass() {
        let snapshot = WindowsRouteSnapshot {
            active_vpn_interface: Some("WireGuard Tunnel".to_string()),
            proxy_uplink_interface: Some("Ethernet".to_string()),
            last_reason: None,
        };
        let reason = vpn_chain_block_reason(&snapshot).expect("VPN bypass should block");
        assert!(reason.contains("stopping Windows TUN"));
        assert!(reason.contains("Ethernet"));
    }

    #[test]
    fn vpn_chain_block_reason_blocks_unresolved_proxy_route() {
        let snapshot = WindowsRouteSnapshot {
            active_vpn_interface: Some("Mullvad".to_string()),
            proxy_uplink_interface: None,
            last_reason: None,
        };
        let reason =
            vpn_chain_block_reason(&snapshot).expect("unresolved proxy route should block");
        assert!(reason.contains("could not be resolved"));
    }

    #[test]
    fn vpn_chain_block_reason_allows_z2_and_valid_chain() {
        assert!(vpn_chain_block_reason(&WindowsRouteSnapshot {
            active_vpn_interface: None,
            proxy_uplink_interface: Some("Ethernet".to_string()),
            last_reason: None,
        })
        .is_none());
        assert!(vpn_chain_block_reason(&WindowsRouteSnapshot {
            active_vpn_interface: Some("Mullvad".to_string()),
            proxy_uplink_interface: Some("Mullvad".to_string()),
            last_reason: None,
        })
        .is_none());
    }

    #[test]
    fn parses_mullvad_status_output() {
        let output = "\
Connected to wg-test-001 in Gothenburg, Sweden
    Visible location:       Sweden, Gothenburg. IPv4: 198.51.100.1
";
        let (state, visible) = parse_mullvad_status_output(output);
        assert_eq!(
            state.as_deref(),
            Some("Connected to wg-test-001 in Gothenburg, Sweden")
        );
        assert_eq!(
            visible.as_deref(),
            Some("Sweden, Gothenburg. IPv4: 198.51.100.1")
        );
    }

    #[test]
    fn parses_mullvad_disconnected_output() {
        let output = "\
Disconnected
    Visible location:       Germany, Berlin. IPv4: 203.0.113.171
";
        let (state, visible) = parse_mullvad_status_output(output);
        assert_eq!(state.as_deref(), Some("Disconnected"));
        assert_eq!(
            visible.as_deref(),
            Some("Germany, Berlin. IPv4: 203.0.113.171")
        );
    }

    #[test]
    fn parses_mullvad_status_json_details() {
        let json = r#"{
          "state": "connected",
          "details": {
            "endpoint": {
              "address": "198.51.100.74:8978",
              "protocol": "udp",
              "tunnel_type": "wireguard",
              "tunnel_interface": "Mullvad"
            },
            "location": {
              "ipv4": "198.51.100.1",
              "ipv6": null,
              "country": "Sweden",
              "city": "Gothenburg",
              "mullvad_exit_ip": true,
              "hostname": "wg-test-001",
              "bridge_hostname": null,
              "entry_hostname": "wg-entry-001",
              "obfuscator_hostname": null
            },
            "locked_down": true
          }
        }"#;
        let parsed = parse_mullvad_status_json(json).expect("json should parse");
        assert_eq!(parsed.state.as_deref(), Some("connected"));
        assert_eq!(
            parsed.visible_location.as_deref(),
            Some("Sweden, Gothenburg. IPv4: 198.51.100.1")
        );
        assert_eq!(parsed.visible_ipv4.as_deref(), Some("198.51.100.1"));
        assert_eq!(parsed.mullvad_exit_ip, Some(true));
        assert_eq!(parsed.locked_down, Some(true));
        assert_eq!(
            parsed.endpoint_address.as_deref(),
            Some("198.51.100.74:8978")
        );
        assert_eq!(parsed.endpoint_ip.as_deref(), Some("198.51.100.74"));
        assert_eq!(parsed.endpoint_port, Some(8978));
        assert_eq!(parsed.endpoint_protocol.as_deref(), Some("udp"));
        assert_eq!(parsed.tunnel_interface.as_deref(), Some("Mullvad"));
        assert_eq!(parsed.relay_hostname.as_deref(), Some("wg-test-001"));
        assert_eq!(parsed.entry_hostname.as_deref(), Some("wg-entry-001"));
    }

    #[test]
    fn parses_mullvad_endpoint_address() {
        assert_eq!(
            parse_mullvad_endpoint_address("198.51.100.74:8978"),
            (Some("198.51.100.74".to_string()), Some(8978))
        );
        assert_eq!(
            parse_mullvad_endpoint_address("[2001:db8::1]:51820"),
            (Some("2001:db8::1".to_string()), Some(51820))
        );
        assert_eq!(
            parse_mullvad_endpoint_address("198.51.100.74"),
            (Some("198.51.100.74".to_string()), None)
        );
        assert_eq!(
            parse_mullvad_endpoint_address("not an endpoint"),
            (None, None)
        );
    }

    #[test]
    fn mullvad_transport_bypasses_only_when_connected() {
        let mut status = WindowsMullvadStatus {
            cli_path: None,
            state: Some("connected".to_string()),
            visible_location: None,
            visible_ipv4: None,
            visible_ipv6: None,
            mullvad_exit_ip: None,
            locked_down: None,
            endpoint_address: None,
            endpoint_ip: Some("198.51.100.74".to_string()),
            endpoint_port: Some(8978),
            endpoint_protocol: Some("udp".to_string()),
            tunnel_interface: Some("Mullvad".to_string()),
            relay_hostname: Some("wg-test-001".to_string()),
            relay_ipv4: Some("198.51.100.74".to_string()),
            relay_ipv6: Some("2001:db8::1".to_string()),
            entry_hostname: None,
            entry_ipv4: None,
            entry_ipv6: None,
            bridge_hostname: None,
            obfuscator_hostname: None,
            tunnel_protocol: Some("WireGuard".to_string()),
            error: None,
        };
        assert_eq!(
            mullvad_transport_bypasses(&status),
            vec!["198.51.100.74".to_string(), "2001:db8::1".to_string()]
        );
        status.state = Some("disconnected".to_string());
        assert!(mullvad_transport_bypasses(&status).is_empty());
    }

    #[test]
    fn parses_mullvad_relay_list_entry_ips() {
        let list = "\
Sweden (se)
    Gothenburg (got) @ 57.70887°N, 11.97456°W
        wg-test-001 (198.51.100.1, 2001:db8:6:f011::a01f) - WireGuard, hosted by 64512 (owned)
        wg-test-002 (198.51.100.2) - WireGuard, hosted by 64512 (owned)
";
        let (ipv4, ipv6) =
            parse_mullvad_relay_list_entry(list, "wg-test-001").expect("relay should parse");
        assert_eq!(ipv4, "198.51.100.1");
        assert_eq!(ipv6.as_deref(), Some("2001:db8:6:f011::a01f"));

        let (ipv4, ipv6) =
            parse_mullvad_relay_list_entry(list, "wg-test-002").expect("relay should parse");
        assert_eq!(ipv4, "198.51.100.2");
        assert_eq!(ipv6, None);
        assert!(parse_mullvad_relay_list_entry(list, "wg-test-003").is_none());
    }

    #[test]
    fn parses_mullvad_relay_tunnel_protocol() {
        let relay = "\
Generic constraints
    Location:               city ber, de
    Tunnel protocol:        WireGuard
";
        assert_eq!(
            parse_mullvad_relay_tunnel_protocol(relay).as_deref(),
            Some("WireGuard")
        );
    }

    #[test]
    fn parses_wireguard_interfaces() {
        assert_eq!(
            parse_wireguard_interfaces("wg-office Mullvad\nwg-lab"),
            vec![
                "wg-office".to_string(),
                "Mullvad".to_string(),
                "wg-lab".to_string()
            ]
        );
        assert!(parse_wireguard_interfaces("  \n").is_empty());
    }

    #[test]
    fn parses_wireguard_endpoint_ips() {
        let endpoints = "\
abc123 198.51.100.10:51820
def456 [2001:db8::10]:51820
ghi789 example.invalid:51820
";
        assert_eq!(
            parse_wireguard_endpoint_ips(endpoints),
            vec!["198.51.100.10".to_string(), "2001:db8::10".to_string()]
        );
    }

    #[test]
    fn wireguard_transport_bypasses_are_ip_literals_only() {
        let status = WindowsWireGuardStatus {
            cli_path: None,
            interfaces: vec!["wg-office".to_string()],
            endpoint_ips: vec![
                "198.51.100.10".to_string(),
                "not-an-ip".to_string(),
                "2001:db8::10".to_string(),
            ],
            locked_down: Some(false),
            lockdown_reason: None,
            error: None,
        };
        assert_eq!(
            wireguard_transport_bypasses(&status),
            vec!["198.51.100.10".to_string(), "2001:db8::10".to_string()]
        );
    }

    #[test]
    fn builds_ipv4_proxy_vpn_route_plan() {
        let plan =
            build_proxy_route_plan("198.51.100.10", "WireGuard Tunnel", 42).expect("route plan");
        assert_eq!(plan.destination_prefix, "198.51.100.10/32");
        assert_eq!(plan.next_hop, "0.0.0.0");
        assert!(plan.add_command.contains("-InterfaceIndex 42"));
        assert!(plan.add_command.contains("-PolicyStore ActiveStore"));
        assert!(plan.add_command.contains("-RouteMetric 1"));
        assert!(plan
            .remove_command
            .contains("-DestinationPrefix '198.51.100.10/32'"));
        assert!(plan.remove_command.contains("-Confirm:$false"));
    }

    #[test]
    fn builds_ipv6_proxy_vpn_route_plan() {
        let plan =
            build_proxy_route_plan("2001:db8::10", "WireGuard Tunnel", 7).expect("route plan");
        assert_eq!(plan.destination_prefix, "2001:db8::10/128");
        assert_eq!(plan.next_hop, "::");
        assert!(plan.add_command.contains("-NextHop '::'"));
        assert!(plan.add_command.contains("-InterfaceIndex 7"));
    }

    #[test]
    fn power_shell_single_quotes_are_escaped() {
        assert_eq!(ps_single_quote("Bob's VPN"), "Bob''s VPN");
    }

    #[test]
    fn proxy_route_plan_rejects_non_ip_targets() {
        let error = build_proxy_route_plan("proxy.example", "WireGuard Tunnel", 42)
            .expect_err("hostnames are not route-plan targets");
        assert!(error.to_string().contains("IP literal"));
    }

    #[test]
    fn proxy_route_identity_uses_prefix_interface_and_next_hop() {
        let base =
            build_proxy_route_plan("198.51.100.10", "WireGuard Tunnel", 42).expect("route plan");
        let same = build_proxy_route_plan("198.51.100.10", "Renamed VPN", 42).expect("route plan");
        let other_interface =
            build_proxy_route_plan("198.51.100.10", "WireGuard Tunnel", 7).expect("route plan");
        let other_prefix =
            build_proxy_route_plan("198.51.100.11", "WireGuard Tunnel", 42).expect("route plan");

        assert!(same_proxy_route(&base, &same));
        assert!(!same_proxy_route(&base, &other_interface));
        assert!(!same_proxy_route(&base, &other_prefix));
    }

    #[test]
    fn wintun_egress_identity_is_stable_distinct_and_guid_shaped() {
        let key = wintun_egress_filter_key("socks5proxy-z4");
        // Stable for a given session tag, varies by tag, GUID-shaped.
        assert_eq!(key, wintun_egress_filter_key("socks5proxy-z4"));
        assert_ne!(key, wintun_egress_filter_key("other-tag"));
        assert!(key.starts_with('{') && key.ends_with('}') && key.len() == 38);
        // Must not collide with any planned role's key (own filter, own GUID).
        for identity in wfp_rule_identities("socks5proxy-z4") {
            assert_ne!(key, identity.key, "collides with role {}", identity.role);
        }
    }

    #[test]
    fn wintun_egress_rollback_is_a_filter_delete_matching_the_status() {
        let status = wintun_egress_filter_status("socks5proxy-z4");
        let rollback = wintun_egress_rollback_operation("socks5proxy-z4");
        // Same key on both so the tracked filter and its teardown op line up.
        assert_eq!(status.filter_id, rollback.key);
        assert_eq!(status.filter_id, wintun_egress_filter_key("socks5proxy-z4"));
        // Teardown treats it as a filter (layer FWPM_LAYER_*) and deletes by key,
        // so the existing rollback path removes it without plan changes.
        assert_eq!(rollback.action, "delete");
        assert!(rollback.layer.starts_with("FWPM_LAYER_"));
        assert_eq!(rollback.role, WFP_WINTUN_EGRESS_ROLE);
    }

    #[test]
    fn wfp_exception_plan_is_not_required_without_connected_mullvad() {
        let status = mullvad_status_for_plan("disconnected");
        let firewall = firewall_preflight_for_plan(false, false);
        let plan = wfp_exception_plan(&status, &firewall);

        assert!(!plan.required);
        assert!(!plan.ready);
        assert_eq!(plan.status, "not_required");
        assert!(plan.blockers.is_empty());
        assert!(plan.planned_allows.is_empty());
        assert!(plan.planned_filter_identities.is_empty());
    }

    #[test]
    fn wfp_exception_plan_blocks_connected_mullvad_without_elevation() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(false, false);
        let plan = wfp_exception_plan(&status, &firewall);

        assert!(plan.required);
        assert!(!plan.ready);
        assert_eq!(plan.status, "blocked");
        assert!(plan
            .blockers
            .iter()
            .any(|blocker| blocker.contains("Administrator rights")));
        assert!(plan
            .blockers
            .iter()
            .any(|blocker| blocker.contains("ERROR_ACCESS_DENIED")));
        assert!(plan
            .planned_allows
            .iter()
            .any(|allow| allow.contains("tun2proxy")));
        assert_eq!(plan.planned_filter_identities.len(), 6);
        assert_eq!(plan.session_tag, "socks5proxy-z4");
    }

    #[test]
    fn wfp_exception_plan_can_be_ready_but_still_only_declarative() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(true, true);
        let plan = wfp_exception_plan(&status, &firewall);

        assert!(plan.required);
        assert!(plan.ready);
        assert_eq!(plan.status, "ready");
        assert!(plan.blockers.is_empty());
        assert_eq!(plan.mullvad_tunnel_interface.as_deref(), Some("Mullvad"));
        assert_eq!(plan.mullvad_endpoint_ip.as_deref(), Some("198.51.100.74"));
        assert!(plan
            .planned_cleanup
            .iter()
            .any(|cleanup| cleanup.contains("Remove")));
    }

    #[test]
    fn wfp_rule_identities_are_stable_and_guid_shaped() {
        let first = wfp_rule_identities("socks5proxy-z4");
        let second = wfp_rule_identities("socks5proxy-z4");
        let other = wfp_rule_identities("socks5proxy-other");

        assert_eq!(first, second);
        assert_ne!(first[0].key, other[0].key);
        assert!(first.iter().any(|identity| identity.role == "provider"));
        assert!(first
            .iter()
            .any(|identity| identity.role == "allow_tun2proxy"));
        for identity in first {
            assert!(identity.key.starts_with('{'));
            assert!(identity.key.ends_with('}'));
            assert_eq!(identity.key.len(), 38);
            assert!(identity.display_name.contains("SOCKS5Proxy Z4"));
        }
    }

    #[test]
    fn wfp_operation_plan_is_empty_when_not_required() {
        let status = mullvad_status_for_plan("disconnected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);

        assert!(!operation_plan.required);
        assert!(!operation_plan.ready);
        assert_eq!(operation_plan.status, "not_required");
        assert!(operation_plan.cleanup_before_apply.is_empty());
        assert!(operation_plan.apply_operations.is_empty());
        assert!(operation_plan.rollback_operations.is_empty());
        assert!(operation_plan.expected_runtime_filters.is_empty());
    }

    #[test]
    fn wfp_operation_plan_preserves_blockers_without_live_apply() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(false, false);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);

        assert!(operation_plan.required);
        assert!(!operation_plan.ready);
        assert_eq!(operation_plan.status, "blocked");
        assert!(operation_plan
            .blockers
            .iter()
            .any(|blocker| blocker.contains("Administrator rights")));
        assert_eq!(operation_plan.apply_operations.len(), 6);
        assert_eq!(operation_plan.expected_runtime_filters.len(), 4);
    }

    #[test]
    fn wfp_operation_plan_orders_apply_cleanup_and_runtime_filters() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);

        assert!(operation_plan.required);
        assert!(operation_plan.ready);
        assert_eq!(operation_plan.status, "ready");
        // 6 planned identities + the two dynamically-applied permits (Wintun egress and
        // the Mullvad-DNS-sublayer hole), which are purged first on both cleanup and
        // rollback so they cannot pin the provider.
        assert_eq!(operation_plan.cleanup_before_apply.len(), 8);
        assert_eq!(operation_plan.apply_operations.len(), 6);
        assert_eq!(operation_plan.rollback_operations.len(), 8);
        assert_eq!(
            operation_plan.apply_operations[0].role, "provider",
            "provider must be created before sublayer and filters"
        );
        assert_eq!(
            operation_plan.apply_operations[1].role, "sublayer",
            "sublayer must be created before layer filters"
        );
        assert_eq!(
            operation_plan.cleanup_before_apply[0].role, "allow_wintun_egress",
            "the Wintun-egress permit is purged before any planned identity"
        );
        assert_eq!(
            operation_plan.cleanup_before_apply[1].role, "allow_wintun_dns",
            "the Wintun-DNS permit is purged before any planned identity too"
        );
        assert_eq!(
            operation_plan.rollback_operations[0].role, "allow_wintun_egress",
            "the Wintun-egress permit is deleted before the provider it references"
        );
        assert_eq!(
            operation_plan.rollback_operations[1].role, "allow_wintun_dns",
            "the Wintun-DNS permit is deleted before the provider it references too"
        );
        assert_eq!(
            operation_plan.rollback_operations[2].role, "allow_mullvad_transport",
            "rollback removes filters before shared WFP objects"
        );
        assert_eq!(
            operation_plan
                .rollback_operations
                .last()
                .map(|operation| operation.role.as_str()),
            Some("provider")
        );
        assert_eq!(operation_plan.expected_runtime_filters.len(), 4);
        assert!(operation_plan
            .expected_runtime_filters
            .iter()
            .all(|filter| filter.session_tag == "socks5proxy-z4"));
        assert!(operation_plan
            .expected_runtime_filters
            .iter()
            .any(|filter| filter.display_name.contains("allow tun2proxy")));
        assert!(operation_plan
            .expected_runtime_filters
            .iter()
            .all(|filter| filter.layer.starts_with("FWPM_LAYER_")));
    }

    #[test]
    fn wfp_rollback_plan_is_not_required_for_disconnected_mullvad() {
        let status = mullvad_status_for_plan("disconnected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let report = rollback_wfp_operation_plan(&operation_plan).expect("rollback report");

        assert!(!report.attempted);
        assert_eq!(report.status, "not_required");
        assert!(report.blockers.is_empty());
        assert!(report.deleted.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn applied_wfp_cleanup_is_not_required_for_disconnected_mullvad() {
        let status = mullvad_status_for_plan("disconnected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let report = rollback_applied_wfp_operation_plan(&operation_plan).expect("cleanup report");

        assert!(!report.attempted);
        assert_eq!(report.status, "not_required");
        assert!(report.blockers.is_empty());
        assert!(report.deleted.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn wfp_delete_missing_codes_are_idempotent_for_expected_roles() {
        assert!(wfp_delete_missing_ok(
            "allow_tun2proxy",
            FWP_E_FILTER_NOT_FOUND_CODE
        ));
        assert!(wfp_delete_missing_ok(
            "provider",
            FWP_E_PROVIDER_NOT_FOUND_CODE
        ));
        assert!(wfp_delete_missing_ok(
            "sublayer",
            FWP_E_SUBLAYER_NOT_FOUND_CODE
        ));
        assert!(wfp_delete_missing_ok(
            "allow_controller",
            FWP_E_NOT_FOUND_CODE
        ));
        assert!(!wfp_delete_missing_ok("provider", 5));
    }

    #[test]
    fn wfp_rollback_plan_is_blocked_without_explicit_mutation_gate() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        std::env::remove_var(ENABLE_WFP_MUTATION_ENV);
        let report = rollback_wfp_operation_plan(&operation_plan).expect("rollback report");

        assert!(!report.attempted);
        assert_eq!(report.status, "blocked");
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains(ENABLE_WFP_MUTATION_ENV)));
        assert!(report.deleted.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn wfp_apply_plan_is_not_required_for_disconnected_mullvad() {
        let status = mullvad_status_for_plan("disconnected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let readiness = wfp_apply_readiness(&exception_plan, &operation_plan);
        let report = apply_wfp_operation_plan(&operation_plan, &readiness).expect("apply report");

        assert!(!report.attempted);
        assert_eq!(report.status, "not_required");
        assert!(report.blockers.is_empty());
        assert!(report.applied.is_empty());
        assert!(report.deleted.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn wfp_apply_plan_blocks_when_readiness_is_incomplete() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let readiness = wfp_apply_readiness(&exception_plan, &operation_plan);
        let report = apply_wfp_operation_plan(&operation_plan, &readiness).expect("apply report");

        assert!(!report.attempted);
        assert_eq!(report.status, "blocked");
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains("proxy server IP")));
        assert!(report.applied.is_empty());
        assert!(report.deleted.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn wfp_apply_plan_blocks_without_explicit_mutation_gate() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let context = wfp_apply_context(
            Some("203.0.113.70"),
            exception_plan.app_path.clone(),
            exception_plan.tun2proxy_path.clone(),
            Some("Mullvad"),
            Some(39),
            None,
            Some("198.51.100.74"),
        );
        let readiness =
            wfp_apply_readiness_with_context(&exception_plan, &operation_plan, &context);
        assert!(readiness.ready);
        std::env::remove_var(ENABLE_WFP_MUTATION_ENV);
        let report = apply_wfp_operation_plan(&operation_plan, &readiness).expect("apply report");

        assert!(!report.attempted);
        assert_eq!(report.status, "blocked");
        assert!(report
            .blockers
            .iter()
            .any(|blocker| blocker.contains(ENABLE_WFP_MUTATION_ENV)));
        assert!(report.applied.is_empty());
        assert!(report.deleted.is_empty());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn wfp_apply_readiness_is_empty_when_not_required() {
        let status = mullvad_status_for_plan("disconnected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let readiness = wfp_apply_readiness(&exception_plan, &operation_plan);

        assert!(!readiness.required);
        assert!(!readiness.ready);
        assert_eq!(readiness.status, "not_required");
        assert!(readiness.blockers.is_empty());
        assert!(readiness.role_specs.is_empty());
    }

    #[test]
    fn wfp_apply_readiness_preserves_exception_plan_blockers() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(false, false);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let readiness = wfp_apply_readiness(&exception_plan, &operation_plan);

        assert!(readiness.required);
        assert!(!readiness.ready);
        assert_eq!(readiness.status, "blocked");
        assert!(readiness
            .blockers
            .iter()
            .any(|blocker| blocker.contains("Administrator rights")));
        assert_eq!(readiness.role_specs.len(), 6);
    }

    #[test]
    fn wfp_apply_readiness_requires_proxy_enforcement_details_before_live_apply() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let readiness = wfp_apply_readiness(&exception_plan, &operation_plan);

        assert!(readiness.required);
        assert!(!readiness.ready);
        assert_eq!(readiness.status, "blocked");
        assert!(readiness
            .role_specs
            .iter()
            .filter(|spec| spec.role == "allow_tun2proxy" || spec.role == "allow_controller")
            .all(|spec| spec.ready));
        let enforce = readiness
            .role_specs
            .iter()
            .find(|spec| spec.role == "enforce_proxy_vpn_route")
            .expect("enforce role");
        assert!(!enforce.ready);
        assert!(enforce
            .blockers
            .iter()
            .any(|blocker| blocker.contains("proxy server IP")));
    }

    #[test]
    fn wfp_apply_readiness_accepts_complete_proxy_and_mullvad_context() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let context = wfp_apply_context(
            Some("203.0.113.70"),
            exception_plan.app_path.clone(),
            exception_plan.tun2proxy_path.clone(),
            Some("Mullvad"),
            Some(39),
            None,
            Some("198.51.100.74"),
        );
        let readiness =
            wfp_apply_readiness_with_context(&exception_plan, &operation_plan, &context);

        assert!(readiness.required);
        assert!(readiness.ready);
        assert_eq!(readiness.status, "ready");
        assert!(readiness.blockers.is_empty());
        let enforce = readiness
            .role_specs
            .iter()
            .find(|spec| spec.role == "enforce_proxy_vpn_route")
            .expect("enforce role");
        assert!(enforce.ready);
        assert!(enforce
            .conditions
            .iter()
            .any(|condition| condition.contains("203.0.113.70")));
        assert!(enforce
            .conditions
            .iter()
            .any(|condition| condition.contains("NEXTHOP_INTERFACE_INDEX")));
        assert_eq!(readiness.context.mullvad_tunnel_interface_index, Some(39));
    }

    #[test]
    fn wfp_apply_readiness_rejects_non_ip_proxy_context() {
        let status = mullvad_status_for_plan("connected");
        let firewall = firewall_preflight_for_plan(true, true);
        let exception_plan = wfp_exception_plan(&status, &firewall);
        let operation_plan = wfp_operation_plan(&exception_plan);
        let context = wfp_apply_context(
            Some("proxy.example.invalid"),
            exception_plan.app_path.clone(),
            exception_plan.tun2proxy_path.clone(),
            Some("Mullvad"),
            Some(39),
            None,
            Some("198.51.100.74"),
        );
        let readiness =
            wfp_apply_readiness_with_context(&exception_plan, &operation_plan, &context);

        assert!(readiness.required);
        assert!(!readiness.ready);
        assert_eq!(readiness.status, "blocked");
        assert!(readiness.context.proxy_ip.is_none());
        assert!(readiness
            .blockers
            .iter()
            .any(|blocker| blocker.contains("proxy server IP must be an IP literal")));
    }

    #[test]
    fn parse_wfp_guid_accepts_braced_guid_and_rejects_invalid_input() {
        let guid = parse_wfp_guid("{d601fd31-fe69-5e48-be03-a9ec0e4e4111}")
            .expect("valid deterministic guid");
        assert_eq!(guid.data1, 0xd601fd31);
        assert_eq!(guid.data2, 0xfe69);
        assert_eq!(guid.data3, 0x5e48);
        assert_eq!(guid.data4, [0xbe, 0x03, 0xa9, 0xec, 0x0e, 0x4e, 0x41, 0x11]);
        assert!(parse_wfp_guid("not-a-guid").is_err());
    }

    #[test]
    fn mullvad_chain_guard_blocks_connected_mullvad_without_override() {
        let status = WindowsMullvadStatus {
            cli_path: None,
            state: Some("connected".to_string()),
            visible_location: None,
            visible_ipv4: None,
            visible_ipv6: None,
            mullvad_exit_ip: None,
            locked_down: None,
            endpoint_address: Some("198.51.100.74:8978".to_string()),
            endpoint_ip: Some("198.51.100.74".to_string()),
            endpoint_port: Some(8978),
            endpoint_protocol: Some("udp".to_string()),
            tunnel_interface: Some("Mullvad".to_string()),
            relay_hostname: Some("wg-test-001".to_string()),
            relay_ipv4: Some("198.51.100.74".to_string()),
            relay_ipv6: None,
            entry_hostname: None,
            entry_ipv4: None,
            entry_ipv6: None,
            bridge_hostname: None,
            obfuscator_hostname: None,
            tunnel_protocol: Some("WireGuard".to_string()),
            error: None,
        };

        let reason = mullvad_chain_block_reason(&status, false).expect("should block");
        assert!(reason.contains("WFP kill-switch exception"));
        assert!(mullvad_chain_block_reason(&status, true).is_none());
    }

    #[test]
    fn mullvad_chain_guard_allows_disconnected_or_unlocked_status() {
        let mut status = WindowsMullvadStatus {
            cli_path: None,
            state: Some("disconnected".to_string()),
            visible_location: None,
            visible_ipv4: None,
            visible_ipv6: None,
            mullvad_exit_ip: None,
            locked_down: Some(true),
            endpoint_address: None,
            endpoint_ip: None,
            endpoint_port: None,
            endpoint_protocol: None,
            tunnel_interface: None,
            relay_hostname: None,
            relay_ipv4: None,
            relay_ipv6: None,
            entry_hostname: None,
            entry_ipv4: None,
            entry_ipv6: None,
            bridge_hostname: None,
            obfuscator_hostname: None,
            tunnel_protocol: None,
            error: None,
        };
        assert!(mullvad_chain_block_reason(&status, false).is_none());

        status.state = Some("connected".to_string());
        status.locked_down = Some(false);
        assert!(mullvad_chain_block_reason(&status, false).is_some());
    }
}
