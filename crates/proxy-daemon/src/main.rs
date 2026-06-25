use anyhow::{anyhow, Context};
use proxy_core::daemon::{
    daemon_socket_path, endpoint_display, DaemonRequest, DaemonResponse, NamespaceSessionStatus,
    PinnedProxyRouteStatus,
};
use proxy_core::tun::tun_device_name;
use proxy_core::tun_runner;
use proxy_core::ResolvedProfile;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::ToSocketAddrs;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DAEMON_TUN_STATE_PATH: &str = "/run/socks5proxyd-tun-state.toml";

fn main() {
    init_logging();
    if let Some(url) = diagnostic_probe_arg() {
        if let Err(error) = run_diagnostic_probe(&url) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        return;
    }
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn diagnostic_probe_arg() -> Option<String> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (Some("--diagnostic-probe"), Some(url)) => Some(url),
        _ => None,
    }
}

fn run_diagnostic_probe(url: &str) -> anyhow::Result<()> {
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()?
        .get(url)
        .send()
        .and_then(|response| response.error_for_status())
        .with_context(|| format!("diagnostic probe failed for {url}"))?;
    let body = response.text().unwrap_or_default();
    println!("{}", body.trim());
    Ok(())
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_env("SOCKS5PROXYD_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .try_init();
}

struct ServiceState {
    tun_status: NamespaceSessionStatus,
    tun_active: Option<TunActiveSession>,
}

impl Default for ServiceState {
    fn default() -> Self {
        Self {
            tun_status: NamespaceSessionStatus::stopped(),
            tun_active: None,
        }
    }
}

struct TunActiveSession {
    profile: ResolvedProfile,
    tun_device: String,
    proxy_ip: String,
    proxy_uplink_interface: Option<String>,
    host_vpn_interface: Option<String>,
    tun2proxy_pid: u32,
    owner_uid: u32,
    owner_gid: u32,
    /// `<ip>/32` proxy-server routes we pinned into the main table so the
    /// upstream connection escapes tun2proxy's catch-all (see
    /// `pin_proxy_routes_via_vpn`). Removed on teardown.
    pinned_proxy_routes: Vec<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PersistentTunState {
    profile: ResolvedProfile,
    tun_device: String,
    proxy_ip: String,
    proxy_uplink_interface: Option<String>,
    host_vpn_interface: Option<String>,
    tun2proxy_pid: Option<u32>,
    owner_uid: Option<u32>,
    owner_gid: Option<u32>,
    #[serde(default)]
    pinned_proxy_routes: Vec<String>,
}

#[derive(Clone)]
struct PeerCredentials {
    uid: u32,
    gid: u32,
}

fn run() -> anyhow::Result<()> {
    if !cfg!(target_os = "linux") {
        anyhow::bail!("socks5proxyd is only supported on Linux");
    }

    let state = Arc::new(Mutex::new(ServiceState::default()));
    recover_from_disk(&state)?;

    let socket_path = daemon_socket_path();
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let _ = fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o666))?;
    tracing::info!(socket = %socket_path.display(), "socks5proxyd listening");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(error) = handle_stream(stream, &state) {
                    tracing::warn!(error = %error, "failed to handle daemon request");
                }
            }
            Err(error) => tracing::warn!(error = %error, "unix socket accept failed"),
        }
    }

    Ok(())
}

fn handle_stream(stream: UnixStream, state: &Arc<Mutex<ServiceState>>) -> anyhow::Result<()> {
    let peer = peer_credentials(&stream)?;
    let mut line = String::new();
    let mut reader = BufReader::new(stream.try_clone()?);
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Ok(());
    }
    let request = match serde_json::from_str::<DaemonRequest>(&line) {
        Ok(request) => request,
        Err(error) => {
            let response = DaemonResponse {
                ok: false,
                status: state
                    .lock()
                    .ok()
                    .map(|guard| guard.tun_status.clone())
                    .unwrap_or_else(|| NamespaceSessionStatus {
                        state: "error".to_string(),
                        last_error: Some(error.to_string()),
                        ..NamespaceSessionStatus::default()
                    }),
                error: Some(format!("invalid daemon request: {error}")),
            };
            let mut writer = stream;
            let payload = serde_json::to_string(&response)?;
            writer.write_all(payload.as_bytes())?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            return Ok(());
        }
    };
    let response = match catch_unwind(AssertUnwindSafe(|| handle_request(request, peer, state))) {
        Ok(response) => response,
        Err(_) => DaemonResponse {
            ok: false,
            status: state
                .lock()
                .ok()
                .map(|guard| guard.tun_status.clone())
                .unwrap_or_else(|| NamespaceSessionStatus {
                    state: "error".to_string(),
                    last_error: Some("socks5proxyd request handler panicked".to_string()),
                    ..NamespaceSessionStatus::default()
                }),
            error: Some("socks5proxyd request handler panicked".to_string()),
        },
    };
    let mut writer = stream;
    let payload = serde_json::to_string(&response)?;
    writer.write_all(payload.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn handle_request(
    request: DaemonRequest,
    peer: PeerCredentials,
    state: &Arc<Mutex<ServiceState>>,
) -> DaemonResponse {
    match dispatch_request(request, peer, state) {
        Ok(status) => DaemonResponse {
            ok: true,
            status,
            error: None,
        },
        Err(error) => {
            let status = state
                .lock()
                .ok()
                .map(|guard| guard.tun_status.clone())
                .unwrap_or_else(|| NamespaceSessionStatus {
                    state: "error".to_string(),
                    last_error: Some(error.to_string()),
                    ..NamespaceSessionStatus::default()
                });
            DaemonResponse {
                ok: false,
                status,
                error: Some(error.to_string()),
            }
        }
    }
}

fn dispatch_request(
    request: DaemonRequest,
    peer: PeerCredentials,
    state: &Arc<Mutex<ServiceState>>,
) -> anyhow::Result<NamespaceSessionStatus> {
    match request {
        DaemonRequest::StartTunSession { profile } => start_tun_session(state, profile, peer),
        DaemonRequest::StopTunSession => stop_tun_session(state, Some(peer)),
        DaemonRequest::GetTunStatus => get_tun_status(state),
        DaemonRequest::RecoverState => {
            recover_from_disk(state)?;
            get_tun_status(state)
        }
    }
}

fn start_tun_session(
    state: &Arc<Mutex<ServiceState>>,
    profile: ResolvedProfile,
    peer: PeerCredentials,
) -> anyhow::Result<NamespaceSessionStatus> {
    if state
        .lock()
        .map_err(|_| anyhow!("state lock poisoned"))?
        .tun_active
        .is_some()
    {
        stop_tun_session(state, Some(peer.clone()))?;
    }

    let route = HostRouteStatus::ok_for_profile(&profile)?;

    if !route.valid {
        let blocked = NamespaceSessionStatus {
            state: "blocked".to_string(),
            profile_id: Some(profile.id.clone()),
            profile_name: Some(profile.name.clone()),
            proxy_host: Some(endpoint_display(&profile.endpoint)),
            proxy_ip: Some(route.proxy_ip),
            host_vpn_interface: route.host_vpn_interface,
            proxy_uplink_interface: route.proxy_uplink_interface,
            owner_uid: Some(peer.uid),
            last_reason: Some(
                route
                    .reason
                    .unwrap_or_else(|| "Blocked waiting for a valid host VPN uplink".to_string()),
            ),
            ..NamespaceSessionStatus::default()
        };
        let mut guard = state.lock().map_err(|_| anyhow!("state lock poisoned"))?;
        guard.tun_status = blocked.clone();
        guard.tun_active = None;
        remove_tun_state_file()?;
        return Ok(blocked);
    }

    // Detect active VPN relay IPs and add them to the bypass list before starting
    // tun2proxy.  tun2proxy's --setup intercepts all packets via policy routing,
    // including kernel WireGuard UDP traffic.  Without bypassing the relay IPs,
    // WireGuard keepalives get swallowed, the tunnel degrades, and the VPN kill
    // switch blocks everything.
    let relay_ips = collect_vpn_relay_ips();
    if !relay_ips.is_empty() {
        tracing::info!(ips = ?relay_ips, "adding VPN relay IPs to tun2proxy bypass");
    }
    let mut tun_profile = profile.clone();
    for ip in &relay_ips {
        if !tun_profile.bypass.contains(ip) {
            tun_profile.bypass.push(ip.clone());
        }
    }

    flush_system_dns_cache();
    let child = tun_runner::spawn(&tun_profile).map_err(|error| anyhow!(error.to_string()))?;

    // Fix tun2proxy's coexistence with a fwmark policy-routing VPN (wg-quick /
    // Mullvad). `proxy_uplink_interface` is computed *before* the spawn above,
    // so it reflects the real pre-tun2proxy uplink (the VPN, when one is up).
    // See `pin_vpn_coexistence_routes` for the full rationale.
    let pinned_proxy_routes = pin_vpn_coexistence_routes(&profile, &route, &relay_ips);

    // When the Mullvad app is running its kill-switch blocks all traffic that
    // does not exit via wg0-mullvad, including packets going to the proxy TUN.
    // Install a priority -1 nftables bypass so the TUN can receive/send traffic
    // while the kill-switch remains active for all other interfaces.
    // This is a no-op for the NetworkManager / wg-quick WireGuard case, which
    // does not install `table inet mullvad` and therefore returns false here.
    if detect_mullvad_killswitch() {
        let tun_name = tun_device_name(&profile.id);
        if !install_mullvad_tun_bypass(&tun_name) {
            tracing::warn!("Mullvad kill-switch bypass could not be installed; traffic to the TUN may be blocked");
        }
    }

    let active = TunActiveSession {
        profile: profile.clone(),
        tun_device: tun_device_name(&profile.id),
        proxy_ip: route.proxy_ip.clone(),
        proxy_uplink_interface: route.proxy_uplink_interface.clone(),
        host_vpn_interface: route.host_vpn_interface.clone(),
        tun2proxy_pid: child.id(),
        owner_uid: peer.uid,
        owner_gid: peer.gid,
        pinned_proxy_routes,
    };
    persist_tun_session(&active)?;

    let status = tun_status_from_active(
        &active,
        "connected",
        Some("Daemon-managed TUN routing active.".to_string()),
        None,
    );
    let mut guard = state.lock().map_err(|_| anyhow!("state lock poisoned"))?;
    guard.tun_active = Some(active);
    guard.tun_status = status.clone();
    Ok(status)
}

fn stop_tun_session(
    state: &Arc<Mutex<ServiceState>>,
    peer: Option<PeerCredentials>,
) -> anyhow::Result<NamespaceSessionStatus> {
    let active = {
        let mut guard = state.lock().map_err(|_| anyhow!("state lock poisoned"))?;
        if let (Some(active), Some(peer)) = (guard.tun_active.as_ref(), peer) {
            ensure_tun_owner(active, &peer)?;
        }
        guard.tun_active.take()
    };
    if let Some(active) = active {
        teardown_tun_environment(&active)?;
    }
    remove_tun_state_file()?;
    let stopped = NamespaceSessionStatus::stopped();
    let mut guard = state.lock().map_err(|_| anyhow!("state lock poisoned"))?;
    guard.tun_status = stopped.clone();
    Ok(stopped)
}

fn get_tun_status(state: &Arc<Mutex<ServiceState>>) -> anyhow::Result<NamespaceSessionStatus> {
    let maybe_active = {
        let guard = state.lock().map_err(|_| anyhow!("state lock poisoned"))?;
        guard
            .tun_active
            .as_ref()
            .map(|active: &TunActiveSession| TunActiveSnapshot {
                profile: active.profile.clone(),
                tun_device: active.tun_device.clone(),
                proxy_ip: active.proxy_ip.clone(),
                tun2proxy_pid: active.tun2proxy_pid,
                owner_uid: active.owner_uid,
                pinned_proxy_routes: active.pinned_proxy_routes.clone(),
            })
    };

    let Some(active) = maybe_active else {
        return Ok(state
            .lock()
            .map_err(|_| anyhow!("state lock poisoned"))?
            .tun_status
            .clone());
    };

    if process_gone(active.tun2proxy_pid)? {
        let _ = teardown_tun_snapshot(&active);
        remove_tun_state_file()?;
        let error = NamespaceSessionStatus {
            state: "error".to_string(),
            profile_id: Some(active.profile.id),
            profile_name: Some(active.profile.name),
            proxy_host: Some(endpoint_display(&active.profile.endpoint)),
            proxy_ip: Some(active.proxy_ip),
            tun2proxy_pid: Some(active.tun2proxy_pid),
            owner_uid: Some(active.owner_uid),
            last_error: Some("tun2proxy exited unexpectedly".to_string()),
            ..NamespaceSessionStatus::default()
        };
        let mut guard = state.lock().map_err(|_| anyhow!("state lock poisoned"))?;
        guard.tun_active = None;
        guard.tun_status = error.clone();
        return Ok(error);
    }

    let mut guard = state.lock().map_err(|_| anyhow!("state lock poisoned"))?;
    if let Some(active) = guard.tun_active.as_ref() {
        guard.tun_status = tun_status_from_active(
            active,
            "connected",
            Some("Daemon-managed TUN routing active.".to_string()),
            None,
        );
    }
    Ok(guard.tun_status.clone())
}

#[derive(Clone)]
struct TunActiveSnapshot {
    profile: ResolvedProfile,
    tun_device: String,
    proxy_ip: String,
    tun2proxy_pid: u32,
    owner_uid: u32,
    pinned_proxy_routes: Vec<String>,
}

fn recover_from_disk(state: &Arc<Mutex<ServiceState>>) -> anyhow::Result<()> {
    recover_tun_from_disk(state)
}

fn recover_tun_from_disk(state: &Arc<Mutex<ServiceState>>) -> anyhow::Result<()> {
    let path = tun_state_path();
    if !path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(&path)?;
    let persisted = toml::from_str::<PersistentTunState>(&text)?;
    let snapshot = TunActiveSnapshot {
        profile: persisted.profile,
        tun_device: persisted.tun_device,
        proxy_ip: persisted.proxy_ip,
        tun2proxy_pid: persisted.tun2proxy_pid.unwrap_or_default(),
        owner_uid: persisted.owner_uid.unwrap_or_default(),
        pinned_proxy_routes: persisted.pinned_proxy_routes,
    };
    let _ = teardown_tun_snapshot(&snapshot);
    remove_tun_state_file()?;
    let mut guard = state.lock().map_err(|_| anyhow!("state lock poisoned"))?;
    guard.tun_active = None;
    guard.tun_status = NamespaceSessionStatus::stopped();
    Ok(())
}

fn persist_tun_session(active: &TunActiveSession) -> anyhow::Result<()> {
    let persisted = PersistentTunState {
        profile: active.profile.clone(),
        tun_device: active.tun_device.clone(),
        proxy_ip: active.proxy_ip.clone(),
        proxy_uplink_interface: active.proxy_uplink_interface.clone(),
        host_vpn_interface: active.host_vpn_interface.clone(),
        tun2proxy_pid: Some(active.tun2proxy_pid),
        owner_uid: Some(active.owner_uid),
        owner_gid: Some(active.owner_gid),
        pinned_proxy_routes: active.pinned_proxy_routes.clone(),
    };
    let path = tun_state_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, toml::to_string(&persisted)?)?;
    Ok(())
}

fn remove_tun_state_file() -> anyhow::Result<()> {
    let path = tun_state_path();
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn tun_state_path() -> PathBuf {
    std::env::var_os("SOCKS5PROXYD_TUN_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DAEMON_TUN_STATE_PATH))
}

#[derive(Clone)]
struct HostRouteStatus {
    valid: bool,
    proxy_ip: String,
    host_vpn_interface: Option<String>,
    proxy_uplink_interface: Option<String>,
    reason: Option<String>,
}

impl HostRouteStatus {
    fn ok_for_profile(profile: &ResolvedProfile) -> anyhow::Result<Self> {
        let proxy_ip = resolve_proxy_ip(profile)?;
        let proxy_uplink_interface = route_interface_to(&proxy_ip)?;
        // The uplink is resolved before tun2proxy spawns, so it reflects the real
        // pre-tun2proxy route to the proxy. When that route exits via a VPN-like
        // interface, the proxy egress is the VPN: report it so the desktop flow
        // model can render the "VPN" node (it keys off vpn == uplink).
        let host_vpn_interface = proxy_uplink_interface
            .as_deref()
            .filter(|iface| vpn_like(iface))
            .map(str::to_string);
        Ok(Self {
            valid: true,
            proxy_ip,
            host_vpn_interface,
            proxy_uplink_interface,
            reason: Some("TUN routing active.".to_string()),
        })
    }
}

fn resolve_proxy_ip(profile: &ResolvedProfile) -> anyhow::Result<String> {
    let target = (profile.endpoint.host.as_str(), profile.endpoint.port)
        .to_socket_addrs()?
        .find(|addr| addr.is_ipv4())
        .ok_or_else(|| anyhow!("proxy host did not resolve to an IPv4 address"))?;
    Ok(target.ip().to_string())
}

/// All distinct IPv4 addresses the proxy host resolves to. The host may have
/// several A records, so we pin a route for each rather than only the first.
fn resolve_proxy_ipv4s(profile: &ResolvedProfile) -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(addrs) = (profile.endpoint.host.as_str(), profile.endpoint.port).to_socket_addrs() {
        for addr in addrs.filter(|a| a.is_ipv4()) {
            let ip = addr.ip().to_string();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }
    ips
}

/// When tun2proxy runs alongside a fwmark policy-routing VPN (wg-quick /
/// Mullvad), its `--setup` installs `0.0.0.0/1` + `128.0.0.0/1` catch-alls in
/// the main table. Those /1 routes defeat *two* things the VPN relies on:
///   - they shadow tun2proxy's own proxy/relay bypass routes (which land in the
///     VPN's policy table, e.g. wg table 51916), and
///   - they are not removed by wg-quick's `suppress_prefixlength 0` ip-rule
///     (which only suppresses the /0 default), so even the VPN's *own*
///     encrypted packets to its relay endpoint get pulled into the TUN.
///
/// We restore correct behaviour by pinning more-specific `/32` host routes into
/// the *main* table, which win by longest-prefix match over the /1 catch-alls:
///   1. proxy server IP(s)  -> via the VPN interface     (traffic: VPN→proxy)
///   2. VPN relay/endpoint IP(s) -> via the physical gateway (so the tunnel's
///      own encrypted UDP escapes the TUN instead of looping into tun2proxy)
///
/// No-op when the proxy is not reached through a VPN. Returns the list of
/// pinned `/32` destinations for teardown. Best-effort: failures are logged.
fn pin_vpn_coexistence_routes(
    profile: &ResolvedProfile,
    route: &HostRouteStatus,
    relay_ips: &[String],
) -> Vec<String> {
    let Some(vpn_iface) = route
        .proxy_uplink_interface
        .as_deref()
        .filter(|iface| vpn_like(iface))
    else {
        return Vec::new();
    };

    let mut pinned = Vec::new();

    // 1. Proxy server IP(s) ride the VPN tunnel.
    for ip in resolve_proxy_ipv4s(profile) {
        if pin_host_route(&ip, None, vpn_iface) {
            pinned.push(ip);
        }
    }

    // 2. VPN relay/endpoint IP(s) must escape via the physical uplink, or the
    //    tunnel cannot carry anything (it would route its own ciphertext into
    //    the TUN).
    match physical_default_gateway() {
        Some((gw, dev)) => {
            for ip in relay_ips.iter().filter(|ip| is_ipv4_literal(ip)) {
                if pin_host_route(ip, gw.as_deref(), &dev) {
                    pinned.push(ip.clone());
                }
            }
        }
        None => {
            tracing::warn!(
                "no physical default gateway found; VPN relay packets may loop into the TUN"
            );
        }
    }

    pinned
}

/// `ip route replace <ip>/32 [via <gw>] dev <dev>`. Returns true on success.
fn pin_host_route(ip: &str, gw: Option<&str>, dev: &str) -> bool {
    let dest = format!("{ip}/32");
    let mut args = vec!["route", "replace", &dest];
    if let Some(gw) = gw {
        args.push("via");
        args.push(gw);
    }
    args.push("dev");
    args.push(dev);
    match Command::new("ip").args(&args).status() {
        Ok(s) if s.success() => {
            tracing::info!(route = %dest, via = ?gw, iface = %dev, "pinned host route");
            true
        }
        Ok(s) => {
            tracing::warn!(route = %dest, via = ?gw, iface = %dev, status = ?s, "failed to pin host route");
            false
        }
        Err(error) => {
            tracing::warn!(route = %dest, %error, "failed to run ip route replace");
            false
        }
    }
}

/// Remove the `/32` routes pinned by `pin_vpn_coexistence_routes`. Identified by
/// destination, so the gateway / interface is not needed here.
fn unpin_proxy_routes(ips: &[String]) {
    for ip in ips {
        let dest = format!("{ip}/32");
        let _ = Command::new("ip").args(["route", "del", &dest]).status();
    }
}

/// Returns true when Mullvad's nftables kill-switch table is present.
/// The Mullvad app (but not wg-quick / NetworkManager WireGuard) installs
/// `table inet mullvad` with `policy drop` output/input chains.  This is the
/// reliable signal that the kill-switch is active and a bypass is needed.
fn detect_mullvad_killswitch() -> bool {
    Command::new("nft")
        .args(["list", "table", "inet", "mullvad"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Insert accept rules for the proxy TUN at the HEAD of Mullvad's own output
/// and input chains.
///
/// A separate nftables table at a lower priority does NOT work: in nftables,
/// `accept` in one base chain only terminates that chain — the kernel still
/// calls every other chain registered at the same hook point in priority order,
/// so Mullvad's own chain (with its final `reject`) runs regardless.
///
/// The only reliable solution is to insert our allow rules INSIDE Mullvad's
/// chains (before its `reject`):
///   - output chain: `oif "<tun>" accept`  → packets can enter the TUN
///   - input chain:  `iif "<tun>" accept`  → tun2proxy responses can return
///
/// tun2proxy's upstream TCP connections go via `wg0-mullvad` (pinned host
/// route) and are accepted by Mullvad's existing `oif "wg0-mullvad" accept`
/// rule, so actual internet egress still flows through the VPN tunnel.
fn install_mullvad_tun_bypass(tun_device: &str) -> bool {
    let steps: &[&[&str]] = &[
        &[
            "insert", "rule", "inet", "mullvad", "output", "oif", tun_device, "accept",
        ],
        &[
            "insert", "rule", "inet", "mullvad", "input", "iif", tun_device, "accept",
        ],
    ];
    for step in steps {
        match Command::new("nft").args(*step).status() {
            Ok(s) if s.success() => {}
            Ok(s) => {
                tracing::warn!(args = ?step, %s, "failed to insert Mullvad bypass rule");
                return false;
            }
            Err(e) => {
                tracing::warn!(error = %e, "failed to run nft insert rule for Mullvad bypass");
                return false;
            }
        }
    }
    tracing::info!(tun = %tun_device, "inserted Mullvad kill-switch TUN bypass rules");
    true
}

/// Remove the bypass rules we inserted into Mullvad's chains.
/// Finds them by handle using `nft -a list chain`, then deletes each one.
/// No-op when the table or our rules do not exist.
fn remove_mullvad_tun_bypass(tun_device: &str) {
    for (chain, keyword) in [("output", "oif"), ("input", "iif")] {
        let Ok(out) = Command::new("nft")
            .args(["-a", "list", "chain", "inet", "mullvad", chain])
            .output()
        else {
            continue;
        };
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            if line.contains(tun_device) && line.contains(keyword) {
                if let Some(handle) = parse_nft_handle(line) {
                    let _ = Command::new("nft")
                        .args([
                            "delete",
                            "rule",
                            "inet",
                            "mullvad",
                            chain,
                            "handle",
                            &handle.to_string(),
                        ])
                        .status();
                }
            }
        }
    }
}

/// Extract the handle number from an `nft -a list chain` output line.
/// Lines look like: `oif "s5p..." accept # handle 42`
fn parse_nft_handle(line: &str) -> Option<u64> {
    line.split("# handle ")
        .nth(1)?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn is_ipv4_literal(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>().is_ok()
}

/// The lowest-metric IPv4 default route that is neither a VPN nor a tun2proxy
/// TUN device — i.e. the real physical uplink the VPN's ciphertext should use.
/// Returns `(gateway, device)`; the gateway is `None` for point-to-point links.
fn physical_default_gateway() -> Option<(Option<String>, String)> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let text = String::from_utf8_lossy(&output.stdout);

    let mut best: Option<(u32, Option<String>, String)> = None;
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let dev = field_after(&tokens, "dev")?.to_string();
        if vpn_like(&dev) || dev.starts_with("s5p") {
            continue;
        }
        let gw = field_after(&tokens, "via").map(str::to_string);
        let metric = field_after(&tokens, "metric")
            .and_then(|m| m.parse::<u32>().ok())
            .unwrap_or(0);
        if best.as_ref().is_none_or(|(m, _, _)| metric < *m) {
            best = Some((metric, gw, dev));
        }
    }
    best.map(|(_, gw, dev)| (gw, dev))
}

fn field_after<'a>(tokens: &[&'a str], key: &str) -> Option<&'a str> {
    tokens
        .iter()
        .position(|t| *t == key)
        .and_then(|i| tokens.get(i + 1))
        .copied()
}

fn teardown_tun_environment(active: &TunActiveSession) -> anyhow::Result<()> {
    let snapshot = TunActiveSnapshot {
        profile: active.profile.clone(),
        tun_device: active.tun_device.clone(),
        proxy_ip: active.proxy_ip.clone(),
        tun2proxy_pid: active.tun2proxy_pid,
        owner_uid: active.owner_uid,
        pinned_proxy_routes: active.pinned_proxy_routes.clone(),
    };
    teardown_tun_snapshot(&snapshot)
}

fn teardown_tun_snapshot(active: &TunActiveSnapshot) -> anyhow::Result<()> {
    let _ = kill_pid(active.tun2proxy_pid);
    let _ = Command::new("ip")
        .args(["link", "delete", "dev", &active.tun_device])
        .status();
    unpin_proxy_routes(&active.pinned_proxy_routes);
    remove_mullvad_tun_bypass(&active.tun_device);
    Ok(())
}

fn tun_status_from_active(
    active: &TunActiveSession,
    state_name: &str,
    last_reason: Option<String>,
    last_error: Option<String>,
) -> NamespaceSessionStatus {
    NamespaceSessionStatus {
        state: state_name.to_string(),
        profile_id: Some(active.profile.id.clone()),
        profile_name: Some(active.profile.name.clone()),
        proxy_host: Some(endpoint_display(&active.profile.endpoint)),
        proxy_ip: Some(active.proxy_ip.clone()),
        tun2proxy_pid: Some(active.tun2proxy_pid),
        host_vpn_interface: active.host_vpn_interface.clone(),
        proxy_uplink_interface: active.proxy_uplink_interface.clone(),
        owner_uid: Some(active.owner_uid),
        pinned_proxy_routes: active
            .pinned_proxy_routes
            .iter()
            .map(|destination_prefix| PinnedProxyRouteStatus {
                destination_prefix: destination_prefix.clone(),
                interface_index: 0,
                next_hop: String::new(),
            })
            .collect(),
        last_error,
        last_reason,
        ..NamespaceSessionStatus::default()
    }
}

fn kill_pid(pid: u32) -> anyhow::Result<()> {
    if pid == 0 {
        return Ok(());
    }
    let _ = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    std::thread::sleep(std::time::Duration::from_millis(300));
    if !child_exited(pid)? {
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        let _ = reap_child(pid);
    }
    Ok(())
}

fn child_exited(pid: u32) -> anyhow::Result<bool> {
    if pid == 0 {
        return Ok(true);
    }
    reap_child(pid)
}

fn process_gone(pid: u32) -> anyhow::Result<bool> {
    if pid == 0 {
        return Ok(true);
    }
    let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if ret == 0 {
        return Ok(false);
    }
    let errno = std::io::Error::last_os_error();
    match errno.raw_os_error() {
        Some(libc::EPERM) => Ok(false),
        Some(libc::ESRCH) => Ok(true),
        _ => Err(errno.into()),
    }
}

fn reap_child(pid: u32) -> anyhow::Result<bool> {
    let mut status: libc::c_int = 0;
    let ret = unsafe {
        libc::waitpid(
            pid as libc::pid_t,
            &mut status as *mut libc::c_int,
            libc::WNOHANG,
        )
    };
    if ret == pid as libc::pid_t {
        return Ok(true);
    }
    if ret == 0 {
        return Ok(false);
    }
    let errno = std::io::Error::last_os_error();
    match errno.raw_os_error() {
        Some(libc::ECHILD) => Ok(true),
        Some(libc::ESRCH) => Ok(true),
        _ => Err(errno.into()),
    }
}

fn peer_credentials(stream: &UnixStream) -> anyhow::Result<PeerCredentials> {
    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr() as *mut libc::c_void,
            &mut len as *mut libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let credentials = unsafe { credentials.assume_init() };
    Ok(PeerCredentials {
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

fn ensure_tun_owner(active: &TunActiveSession, peer: &PeerCredentials) -> anyhow::Result<()> {
    if peer.uid == 0 || peer.uid == active.owner_uid {
        return Ok(());
    }
    Err(anyhow!(
        "TUN session belongs to uid {}, request came from uid {}",
        active.owner_uid,
        peer.uid
    ))
}

fn route_interface_to(target: &str) -> anyhow::Result<Option<String>> {
    let output = output(Command::new("ip").args(["route", "get", target]))?;
    Ok(parse_route_dev(&output))
}

fn parse_route_dev(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        parts
            .iter()
            .position(|part| *part == "dev")
            .and_then(|index| parts.get(index + 1))
            .map(|value| (*value).to_string())
    })
}

/// Collect the peer endpoint IPs of all active WireGuard-like VPN interfaces.
/// tun2proxy's `--setup` uses policy routing that intercepts ALL packets, including
/// the kernel WireGuard module's UDP keepalives.  Those packets must be bypassed so
/// the WireGuard tunnel stays up while tun2proxy handles everything else.
///
/// Detection order:
fn flush_system_dns_cache() {
    // Flush systemd-resolved's DNS cache before tun2proxy starts. Virtual
    // IP→hostname mappings from a previous session remain cached in the OS and
    // browser; the new tun2proxy instance has no knowledge of those mappings and
    // would forward the raw virtual IP (198.18.0.x) to the SOCKS5 proxy instead of
    // the hostname, causing HostUnreachable for every connection until the cache
    // naturally expires. Flushing here eliminates the OS-level stale entries;
    // browsers with their own caches (e.g. Firefox) need a manual restart or cache
    // clear (about:networking#dns) to get the same effect.
    match Command::new("resolvectl").arg("flush-caches").status() {
        Ok(s) if s.success() => tracing::info!("flushed system DNS cache"),
        Ok(s) => tracing::warn!(status = %s, "resolvectl flush-caches exited non-zero"),
        Err(e) => tracing::warn!(error = %e, "resolvectl flush-caches failed"),
    }
}

/// 1. `wg show <iface> endpoints` — standard kernel/userspace WireGuard
/// 2. `mullvad status --verbose` — Mullvad-managed WireGuard (blocks `wg show`)
fn collect_vpn_relay_ips() -> Vec<String> {
    let mut relay_ips = Vec::new();

    // Method 1: wg show (works for standard WireGuard; Mullvad blocks this)
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for iface in entries
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| vpn_like(n))
        {
            let out = Command::new("wg")
                .args(["show", &iface, "endpoints"])
                .output()
                .ok()
                .filter(|o| o.status.success());
            let Some(out) = out else { continue };
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let Some(addr) = line.split_whitespace().nth(1) else {
                    continue;
                };
                if addr == "(none)" {
                    continue;
                }
                parse_addr_ip(addr, &mut relay_ips);
            }
        }
    }

    // Method 2: mullvad status --verbose
    // Output contains: "    Relay:  server-name (IP:PORT/UDP)"
    let mullvad_out = Command::new("mullvad")
        .args(["status", "--verbose"])
        .output()
        .ok()
        .filter(|o| o.status.success());
    if let Some(out) = mullvad_out {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let Some(rest) = line.trim().strip_prefix("Relay:") else {
                continue;
            };
            // rest = "  server-name (198.51.100.7:51820/UDP)"
            let Some(paren) = rest.find('(') else {
                continue;
            };
            let inside = &rest[paren + 1..];
            let Some(close) = inside.find(')') else {
                continue;
            };
            // "198.51.100.7:51820/UDP" → strip protocol → "198.51.100.7:51820"
            let addr = inside[..close]
                .split('/')
                .next()
                .unwrap_or(&inside[..close]);
            parse_addr_ip(addr, &mut relay_ips);
        }
    }

    relay_ips
}

/// Parse a bare `IP:PORT` or `[IPv6]:PORT` address and push the IP into `out`.
fn parse_addr_ip(addr: &str, out: &mut Vec<String>) {
    let ip = if addr.starts_with('[') {
        // IPv6 [IP]:PORT
        addr.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
            .to_string()
    } else {
        // IPv4 IP:PORT  (or bare IP with no port)
        addr.rsplit_once(':')
            .map(|(ip, _)| ip.to_string())
            .unwrap_or_else(|| addr.to_string())
    };
    if !ip.is_empty() && !out.contains(&ip) {
        out.push(ip);
    }
}

fn vpn_like(name: &str) -> bool {
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
    .any(|needle| lower.starts_with(needle) || lower.contains(needle))
}

fn output(command: &mut Command) -> anyhow::Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
