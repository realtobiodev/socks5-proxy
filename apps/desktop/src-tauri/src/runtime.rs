//! Runtime lifecycle: spawn TUN session, stop runtime, atomic restart, artifacts.

use proxy_core::paths::{
    remove_if_exists, runtime_marker_dir, runtime_state_path, system_proxy_snapshot_path,
};
use proxy_core::system_proxy::{self, save_snapshot};
use proxy_core::tun::tun_device_name;
use proxy_core::{tun_runner, ResolvedProfile, RoutingMode};
use std::fs;
use std::path::Path;
use std::process::Child;
use tauri::AppHandle;

use crate::network::{build_traffic_flow, build_vpn_status};
use crate::platform;
use crate::tray::update_tray_ui;
use crate::tun_backend;
use crate::types::{
    ConnectionState, NetworkSnapshot, PersistentRuntimeState, RuntimeArtifacts, RuntimeSnapshot,
    SharedRuntimeState, TUNAction, TrafficFlow, TrayHandles, VpnStatus,
};
use crate::util::{current_unix_timestamp, generate_session_id};
use crate::watcher::start_tun_child_monitor;

pub fn stop_runtime(
    app: &AppHandle,
    tray: &TrayHandles,
    state: &SharedRuntimeState,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let recovery_watchdog = {
        let mut runtime = state
            .lock()
            .map_err(|_| "runtime lock poisoned".to_string())?;
        runtime.windows_recovery_watchdog.take()
    };

    let (
        child,
        snapshot,
        local_system_proxy,
        exit_poll_stop,
        network_watch_stop,
        artifacts,
        session_id,
        was_tun,
    ) = {
        let mut runtime = state
            .lock()
            .map_err(|_| "runtime lock poisoned".to_string())?;
        runtime.generation += 1;
        let child = runtime.child.take();
        let snapshot = runtime.system_snapshot.take();
        let local_system_proxy = runtime.local_system_proxy.take();
        let exit_poll_stop = runtime.exit_poll_stop.take();
        let network_watch_stop = runtime.network_watch_stop.take();
        let artifacts = runtime.runtime_artifacts.take();
        let session_id = runtime.current_session_id.take();
        let was_tun = runtime
            .active_profile
            .as_ref()
            .map(|profile| profile.routing_mode == RoutingMode::Tun)
            .unwrap_or(false);
        runtime.connection_state = ConnectionState::Stopped;
        runtime.active_profile = None;
        runtime.exit_status = Default::default();
        runtime.vpn_status = VpnStatus::default();
        runtime.traffic_flow = TrafficFlow::default_disconnected();
        runtime.last_error = None;
        (
            child,
            snapshot,
            local_system_proxy,
            exit_poll_stop,
            network_watch_stop,
            artifacts,
            session_id,
            was_tun,
        )
    };

    if let Some(stop_sender) = exit_poll_stop {
        let _ = stop_sender.send(());
    }
    if let Some(stop_sender) = network_watch_stop {
        let _ = stop_sender.send(());
    }

    let mut errors = Vec::new();

    #[cfg(target_os = "windows")]
    if let Some(watchdog) = recovery_watchdog {
        if let Err(error) = watchdog.cancel() {
            errors.push(error);
        }
    }

    if let Some(mut child) = child {
        let pgid = child.id();
        if let Err(error) = child.kill() {
            tracing::warn!(error = %error, pid = pgid, "child.kill() failed; trying process-group kill");
        }
        // Also kill the process group in case tun2proxy-bin is a sudo grandchild
        // that outlives its sudo parent (only relevant for the sudo fallback path;
        // process_group(0) ensures the group equals the sudo PID).
        #[cfg(unix)]
        unsafe {
            libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
        }
        let _ = child.wait();
    }

    if was_tun {
        if let Err(error) = tun_backend::stop() {
            errors.push(error.to_string());
        }
    }

    // Privileged cleanup: kill any orphaned tun2proxy-bin that survived above.
    if !was_tun {
        if let Some(ref art) = artifacts {
            platform::kill_tun_orphan(&art.tun_device);
        }
    }

    if let Some(snapshot) = snapshot {
        if let Err(error) = system_proxy::restore(snapshot) {
            errors.push(error.to_string());
        }
        if let Ok(path) = system_proxy_snapshot_path() {
            let _ = remove_if_exists(&path);
        }
    }

    if let Some(proxy) = local_system_proxy {
        if let Err(error) = proxy.handle.shutdown() {
            errors.push(error);
        }
    }

    if let Some(artifacts) = artifacts {
        if let Err(error) = cleanup_runtime_artifacts(&artifacts) {
            tracing::warn!(
                error = %error,
                "runtime artifact cleanup failed after runtime was stopped"
            );
        }
    } else if let Some(sid) = session_id {
        // Only remove the state file if it belongs to *this* session.
        let _ = remove_runtime_state_file_if_session_matches(&sid);
    }

    let snapshot = {
        let mut runtime = state
            .lock()
            .map_err(|_| "runtime lock poisoned".to_string())?;
        if !errors.is_empty() {
            runtime.connection_state = ConnectionState::Error;
            runtime.last_error = Some(errors.join("; "));
        }
        RuntimeSnapshot::from(&*runtime)
    };
    update_tray_ui(app, tray, &snapshot);

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// State machine entry for the network watcher's decisions.
///
/// Restart is implemented as an atomic stop+start under a single critical
/// section to avoid the previous race where a second watcher tick saw
/// `child.is_none()` between the Stop and Start halves and issued another Start.
#[allow(dead_code)]
pub fn apply_tun_action(
    app: &AppHandle,
    tray: &TrayHandles,
    state: &SharedRuntimeState,
    profile: &ResolvedProfile,
    generation: u64,
    action: TUNAction,
    snapshot: &NetworkSnapshot,
) {
    match action {
        TUNAction::Start => {
            // Grab the restart_lock token for this start; abort if we lose the race.
            let lock_token = match acquire_restart_token(state) {
                Some(token) => token,
                None => return,
            };
            do_start(app, tray, state, profile, generation, snapshot, lock_token);
        }
        TUNAction::Restart => {
            // Atomic stop+start: hold the restart_lock across both halves so the
            // watcher cannot observe child.is_none() and trigger an extra Start.
            let lock_token = match acquire_restart_token(state) {
                Some(token) => token,
                None => return,
            };

            if let Some(snap) = transition_tun_state_for_restart(state, profile, snapshot) {
                update_tray_ui(app, tray, &snap);
            }
            let _ = stop_tun_session_only(state, /*caller_holds_restart_lock=*/ true);
            do_start(app, tray, state, profile, generation, snapshot, lock_token);
        }
        TUNAction::Block => {
            let _ = stop_tun_session_only(state, false);
            let snapshot_out = {
                let mut runtime = match state.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return,
                };
                runtime.connection_state = ConnectionState::Blocked;
                runtime.exit_status = Default::default();
                runtime.vpn_status = build_vpn_status(profile, snapshot, runtime.connection_state);
                runtime.traffic_flow = build_traffic_flow(
                    Some(profile),
                    &runtime.vpn_status,
                    runtime.connection_state,
                );
                RuntimeSnapshot::from(&*runtime)
            };
            update_tray_ui(app, tray, &snapshot_out);
        }
    }
}

#[allow(dead_code)]
fn acquire_restart_token(state: &SharedRuntimeState) -> Option<u64> {
    let mut runtime = state.lock().ok()?;
    runtime.restart_lock = runtime.restart_lock.wrapping_add(1);
    Some(runtime.restart_lock)
}

#[allow(dead_code)]
fn do_start(
    app: &AppHandle,
    tray: &TrayHandles,
    state: &SharedRuntimeState,
    profile: &ResolvedProfile,
    generation: u64,
    snapshot: &NetworkSnapshot,
    expected_restart_lock: u64,
) {
    let result = spawn_tun_session(profile, snapshot.active_vpn_interface.clone());
    let mut started_session_id = None;
    let runtime_snapshot = {
        let mut runtime = match state.lock() {
            Ok(runtime) => runtime,
            Err(_) => return,
        };
        // Bail out if this start has been superseded — either because the user
        // stopped the runtime (generation moved) or another restart fired
        // (restart_lock moved). In both cases we are an orphan and must clean up.
        let superseded = runtime.generation != generation
            || runtime.restart_lock != expected_restart_lock
            || runtime
                .active_profile
                .as_ref()
                .map(|active| active.id.as_str())
                != Some(profile.id.as_str());

        if superseded {
            if let Ok((mut child, artifacts)) = result {
                let _ = child.kill();
                let _ = child.wait();
                let _ = cleanup_runtime_artifacts(&artifacts);
            }
            return;
        }

        match result {
            Ok((child, artifacts)) => {
                started_session_id = Some(artifacts.session_id.clone());
                runtime.current_session_id = Some(artifacts.session_id.clone());
                runtime.child = Some(child);
                runtime.runtime_artifacts = Some(artifacts);
                runtime.connection_state = ConnectionState::Connected;
                runtime.last_error = None;
            }
            Err(error) => {
                runtime.child = None;
                runtime.runtime_artifacts = None;
                runtime.connection_state = ConnectionState::Error;
                runtime.last_error = Some(error);
            }
        }

        runtime.vpn_status = build_vpn_status(profile, snapshot, runtime.connection_state);
        runtime.traffic_flow =
            build_traffic_flow(Some(profile), &runtime.vpn_status, runtime.connection_state);
        RuntimeSnapshot::from(&*runtime)
    };
    update_tray_ui(app, tray, &runtime_snapshot);

    if let Some(session_id) = started_session_id {
        start_tun_child_monitor(
            app.clone(),
            tray.clone(),
            state.clone(),
            profile.clone(),
            generation,
            session_id,
        );
    }
}

#[allow(dead_code)]
pub fn transition_tun_state_for_restart(
    state: &SharedRuntimeState,
    profile: &ResolvedProfile,
    snapshot: &NetworkSnapshot,
) -> Option<RuntimeSnapshot> {
    let mut runtime = state.lock().ok()?;
    runtime.connection_state = ConnectionState::Rebinding;
    runtime.vpn_status = build_vpn_status(profile, snapshot, runtime.connection_state);
    runtime.traffic_flow =
        build_traffic_flow(Some(profile), &runtime.vpn_status, runtime.connection_state);
    Some(RuntimeSnapshot::from(&*runtime))
}

/// Stop only the TUN session (used by Restart and Block).
///
/// `caller_holds_restart_lock` documents that the caller has already bumped the
/// restart_lock and any concurrent watcher Start will be discarded.
#[allow(dead_code)]
pub fn stop_tun_session_only(
    state: &SharedRuntimeState,
    _caller_holds_restart_lock: bool,
) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let recovery_watchdog = {
        let mut runtime = state
            .lock()
            .map_err(|_| "runtime lock poisoned".to_string())?;
        runtime.windows_recovery_watchdog.take()
    };

    let (child, artifacts, session_id) = {
        let mut runtime = state
            .lock()
            .map_err(|_| "runtime lock poisoned".to_string())?;
        let sid = runtime.current_session_id.take();
        (runtime.child.take(), runtime.runtime_artifacts.take(), sid)
    };

    #[cfg(target_os = "windows")]
    if let Some(watchdog) = recovery_watchdog {
        watchdog.cancel()?;
    }

    if let Some(mut child) = child {
        let _ = child.kill();
        #[cfg(unix)]
        unsafe {
            let pgid = child.id();
            libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
        }
        let _ = child.wait();
    }

    // Privileged cleanup: kill any orphaned tun2proxy-bin that survived above.
    if let Some(ref art) = artifacts {
        platform::kill_tun_orphan(&art.tun_device);
    }

    if let Some(artifacts) = artifacts {
        cleanup_runtime_artifacts(&artifacts)?;
    } else if let Some(sid) = session_id {
        let _ = remove_runtime_state_file_if_session_matches(&sid);
    }

    Ok(())
}

#[allow(dead_code)]
pub fn spawn_tun_session(
    profile: &ResolvedProfile,
    bound_vpn_interface: Option<String>,
) -> Result<(Child, RuntimeArtifacts), String> {
    let child = tun_runner::spawn(profile).map_err(|e| e.to_string())?;
    let session_id = generate_session_id();
    let artifacts = RuntimeArtifacts::new(
        &session_id,
        profile,
        child.id(),
        bound_vpn_interface,
        Vec::new(),
        Vec::new(),
    )
    .map_err(|error| format!("failed to create runtime artifacts: {error}"))?;

    persist_runtime_artifacts_state(profile, &artifacts)?;

    Ok((child, artifacts))
}

pub fn persist_runtime_artifacts_state(
    profile: &ResolvedProfile,
    artifacts: &RuntimeArtifacts,
) -> Result<(), String> {
    write_runtime_state(&PersistentRuntimeState {
        session_id: artifacts.session_id.clone(),
        profile_id: profile.id.clone(),
        tun_device: artifacts.tun_device.clone(),
        tun_marker: artifacts.tun_marker.clone(),
        route_marker: artifacts.route_marker.clone(),
        proxy_pid: artifacts.proxy_pid,
        pinned_proxy_routes: artifacts.pinned_proxy_routes.clone(),
        wfp_filters: artifacts.wfp_filters.clone(),
        created_unix: artifacts.created_unix,
    })
}

pub fn cleanup_runtime_artifacts(artifacts: &RuntimeArtifacts) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = platform::cleanup_pinned_proxy_routes(&artifacts.pinned_proxy_routes) {
        errors.push(error);
    }
    #[cfg(target_os = "windows")]
    if let Err(error) =
        proxy_platform_windows::cleanup_persisted_wfp_filters(&artifacts.wfp_filters)
    {
        errors.push(error.to_string());
    }
    if let Err(error) = platform::cleanup_tun_device(&artifacts.tun_device) {
        errors.push(error);
    }
    if let Err(error) = remove_if_exists(Path::new(&artifacts.tun_marker)) {
        errors.push(error.to_string());
    }
    if let Err(error) = remove_if_exists(Path::new(&artifacts.route_marker)) {
        errors.push(error.to_string());
    }
    // Only delete the runtime state file if it belongs to *this* session; another
    // (newer) session may have just written its own.
    if let Err(error) = remove_runtime_state_file_if_session_matches(&artifacts.session_id) {
        errors.push(error);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn remove_runtime_state_file_if_session_matches(session_id: &str) -> Result<(), String> {
    let path = runtime_state_path().map_err(|e| e.to_string())?;
    let Ok(text) = fs::read_to_string(&path) else {
        return Ok(());
    };
    let Ok(state) = toml::from_str::<PersistentRuntimeState>(&text) else {
        // Corrupted file — best to remove it.
        return remove_if_exists(&path).map_err(|e| e.to_string());
    };
    if state.session_id == session_id {
        remove_if_exists(&path).map_err(|e| e.to_string())?;
    } else {
        tracing::debug!(
            current = %session_id,
            on_disk = %state.session_id,
            "skipping runtime-state cleanup — file belongs to another session"
        );
    }
    Ok(())
}

#[allow(dead_code)]
fn write_runtime_state(state: &PersistentRuntimeState) -> Result<(), String> {
    let path = runtime_state_path().map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }

    let temp = path.with_extension("toml.tmp");
    let text = toml::to_string(state).map_err(|error| error.to_string())?;
    fs::write(&temp, text).map_err(|error| error.to_string())?;
    fs::rename(temp, path).map_err(|error| error.to_string())
}

pub fn perform_startup_cleanup() -> Result<(), String> {
    let _ = tun_backend::recover();

    // (a) Restore a leaked system-proxy snapshot if a previous run crashed.
    if let Ok(path) = system_proxy_snapshot_path() {
        match system_proxy::take_persisted_snapshot(&path) {
            Ok(Some(snapshot)) => {
                tracing::info!("recovering system-proxy snapshot from previous run");
                if let Err(error) = system_proxy::restore(snapshot) {
                    tracing::warn!(error = %error, "failed to restore system-proxy snapshot");
                }
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(error = %error, "failed to read system-proxy snapshot"),
        }
    }

    // (b) Recover orphaned TUN devices and tun2proxy pids.
    let path = runtime_state_path().map_err(|e| e.to_string())?;
    if !path.exists() {
        return Ok(());
    }

    let text = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    let state = toml::from_str::<PersistentRuntimeState>(&text)
        .map_err(|error| format!("failed to parse runtime recovery state: {error}"))?;

    // Prefer the privileged helper first so stale interfaces from pkexec/sudo
    // sessions do not survive just because the desktop app itself is unprivileged.
    platform::kill_tun_orphan(&state.tun_device);

    if let Some(pid) = state.proxy_pid {
        if platform::process_exists(pid)? {
            platform::kill_process(pid)?;
        }
    }

    if let Err(error) = platform::cleanup_tun_device(&state.tun_device) {
        tracing::warn!(error = %error, "failed to clean recovered tun device");
    }
    if let Err(error) = platform::cleanup_pinned_proxy_routes(&state.pinned_proxy_routes) {
        tracing::warn!(error = %error, "failed to clean recovered pinned proxy routes");
    }
    #[cfg(target_os = "windows")]
    if let Err(error) = proxy_platform_windows::cleanup_persisted_wfp_filters(&state.wfp_filters) {
        tracing::warn!(error = %error, "failed to clean recovered WFP filters");
    }
    let _ = remove_if_exists(Path::new(&state.tun_marker));
    let _ = remove_if_exists(Path::new(&state.route_marker));
    let _ = remove_if_exists(&path);

    Ok(())
}

/// Persist the system-proxy snapshot so it survives a crash.
pub fn persist_system_snapshot(snapshot: &proxy_core::system_proxy::SystemProxySnapshot) {
    if let Ok(path) = system_proxy_snapshot_path() {
        if let Err(error) = save_snapshot(&path, snapshot) {
            tracing::warn!(error = %error, "failed to persist system-proxy snapshot");
        }
    }
}

impl RuntimeArtifacts {
    pub fn new(
        session_id: &str,
        profile: &ResolvedProfile,
        proxy_pid: u32,
        bound_vpn_interface: Option<String>,
        pinned_proxy_routes: Vec<proxy_core::PinnedProxyRouteStatus>,
        wfp_filters: Vec<proxy_core::WfpFilterStatus>,
    ) -> Result<Self, std::io::Error> {
        let marker_dir = runtime_marker_dir().map_err(std::io::Error::other)?;
        fs::create_dir_all(&marker_dir)?;
        let tun_marker = marker_dir.join(format!("{session_id}-tun.marker"));
        let route_marker = marker_dir.join(format!("{session_id}-route.marker"));
        fs::write(&tun_marker, profile.id.as_bytes())?;
        fs::write(&route_marker, profile.endpoint.host.as_bytes())?;

        Ok(Self {
            session_id: session_id.to_string(),
            tun_device: tun_device_name(&profile.id),
            tun_marker: tun_marker.display().to_string(),
            route_marker: route_marker.display().to_string(),
            proxy_pid: Some(proxy_pid),
            pinned_proxy_routes,
            wfp_filters,
            created_unix: current_unix_timestamp(),
            bound_vpn_interface,
        })
    }
}
