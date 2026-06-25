//! Background threads: exit-status polling and network state observation.
//!
//! The network watcher uses an adaptive interval: while state is changing the
//! poll interval stays at [`consts::WATCH_INTERVAL_MIN`]; after a period of
//! stability it backs off geometrically toward [`consts::WATCH_INTERVAL_MAX`].

use proxy_core::{ResolvedProfile, TraySettings};
use std::process::ExitStatus;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tauri::AppHandle;

use crate::geo::lookup_exit_status;
use crate::network::{
    apply_network_snapshot, build_traffic_flow, build_vpn_status, inspect_network_for_profile,
};
use crate::runtime::{apply_tun_action, cleanup_runtime_artifacts};
use crate::tray::update_tray_ui;
use crate::types::consts::{
    CHILD_WATCH_INTERVAL, VPN_STABILITY_POLLS, WATCH_INTERVAL_MAX, WATCH_INTERVAL_MIN,
};
use crate::types::{ConnectionState, RuntimeSnapshot, SharedRuntimeState, TUNAction, TrayHandles};

pub fn start_exit_status_poller(
    app: AppHandle,
    tray: TrayHandles,
    state: SharedRuntimeState,
    profile: ResolvedProfile,
    tray_settings: TraySettings,
    generation: u64,
) -> Result<(), String> {
    let (stop_sender, stop_receiver) = mpsc::channel();
    {
        let mut runtime = state
            .lock()
            .map_err(|_| "runtime lock poisoned".to_string())?;
        runtime.exit_poll_stop = Some(stop_sender);
    }

    thread::spawn(move || loop {
        let should_query = {
            let runtime = match state.lock() {
                Ok(runtime) => runtime,
                Err(_) => return,
            };
            if runtime.generation != generation
                || runtime
                    .active_profile
                    .as_ref()
                    .map(|active| active.id.as_str())
                    != Some(profile.id.as_str())
            {
                return;
            }

            runtime.connection_state == ConnectionState::Connected
        };

        let exit_status = if should_query {
            // Reload tray settings each cycle so a display-mode / prefix change made in
            // the settings UI takes effect on the next poll instead of being frozen at
            // the value captured when the poller started.
            let settings = crate::load_or_default_config()
                .map(|config| config.tray_settings)
                .unwrap_or_else(|_| tray_settings.clone());
            lookup_exit_status(&profile, &settings)
        } else {
            Default::default()
        };

        let snapshot = {
            let mut runtime = match state.lock() {
                Ok(runtime) => runtime,
                Err(_) => return,
            };

            if runtime.generation != generation
                || runtime
                    .active_profile
                    .as_ref()
                    .map(|active| active.id.as_str())
                    != Some(profile.id.as_str())
            {
                return;
            }

            runtime.exit_status = exit_status;
            RuntimeSnapshot::from(&*runtime)
        };
        update_tray_ui(&app, &tray, &snapshot);

        // When the proxy is not yet connected (e.g. TUN still rebinding) use a
        // short retry so the exit IP appears promptly after connection rather
        // than waiting a full refresh cycle.
        let wait = if should_query {
            Duration::from_secs(tray_settings.refresh_interval_secs)
        } else {
            Duration::from_secs(10)
        };
        match stop_receiver.recv_timeout(wait) {
            Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    });

    Ok(())
}

#[allow(dead_code)]
pub fn start_network_watcher(
    app: AppHandle,
    tray: TrayHandles,
    state: SharedRuntimeState,
    profile: ResolvedProfile,
    generation: u64,
) -> Result<(), String> {
    let (stop_sender, stop_receiver) = mpsc::channel();
    {
        let mut runtime = state
            .lock()
            .map_err(|_| "runtime lock poisoned".to_string())?;
        runtime.network_watch_stop = Some(stop_sender);
    }

    thread::spawn(move || {
        let mut last_signature = String::new();
        let mut stable_count = 0_u8;
        let mut interval = WATCH_INTERVAL_MIN;

        loop {
            let snapshot = inspect_network_for_profile(&profile);
            let signature = snapshot.signature();
            let changed = signature != last_signature;
            if changed {
                last_signature = signature;
                stable_count = 1;
                interval = WATCH_INTERVAL_MIN;
            } else {
                stable_count = stable_count.saturating_add(1);
                // Adaptive backoff: once we've seen several stable polls, double
                // the interval each iteration up to WATCH_INTERVAL_MAX.
                if stable_count > VPN_STABILITY_POLLS {
                    interval = (interval * 2).min(WATCH_INTERVAL_MAX);
                }
            }

            let action = {
                let mut runtime = match state.lock() {
                    Ok(runtime) => runtime,
                    Err(_) => return,
                };

                if runtime.generation != generation
                    || runtime
                        .active_profile
                        .as_ref()
                        .map(|active| active.id.as_str())
                        != Some(profile.id.as_str())
                {
                    return;
                }

                apply_network_snapshot(&mut runtime, &profile, &snapshot);

                if stable_count < VPN_STABILITY_POLLS {
                    None
                } else if runtime.child.is_none()
                    && runtime.connection_state != ConnectionState::Error
                {
                    Some(TUNAction::Start)
                } else {
                    None
                }
            };

            if let Some(action) = action {
                apply_tun_action(&app, &tray, &state, &profile, generation, action, &snapshot);
            } else {
                let snap = {
                    let runtime = match state.lock() {
                        Ok(runtime) => runtime,
                        Err(_) => return,
                    };
                    RuntimeSnapshot::from(&*runtime)
                };
                update_tray_ui(&app, &tray, &snap);
            }

            match stop_receiver.recv_timeout(interval) {
                Ok(_) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        }
    });

    Ok(())
}

#[allow(dead_code)]
pub fn start_tun_child_monitor(
    app: AppHandle,
    tray: TrayHandles,
    state: SharedRuntimeState,
    profile: ResolvedProfile,
    generation: u64,
    session_id: String,
) {
    thread::spawn(move || loop {
        thread::sleep(CHILD_WATCH_INTERVAL);

        let outcome = {
            let mut runtime = match state.lock() {
                Ok(runtime) => runtime,
                Err(_) => return,
            };

            if runtime.generation != generation
                || runtime
                    .active_profile
                    .as_ref()
                    .map(|active| active.id.as_str())
                    != Some(profile.id.as_str())
                || runtime.current_session_id.as_deref() != Some(session_id.as_str())
            {
                return;
            }

            let wait_result = match runtime.child.as_mut() {
                Some(child) => child.try_wait(),
                None => return,
            };

            match wait_result {
                Ok(None) => None,
                Ok(Some(status)) => {
                    let _ = runtime.child.take();
                    let artifacts = runtime.runtime_artifacts.take();
                    runtime.current_session_id = None;
                    runtime.connection_state = ConnectionState::Error;
                    runtime.last_error = Some(format_unexpected_tun_exit(status));
                    runtime.exit_status = Default::default();
                    let snapshot = inspect_network_for_profile(&profile);
                    runtime.vpn_status =
                        build_vpn_status(&profile, &snapshot, runtime.connection_state);
                    runtime.traffic_flow = build_traffic_flow(
                        Some(&profile),
                        &runtime.vpn_status,
                        runtime.connection_state,
                    );
                    Some((RuntimeSnapshot::from(&*runtime), artifacts))
                }
                Err(error) => {
                    let _ = runtime.child.take();
                    let artifacts = runtime.runtime_artifacts.take();
                    runtime.current_session_id = None;
                    runtime.connection_state = ConnectionState::Error;
                    runtime.last_error =
                        Some(format!("failed to monitor tun2proxy process: {error}"));
                    runtime.exit_status = Default::default();
                    let snapshot = inspect_network_for_profile(&profile);
                    runtime.vpn_status =
                        build_vpn_status(&profile, &snapshot, runtime.connection_state);
                    runtime.traffic_flow = build_traffic_flow(
                        Some(&profile),
                        &runtime.vpn_status,
                        runtime.connection_state,
                    );
                    Some((RuntimeSnapshot::from(&*runtime), artifacts))
                }
            }
        };

        let Some((snapshot, artifacts)) = outcome else {
            continue;
        };

        if let Some(artifacts) = artifacts {
            let _ = cleanup_runtime_artifacts(&artifacts);
        }

        update_tray_ui(&app, &tray, &snapshot);
        return;
    });
}

#[allow(dead_code)]
fn format_unexpected_tun_exit(status: ExitStatus) -> String {
    if status.success() {
        "tun2proxy exited unexpectedly".to_string()
    } else if let Some(code) = status.code() {
        if code == 1 {
            #[cfg(target_os = "windows")]
            {
                return "tun2proxy exited with status 1. On Windows this usually means the app was not elevated, Wintun is missing, or tun2proxy could not configure the virtual adapter."
                    .to_string();
            }
            #[cfg(not(target_os = "windows"))]
            {
                "tun2proxy exited with status 1. On Linux this usually means pkexec/sudo privileges were not available for TProxy setup. Run scripts/install-deps-linux.sh and make sure a desktop polkit agent is running, or launch the app as root."
                .to_string()
            }
        } else {
            format!("tun2proxy exited unexpectedly with status {code}")
        }
    } else {
        "tun2proxy exited unexpectedly without an exit code".to_string()
    }
}
