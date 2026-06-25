use proxy_core::proxy_url::socks5_url;
use proxy_core::socks5;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use proxy_core::system_local_endpoint;
use proxy_core::system_proxy;
use proxy_core::tun::tun2proxy_args;
use proxy_core::{endpoint_display, AppConfig, ResolvedProfile, RoutingMode};
use serde::{Deserialize, Serialize};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::network::{inspect_network_for_profile, resolve_route_target};
use crate::platform;
use crate::tun_backend;
use crate::types::{ConnectionState, SharedRuntimeState};
use crate::util::{current_unix_timestamp, generate_session_id};

const PROBE_URL: &str = "https://api.ipify.org?format=json";
const DNS_FREE_PROBE_URL: &str = "https://1.1.1.1/cdn-cgi/trace";
const BROWSER_LIKE_PROBE_URL: &str = "https://example.com/";
const DIAGNOSTIC_HTTP_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticStatus {
    Pass,
    Warn,
    Fail,
    Skipped,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticStep {
    pub id: String,
    pub label: String,
    pub status: DiagnosticStatus,
    pub details: String,
    pub duration_ms: u128,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticReport {
    pub overall_status: DiagnosticStatus,
    pub generated_unix: u64,
    pub profile_name: Option<String>,
    pub routing_mode: String,
    pub steps: Vec<DiagnosticStep>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticStepPlan {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DiagnosticProgressEvent {
    pub phase: String,
    pub run_id: String,
    pub profile_name: Option<String>,
    pub routing_mode: String,
    pub completed_steps: usize,
    pub total_steps: usize,
    pub current_step_id: Option<String>,
    pub current_step_label: Option<String>,
    pub steps: Option<Vec<DiagnosticStepPlan>>,
    pub step: Option<DiagnosticStep>,
    pub report: Option<DiagnosticReport>,
    pub error: Option<String>,
}

struct DiagnosticTask {
    position: usize,
    plan: DiagnosticStepPlan,
    job: Box<dyn FnOnce() -> DiagnosticStep + Send>,
}

enum TaskUpdate {
    Started {
        plan: DiagnosticStepPlan,
    },
    Finished {
        position: usize,
        step: DiagnosticStep,
    },
}

pub fn run_diagnostics<F>(
    state: &SharedRuntimeState,
    config: AppConfig,
    on_progress: F,
) -> Result<DiagnosticReport, String>
where
    F: Fn(DiagnosticProgressEvent),
{
    let config = config.canonicalized().map_err(|error| error.to_string())?;
    let selector = config
        .active_profile_id
        .as_deref()
        .or(config.selected_profile_id.as_deref());
    let profile = config
        .resolve_profile_by_selector(selector)
        .map_err(|error| error.to_string())?;

    let mut steps = Vec::new();
    steps.push(step(
        "profile",
        "Active profile",
        DiagnosticStatus::Pass,
        format!(
            "Using profile '{}' in {} mode for {}.",
            profile.name,
            profile.routing_mode,
            endpoint_display(&profile.endpoint)
        ),
        0,
        None,
    ));

    let runtime = {
        let runtime = state
            .lock()
            .map_err(|_| "runtime lock poisoned".to_string())?;
        RuntimeDiagnosticSnapshot {
            connection_state: runtime.connection_state,
            active_profile_id: runtime
                .active_profile
                .as_ref()
                .map(|profile| profile.id.clone()),
            has_system_snapshot: runtime.system_snapshot.is_some(),
            local_system_proxy_port: runtime.local_system_proxy.as_ref().map(|proxy| proxy.port),
            runtime_artifacts: runtime.runtime_artifacts.as_ref().map(|artifacts| {
                RuntimeArtifactSnapshot {
                    tun_device: artifacts.tun_device.clone(),
                    proxy_pid: artifacts.proxy_pid,
                    bound_vpn_interface: artifacts.bound_vpn_interface.clone(),
                    wfp_filter_count: artifacts.wfp_filters.len(),
                }
            }),
            last_error: runtime.last_error.clone(),
        }
    };

    let run_id = generate_session_id();
    let routing_mode = profile.routing_mode.to_string();
    let profile_name = Some(profile.name.clone());
    let network_probe_profile = effective_tun_diagnostic_profile(&profile);

    let mut planned = Vec::new();
    let mut steps: Vec<Option<DiagnosticStep>> = Vec::new();
    let mut async_tasks = Vec::new();
    let mut completed_steps = 0usize;

    push_immediate_step(
        &mut planned,
        &mut steps,
        &mut completed_steps,
        step(
            "profile",
            "Active profile",
            DiagnosticStatus::Pass,
            format!(
                "Using profile '{}' in {} mode for {}.",
                profile.name,
                profile.routing_mode,
                endpoint_display(&profile.endpoint)
            ),
            0,
            None,
        ),
    );
    push_immediate_step(
        &mut planned,
        &mut steps,
        &mut completed_steps,
        runtime_step(&profile, &runtime),
    );

    push_async_task(
        &mut planned,
        &mut steps,
        &mut async_tasks,
        "route_to_proxy",
        "Route to proxy",
        {
            let profile = network_probe_profile.clone();
            move || route_step(&profile)
        },
    );

    match profile.routing_mode {
        RoutingMode::System => {
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "socks_handshake",
                "SOCKS5 handshake",
                {
                    let profile = network_probe_profile.clone();
                    move || socks_handshake_step(&profile)
                },
            );
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "exit_ip_lookup",
                "Exit IP through SOCKS5",
                {
                    let profile = network_probe_profile.clone();
                    let config = config.clone();
                    move || exit_lookup_step(&profile, &config)
                },
            );

            let effective_profile =
                effective_system_profile(&profile, runtime.local_system_proxy_port.is_some());
            let compatibility_step = if let Some(message) =
                system_proxy::compatibility_warning(&profile)
            {
                step(
                        "system_proxy_compatibility",
                        "System proxy compatibility",
                        DiagnosticStatus::Fail,
                        "This profile cannot be used reliably through the available system proxy settings.",
                        0,
                        Some(message),
                    )
            } else {
                step(
                    "system_proxy_compatibility",
                    "System proxy compatibility",
                    DiagnosticStatus::Pass,
                    "Profile is compatible with the available system proxy settings.",
                    0,
                    None,
                )
            };
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                compatibility_step,
            );
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                step(
                    "system_proxy_local_adapter",
                    "Local system proxy adapter",
                    if runtime.local_system_proxy_port.is_some() {
                        DiagnosticStatus::Pass
                    } else {
                        DiagnosticStatus::Warn
                    },
                    runtime
                        .local_system_proxy_port
                        .map(|port| format!("Local SOCKS5 adapter is bound on 127.0.0.1:{port}."))
                        .unwrap_or_else(|| {
                            "Local SOCKS5 adapter is not running in the current runtime."
                                .to_string()
                        }),
                    0,
                    None,
                ),
            );
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                step(
                    "system_proxy_state",
                    "System proxy state",
                    if runtime.has_system_snapshot {
                        DiagnosticStatus::Pass
                    } else {
                        DiagnosticStatus::Warn
                    },
                    if runtime.has_system_snapshot {
                        "System proxy snapshot is active."
                    } else {
                        "No active system proxy snapshot is present in this runtime."
                    },
                    0,
                    None,
                ),
            );
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                step(
                    "system_dns_scope",
                    "System DNS scope",
                    DiagnosticStatus::Warn,
                    "System proxy mode now routes through the embedded local SOCKS5 adapter; app-specific DNS behavior can still vary.",
                    0,
                    None,
                ),
            );
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "system_proxy_local_handshake",
                "Local SOCKS5 handshake",
                {
                    let effective_profile = effective_profile.clone();
                    move || {
                        timed_step(
                            "system_proxy_local_handshake",
                            "Local SOCKS5 handshake",
                            &effective_profile,
                            || {
                                socks5::handshake(&effective_profile.endpoint)
                                    .map(|_| {
                                        "Local SOCKS5 adapter handshake succeeded.".to_string()
                                    })
                                    .map_err(|error| error.to_string())
                            },
                        )
                    }
                },
            );
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "system_proxy_exit_ip_lookup",
                "Exit IP through local system adapter",
                {
                    let effective_profile = effective_profile.clone();
                    let config = config.clone();
                    move || {
                        exit_lookup_step_named(
                            &effective_profile,
                            &config,
                            "system_proxy_exit_ip_lookup",
                            "Exit IP through local system adapter",
                        )
                    }
                },
            );
        }
        RoutingMode::Tun => {
            #[cfg(target_os = "windows")]
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                windows_tun_preflight_step(),
            );
            #[cfg(target_os = "windows")]
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                windows_mullvad_preflight_step(),
            );
            #[cfg(target_os = "windows")]
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                windows_wireguard_preflight_step(),
            );
            #[cfg(target_os = "windows")]
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                windows_mullvad_z4_guard_step(),
            );
            #[cfg(target_os = "windows")]
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                windows_firewall_wfp_preflight_step(),
            );
            #[cfg(target_os = "windows")]
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                windows_wfp_exception_plan_step(),
            );
            push_immediate_step(
                &mut planned,
                &mut steps,
                &mut completed_steps,
                tun_dns_policy_step(&profile),
            );
            #[cfg(target_os = "windows")]
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "tun_dns_route_policy",
                "TUN DNS route policy",
                {
                    let profile = profile.clone();
                    let tun_device = runtime
                        .runtime_artifacts
                        .as_ref()
                        .map(|artifacts| artifacts.tun_device.clone());
                    move || windows_tun_dns_route_policy_step(&profile, tun_device)
                },
            );
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "tun_chain_policy",
                "TUN VPN chain policy",
                {
                    let profile = network_probe_profile.clone();
                    move || tun_chain_policy_step(&profile)
                },
            );
            #[cfg(target_os = "windows")]
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "windows_proxy_vpn_route_plan",
                "Proxy VPN route plan",
                {
                    let profile = network_probe_profile.clone();
                    move || windows_proxy_vpn_route_plan_step(&profile)
                },
            );
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "socks_handshake",
                "SOCKS5 handshake",
                {
                    let profile = network_probe_profile.clone();
                    move || socks_handshake_step(&profile)
                },
            );
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "exit_ip_lookup",
                "Exit IP through SOCKS5",
                {
                    let profile = network_probe_profile.clone();
                    let config = config.clone();
                    move || exit_lookup_step(&profile, &config)
                },
            );
            if let Some(artifacts) = &runtime.runtime_artifacts {
                push_immediate_step(
                    &mut planned,
                    &mut steps,
                    &mut completed_steps,
                    tun_upstream_configuration_step(&network_probe_profile),
                );
                push_immediate_step(
                    &mut planned,
                    &mut steps,
                    &mut completed_steps,
                    step(
                        "tun_runtime_artifacts",
                        "TUN runtime artifacts",
                        DiagnosticStatus::Pass,
                        format!(
                            "TUN device {} is tracked with pid {:?}.",
                            artifacts.tun_device, artifacts.proxy_pid
                        ),
                        0,
                        None,
                    ),
                );
                #[cfg(target_os = "windows")]
                push_immediate_step(
                    &mut planned,
                    &mut steps,
                    &mut completed_steps,
                    step(
                        "windows_z4_runtime_wfp_filters",
                        "Windows Z4 runtime WFP filters",
                        if artifacts.bound_vpn_interface.is_some()
                            && artifacts.wfp_filter_count == 0
                        {
                            DiagnosticStatus::Fail
                        } else if artifacts.bound_vpn_interface.is_none() {
                            DiagnosticStatus::Skipped
                        } else {
                            DiagnosticStatus::Pass
                        },
                        if artifacts.bound_vpn_interface.is_some()
                            && artifacts.wfp_filter_count == 0
                        {
                            "No scoped Z4 WFP filters are tracked for the active TUN session."
                                .to_string()
                        } else if artifacts.bound_vpn_interface.is_none() {
                            "No VPN binding is recorded; Z4 WFP filters are not required for direct Z2 TUN."
                                .to_string()
                        } else {
                            format!(
                                "{} scoped Z4 WFP filters are tracked for the active TUN session.",
                                artifacts.wfp_filter_count
                            )
                        },
                        0,
                        None,
                    ),
                );
                push_immediate_step(
                    &mut planned,
                    &mut steps,
                    &mut completed_steps,
                    tun_device_step(&artifacts.tun_device),
                );
                push_immediate_step(
                    &mut planned,
                    &mut steps,
                    &mut completed_steps,
                    process_step("tun2proxy_process", "TUN tun2proxy", artifacts.proxy_pid),
                );
                push_immediate_step(
                    &mut planned,
                    &mut steps,
                    &mut completed_steps,
                    step(
                        "tun_vpn_binding",
                        "TUN VPN binding",
                        DiagnosticStatus::Pass,
                        artifacts
                            .bound_vpn_interface
                            .as_ref()
                            .map(|iface| {
                                format!(
                                    "TUN session was bound while VPN interface {iface} was active."
                                )
                            })
                            .unwrap_or_else(|| {
                                "No VPN interface binding was recorded.".to_string()
                            }),
                        0,
                        None,
                    ),
                );
            } else {
                push_immediate_step(
                    &mut planned,
                    &mut steps,
                    &mut completed_steps,
                    step(
                        "tun_runtime_artifacts",
                        "TUN runtime artifacts",
                        DiagnosticStatus::Fail,
                        "No TUN runtime artifacts are tracked for the current session.",
                        0,
                        None,
                    ),
                );
            }
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "direct_https_probe",
                "Direct HTTPS probe",
                {
                    let profile = network_probe_profile.clone();
                    move || direct_https_probe_step(&profile)
                },
            );
            push_async_task(
                &mut planned,
                &mut steps,
                &mut async_tasks,
                "browser_like_https_probe",
                "Browser-like HTTPS probe",
                {
                    let profile = network_probe_profile.clone();
                    move || browser_like_https_probe_step(&profile)
                },
            );
        }
    }

    let total_steps = planned.len();
    on_progress(DiagnosticProgressEvent {
        phase: "started".to_string(),
        run_id: run_id.clone(),
        profile_name: profile_name.clone(),
        routing_mode: routing_mode.clone(),
        completed_steps: 0,
        total_steps,
        current_step_id: None,
        current_step_label: None,
        steps: Some(planned.clone()),
        step: None,
        report: None,
        error: None,
    });

    let mut emitted_completed_steps = 0usize;
    for step in steps.iter().flatten() {
        emitted_completed_steps += 1;
        on_progress(DiagnosticProgressEvent {
            phase: "step_finished".to_string(),
            run_id: run_id.clone(),
            profile_name: profile_name.clone(),
            routing_mode: routing_mode.clone(),
            completed_steps: emitted_completed_steps.min(total_steps),
            total_steps,
            current_step_id: None,
            current_step_label: None,
            steps: None,
            step: Some(step.clone()),
            report: None,
            error: None,
        });
    }

    completed_steps = steps.iter().flatten().count();
    collect_async_steps(
        async_tasks,
        &mut steps,
        &run_id,
        profile_name.clone(),
        routing_mode.clone(),
        completed_steps,
        total_steps,
        &on_progress,
    );

    let steps = steps.into_iter().flatten().collect::<Vec<_>>();
    let report = DiagnosticReport {
        overall_status: aggregate_status(&steps),
        generated_unix: current_unix_timestamp(),
        profile_name: profile_name.clone(),
        routing_mode: routing_mode.clone(),
        steps,
    };
    on_progress(DiagnosticProgressEvent {
        phase: "finished".to_string(),
        run_id,
        profile_name,
        routing_mode,
        completed_steps: total_steps,
        total_steps,
        current_step_id: None,
        current_step_label: None,
        steps: None,
        step: None,
        report: Some(report.clone()),
        error: None,
    });

    Ok(report)
}

#[derive(Clone)]
struct RuntimeDiagnosticSnapshot {
    connection_state: ConnectionState,
    active_profile_id: Option<String>,
    has_system_snapshot: bool,
    local_system_proxy_port: Option<u16>,
    runtime_artifacts: Option<RuntimeArtifactSnapshot>,
    last_error: Option<String>,
}

#[derive(Clone)]
struct RuntimeArtifactSnapshot {
    tun_device: String,
    proxy_pid: Option<u32>,
    bound_vpn_interface: Option<String>,
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    wfp_filter_count: usize,
}

fn push_immediate_step(
    planned: &mut Vec<DiagnosticStepPlan>,
    steps: &mut Vec<Option<DiagnosticStep>>,
    completed_steps: &mut usize,
    step: DiagnosticStep,
) {
    planned.push(DiagnosticStepPlan {
        id: step.id.clone(),
        label: step.label.clone(),
    });
    steps.push(Some(step));
    *completed_steps += 1;
}

fn push_async_task<F>(
    planned: &mut Vec<DiagnosticStepPlan>,
    steps: &mut Vec<Option<DiagnosticStep>>,
    tasks: &mut Vec<DiagnosticTask>,
    id: &str,
    label: &str,
    job: F,
) where
    F: FnOnce() -> DiagnosticStep + Send + 'static,
{
    let position = planned.len();
    let plan = DiagnosticStepPlan {
        id: id.to_string(),
        label: label.to_string(),
    };
    planned.push(plan.clone());
    steps.push(None);
    tasks.push(DiagnosticTask {
        position,
        plan,
        job: Box::new(job),
    });
}

fn collect_async_steps<F>(
    tasks: Vec<DiagnosticTask>,
    steps: &mut [Option<DiagnosticStep>],
    run_id: &str,
    profile_name: Option<String>,
    routing_mode: String,
    mut completed_steps: usize,
    total_steps: usize,
    on_progress: &F,
) where
    F: Fn(DiagnosticProgressEvent),
{
    if tasks.is_empty() {
        return;
    }

    let (sender, receiver) = mpsc::channel();
    for task in tasks {
        let sender = sender.clone();
        thread::spawn(move || {
            let _ = sender.send(TaskUpdate::Started {
                plan: task.plan.clone(),
            });
            let step = (task.job)();
            let _ = sender.send(TaskUpdate::Finished {
                position: task.position,
                step,
            });
        });
    }
    drop(sender);

    let task_count = steps.iter().filter(|step| step.is_none()).count();
    let mut finished = 0usize;
    while finished < task_count {
        let Ok(update) = receiver.recv() else {
            break;
        };
        match update {
            TaskUpdate::Started { plan } => {
                on_progress(DiagnosticProgressEvent {
                    phase: "step_started".to_string(),
                    run_id: run_id.to_string(),
                    profile_name: profile_name.clone(),
                    routing_mode: routing_mode.clone(),
                    completed_steps,
                    total_steps,
                    current_step_id: Some(plan.id),
                    current_step_label: Some(plan.label),
                    steps: None,
                    step: None,
                    report: None,
                    error: None,
                });
            }
            TaskUpdate::Finished { position, step } => {
                finished += 1;
                completed_steps += 1;
                steps[position] = Some(step.clone());
                on_progress(DiagnosticProgressEvent {
                    phase: "step_finished".to_string(),
                    run_id: run_id.to_string(),
                    profile_name: profile_name.clone(),
                    routing_mode: routing_mode.clone(),
                    completed_steps,
                    total_steps,
                    current_step_id: None,
                    current_step_label: None,
                    steps: None,
                    step: Some(step),
                    report: None,
                    error: None,
                });
            }
        }
    }
}

fn runtime_step(profile: &ResolvedProfile, runtime: &RuntimeDiagnosticSnapshot) -> DiagnosticStep {
    let status = if runtime.active_profile_id.as_deref() == Some(profile.id.as_str())
        && matches!(
            runtime.connection_state,
            ConnectionState::Connected | ConnectionState::Blocked | ConnectionState::Rebinding
        ) {
        DiagnosticStatus::Pass
    } else if runtime.connection_state == ConnectionState::Error {
        DiagnosticStatus::Fail
    } else {
        DiagnosticStatus::Warn
    };
    let artifact_details = if runtime.runtime_artifacts.is_some() {
        " Runtime artifacts are present."
    } else {
        " Runtime artifacts are not present."
    };
    step(
        "runtime_state",
        "Runtime state",
        status,
        format!(
            "Runtime state is {:?}.{artifact_details}",
            runtime.connection_state
        ),
        0,
        runtime
            .last_error
            .as_ref()
            .map(|error| sanitize_profile_text(profile, error)),
    )
}

fn socks_handshake_step(profile: &ResolvedProfile) -> DiagnosticStep {
    timed_step("socks_handshake", "SOCKS5 handshake", profile, || {
        socks5::handshake(&profile.endpoint)
            .map(|_| "SOCKS5 handshake succeeded.".to_string())
            .map_err(|error| error.to_string())
    })
}

#[cfg(target_os = "windows")]
fn windows_tun_preflight_step() -> DiagnosticStep {
    let started = Instant::now();
    let preflight = proxy_platform_windows::preflight();
    let status = if preflight.missing_reasons.is_empty() {
        DiagnosticStatus::Pass
    } else if preflight.tun2proxy_path.is_some() || preflight.wintun_path.is_some() {
        DiagnosticStatus::Warn
    } else {
        DiagnosticStatus::Fail
    };
    let mut details = Vec::new();
    details.push(if preflight.elevated {
        "administrator rights: yes".to_string()
    } else {
        "administrator rights: no".to_string()
    });
    details.push(format!(
        "tun2proxy: {}",
        preflight
            .tun2proxy_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "missing".to_string())
    ));
    details.push(format!(
        "wintun: {}",
        preflight
            .wintun_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "missing".to_string())
    ));
    step(
        "windows_tun_preflight",
        "Windows TUN preflight",
        status,
        details.join("; "),
        started.elapsed().as_millis(),
        if preflight.missing_reasons.is_empty() {
            None
        } else {
            Some(preflight.missing_reasons.join("; "))
        },
    )
}

#[cfg(target_os = "windows")]
fn windows_mullvad_preflight_step() -> DiagnosticStep {
    let started = Instant::now();
    let status = proxy_platform_windows::mullvad_status();
    let Some(cli_path) = status.cli_path.as_ref() else {
        return step(
            "windows_mullvad_preflight",
            "Mullvad preflight",
            DiagnosticStatus::Skipped,
            "Mullvad CLI was not found; Z4 cannot be verified on this machine.",
            started.elapsed().as_millis(),
            status.error,
        );
    };

    let state = status.state.as_deref().unwrap_or("unknown");
    let connected = state.to_ascii_lowercase().starts_with("connected");
    let mut details = format!("Mullvad CLI: {}; state: {state}", cli_path.display());
    if let Some(protocol) = status.tunnel_protocol {
        details.push_str(&format!("; tunnel protocol: {protocol}"));
    }
    if let Some(locked_down) = status.locked_down {
        details.push_str(&format!("; lockdown: {locked_down}"));
    }
    if let Some(endpoint) = status.endpoint_address {
        details.push_str(&format!("; endpoint: {endpoint}"));
    }
    if let Some(endpoint_ip) = status.endpoint_ip {
        details.push_str(&format!("; endpoint IP: {endpoint_ip}"));
    }
    if let Some(endpoint_port) = status.endpoint_port {
        details.push_str(&format!("; endpoint port: {endpoint_port}"));
    }
    if let Some(endpoint_protocol) = status.endpoint_protocol {
        details.push_str(&format!("; endpoint protocol: {endpoint_protocol}"));
    }
    if let Some(tunnel_interface) = status.tunnel_interface {
        details.push_str(&format!("; tunnel interface: {tunnel_interface}"));
    }
    if let Some(visible_location) = status.visible_location {
        details.push_str(&format!("; visible location: {visible_location}"));
    }
    if let Some(visible_ipv4) = status.visible_ipv4 {
        details.push_str(&format!("; visible IPv4: {visible_ipv4}"));
    }
    if let Some(mullvad_exit_ip) = status.mullvad_exit_ip {
        details.push_str(&format!("; Mullvad exit IP: {mullvad_exit_ip}"));
    }
    if let Some(relay) = status.relay_hostname {
        details.push_str(&format!("; relay: {relay}"));
    }
    if let Some(relay_ipv4) = status.relay_ipv4 {
        details.push_str(&format!("; relay IPv4: {relay_ipv4}"));
    }
    if let Some(relay_ipv6) = status.relay_ipv6 {
        details.push_str(&format!("; relay IPv6: {relay_ipv6}"));
    }
    if let Some(entry) = status.entry_hostname {
        details.push_str(&format!("; entry relay: {entry}"));
    }
    if let Some(entry_ipv4) = status.entry_ipv4 {
        details.push_str(&format!("; entry IPv4: {entry_ipv4}"));
    }
    if let Some(entry_ipv6) = status.entry_ipv6 {
        details.push_str(&format!("; entry IPv6: {entry_ipv6}"));
    }
    if let Some(bridge) = status.bridge_hostname {
        details.push_str(&format!("; bridge: {bridge}"));
    }
    if let Some(obfuscator) = status.obfuscator_hostname {
        details.push_str(&format!("; obfuscator: {obfuscator}"));
    }
    if !connected {
        details.push_str("; Z4 live verification requires Mullvad to be connected.");
    }
    let diagnostic_status = if status.error.is_some() {
        DiagnosticStatus::Warn
    } else {
        DiagnosticStatus::Pass
    };
    step(
        "windows_mullvad_preflight",
        "Mullvad preflight",
        diagnostic_status,
        details,
        started.elapsed().as_millis(),
        status.error,
    )
}

#[cfg(target_os = "windows")]
fn windows_wireguard_preflight_step() -> DiagnosticStep {
    let started = Instant::now();
    let status = proxy_platform_windows::wireguard_status();
    let Some(cli_path) = status.cli_path.as_ref() else {
        return step(
            "windows_wireguard_preflight",
            "WireGuard preflight",
            DiagnosticStatus::Skipped,
            "wg.exe was not found; standard WireGuard Z3 cannot be verified on this machine.",
            started.elapsed().as_millis(),
            status.error,
        );
    };

    let mut details = format!("wg CLI: {}", cli_path.display());
    if status.interfaces.is_empty() {
        details.push_str("; no active WireGuard interfaces reported.");
    } else {
        details.push_str(&format!(
            "; interfaces: {}; endpoint bypass IPs: {}",
            status.interfaces.join(", "),
            if status.endpoint_ips.is_empty() {
                "none".to_string()
            } else {
                status.endpoint_ips.join(", ")
            }
        ));
    }
    details.push_str(
        "; if WireGuard's kill-switch is enabled, Z3 requires a WFP exception or a clear blocked status.",
    );

    let diagnostic_status = if status.error.is_some() {
        DiagnosticStatus::Warn
    } else if status.interfaces.is_empty() {
        DiagnosticStatus::Skipped
    } else {
        DiagnosticStatus::Pass
    };

    step(
        "windows_wireguard_preflight",
        "WireGuard preflight",
        diagnostic_status,
        details,
        started.elapsed().as_millis(),
        status.error,
    )
}

#[cfg(target_os = "windows")]
fn windows_mullvad_z4_guard_step() -> DiagnosticStep {
    let started = Instant::now();
    let status = proxy_platform_windows::mullvad_status();
    windows_mullvad_z4_guard_step_from_status(&status, started.elapsed().as_millis())
}

#[cfg(target_os = "windows")]
fn windows_mullvad_z4_guard_step_from_status(
    status: &proxy_platform_windows::WindowsMullvadStatus,
    duration_ms: u128,
) -> DiagnosticStep {
    let connected = status
        .state
        .as_deref()
        .map(|state| state.to_ascii_lowercase().starts_with("connected"))
        .unwrap_or(false);

    if connected {
        let endpoint = status
            .endpoint_address
            .as_deref()
            .or(status.relay_hostname.as_deref())
            .unwrap_or("unknown endpoint");
        return step(
            "windows_mullvad_z4_guard",
            "Mullvad Z4 WFP guard",
            DiagnosticStatus::Pass,
            format!("Mullvad is connected ({endpoint}); Z4 will require the scoped WFP kill-switch exception before Windows TUN routing starts."),
            duration_ms,
            Some("Continue with the Windows Z4 WFP exception plan below; it must be ready before connecting through active Mullvad.".to_string()),
        );
    }

    if let Some(error) = status.error.clone() {
        return step(
            "windows_mullvad_z4_guard",
            "Mullvad Z4 WFP guard",
            DiagnosticStatus::Warn,
            "Mullvad status could not be verified; Z4 live verification is not available.",
            duration_ms,
            Some(error),
        );
    }

    step(
        "windows_mullvad_z4_guard",
        "Mullvad Z4 WFP guard",
        DiagnosticStatus::Pass,
        "No connected Mullvad tunnel is active; guarded Z2 live testing is not blocked by the Z4 WFP guard.",
        duration_ms,
        None,
    )
}

#[cfg(target_os = "windows")]
fn windows_firewall_wfp_preflight_step() -> DiagnosticStep {
    let started = Instant::now();
    let status = proxy_platform_windows::firewall_preflight();
    windows_firewall_wfp_preflight_step_from_status(&status, started.elapsed().as_millis())
}

#[cfg(target_os = "windows")]
fn windows_firewall_wfp_preflight_step_from_status(
    status: &proxy_platform_windows::WindowsFirewallPreflight,
    duration_ms: u128,
) -> DiagnosticStep {
    let profile_count = status
        .firewall_profiles_count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let rule_count = status
        .matching_firewall_rule_count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let mut details = format!(
        "Firewall profiles: {profile_count}; visible Mullvad/WireGuard/socks5proxy/tun2proxy rules: {rule_count}; WFP state readable: {}.",
        status.wfp_state_available
    );
    if !status.elevated {
        details.push_str(
            " This process is not elevated; WFP state inspection requires administrator rights.",
        );
    }
    if let Some(error) = status.wfp_state_error.as_deref() {
        details.push_str(&format!(" WFP state check: {error}"));
    }

    let diagnostic_status = if status.error.is_some() || !status.wfp_state_available {
        DiagnosticStatus::Warn
    } else {
        DiagnosticStatus::Pass
    };

    step(
        "windows_firewall_wfp_preflight",
        "Windows Firewall/WFP preflight",
        diagnostic_status,
        details,
        duration_ms,
        status.error.clone(),
    )
}

#[cfg(target_os = "windows")]
fn windows_wfp_exception_plan_step() -> DiagnosticStep {
    let started = Instant::now();
    let mullvad = proxy_platform_windows::mullvad_status();
    let firewall = proxy_platform_windows::firewall_preflight();
    let plan = proxy_platform_windows::wfp_exception_plan(&mullvad, &firewall);
    windows_wfp_exception_plan_step_from_plan(&plan, started.elapsed().as_millis())
}

#[cfg(target_os = "windows")]
fn windows_wfp_exception_plan_step_from_plan(
    plan: &proxy_platform_windows::WindowsWfpExceptionPlan,
    duration_ms: u128,
) -> DiagnosticStep {
    if !plan.required {
        return step(
            "windows_wfp_exception_plan",
            "Windows Z4 WFP exception plan",
            DiagnosticStatus::Pass,
            "No connected Mullvad tunnel is active; no Z4 WFP exception is required for the current state.",
            duration_ms,
            None,
        );
    }

    let mut details = format!(
        "Z4 WFP exception plan status: {}; session tag: {}; planned allows: {}; planned cleanup steps: {}.",
        plan.status,
        plan.session_tag,
        plan.planned_allows.len(),
        plan.planned_cleanup.len()
    );
    details.push_str(&format!(
        " Planned WFP identities: {}.",
        plan.planned_filter_identities.len()
    ));
    if let Some(interface) = plan.mullvad_tunnel_interface.as_deref() {
        details.push_str(&format!(" Mullvad tunnel interface: {interface}."));
    }
    if let Some(endpoint_ip) = plan.mullvad_endpoint_ip.as_deref() {
        details.push_str(&format!(" Mullvad endpoint IP: {endpoint_ip}."));
    }

    let diagnostic_status = if plan.ready {
        DiagnosticStatus::Warn
    } else {
        DiagnosticStatus::Fail
    };
    let error = if plan.blockers.is_empty() {
        Some(
            "The WFP exception is ready and will be applied by an elevated desktop session before TUN routing starts."
                .to_string(),
        )
    } else {
        Some(plan.blockers.join("; "))
    };

    step(
        "windows_wfp_exception_plan",
        "Windows Z4 WFP exception plan",
        diagnostic_status,
        details,
        duration_ms,
        error,
    )
}

fn tun_dns_policy_step(profile: &ResolvedProfile) -> DiagnosticStep {
    if profile.proxy_dns {
        step(
            "tun_dns_policy",
            "TUN DNS policy",
            DiagnosticStatus::Pass,
            "Proxy DNS is enabled; tun2proxy will use virtual DNS and the Windows backend flushes the DNS cache before TUN start.",
            0,
            None,
        )
    } else {
        step(
            "tun_dns_policy",
            "TUN DNS policy",
            DiagnosticStatus::Warn,
            "Proxy DNS is disabled; Windows may resolve names through the system DNS path instead of the proxy.",
            0,
            Some("TUN-3 requires proxy DNS for no-leak operation. Enable 'DNS over proxy' for Windows TUN privacy tests.".to_string()),
        )
    }
}

#[cfg(target_os = "windows")]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsDnsRouteRecord {
    ip: Option<String>,
    interface_alias: Option<String>,
    destination_prefix: Option<String>,
}

#[cfg(target_os = "windows")]
fn windows_tun_dns_route_policy_step(
    profile: &ResolvedProfile,
    tun_device: Option<String>,
) -> DiagnosticStep {
    let started = Instant::now();
    if !profile.proxy_dns {
        return step(
            "tun_dns_route_policy",
            "TUN DNS route policy",
            DiagnosticStatus::Warn,
            "Proxy DNS is disabled; direct system DNS routes are possible by configuration.",
            started.elapsed().as_millis(),
            None,
        );
    }

    let Some(tun_device) = tun_device else {
        return step(
            "tun_dns_route_policy",
            "TUN DNS route policy",
            DiagnosticStatus::Warn,
            "No active TUN runtime artifacts are tracked; DNS server routes can only be verified during an active TUN session.",
            started.elapsed().as_millis(),
            None,
        );
    };

    match windows_dns_route_records() {
        Ok(records) => windows_tun_dns_route_policy_step_from_records(
            &tun_device,
            &records,
            started.elapsed().as_millis(),
        ),
        Err(error) => step(
            "tun_dns_route_policy",
            "TUN DNS route policy",
            DiagnosticStatus::Warn,
            "Could not inspect Windows DNS server routes.",
            started.elapsed().as_millis(),
            Some(error),
        ),
    }
}

#[cfg(target_os = "windows")]
fn windows_dns_route_records() -> Result<Vec<WindowsDnsRouteRecord>, String> {
    let script = r#"
$servers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  ForEach-Object { $_.ServerAddresses } |
  Where-Object { $_ } |
  Select-Object -Unique
$out = @()
foreach ($server in $servers) {
  $route = Find-NetRoute -RemoteIPAddress $server -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($route) {
    $adapter = Get-NetAdapter -InterfaceIndex ([int]$route.InterfaceIndex) -ErrorAction SilentlyContinue
    $out += [PSCustomObject]@{
      Ip = [string]$server
      InterfaceAlias = if ($adapter) { [string]$adapter.Name } else { $null }
      DestinationPrefix = [string]$route.DestinationPrefix
    }
  }
}
$out | ConvertTo-Json -Depth 4
"#;

    let output = crate::util::console_hidden_command("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<WindowsDnsRouteRecord>>(&text)
        .or_else(|_| {
            serde_json::from_str::<WindowsDnsRouteRecord>(&text).map(|record| vec![record])
        })
        .map_err(|error| format!("failed to parse DNS route JSON: {error}; raw: {text}"))
}

#[cfg(target_os = "windows")]
fn windows_tun_dns_route_policy_step_from_records(
    tun_device: &str,
    records: &[WindowsDnsRouteRecord],
    duration_ms: u128,
) -> DiagnosticStep {
    if records.is_empty() {
        return step(
            "tun_dns_route_policy",
            "TUN DNS route policy",
            DiagnosticStatus::Warn,
            "Windows reported no resolvable IPv4 DNS server routes.",
            duration_ms,
            None,
        );
    }

    let routable_records = records
        .iter()
        .filter(|record| {
            !record
                .ip
                .as_deref()
                .map(|ip| ip == "localhost" || ip.starts_with("127."))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();

    if routable_records.is_empty() {
        return step(
            "tun_dns_route_policy",
            "TUN DNS route policy",
            DiagnosticStatus::Pass,
            "Configured DNS servers are local-only; no external DNS route can bypass the TUN adapter.",
            duration_ms,
            None,
        );
    }

    let leaks = routable_records
        .iter()
        .filter(|record| {
            record
                .interface_alias
                .as_deref()
                .map(|alias| !alias.eq_ignore_ascii_case(tun_device))
                .unwrap_or(true)
        })
        .collect::<Vec<_>>();

    if !leaks.is_empty() {
        let summary = leaks
            .iter()
            .map(|record| {
                format!(
                    "{} via {} ({})",
                    record.ip.as_deref().unwrap_or("unknown"),
                    record
                        .interface_alias
                        .as_deref()
                        .unwrap_or("unknown interface"),
                    record
                        .destination_prefix
                        .as_deref()
                        .unwrap_or("unknown route")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        return step(
            "tun_dns_route_policy",
            "TUN DNS route policy",
            DiagnosticStatus::Fail,
            format!("Configured DNS server routes do not all use active TUN adapter {tun_device}."),
            duration_ms,
            Some(summary),
        );
    }

    step(
        "tun_dns_route_policy",
        "TUN DNS route policy",
        DiagnosticStatus::Pass,
        format!("Configured DNS server routes use active TUN adapter {tun_device}."),
        duration_ms,
        None,
    )
}

fn tun_chain_policy_step(profile: &ResolvedProfile) -> DiagnosticStep {
    let started = Instant::now();
    let snapshot = inspect_network_for_profile(profile);
    tun_chain_policy_step_from_snapshot(profile, &snapshot, started.elapsed().as_millis())
}

#[cfg(target_os = "windows")]
fn windows_proxy_vpn_route_plan_step(profile: &ResolvedProfile) -> DiagnosticStep {
    let started = Instant::now();
    if profile.routing_mode != RoutingMode::Tun {
        return step(
            "windows_proxy_vpn_route_plan",
            "Proxy VPN route plan",
            DiagnosticStatus::Skipped,
            "Proxy VPN route planning only applies to TUN routing.",
            started.elapsed().as_millis(),
            None,
        );
    }

    let Some(target) = resolve_route_target(&profile.endpoint) else {
        return step(
            "windows_proxy_vpn_route_plan",
            "Proxy VPN route plan",
            DiagnosticStatus::Fail,
            "Could not resolve the proxy host to an IP route target.",
            started.elapsed().as_millis(),
            None,
        );
    };

    match proxy_platform_windows::proxy_vpn_route_plan(&target) {
        Ok(Some(plan)) => step(
            "windows_proxy_vpn_route_plan",
            "Proxy VPN route plan",
            DiagnosticStatus::Warn,
            format!(
                "Proxy route target {} needs a host route via VPN interface {} (index {}).",
                plan.destination_prefix, plan.vpn_interface, plan.vpn_interface_index
            ),
            started.elapsed().as_millis(),
            Some(format!(
                "Planned command: {}; cleanup command: {}",
                plan.add_command, plan.remove_command
            )),
        ),
        Ok(None) => step(
            "windows_proxy_vpn_route_plan",
            "Proxy VPN route plan",
            DiagnosticStatus::Pass,
            "No proxy-to-VPN host route is needed: either no active VPN was detected, or the proxy uplink already uses it.",
            started.elapsed().as_millis(),
            None,
        ),
        Err(error) => step(
            "windows_proxy_vpn_route_plan",
            "Proxy VPN route plan",
            DiagnosticStatus::Warn,
            "Could not compute a Windows proxy-to-VPN route plan.",
            started.elapsed().as_millis(),
            Some(error.to_string()),
        ),
    }
}

fn tun_chain_policy_step_from_snapshot(
    profile: &ResolvedProfile,
    snapshot: &crate::types::NetworkSnapshot,
    duration_ms: u128,
) -> DiagnosticStep {
    if profile.routing_mode != RoutingMode::Tun {
        return step(
            "tun_chain_policy",
            "TUN VPN chain policy",
            DiagnosticStatus::Skipped,
            "VPN chain policy only applies to TUN routing.",
            duration_ms,
            None,
        );
    }

    match (
        snapshot.active_vpn_interface.as_deref(),
        snapshot.proxy_uplink_interface.as_deref(),
    ) {
        (None, _) => step(
            "tun_chain_policy",
            "TUN VPN chain policy",
            DiagnosticStatus::Pass,
            "No active VPN interface was detected; this is the direct Z2 TUN topology.",
            duration_ms,
            snapshot.last_reason.clone(),
        ),
        (Some(vpn), Some(proxy)) if vpn == proxy => step(
            "tun_chain_policy",
            "TUN VPN chain policy",
            DiagnosticStatus::Pass,
            format!("Proxy uplink uses active VPN interface {vpn}; Z3/Z4 chain precondition is satisfied."),
            duration_ms,
            snapshot.last_reason.clone(),
        ),
        (Some(vpn), Some(proxy)) => step(
            "tun_chain_policy",
            "TUN VPN chain policy",
            DiagnosticStatus::Fail,
            format!("Active VPN interface {vpn} was detected, but the proxy uplink route uses {proxy}."),
            duration_ms,
            Some("Z3/Z4 require the proxy uplink to ride through the active VPN; otherwise the VPN is bypassed.".to_string()),
        ),
        (Some(vpn), None) => step(
            "tun_chain_policy",
            "TUN VPN chain policy",
            DiagnosticStatus::Fail,
            format!("Active VPN interface {vpn} was detected, but the proxy uplink route could not be resolved."),
            duration_ms,
            Some("Z3/Z4 cannot be verified until the route to the proxy endpoint is known.".to_string()),
        ),
    }
}

fn route_step(profile: &ResolvedProfile) -> DiagnosticStep {
    let started = Instant::now();
    let Some(target) = resolve_route_target(&profile.endpoint) else {
        return step(
            "route_to_proxy",
            "Route to proxy",
            DiagnosticStatus::Fail,
            "Could not resolve the proxy host to a route target.",
            started.elapsed().as_millis(),
            None,
        );
    };
    match platform::route_interface_to(&target) {
        Ok(Some(interface)) => {
            let snapshot = inspect_network_for_profile(profile);
            let mut details = format!("Proxy route target {target} uses interface {interface}.");
            if snapshot.valid_vpn_uplink() {
                details.push_str(" The proxy route uses the active host VPN.");
            }
            step(
                "route_to_proxy",
                "Route to proxy",
                DiagnosticStatus::Pass,
                details,
                started.elapsed().as_millis(),
                snapshot.last_reason,
            )
        }
        Ok(None) => step(
            "route_to_proxy",
            "Route to proxy",
            DiagnosticStatus::Warn,
            format!("No interface was reported for route target {target}."),
            started.elapsed().as_millis(),
            None,
        ),
        Err(error) => step(
            "route_to_proxy",
            "Route to proxy",
            DiagnosticStatus::Warn,
            format!("Could not inspect route target {target}."),
            started.elapsed().as_millis(),
            Some(sanitize_profile_text(profile, &error)),
        ),
    }
}

fn exit_lookup_step(profile: &ResolvedProfile, config: &AppConfig) -> DiagnosticStep {
    exit_lookup_step_named(profile, config, "exit_ip_lookup", "Exit IP through SOCKS5")
}

fn exit_lookup_step_named(
    profile: &ResolvedProfile,
    config: &AppConfig,
    id: &str,
    label: &str,
) -> DiagnosticStep {
    let started = Instant::now();
    if !config.tray_settings.exit_ip_lookup_enabled {
        return step(
            id,
            label,
            DiagnosticStatus::Skipped,
            "Exit IP lookup is disabled in settings.",
            0,
            None,
        );
    }
    let exit_ip_result = lookup_exit_ip_via_socks5_for_diagnostics(profile);
    if let Ok(exit_ip) = exit_ip_result {
        #[cfg(target_os = "windows")]
        if profile.routing_mode == RoutingMode::Tun {
            let mullvad = proxy_platform_windows::mullvad_status();
            if mullvad.state.as_deref() == Some("connected")
                && mullvad.visible_ipv4.as_deref() == Some(exit_ip.as_str())
            {
                return step(
                    id,
                    label,
                    DiagnosticStatus::Fail,
                    format!(
                        "SOCKS5 egress IP is {exit_ip}, which matches Mullvad's visible IPv4."
                    ),
                    started.elapsed().as_millis(),
                    Some("The proxy egress is indistinguishable from the Mullvad tunnel exit; browser traffic may be riding Mullvad without reaching the SOCKS5 proxy's external exit.".to_string()),
                );
            }
        }
        step(
            id,
            label,
            DiagnosticStatus::Pass,
            format!("SOCKS5 egress IP is {exit_ip}."),
            started.elapsed().as_millis(),
            None,
        )
    } else {
        step(
            id,
            label,
            DiagnosticStatus::Fail,
            "Exit IP lookup through the SOCKS5 proxy failed.",
            started.elapsed().as_millis(),
            exit_ip_result
                .err()
                .map(|error| sanitize_profile_text(profile, &error)),
        )
    }
}

fn lookup_exit_ip_via_socks5_for_diagnostics(profile: &ResolvedProfile) -> Result<String, String> {
    #[derive(Deserialize)]
    struct IpifyResponse {
        ip: String,
    }

    let proxy_url = socks5_url(&profile.endpoint).replacen("socks5://", "socks5h://", 1);
    let proxy = reqwest::Proxy::all(proxy_url)
        .map_err(|error| format!("failed to configure SOCKS5 client: {error}"))?;
    reqwest::blocking::Client::builder()
        .timeout(DIAGNOSTIC_HTTP_TIMEOUT)
        .proxy(proxy)
        .build()
        .map_err(|error| format!("failed to build SOCKS5 HTTP client: {error}"))?
        .get(PROBE_URL)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(describe_reqwest_error)?
        .json::<IpifyResponse>()
        .map(|response| response.ip)
        .map_err(|error| format!("failed to parse exit IP response: {error}"))
}

fn tun_upstream_configuration_step(profile: &ResolvedProfile) -> DiagnosticStep {
    let args = tun2proxy_args(profile)
        .into_iter()
        .map(|arg| sanitize_profile_text(profile, &arg))
        .collect::<Vec<_>>()
        .join(" ");
    step(
        "tun_upstream_configuration",
        "TUN upstream configuration",
        DiagnosticStatus::Pass,
        format!(
            "tun2proxy upstream is {}; proxy_dns={}; args: {}",
            sanitize_profile_text(profile, &socks5_url(&profile.endpoint)),
            profile.proxy_dns,
            args
        ),
        0,
        None,
    )
}

#[allow(dead_code)]
fn system_steps(
    profile: &ResolvedProfile,
    runtime: &RuntimeDiagnosticSnapshot,
    config: &AppConfig,
) -> Vec<DiagnosticStep> {
    let effective_profile =
        effective_system_profile(profile, runtime.local_system_proxy_port.is_some());
    let compatibility_step = if let Some(message) = system_proxy::compatibility_warning(profile) {
        step(
            "system_proxy_compatibility",
            "System proxy compatibility",
            DiagnosticStatus::Fail,
            "This profile cannot be used reliably through the available system proxy settings.",
            0,
            Some(message),
        )
    } else {
        step(
            "system_proxy_compatibility",
            "System proxy compatibility",
            DiagnosticStatus::Pass,
            "Profile is compatible with the available system proxy settings.",
            0,
            None,
        )
    };

    vec![
        compatibility_step,
        step(
            "system_proxy_local_adapter",
            "Local system proxy adapter",
            if runtime.local_system_proxy_port.is_some() {
                DiagnosticStatus::Pass
            } else {
                DiagnosticStatus::Warn
            },
            runtime
                .local_system_proxy_port
                .map(|port| format!("Local SOCKS5 adapter is bound on 127.0.0.1:{port}."))
                .unwrap_or_else(|| "Local SOCKS5 adapter is not running in the current runtime.".to_string()),
            0,
            None,
        ),
        step(
            "system_proxy_state",
            "System proxy state",
            if runtime.has_system_snapshot {
                DiagnosticStatus::Pass
            } else {
                DiagnosticStatus::Warn
            },
            if runtime.has_system_snapshot {
                "System proxy snapshot is active."
            } else {
                "No active system proxy snapshot is present in this runtime."
            },
            0,
            None,
        ),
        step(
            "system_dns_scope",
            "System DNS scope",
            DiagnosticStatus::Warn,
            "System proxy mode now routes through the embedded local SOCKS5 adapter; app-specific DNS behavior can still vary.",
            0,
            None,
        ),
        timed_step("system_proxy_local_handshake", "Local SOCKS5 handshake", &effective_profile, || {
            socks5::handshake(&effective_profile.endpoint)
                .map(|_| "Local SOCKS5 adapter handshake succeeded.".to_string())
                .map_err(|error| error.to_string())
        }),
        exit_lookup_step(&effective_profile, config),
    ]
}

fn effective_system_profile(
    profile: &ResolvedProfile,
    local_proxy_active: bool,
) -> ResolvedProfile {
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    let _ = local_proxy_active;

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    if profile.routing_mode == RoutingMode::System && local_proxy_active {
        let mut effective = profile.clone();
        effective.endpoint = system_local_endpoint();
        return effective;
    }

    profile.clone()
}

fn effective_tun_diagnostic_profile(profile: &ResolvedProfile) -> ResolvedProfile {
    if profile.routing_mode != RoutingMode::Tun {
        return profile.clone();
    }

    let Ok(status) = tun_backend::status() else {
        return profile.clone();
    };
    let Some(proxy_ip) = status.proxy_ip else {
        return profile.clone();
    };

    let mut effective = profile.clone();
    effective.endpoint.host = proxy_ip;
    effective
}

#[allow(dead_code)]
fn tun_steps(
    profile: &ResolvedProfile,
    runtime: &RuntimeDiagnosticSnapshot,
) -> Vec<DiagnosticStep> {
    let mut steps = Vec::new();
    if let Some(artifacts) = &runtime.runtime_artifacts {
        steps.push(step(
            "tun_runtime_artifacts",
            "TUN runtime artifacts",
            DiagnosticStatus::Pass,
            format!(
                "TUN device {} is tracked with pid {:?}.",
                artifacts.tun_device, artifacts.proxy_pid
            ),
            0,
            None,
        ));
        steps.push(tun_device_step(&artifacts.tun_device));
        steps.push(process_step(
            "tun2proxy_process",
            "TUN tun2proxy",
            artifacts.proxy_pid,
        ));
        steps.push(step(
            "tun_vpn_binding",
            "TUN VPN binding",
            DiagnosticStatus::Pass,
            artifacts
                .bound_vpn_interface
                .as_ref()
                .map(|iface| {
                    format!("TUN session was bound while VPN interface {iface} was active.")
                })
                .unwrap_or_else(|| "No VPN interface binding was recorded.".to_string()),
            0,
            None,
        ));
    } else {
        steps.push(step(
            "tun_runtime_artifacts",
            "TUN runtime artifacts",
            DiagnosticStatus::Fail,
            "No TUN runtime artifacts are tracked for the current session.",
            0,
            None,
        ));
    }
    steps.push(direct_https_probe_step(profile));
    if profile.routing_mode == RoutingMode::Tun {
        steps.push(browser_like_https_probe_step(profile));
    }
    steps
}

fn direct_https_probe_step(profile: &ResolvedProfile) -> DiagnosticStep {
    timed_step("direct_https_probe", "Direct HTTPS probe", profile, || {
        let probe_url = if profile.routing_mode == RoutingMode::Tun {
            DNS_FREE_PROBE_URL
        } else {
            PROBE_URL
        };
        let success_details = if profile.routing_mode == RoutingMode::Tun {
            "DNS-free HTTPS probe succeeded from the active TUN path."
        } else {
            "Direct HTTPS probe succeeded from the host network stack."
        };

        reqwest::blocking::Client::builder()
            .timeout(DIAGNOSTIC_HTTP_TIMEOUT)
            .build()
            .map_err(|error| error.to_string())?
            .get(probe_url)
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(describe_reqwest_error)?
            .text()
            .map(|_| success_details.to_string())
            .map_err(|error| error.to_string())
    })
}

fn browser_like_https_probe_step(profile: &ResolvedProfile) -> DiagnosticStep {
    timed_step(
        "browser_like_https_probe",
        "Browser-like HTTPS probe",
        profile,
        || {
            reqwest::blocking::Client::builder()
                .timeout(DIAGNOSTIC_HTTP_TIMEOUT)
                .build()
                .map_err(|error| error.to_string())?
                .get(BROWSER_LIKE_PROBE_URL)
                .send()
                .and_then(|response| response.error_for_status())
                .map_err(describe_reqwest_error)?
                .text()
                .map(|_| "DNS + HTTPS probe succeeded from the active TUN path.".to_string())
                .map_err(|error| error.to_string())
        },
    )
}

fn describe_reqwest_error(error: reqwest::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = std::error::Error::source(&error);
    while let Some(error) = source {
        parts.push(error.to_string());
        source = error.source();
    }
    parts.join(": ")
}

fn tun_device_step(tun_device: &str) -> DiagnosticStep {
    #[cfg(target_os = "linux")]
    {
        command_probe_step(
            "tun_device",
            "TUN device",
            "ip",
            &["link", "show", "dev", tun_device],
            format!("TUN device {tun_device} exists."),
        )
    }
    #[cfg(target_os = "windows")]
    {
        command_probe_step(
            "tun_device",
            "TUN adapter",
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                &format!("Get-NetAdapter -Name '{tun_device}' -ErrorAction Stop | Out-Null"),
            ],
            format!("TUN adapter {tun_device} exists."),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        step(
            "tun_device",
            "TUN device",
            DiagnosticStatus::Skipped,
            "TUN device inspection is not implemented on this platform.",
            0,
            None,
        )
    }
}

fn process_step(id: &str, label: &str, pid: Option<u32>) -> DiagnosticStep {
    let Some(pid) = pid else {
        return step(
            id,
            label,
            DiagnosticStatus::Fail,
            "No process id is tracked.",
            0,
            None,
        );
    };
    match platform::process_exists(pid) {
        Ok(true) => step(
            id,
            label,
            DiagnosticStatus::Pass,
            format!("Process pid {pid} is running."),
            0,
            None,
        ),
        Ok(false) => step(
            id,
            label,
            DiagnosticStatus::Fail,
            format!("Process pid {pid} is not running."),
            0,
            None,
        ),
        Err(error) => step(
            id,
            label,
            DiagnosticStatus::Warn,
            format!("Could not inspect process pid {pid}."),
            0,
            Some(error),
        ),
    }
}

fn command_probe_step(
    id: &str,
    label: &str,
    program: &str,
    args: &[&str],
    success_details: String,
) -> DiagnosticStep {
    let started = Instant::now();
    match crate::util::console_hidden_command(program).args(args).output() {
        Ok(output) if output.status.success() => step(
            id,
            label,
            DiagnosticStatus::Pass,
            success_details,
            started.elapsed().as_millis(),
            None,
        ),
        Ok(output) => step(
            id,
            label,
            DiagnosticStatus::Fail,
            format!("Command `{program}` did not succeed."),
            started.elapsed().as_millis(),
            Some(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        ),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                || error.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            step(
                id,
                label,
                DiagnosticStatus::Skipped,
                format!("Could not run `{program}`."),
                started.elapsed().as_millis(),
                Some(error.to_string()),
            )
        }
        Err(error) => step(
            id,
            label,
            DiagnosticStatus::Warn,
            format!("Could not run `{program}`."),
            started.elapsed().as_millis(),
            Some(error.to_string()),
        ),
    }
}

fn timed_step<F>(id: &str, label: &str, profile: &ResolvedProfile, check: F) -> DiagnosticStep
where
    F: FnOnce() -> Result<String, String>,
{
    let started = Instant::now();
    match check() {
        Ok(details) => step(
            id,
            label,
            DiagnosticStatus::Pass,
            details,
            started.elapsed().as_millis(),
            None,
        ),
        Err(error) => step(
            id,
            label,
            DiagnosticStatus::Fail,
            format!("{label} failed."),
            started.elapsed().as_millis(),
            Some(sanitize_profile_text(profile, &error)),
        ),
    }
}

fn step(
    id: &str,
    label: &str,
    status: DiagnosticStatus,
    details: impl Into<String>,
    duration_ms: u128,
    error: Option<String>,
) -> DiagnosticStep {
    DiagnosticStep {
        id: id.to_string(),
        label: label.to_string(),
        status,
        details: details.into(),
        duration_ms,
        error,
    }
}

fn aggregate_status(steps: &[DiagnosticStep]) -> DiagnosticStatus {
    if steps
        .iter()
        .any(|step| step.status == DiagnosticStatus::Fail)
    {
        DiagnosticStatus::Fail
    } else if steps
        .iter()
        .any(|step| step.status == DiagnosticStatus::Warn)
    {
        DiagnosticStatus::Warn
    } else if steps
        .iter()
        .any(|step| step.status == DiagnosticStatus::Skipped)
    {
        DiagnosticStatus::Skipped
    } else {
        DiagnosticStatus::Pass
    }
}

fn sanitize_profile_text(profile: &ResolvedProfile, text: &str) -> String {
    let mut sanitized = text.to_string();
    for secret in [
        profile.endpoint.username.as_deref(),
        profile.endpoint.password.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|value| !value.is_empty())
    {
        sanitized = sanitized.replace(secret, "[redacted]");
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_core::{ProxyEndpoint, RoutingMode};

    fn test_step(status: DiagnosticStatus) -> DiagnosticStep {
        step("id", "label", status, "details", 0, None)
    }

    fn profile() -> ResolvedProfile {
        ResolvedProfile {
            id: "profile".to_string(),
            name: "Profile".to_string(),
            endpoint: ProxyEndpoint {
                host: "proxy.example".to_string(),
                port: 1080,
                username: Some("user".to_string()),
                password: Some("secret".to_string()),
            },
            routing_mode: RoutingMode::Tun,
            proxy_dns: true,
            startup_cleanup_enabled: true,
            bypass: Vec::new(),
        }
    }

    #[test]
    fn aggregate_status_prioritizes_fail_warn_skipped_pass() {
        assert_eq!(
            aggregate_status(&[test_step(DiagnosticStatus::Pass)]),
            DiagnosticStatus::Pass
        );
        assert_eq!(
            aggregate_status(&[
                test_step(DiagnosticStatus::Pass),
                test_step(DiagnosticStatus::Skipped)
            ]),
            DiagnosticStatus::Skipped
        );
        assert_eq!(
            aggregate_status(&[
                test_step(DiagnosticStatus::Skipped),
                test_step(DiagnosticStatus::Warn)
            ]),
            DiagnosticStatus::Warn
        );
        assert_eq!(
            aggregate_status(&[
                test_step(DiagnosticStatus::Warn),
                test_step(DiagnosticStatus::Fail)
            ]),
            DiagnosticStatus::Fail
        );
    }

    #[test]
    fn sanitizes_credentials_from_errors() {
        let sanitized = sanitize_profile_text(
            &profile(),
            "failed for socks5://user:secret@proxy.example:1080",
        );
        assert!(!sanitized.contains("user"));
        assert!(!sanitized.contains("secret"));
        assert!(sanitized.contains("[redacted]"));
    }

    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn system_mode_diagnostics_use_local_auth_adapter_when_active() {
        let mut profile = profile();
        profile.routing_mode = RoutingMode::System;

        let active = effective_system_profile(&profile, true);
        assert_eq!(
            active.endpoint.host,
            proxy_core::local_socks::LOCAL_SOCKS_HOST
        );
        assert_eq!(
            active.endpoint.port,
            proxy_core::local_socks::LOCAL_SOCKS_PORT
        );

        let inactive = effective_system_profile(&profile, false);
        assert_eq!(inactive.endpoint.host, "proxy.example");
        assert_eq!(inactive.endpoint.port, 1080);
    }

    #[test]
    fn tun_chain_policy_passes_for_direct_z2_without_vpn() {
        let profile = profile();
        let step = tun_chain_policy_step_from_snapshot(
            &profile,
            &crate::types::NetworkSnapshot {
                default_route_interface: Some("Ethernet".to_string()),
                active_vpn_interface: None,
                proxy_uplink_interface: Some("Ethernet".to_string()),
                last_reason: None,
            },
            0,
        );
        assert_eq!(step.status, DiagnosticStatus::Pass);
        assert!(step.details.contains("Z2"));
    }

    #[test]
    fn tun_chain_policy_passes_when_proxy_uses_active_vpn() {
        let profile = profile();
        let step = tun_chain_policy_step_from_snapshot(
            &profile,
            &crate::types::NetworkSnapshot {
                default_route_interface: Some("Mullvad".to_string()),
                active_vpn_interface: Some("Mullvad".to_string()),
                proxy_uplink_interface: Some("Mullvad".to_string()),
                last_reason: None,
            },
            0,
        );
        assert_eq!(step.status, DiagnosticStatus::Pass);
        assert!(step.details.contains("Z3/Z4"));
    }

    #[test]
    fn tun_chain_policy_fails_when_proxy_bypasses_active_vpn() {
        let profile = profile();
        let step = tun_chain_policy_step_from_snapshot(
            &profile,
            &crate::types::NetworkSnapshot {
                default_route_interface: Some("Mullvad".to_string()),
                active_vpn_interface: Some("Mullvad".to_string()),
                proxy_uplink_interface: Some("Ethernet".to_string()),
                last_reason: None,
            },
            0,
        );
        assert_eq!(step.status, DiagnosticStatus::Fail);
        assert!(step.error.unwrap().contains("VPN is bypassed"));
    }

    #[cfg(target_os = "windows")]
    fn mullvad_status_for_test(
        state: Option<&str>,
        endpoint: Option<&str>,
        error: Option<&str>,
    ) -> proxy_platform_windows::WindowsMullvadStatus {
        proxy_platform_windows::WindowsMullvadStatus {
            cli_path: None,
            state: state.map(ToString::to_string),
            visible_location: None,
            visible_ipv4: None,
            visible_ipv6: None,
            mullvad_exit_ip: None,
            locked_down: None,
            endpoint_address: endpoint.map(ToString::to_string),
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
            error: error.map(ToString::to_string),
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn mullvad_z4_guard_passes_when_mullvad_is_connected() {
        let status = mullvad_status_for_test(Some("connected"), Some("198.51.100.74:8978"), None);
        let step = windows_mullvad_z4_guard_step_from_status(&status, 0);
        assert_eq!(step.status, DiagnosticStatus::Pass);
        assert!(step.details.contains("WFP"));
        assert!(step.details.contains("198.51.100.74:8978"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn mullvad_z4_guard_passes_when_mullvad_is_disconnected() {
        let status = mullvad_status_for_test(Some("disconnected"), None, None);
        let step = windows_mullvad_z4_guard_step_from_status(&status, 0);
        assert_eq!(step.status, DiagnosticStatus::Pass);
        assert!(step.details.contains("Z2"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn mullvad_z4_guard_warns_when_status_is_unavailable() {
        let status = mullvad_status_for_test(None, None, Some("mullvad.exe was not found."));
        let step = windows_mullvad_z4_guard_step_from_status(&status, 0);
        assert_eq!(step.status, DiagnosticStatus::Warn);
        assert!(step.error.unwrap().contains("mullvad.exe"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn firewall_wfp_preflight_warns_when_wfp_state_needs_admin() {
        let status = proxy_platform_windows::WindowsFirewallPreflight {
            elevated: false,
            firewall_profiles_count: Some(3),
            matching_firewall_rule_count: Some(0),
            wfp_state_available: false,
            wfp_state_error: Some("ERROR_ACCESS_DENIED".to_string()),
            error: None,
        };
        let step = windows_firewall_wfp_preflight_step_from_status(&status, 0);
        assert_eq!(step.status, DiagnosticStatus::Warn);
        assert!(step.details.contains("administrator rights"));
        assert!(step.details.contains("ERROR_ACCESS_DENIED"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn firewall_wfp_preflight_passes_when_wfp_state_is_readable() {
        let status = proxy_platform_windows::WindowsFirewallPreflight {
            elevated: true,
            firewall_profiles_count: Some(3),
            matching_firewall_rule_count: Some(1),
            wfp_state_available: true,
            wfp_state_error: None,
            error: None,
        };
        let step = windows_firewall_wfp_preflight_step_from_status(&status, 0);
        assert_eq!(step.status, DiagnosticStatus::Pass);
        assert!(step.details.contains("visible Mullvad/WireGuard"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn wfp_exception_plan_passes_when_not_required() {
        let plan = proxy_platform_windows::WindowsWfpExceptionPlan {
            required: false,
            ready: false,
            status: "not_required".to_string(),
            blockers: Vec::new(),
            warnings: Vec::new(),
            app_path: None,
            tun2proxy_path: None,
            mullvad_tunnel_interface: None,
            mullvad_endpoint_ip: None,
            planned_allows: Vec::new(),
            planned_cleanup: Vec::new(),
            planned_filter_identities: Vec::new(),
            session_tag: "socks5proxy-z4".to_string(),
        };
        let step = windows_wfp_exception_plan_step_from_plan(&plan, 0);
        assert_eq!(step.status, DiagnosticStatus::Pass);
        assert!(step.details.contains("no Z4 WFP exception is required"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn wfp_exception_plan_fails_when_blocked() {
        let plan = proxy_platform_windows::WindowsWfpExceptionPlan {
            required: true,
            ready: false,
            status: "blocked".to_string(),
            blockers: vec!["Administrator rights are required".to_string()],
            warnings: Vec::new(),
            app_path: None,
            tun2proxy_path: None,
            mullvad_tunnel_interface: Some("Mullvad".to_string()),
            mullvad_endpoint_ip: Some("198.51.100.74".to_string()),
            planned_allows: vec!["Allow tun2proxy".to_string()],
            planned_cleanup: vec!["Remove filters".to_string()],
            planned_filter_identities: Vec::new(),
            session_tag: "socks5proxy-z4".to_string(),
        };
        let step = windows_wfp_exception_plan_step_from_plan(&plan, 0);
        assert_eq!(step.status, DiagnosticStatus::Fail);
        assert!(step.details.contains("blocked"));
        assert!(step.error.unwrap().contains("Administrator rights"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn wfp_exception_plan_warns_when_ready_but_not_live() {
        let plan = proxy_platform_windows::WindowsWfpExceptionPlan {
            required: true,
            ready: true,
            status: "ready".to_string(),
            blockers: Vec::new(),
            warnings: Vec::new(),
            app_path: None,
            tun2proxy_path: None,
            mullvad_tunnel_interface: Some("Mullvad".to_string()),
            mullvad_endpoint_ip: Some("198.51.100.74".to_string()),
            planned_allows: vec!["Allow tun2proxy".to_string()],
            planned_cleanup: vec!["Remove filters".to_string()],
            planned_filter_identities: Vec::new(),
            session_tag: "socks5proxy-z4".to_string(),
        };
        let step = windows_wfp_exception_plan_step_from_plan(&plan, 0);
        assert_eq!(step.status, DiagnosticStatus::Warn);
        assert!(step.error.unwrap().contains("will be applied"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dns_route_policy_passes_when_dns_routes_use_tun() {
        let records = vec![WindowsDnsRouteRecord {
            ip: Some("10.64.0.1".to_string()),
            interface_alias: Some("s5pz2test".to_string()),
            destination_prefix: Some("0.0.0.0/0".to_string()),
        }];
        let step = windows_tun_dns_route_policy_step_from_records("s5pz2test", &records, 0);
        assert_eq!(step.status, DiagnosticStatus::Pass);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dns_route_policy_ignores_loopback_dns_routes() {
        let records = vec![WindowsDnsRouteRecord {
            ip: Some("127.0.0.1".to_string()),
            interface_alias: None,
            destination_prefix: None,
        }];
        let step = windows_tun_dns_route_policy_step_from_records("s5pz2test", &records, 0);
        assert_eq!(step.status, DiagnosticStatus::Pass);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dns_route_policy_fails_when_dns_routes_bypass_tun() {
        let records = vec![WindowsDnsRouteRecord {
            ip: Some("192.168.178.1".to_string()),
            interface_alias: Some("WLAN".to_string()),
            destination_prefix: Some("192.168.178.0/24".to_string()),
        }];
        let step = windows_tun_dns_route_policy_step_from_records("s5pz2test", &records, 0);
        assert_eq!(step.status, DiagnosticStatus::Fail);
        assert!(step.error.unwrap().contains("WLAN"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dns_route_policy_warns_when_no_dns_routes_are_resolved() {
        let step = windows_tun_dns_route_policy_step_from_records("s5pz2test", &[], 0);
        assert_eq!(step.status, DiagnosticStatus::Warn);
    }
}
