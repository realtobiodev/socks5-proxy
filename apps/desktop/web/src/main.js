const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const isWindows = navigator.userAgent.includes("Windows");

const manageElements = {
  root: document.querySelector("#manageView"),
  statusDot: document.querySelector("#manageStatusDot"),
  statusTitle: document.querySelector("#manageStatusTitle"),
  statusMeta: document.querySelector("#manageStatusMeta"),
  refreshBtn: document.querySelector("#manageRefreshBtn"),
  flowSummary: document.querySelector("#manageFlowSummary"),
  vpnSummary: document.querySelector("#manageVpnSummary"),
  connectBtn: document.querySelector("#manageConnectBtn"),
  disconnectBtn: document.querySelector("#manageDisconnectBtn"),
  profileList: document.querySelector("#manageProfileList"),
  form: document.querySelector("#manageForm"),
  profileId: document.querySelector("#profileId"),
  indicatorMode: document.querySelector("#indicatorMode"),
  name: document.querySelector("#name"),
  host: document.querySelector("#host"),
  port: document.querySelector("#port"),
  username: document.querySelector("#username"),
  password: document.querySelector("#password"),
  credentialPreset: document.querySelector("#credentialPreset"),
  credentialList: document.querySelector("#credentialList"),
  proxyDNS: document.querySelector("#proxyDNS"),
  tunModeNotice: document.querySelector("#tunModeNotice"),
  systemModeNotice: document.querySelector("#systemModeNotice"),
  startupCleanupEnabled: document.querySelector("#startupCleanupEnabled"),
  bypass: document.querySelector("#bypass"),
  desktopAppSelect: document.querySelector("#desktopAppSelect"),
  addDesktopAppBtn: document.querySelector("#addDesktopAppBtn"),
  manualAppLabel: document.querySelector("#manualAppLabel"),
  manualAppCommand: document.querySelector("#manualAppCommand"),
  manualAppArgs: document.querySelector("#manualAppArgs"),
  addManualAppBtn: document.querySelector("#addManualAppBtn"),
  appLauncherList: document.querySelector("#appLauncherList"),
  exitLookupEnabled: document.querySelector("#exitLookupEnabled"),
  geoLookupEnabled: document.querySelector("#geoLookupEnabled"),
  ipPrefixSegments: document.querySelector("#ipPrefixSegments"),
  refreshIntervalSecs: document.querySelector("#refreshIntervalSecs"),
  runDiagnosticsBtn: document.querySelector("#runDiagnosticsBtn"),
  diagnosticSummary: document.querySelector("#diagnosticSummary"),
  diagnosticSteps: document.querySelector("#diagnosticSteps"),
  newProfileBtn: document.querySelector("#newProfileBtn"),
  duplicateProfileBtn: document.querySelector("#duplicateProfileBtn"),
  deleteProfileBtn: document.querySelector("#deleteProfileBtn"),
  saveBtn: document.querySelector("#saveBtn"),
  testBtn: document.querySelector("#testBtn"),
  activateBtn: document.querySelector("#activateBtn"),
  message: document.querySelector("#message"),
};

const state = {
  pendingAction: null,
  config: null,
  status: null,
  selectedProfileId: null,
  desktopApps: [],
  diagnosticReport: null,
  diagnosticProgress: null,
  diagnosticsRunning: false,
};

function clone(value) {
  if (typeof structuredClone === "function") {
    return structuredClone(value);
  }
  return JSON.parse(JSON.stringify(value));
}

function generateId(prefix) {
  if (globalThis.crypto?.randomUUID) {
    return `${prefix}-${globalThis.crypto.randomUUID()}`;
  }
  return `${prefix}-${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 10)}`;
}

function namespaceLauncherError(command) {
  const trimmed = command.trim();
  if (trimmed.startsWith("/snap/bin/") || trimmed.startsWith("/var/lib/snapd/snap/bin/")) {
    return "Snap apps cannot be launched in namespace mode. Install a non-Snap package and add that binary instead.";
  }
  const name = trimmed.split("/").pop().toLowerCase();
  if (["gnome-terminal", "gnome-terminal.wrapper", "kgx", "konsole"].includes(name)) {
    return "This terminal delegates through the desktop session and will not reliably stay inside the namespace. Use diagnostics or xterm instead.";
  }
  return null;
}

function defaultProfile(name = "New Profile") {
  return {
    id: generateId("profile"),
    name,
    target: {
      kind: "structured",
      host: "",
      port: 1080,
      credentials: [],
      selected_credential_id: null,
    },
    routing_mode: "tun",
    proxy_dns: true,
    startup_cleanup_enabled: true,
    bypass: [],
    _credentialText: "",
  };
}

function normalizeLauncher(launcher) {
  return {
    id: launcher.id || generateId("app"),
    label: launcher.label || launcher.name || launcher.command || "App",
    kind: launcher.kind || "manual",
    command: launcher.command || "",
    args: Array.isArray(launcher.args) ? launcher.args : [],
    working_dir: launcher.working_dir || null,
    icon: launcher.icon || null,
    enabled: launcher.enabled !== false,
  };
}

function ensureStructuredTarget(profile) {
  if (profile.target?.kind === "raw_import") {
    const entries = profile.target.entries || [];
    const uniqueHosts = new Set(
      entries.map((e) => `${e.host.trim().toLowerCase()}:${e.port}`)
    );

    if (uniqueHosts.size > 1) {
      // Multi-target import: keep as raw_import, just fill in missing IDs/labels.
      profile.target.entries = entries.map((entry, i) => ({
        ...entry,
        id: entry.id || generateId("entry"),
        label: entry.label || `Proxy ${entry.port}`,
      }));
      profile.target.selected_entry_id ||= profile.target.entries[0]?.id || null;
      profile._credentialText ||= profile.target.entries
        .map((e) => `${e.username}:${e.password}@${e.host}:${e.port}`)
        .join("\n");
      profile.startup_cleanup_enabled ??= true;
      profile.routing_mode ||= "system";
      profile.proxy_dns ??= true;
      profile.bypass ||= [];
      return;
    }

    // Single host: convert to structured.
    profile.target = {
      kind: "structured",
      host: entries[0]?.host || "",
      port: entries[0]?.port || 1080,
      credentials: entries.map((entry, index) => ({
        id: entry.id || generateId("cred"),
        label: entry.label || `Credential ${index + 1}`,
        username: entry.username,
        password: entry.password,
      })),
      selected_credential_id: profile.target.selected_entry_id || entries[0]?.id || null,
    };
  }

  profile.target ||= {
    kind: "structured",
    host: "",
    port: 1080,
    credentials: [],
    selected_credential_id: null,
  };
  profile.target.kind = "structured";
  profile.target.credentials ||= [];
  if (!profile.target.selected_credential_id && profile.target.credentials.length) {
    profile.target.selected_credential_id = profile.target.credentials[0].id;
  }
  profile._credentialText ||= credentialsToText(profile);
  profile.startup_cleanup_enabled ??= true;
  profile.routing_mode ||= "system";
  profile.proxy_dns ??= true;
  profile.bypass ||= [];
}

function normalizeConfig(config) {
  const next = clone(config || {});
  next.enabled = Boolean(next.enabled);
  next.profiles = (next.profiles || []).map((profile) => {
    const normalized = clone(profile);
    ensureStructuredTarget(normalized);
    return normalized;
  });
  if (!next.profiles.length) {
    next.profiles = [defaultProfile("Default")];
  }
  next.selected_profile_id ||= next.active_profile_id || next.profiles[0].id;
  next.active_profile_id ||= next.profiles[0].id;
  next.tray_settings ||= {};
  next.tray_settings.display_mode ||= "flag";
  next.tray_settings.exit_ip_lookup_enabled ??= true;
  next.tray_settings.geo_lookup_enabled ??= true;
  next.tray_settings.ip_prefix_segments ||= 2;
  next.tray_settings.refresh_interval_secs ||= 300;
  next.app_launchers = (next.app_launchers || []).map(normalizeLauncher);
  return next;
}

function currentProfile() {
  return state.config?.profiles.find((profile) => profile.id === state.selectedProfileId) || null;
}

function activeProfile() {
  if (!state.config) {
    return null;
  }
  return (
    state.config.profiles.find((profile) => profile.id === state.config.active_profile_id) ||
    state.config.profiles[0] ||
    null
  );
}

function selectedCredential(profile) {
  if (profile?.target?.kind === "raw_import") {
    return (
      profile.target.entries?.find((e) => e.id === profile.target.selected_entry_id) ||
      profile.target.entries?.[0] ||
      null
    );
  }
  return (
    profile?.target.credentials.find(
      (credential) => credential.id === profile.target.selected_credential_id
    ) ||
    profile?.target.credentials[0] ||
    null
  );
}

function credentialsToText(profile) {
  if (profile?.target?.kind === "raw_import") {
    return (profile.target.entries || [])
      .map((e) => `${e.username}:${e.password}@${e.host}:${e.port}`)
      .join("\n");
  }
  const host = profile.target.host || "";
  const port = profile.target.port || 1080;
  return (profile.target.credentials || [])
    .map((credential) => `${credential.username}:${credential.password}@${host}:${port}`)
    .join("\n");
}

function setMessage(text, isError = false) {
  if (!manageElements.message) {
    return;
  }
  manageElements.message.textContent = text;
  manageElements.message.classList.toggle("error", isError);
}

async function loadStore() {
  const config = await invoke("load_config");
  state.config = normalizeConfig(config);
  state.selectedProfileId = state.config.selected_profile_id;
}

async function loadDesktopApps() {
  if (isWindows) {
    state.desktopApps = [];
    return;
  }
  try {
    state.desktopApps = await invoke("list_desktop_apps");
  } catch (_) {
    state.desktopApps = [];
  }
}

async function refreshStatus() {
  state.status = await invoke("status");
  // Sync authoritative runtime fields after tray or settings actions.
  if (state.config && state.status) {
    state.config.enabled = state.status.enabled;
    if (state.status.active_profile_id) {
      state.config.active_profile_id = state.status.active_profile_id;
    }
  }
  render();
}

function renderProfileButton(profile) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "profile manage-profile";
  if (profile.id === state.config.selected_profile_id) {
    button.classList.add("active");
  }
  button.dataset.id = profile.id;

  const content = document.createElement("div");
  content.className = "profile-content";

  const info = document.createElement("div");
  info.className = "profile-info";
  const name = document.createElement("strong");
  name.textContent = profile.name;
  const endpoint = document.createElement("span");
  if (profile.target.kind === "raw_import") {
    const first = profile.target.entries?.[0];
    const count = profile.target.entries?.length ?? 0;
    endpoint.textContent = first
      ? `${first.host}:${first.port}${count > 1 ? ` +${count - 1} more` : ""}`
      : "—";
  } else {
    endpoint.textContent = `${profile.target.host}:${profile.target.port}`;
  }
  info.append(name, endpoint);

  const badge = document.createElement("span");
  const hasError = Boolean(state.status?.last_error) && state.config.active_profile_id === profile.id;
  const isConnected =
    state.status?.connection_state === "connected" &&
    state.status?.active_profile_id === profile.id &&
    !hasError;
  const isSelected = state.config.selected_profile_id === profile.id;
  if (hasError) {
    badge.className = "profile-badge error";
    badge.textContent = "error";
  } else if (isConnected) {
    badge.className = "profile-badge connected";
    badge.textContent = "connected";
  } else if (isSelected) {
    badge.className = "profile-badge selected";
    badge.textContent = "selected";
  }

  content.append(info);
  if (badge.textContent) {
    content.append(badge);
  }
  button.append(content);
  return button;
}

function namespaceLauncherReady() {
  if (isWindows) {
    return false;
  }
  return (
    state.config?.enabled &&
    state.status?.routing_mode === "namespace" &&
    state.status?.connection_state === "connected"
  );
}

function renderDesktopAppSelect() {
  if (!manageElements.desktopAppSelect) {
    return;
  }
  manageElements.desktopAppSelect.textContent = "";
  const defaultOption = document.createElement("option");
  defaultOption.value = "";
  defaultOption.textContent = state.desktopApps.length ? "Choose installed app" : "No desktop apps found";
  manageElements.desktopAppSelect.append(defaultOption);
  state.desktopApps.forEach((app, index) => {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = app.name;
    manageElements.desktopAppSelect.append(option);
  });
}

function renderAppLaunchers() {
  if (!manageElements.appLauncherList) {
    return;
  }
  const launchReady = namespaceLauncherReady();
  manageElements.appLauncherList.textContent = "";
  const launchers = state.config.app_launchers || [];
  if (!launchers.length) {
    const empty = document.createElement("p");
    empty.className = "muted";
    empty.textContent = "No namespace apps configured.";
    manageElements.appLauncherList.append(empty);
    return;
  }

  launchers.forEach((launcher) => {
    const row = document.createElement("div");
    row.className = "app-launcher";
    row.dataset.id = launcher.id;

    const info = document.createElement("div");
    info.className = "app-launcher-info";
    const title = document.createElement("strong");
    title.textContent = launcher.label;
    const command = document.createElement("span");
    command.textContent = [launcher.command, ...(launcher.args || [])].join(" ");
    info.append(title, command);

    const actions = document.createElement("div");
    actions.className = "app-launcher-actions";
    const toggle = document.createElement("button");
    toggle.type = "button";
    toggle.className = "secondary";
    toggle.dataset.action = "toggle";
    toggle.textContent = launcher.enabled === false ? "Enable" : "Disable";
    const launch = document.createElement("button");
    launch.type = "button";
    launch.dataset.action = "launch";
    launch.textContent = "Launch";
    launch.disabled = !launchReady || launcher.enabled === false;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "secondary";
    remove.dataset.action = "remove";
    remove.textContent = "Remove";
    actions.append(toggle, launch, remove);

    row.append(info, actions);
    manageElements.appLauncherList.append(row);
  });
}

function writeManageForm(profile) {
  if (!profile) {
    return;
  }

  const credential = selectedCredential(profile);
  manageElements.profileId.value = profile.id;
  manageElements.name.value = profile.name;
  const selectedEntry = profile.target.kind === "raw_import" ? selectedCredential(profile) : null;
  manageElements.host.value = selectedEntry?.host ?? profile.target.host ?? "";
  manageElements.port.value = selectedEntry?.port ?? profile.target.port ?? 1080;
  manageElements.username.value = credential?.username || "";
  manageElements.password.value = credential?.password || "";
  manageElements.credentialList.value = profile._credentialText || credentialsToText(profile);
  manageElements.proxyDNS.checked = profile.proxy_dns !== false;
  manageElements.startupCleanupEnabled.checked = Boolean(profile.startup_cleanup_enabled);
  manageElements.bypass.value = (profile.bypass || []).join("\n");
  manageElements.indicatorMode.value = state.config.tray_settings.display_mode || "flag";
  manageElements.exitLookupEnabled.checked = Boolean(
    state.config.tray_settings.exit_ip_lookup_enabled
  );
  manageElements.geoLookupEnabled.checked = Boolean(state.config.tray_settings.geo_lookup_enabled);
  manageElements.ipPrefixSegments.value = state.config.tray_settings.ip_prefix_segments || 2;
  manageElements.refreshIntervalSecs.value =
    state.config.tray_settings.refresh_interval_secs || 300;
  manageElements.tunModeNotice.hidden = profile.routing_mode !== "tun";
  manageElements.systemModeNotice.hidden = profile.routing_mode !== "system";

  const radio = manageElements.form.querySelector(
    `input[name="routing_mode"][value="${profile.routing_mode || "system"}"]`
  );
  if (radio) {
    radio.checked = true;
  }

  manageElements.credentialPreset.textContent = "";
  const defaultOption = document.createElement("option");
  defaultOption.value = "";
  const isMultiTarget = profile.target.kind === "raw_import";
  const presetEntries = isMultiTarget
    ? profile.target.entries || []
    : profile.target.credentials || [];
  defaultOption.textContent = presetEntries.length
    ? "Use current fields or choose a preset"
    : "Use current fields";
  manageElements.credentialPreset.append(defaultOption);
  if (isMultiTarget) {
    (profile.target.entries || []).forEach((entry) => {
      const option = document.createElement("option");
      option.value = entry.id;
      option.textContent = entry.label || `Proxy ${entry.port}`;
      if (entry.id === profile.target.selected_entry_id) option.selected = true;
      manageElements.credentialPreset.append(option);
    });
  } else {
    profile.target.credentials.forEach((credential, index) => {
      const option = document.createElement("option");
      option.value = credential.id;
      option.textContent = credential.label || `Credential ${index + 1}`;
      if (credential.id === profile.target.selected_credential_id) option.selected = true;
      manageElements.credentialPreset.append(option);
    });
  }
}

// Immediate, synchronous UI feedback for connect/disconnect clicks. The backend
// start_proxy/stop_proxy calls take a moment to return, so flip the status strip to a
// pending state right away instead of waiting for the next status poll. The next
// renderManage() (after refreshStatus) overwrites this with the real state.
function setPendingUi(title) {
  state.pendingAction = title;
  if (!manageElements.root) {
    return;
  }
  manageElements.statusDot.className = "status-dot pending";
  manageElements.statusTitle.textContent = title;
  manageElements.statusMeta.textContent = "";
  manageElements.connectBtn.disabled = true;
  manageElements.disconnectBtn.disabled = true;
}

function renderManage() {
  if (!manageElements.root) {
    return;
  }

  manageElements.profileList.textContent = "";
  state.config.profiles.forEach((profile) => {
    manageElements.profileList.append(renderProfileButton(profile));
  });

  const enabled = state.config.enabled;
  // Drive the status display from the real runtime connection_state (synced from the
  // daemon for TUN mode), NOT config.enabled — otherwise an external daemon stop or
  // crash leaves the UI frozen on a stale "Connected"/"Reconnect".
  const cs = state.status?.connection_state;
  const exit = state.status?.exit_status ?? {};
  const exitIp = exit.exit_ip ?? "";
  const exitFlag = exit.country_flag ?? "";
  const exitCode = exit.country_code ?? "";
  const lookupError = exit.lookup_error ?? "";

  let stateKey;
  let stateTitle;
  switch (cs) {
    case "connected":
      // The runtime reports the chain is up. Normally we wait for the exit IP to
      // confirm egress, but if the exit lookup itself errored we must NOT stay on
      // "Connecting…" forever — the connection is established, only the IP/geo probe
      // failed. Show "Connected" in that case (meta carries the lookup note).
      if (exitIp || lookupError) {
        stateKey = "connected";
        stateTitle = "Connected";
      } else {
        stateKey = "pending";
        stateTitle = "Connecting…";
      }
      break;
    case "rebinding":
      stateKey = "pending";
      stateTitle = "Connecting…";
      break;
    case "blocked":
      stateKey = "pending";
      stateTitle = "Blocked";
      break;
    case "error":
      stateKey = "error";
      stateTitle = "Error";
      break;
    case "stopped":
      stateKey = "disconnected";
      stateTitle = "Disconnected";
      break;
    default:
      // No status fetched yet — fall back to the configured intent.
      stateKey = enabled ? "pending" : "disconnected";
      stateTitle = enabled ? "Connecting…" : "Disconnected";
  }
  const connected = stateKey === "connected";
  const disconnected = stateKey === "disconnected";

  // Title: status word + active profile name in parentheses, e.g.
  // "Connected (Default)". Only append the name while there is an active session.
  const activeName = state.status?.active_profile_name;
  manageElements.statusDot.className =
    "status-dot " + (disconnected ? "" : stateKey);
  manageElements.statusTitle.textContent =
    activeName && !disconnected ? `${stateTitle} (${activeName})` : stateTitle;

  // Status-line meta: " • 🇫🇷 FR • 203.0.113.45" when connected; the error reason
  // when errored; empty otherwise. The country flag is rendered as an <img> (not the
  // emoji), because Windows fonts have no flag glyphs — see flags/<cc>.png assets.
  const meta = manageElements.statusMeta;
  meta.textContent = "";
  if (stateKey === "error") {
    if (state.status?.last_error) meta.textContent = ` • ${state.status.last_error}`;
  } else if (connected) {
    const ccLower = exitCode ? exitCode.toLowerCase() : "";
    if (exitCode || exitIp) meta.append(" • ");
    // Windows fonts have no flag-emoji glyphs, so there we render a PNG image.
    // Other platforms render the flag emoji natively, so keep using it.
    if (isWindows && ccLower) {
      const img = document.createElement("img");
      img.className = "flag-img";
      img.src = `flags/${ccLower}.png`;
      img.alt = exitCode;
      // Missing asset (rare country) → drop the image, keep the text code.
      img.addEventListener("error", () => img.remove());
      meta.append(img);
    } else if (!isWindows && exitFlag) {
      meta.append(`${exitFlag} `);
    }
    if (exitCode) meta.append(exitCode);
    if (exitIp) {
      if (exitCode) meta.append(" • ");
      meta.append(exitIp);
    }
    if (lookupError) meta.append(" · Geo lookup failed");
  }

  manageElements.refreshBtn.disabled = !connected;

  // Flow tooltip: only show a traffic path when there is an active session. While
  // disconnected the flow is unknown, so show just "Disconnected" instead of a stale
  // or default path.
  if (disconnected) {
    manageElements.flowSummary.textContent = "Disconnected";
    manageElements.vpnSummary.textContent = "";
  } else {
    manageElements.flowSummary.textContent =
      state.status?.traffic_flow?.nodes?.join(" → ") || "Apps → WAN";
    manageElements.vpnSummary.textContent = state.status?.vpn_status?.last_reason || "";
  }

  manageElements.connectBtn.textContent = disconnected ? "Connect" : "Reconnect";
  // Disable the primary button while a connection is in progress, and the disconnect
  // button when there is nothing to tear down. (Re)enabling here also clears the
  // optimistic state set synchronously on click by setPendingUi().
  manageElements.connectBtn.disabled = stateKey === "pending";
  manageElements.disconnectBtn.disabled = disconnected;
  if (state.pendingAction) {
    manageElements.statusDot.className = "status-dot pending";
    manageElements.statusTitle.textContent = state.pendingAction;
    manageElements.statusMeta.textContent = "";
    manageElements.connectBtn.disabled = true;
    manageElements.disconnectBtn.disabled = true;
  }
  renderDesktopAppSelect();
  renderAppLaunchers();
  renderDiagnostics();
  // Skip overwriting form fields while the user is actively editing them.
  if (!manageElements.form?.contains(document.activeElement)) {
    writeManageForm(currentProfile() || active || state.config.profiles[0]);
  }
}

function diagnosticStatusLabel(status) {
  switch (status) {
    case "pass":
      return "Pass";
    case "warn":
      return "Warning";
    case "fail":
      return "Fail";
    case "skipped":
      return "Skipped";
    default:
      return "Unknown";
  }
}

function diagnosticProgressBadge(step) {
  if (step.result?.status) {
    return diagnosticStatusLabel(step.result.status);
  }
  if (step.phase === "running") {
    return "Running";
  }
  return "Queued";
}

function applyDiagnosticProgress(event) {
  if (!event?.phase) {
    return;
  }

  if (event.phase === "started") {
    state.diagnosticProgress = {
      runId: event.run_id,
      profileName: event.profile_name || "No profile",
      routingMode: event.routing_mode || "unknown",
      completedSteps: event.completed_steps || 0,
      totalSteps: event.total_steps || 0,
      currentStepId: null,
      currentStepLabel: null,
      error: null,
      steps: (event.steps || []).map((step) => ({
        id: step.id,
        label: step.label,
        phase: "pending",
        result: null,
      })),
    };
    state.diagnosticReport = null;
    state.diagnosticsRunning = true;
    renderDiagnostics();
    return;
  }

  if (!state.diagnosticProgress || state.diagnosticProgress.runId !== event.run_id) {
    return;
  }

  state.diagnosticProgress.completedSteps = event.completed_steps ?? state.diagnosticProgress.completedSteps;
  state.diagnosticProgress.totalSteps = event.total_steps ?? state.diagnosticProgress.totalSteps;

  if (event.phase === "step_started") {
    state.diagnosticProgress.currentStepId = event.current_step_id || null;
    state.diagnosticProgress.currentStepLabel = event.current_step_label || null;
    state.diagnosticProgress.steps.forEach((step) => {
      if (step.result) {
        step.phase = "done";
      } else if (step.id === event.current_step_id) {
        step.phase = "running";
      } else if (step.phase !== "done") {
        step.phase = "pending";
      }
    });
  } else if (event.phase === "step_finished" && event.step) {
    const existing = state.diagnosticProgress.steps.find((step) => step.id === event.step.id);
    if (existing) {
      existing.phase = "done";
      existing.result = event.step;
    }
    if (state.diagnosticProgress.currentStepId === event.step.id) {
      state.diagnosticProgress.currentStepId = null;
      state.diagnosticProgress.currentStepLabel = null;
    }
  } else if (event.phase === "finished" && event.report) {
    state.diagnosticReport = event.report;
    state.diagnosticProgress = null;
    state.diagnosticsRunning = false;
  } else if (event.phase === "failed") {
    state.diagnosticProgress.error = event.error || "Diagnostics failed.";
    state.diagnosticsRunning = false;
  }

  renderDiagnostics();
}

function renderDiagnostics() {
  if (!manageElements.diagnosticSummary || !manageElements.diagnosticSteps) {
    return;
  }
  manageElements.runDiagnosticsBtn.disabled = state.diagnosticsRunning;
  manageElements.diagnosticSteps.textContent = "";
  manageElements.runDiagnosticsBtn.textContent = state.diagnosticsRunning
    ? "Checking..."
    : "Run diagnostics";

  if (state.diagnosticsRunning && state.diagnosticProgress) {
    const progress = state.diagnosticProgress;
    const currentText = progress.currentStepLabel
      ? ` · Current: ${progress.currentStepLabel}`
      : "";
    manageElements.diagnosticSummary.textContent =
      `Running ${progress.completedSteps}/${progress.totalSteps} · ${progress.profileName} · ${progress.routingMode}${currentText}`;

    for (const step of progress.steps) {
      const row = document.createElement("article");
      const phaseClass =
        step.phase === "running"
          ? "diagnostic-running"
          : step.phase === "pending"
            ? "diagnostic-pending"
            : `diagnostic-${step.result?.status || "unknown"}`;
      row.className = `diagnostic-step ${phaseClass}`;

      const head = document.createElement("div");
      head.className = "diagnostic-step-head";

      const badge = document.createElement("span");
      badge.className = "diagnostic-badge";
      badge.textContent = diagnosticProgressBadge(step);

      const title = document.createElement("strong");
      title.textContent = step.label || step.id || "Diagnostic step";

      const duration = document.createElement("small");
      duration.textContent = step.result ? `${step.result.duration_ms ?? 0} ms` : "…";
      head.append(badge, title, duration);
      row.append(head);

      const details = document.createElement("p");
      details.textContent =
        step.result?.details ||
        (step.phase === "running" ? "Check is running right now." : "Waiting to be checked.");
      row.append(details);

      if (step.result?.error) {
        const error = document.createElement("pre");
        error.textContent = step.result.error;
        row.append(error);
      }

      manageElements.diagnosticSteps.append(row);
    }
    return;
  }

  if (state.diagnosticsRunning) {
    manageElements.diagnosticSummary.textContent = "Diagnostics starting...";
    return;
  }

  const report = state.diagnosticReport;
  if (!report) {
    manageElements.diagnosticSummary.textContent = "No diagnostic run yet.";
    return;
  }

  const generated = report.generated_unix
    ? new Date(report.generated_unix * 1000).toLocaleString()
    : "unknown time";
  manageElements.diagnosticSummary.textContent =
    `${diagnosticStatusLabel(report.overall_status)} · ${report.profile_name || "No profile"} · ${report.routing_mode} · ${generated}`;

  for (const step of report.steps || []) {
    const row = document.createElement("article");
    row.className = `diagnostic-step diagnostic-${step.status || "unknown"}`;

    const head = document.createElement("div");
    head.className = "diagnostic-step-head";

    const badge = document.createElement("span");
    badge.className = "diagnostic-badge";
    badge.textContent = diagnosticStatusLabel(step.status);

    const title = document.createElement("strong");
    title.textContent = step.label || step.id || "Diagnostic step";

    const duration = document.createElement("small");
    duration.textContent = `${step.duration_ms ?? 0} ms`;

    head.append(badge, title, duration);

    const details = document.createElement("p");
    details.textContent = step.details || "";
    row.append(head, details);

    if (step.error) {
      const error = document.createElement("pre");
      error.textContent = step.error;
      row.append(error);
    }
    manageElements.diagnosticSteps.append(row);
  }
}

async function bindDiagnosticEvents() {
  if (typeof listen !== "function") {
    return;
  }
  await listen("diagnostics-progress", (event) => {
    applyDiagnosticProgress(event.payload);
  });
}

function render() {
  if (!state.config) {
    return;
  }
  renderManage();
}

async function parseCredentialText(text) {
  const trimmed = text.trim();
  if (!trimmed) {
    return [];
  }
  const preview = await invoke("preview_raw_entries", { text: trimmed });
  return preview.entries;
}

function splitCommandArgs(input) {
  const args = [];
  let current = "";
  let quote = null;
  for (let index = 0; index < input.length; index += 1) {
    const ch = input[index];
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else if (ch === "\\" && index + 1 < input.length) {
        index += 1;
        current += input[index];
      } else {
        current += ch;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "\\" && index + 1 < input.length) {
      index += 1;
      current += input[index];
    } else if (/\s/.test(ch)) {
      if (current) {
        args.push(current);
        current = "";
      }
    } else {
      current += ch;
    }
  }
  if (current) {
    args.push(current);
  }
  return args;
}

async function saveLaunchers(message) {
  state.config = normalizeConfig(state.config);
  await invoke("save_config", { config: state.config });
  setMessage(message);
  render();
}

async function syncFormToState() {
  if (!state.config) {
    return;
  }

  const profile = currentProfile();
  if (!profile) {
    return;
  }

  profile.name = manageElements.name.value.trim() || profile.name || "Untitled Profile";
  profile.routing_mode =
    manageElements.form.querySelector('input[name="routing_mode"]:checked')?.value || "system";
  profile.proxy_dns = manageElements.proxyDNS.checked;
  profile.startup_cleanup_enabled = manageElements.startupCleanupEnabled.checked;
  profile.bypass = manageElements.bypass.value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  state.config.tray_settings.display_mode = manageElements.indicatorMode.value;
  state.config.tray_settings.exit_ip_lookup_enabled = manageElements.exitLookupEnabled.checked;
  state.config.tray_settings.geo_lookup_enabled = manageElements.geoLookupEnabled.checked;
  state.config.tray_settings.ip_prefix_segments = Number(manageElements.ipPrefixSegments.value) || 2;
  state.config.tray_settings.refresh_interval_secs =
    Number(manageElements.refreshIntervalSecs.value) || 300;

  const imported = await parseCredentialText(manageElements.credentialList.value);
  const manualHost = manageElements.host.value.trim();
  const manualPort = Number(manageElements.port.value) || 1080;
  const uniqueTargets = Array.from(
    new Set(imported.map((entry) => `${entry.host.trim().toLowerCase()}:${entry.port}`))
  );
  // Multi-target import: different host:port per line → save as raw_import.
  if (uniqueTargets.length > 1) {
    const currentSelectedId = manageElements.credentialPreset.value || null;
    const currentText = manageElements.credentialList.value;

    // Text unchanged: only update the selected entry — don't re-parse so that
    // existing entry IDs are preserved and the dropdown selection sticks.
    if (profile.target.kind === "raw_import" && profile._credentialText === currentText) {
      if (currentSelectedId && profile.target.entries?.some((e) => e.id === currentSelectedId)) {
        profile.target.selected_entry_id = currentSelectedId;
      }
      state.config.selected_profile_id = profile.id;
      return;
    }

    // Text changed: re-parse. Try to keep IDs stable by matching on host:port
    // so that a previously chosen selection survives minor credential edits.
    const existingEntries = profile.target.kind === "raw_import" ? (profile.target.entries || []) : [];
    const entries = imported.map((entry) => {
      const existing = existingEntries.find((e) => e.host === entry.host && e.port === entry.port);
      return {
        id: existing?.id || entry.id || generateId("entry"),
        label: existing?.label || `Proxy ${entry.port}`,
        username: entry.username,
        password: entry.password,
        host: entry.host,
        port: entry.port,
      };
    });
    profile.target = {
      kind: "raw_import",
      entries,
      selected_entry_id:
        currentSelectedId && entries.some((e) => e.id === currentSelectedId)
          ? currentSelectedId
          : entries[0]?.id || null,
    };
    profile._credentialText = currentText;
    state.config.selected_profile_id = profile.id;
    return;
  }

  const host = manualHost || imported[0]?.host || "";
  const port = manualHost ? manualPort : imported[0]?.port || manualPort;

  if (!host) {
    throw new Error("Please enter a proxy host or import at least one credential line.");
  }

  const credentials = imported.map((entry, index) => ({
    id: entry.id || generateId("cred"),
    label: entry.label || `Credential ${index + 1}`,
    username: entry.username,
    password: entry.password,
  }));

  const manualUsername = manageElements.username.value;
  const manualPassword = manageElements.password.value;
  if (manualUsername && manualPassword) {
    const existing = credentials.find(
      (credential) =>
        credential.username === manualUsername && credential.password === manualPassword
    );
    if (!existing) {
      credentials.push({
        id: generateId("cred"),
        label: `Credential ${credentials.length + 1}`,
        username: manualUsername,
        password: manualPassword,
      });
    }
  }

  profile.target = {
    kind: "structured",
    host,
    port,
    credentials,
    selected_credential_id:
      credentials.find(
        (credential) =>
          credential.username === manualUsername && credential.password === manualPassword
      )?.id ||
      manageElements.credentialPreset.value ||
      credentials[0]?.id ||
      null,
  };
  profile._credentialText =
    imported.length > 0
      ? imported.map((entry) => `${entry.username}:${entry.password}@${entry.host}:${entry.port}`).join("\n")
      : credentialsToText(profile);
  state.config.selected_profile_id = profile.id;
}

async function saveConfigOnly(message = "Saved.") {
  await syncFormToState();
  state.config = normalizeConfig(state.config);
  const path = await invoke("save_config", { config: state.config });
  setMessage(`${message} ${path}`);
  // Refresh the form unconditionally after save so dropdowns (e.g. credential
  // preset for raw_import profiles) reflect the just-saved state even while a
  // form element still has focus.
  writeManageForm(currentProfile() || activeProfile() || state.config.profiles[0]);
}

async function connectSelectedProfile() {
  await syncFormToState();
  state.config = normalizeConfig(state.config);
  const profileId = state.config.selected_profile_id || state.selectedProfileId;
  await invoke("start_proxy", { config: state.config, profileId });
  state.config.enabled = true;
  state.config.active_profile_id = profileId;
  await refreshStatus();
}

async function disconnectProfile() {
  await invoke("stop_proxy");
  state.config.enabled = false;
  await refreshStatus();
}

async function selectProfile(profileId) {
  try {
    await syncFormToState();
  } catch (_) {
    // Incomplete form (e.g. no host yet) — discard and proceed with switch.
  }
  state.selectedProfileId = profileId;
  state.config.selected_profile_id = profileId;
  await invoke("save_config", { config: state.config });

  if (state.config.enabled && state.config.active_profile_id !== profileId) {
    await invoke("start_proxy", { config: state.config, profileId: profileId });
    state.config.active_profile_id = profileId;
  }

  await refreshStatus();
}

function bindManageEvents() {
  manageElements.profileList?.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-id]");
    if (!button) {
      return;
    }
    try {
      await selectProfile(button.dataset.id);
    } catch (error) {
      setMessage(String(error), true);
    }
  });

  manageElements.credentialPreset?.addEventListener("change", () => {
    const profile = currentProfile();
    if (!profile) return;

    if (profile.target.kind === "raw_import") {
      const entry = profile.target.entries?.find(
        (e) => e.id === manageElements.credentialPreset.value
      );
      if (!entry) return;
      profile.target.selected_entry_id = entry.id;
      manageElements.username.value = entry.username;
      manageElements.password.value = entry.password;
      manageElements.host.value = entry.host;
      manageElements.port.value = entry.port;
      return;
    }

    const credential = profile.target.credentials.find(
      (entry) => entry.id === manageElements.credentialPreset.value
    );
    if (!credential) return;
    manageElements.username.value = credential.username;
    manageElements.password.value = credential.password;
    manageElements.host.value = profile.target.host || "";
    manageElements.port.value = profile.target.port || 1080;
  });

  manageElements.form?.addEventListener("change", (event) => {
    if (event.target.matches('input[name="routing_mode"]')) {
      manageElements.tunModeNotice.hidden = event.target.value !== "tun";
      manageElements.systemModeNotice.hidden = event.target.value !== "system";
    }
  });

  manageElements.form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      await saveConfigOnly("Saved.");
      await refreshStatus();
    } catch (error) {
      setMessage(String(error), true);
    }
  });

  manageElements.testBtn?.addEventListener("click", async () => {
    try {
      await syncFormToState();
      await invoke("test_proxy", {
        config: state.config,
        profileId: state.config.selected_profile_id,
      });
      setMessage("SOCKS5 handshake succeeded.");
    } catch (error) {
      setMessage(String(error), true);
    }
  });

  manageElements.activateBtn?.addEventListener("click", async () => {
    try {
      await connectSelectedProfile();
      setMessage("Connecting in background. Status will update automatically.");
    } catch (error) {
      setMessage(String(error), true);
    }
  });

  manageElements.connectBtn?.addEventListener("click", async () => {
    setPendingUi("Connecting…");
    try {
      await connectSelectedProfile();
      state.pendingAction = null;
      renderManage();
      setMessage("Connecting in background. Status will update automatically.");
    } catch (error) {
      state.pendingAction = null;
      setMessage(String(error), true);
      await refreshStatus().catch(() => {}); // restore real state after a failed start
    }
  });

  manageElements.disconnectBtn?.addEventListener("click", async () => {
    setPendingUi("Disconnecting…");
    try {
      await disconnectProfile();
      state.pendingAction = null;
      renderManage();
      setMessage("Proxy disconnected.");
    } catch (error) {
      state.pendingAction = null;
      setMessage(String(error), true);
      await refreshStatus().catch(() => {}); // restore real state after a failed stop
    }
  });

  manageElements.refreshBtn?.addEventListener("click", async () => {
    try {
      await invoke("refresh_exit_status", { config: state.config });
      await refreshStatus();
      setMessage("Exit IP refreshed.");
    } catch (error) {
      setMessage(String(error), true);
    }
  });

  manageElements.runDiagnosticsBtn?.addEventListener("click", async () => {
    try {
      await syncFormToState();
      state.config = normalizeConfig(state.config);
      state.diagnosticsRunning = true;
      state.diagnosticProgress = null;
      state.diagnosticReport = null;
      renderDiagnostics();
      state.diagnosticReport = await invoke("run_diagnostics", { config: state.config });
      state.diagnosticsRunning = false;
      state.diagnosticProgress = null;
      await refreshStatus();
      setMessage("Diagnostics completed.");
    } catch (error) {
      state.diagnosticsRunning = false;
      state.diagnosticProgress = null;
      setMessage(String(error), true);
      renderDiagnostics();
    }
  });

  manageElements.addDesktopAppBtn?.addEventListener("click", async () => {
    try {
      const selected = state.desktopApps[Number(manageElements.desktopAppSelect.value)];
      if (!selected) {
        throw new Error("Choose an installed app first.");
      }
      state.config.app_launchers ||= [];
      if (state.config.app_launchers.some((launcher) => launcher.command === selected.command)) {
        throw new Error("This app is already configured.");
      }
      const launcherError = namespaceLauncherError(selected.command);
      if (launcherError) {
        throw new Error(launcherError);
      }
      state.config.app_launchers.push(
        normalizeLauncher({
          id: generateId("app"),
          label: selected.name,
          kind: "desktop",
          command: selected.command,
          args: selected.args || [],
          icon: selected.icon || null,
          enabled: true,
        })
      );
      await saveLaunchers("App launcher added.");
    } catch (error) {
      setMessage(String(error), true);
    }
  });

  manageElements.addManualAppBtn?.addEventListener("click", async () => {
    try {
      const command = manageElements.manualAppCommand.value.trim();
      if (!command) {
        throw new Error("Manual app command is required.");
      }
      const launcherError = namespaceLauncherError(command);
      if (launcherError) {
        throw new Error(launcherError);
      }
      const label = manageElements.manualAppLabel.value.trim() || command;
      state.config.app_launchers ||= [];
      state.config.app_launchers.push(
        normalizeLauncher({
          id: generateId("app"),
          label,
          kind: "manual",
          command,
          args: splitCommandArgs(manageElements.manualAppArgs.value),
          enabled: true,
        })
      );
      manageElements.manualAppLabel.value = "";
      manageElements.manualAppCommand.value = "";
      manageElements.manualAppArgs.value = "";
      await saveLaunchers("Manual app launcher added.");
    } catch (error) {
      setMessage(String(error), true);
    }
  });

  manageElements.appLauncherList?.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    const row = event.target.closest(".app-launcher[data-id]");
    if (!button || !row) {
      return;
    }
    const launcher = state.config.app_launchers.find((item) => item.id === row.dataset.id);
    if (!launcher) {
      return;
    }
    try {
      if (button.dataset.action === "remove") {
        state.config.app_launchers = state.config.app_launchers.filter(
          (item) => item.id !== launcher.id
        );
        await saveLaunchers("App launcher removed.");
      } else if (button.dataset.action === "toggle") {
        launcher.enabled = launcher.enabled === false;
        await saveLaunchers(launcher.enabled ? "App launcher enabled." : "App launcher disabled.");
      } else if (button.dataset.action === "launch") {
        await invoke("launch_namespace_app", { launcher });
        await refreshStatus();
        setMessage(`Launched ${launcher.label}.`);
      }
    } catch (error) {
      setMessage(String(error), true);
    }
  });

  manageElements.newProfileBtn?.addEventListener("click", () => {
    const profile = defaultProfile(`Profile ${state.config.profiles.length + 1}`);
    state.config.profiles.push(profile);
    state.config.selected_profile_id = profile.id;
    state.selectedProfileId = profile.id;
    render();
  });

  manageElements.duplicateProfileBtn?.addEventListener("click", async () => {
    await syncFormToState();
    const profile = currentProfile();
    if (!profile) {
      return;
    }
    const copy = clone(profile);
    copy.id = generateId("profile");
    copy.name = `${profile.name} Copy`;
    copy.target.credentials = copy.target.credentials.map((credential) => ({
      ...credential,
      id: generateId("cred"),
    }));
    copy.target.selected_credential_id = copy.target.credentials[0]?.id || null;
    state.config.profiles.push(copy);
    state.config.selected_profile_id = copy.id;
    state.selectedProfileId = copy.id;
    render();
  });

  manageElements.deleteProfileBtn?.addEventListener("click", async () => {
    if (state.config.profiles.length <= 1) {
      setMessage("At least one profile must remain.", true);
      return;
    }
    const index = state.config.profiles.findIndex((profile) => profile.id === state.selectedProfileId);
    if (index === -1) {
      return;
    }
    const [removed] = state.config.profiles.splice(index, 1);
    if (state.config.active_profile_id === removed.id) {
      state.config.active_profile_id = state.config.profiles[0].id;
    }
    state.config.selected_profile_id = state.config.profiles[Math.max(0, index - 1)]?.id || state.config.profiles[0].id;
    state.selectedProfileId = state.config.selected_profile_id;
    render();
  });
}

async function init() {
  await bindDiagnosticEvents();
  await loadStore();
  await loadDesktopApps();
  state.selectedProfileId = state.config.selected_profile_id;
  await refreshStatus();
  render();
  bindManageEvents();
  // Adaptive status polling: once connected the chain is stable, so poll slowly
  // (10s) to minimize the background route/VPN status checks; while connecting or
  // disconnected, poll faster (4s) so state transitions show up promptly.
  const POLL_CONNECTED_MS = 10000;
  const POLL_ACTIVE_MS = 4000;
  const scheduleNextPoll = () => {
    const delay =
      state.status?.connection_state === "connected"
        ? POLL_CONNECTED_MS
        : POLL_ACTIVE_MS;
    window.setTimeout(async () => {
      await refreshStatus().catch(() => {});
      scheduleNextPoll();
    }, delay);
  };
  scheduleNextPoll();
}

init().catch((error) => {
  if (manageElements.message) {
    setMessage(String(error), true);
  }
});
