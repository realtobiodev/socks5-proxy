#!/usr/bin/env bash
# Install dependencies for socks5proxy on Debian/Ubuntu.
#
# By default this installs only the *runtime* dependencies needed to run the
# GUI + daemon (the prebuilt tun2proxy-bin, polkit policy, privileged helpers,
# GTK/WebKit runtime libraries). The runtime install needs no Rust toolchain
# unless the prebuilt tun2proxy download fails and it has to build from source.
# Pass --with-build-deps (or the argument `all`) to additionally install
# everything required to *compile* the project (the -dev libraries, the Rust
# toolchain, and tauri-cli).
#
# The socks5proxyd daemon itself is no longer built or installed here — it is
# shipped inside the .deb produced by scripts/build-desktop-linux.sh, which also
# (re)starts it on install.
#
# Safe to re-run — already-installed steps are skipped.
set -euo pipefail

# ── helpers ──────────────────────────────────────────────────────────────────

has() { command -v "$1" >/dev/null 2>&1; }

step() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }

ok() { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: scripts/install-deps-linux.sh [--with-build-deps]

  (no args)           Install runtime dependencies for the GUI + daemon.
  --with-build-deps   Also install build dependencies (-dev libs, Rust, tauri-cli).
  all                 Alias for --with-build-deps.
  -h, --help          Show this help.
EOF
}

# ── argument parsing ──────────────────────────────────────────────────────────

WITH_BUILD_DEPS=0
case "${1:-}" in
  '') ;;
  --with-build-deps|all) WITH_BUILD_DEPS=1 ;;
  -h|--help) usage; exit 0 ;;
  *)
    printf 'Unknown argument: %s\n\n' "$1" >&2
    usage >&2
    exit 1
    ;;
esac

ensure_packages() {
  local missing=()
  local pkg
  for pkg in "$@"; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'install ok installed'; then
      missing+=("$pkg")
    fi
  done
  if [[ ${#missing[@]} -eq 0 ]]; then
    ok 'All packages already installed'
  else
    printf '    Installing: %s\n' "${missing[*]}"
    sudo apt-get install -y "${missing[@]}"
    ok 'Packages installed'
  fi
}

ensure_cargo() {
  if has cargo; then
    ok "cargo already available ($(cargo --version))"
  else
    printf '    cargo not found — installing via rustup\n'
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    ok "Rust installed ($(cargo --version))"
    printf '    \033[33mNote:\033[0m run \`source "$HOME/.cargo/env"\` or restart your shell\n'
    printf '         to make cargo available in future sessions.\n'
  fi
}

# ── preflight ────────────────────────────────────────────────────────────────

if ! has apt-get; then
  printf 'This script requires apt-get (Debian/Ubuntu). Aborting.\n' >&2
  exit 1
fi

# ── build dependencies (opt-in) ───────────────────────────────────────────────

if [[ "$WITH_BUILD_DEPS" -eq 1 ]]; then
  step 'Installing build dependencies (GTK/WebKit -dev + pkg-config)'
  ensure_packages \
    pkg-config \
    libglib2.0-dev \
    libgtk-3-dev \
    libwebkit2gtk-4.1-dev \
    libjavascriptcoregtk-4.1-dev \
    libsoup-3.0-dev \
    libayatana-appindicator3-dev

  step 'Checking Rust toolchain'
  ensure_cargo

  step 'Checking tauri-cli (required for bundle/install modes)'
  # Any tauri-cli 2.x works with the 2.x tauri crate; install the latest 2.x.
  TAURI_VERSION='2'
  if cargo tauri --version 2>/dev/null | grep -q "^tauri-cli 2"; then
    ok "tauri-cli $(cargo tauri --version 2>/dev/null) already installed"
  else
    printf '    Installing latest tauri-cli 2.x (compiles from source, this takes a few minutes)...\n'
    cargo install tauri-cli --version "^$TAURI_VERSION" --locked
    ok "tauri-cli installed ($(cargo tauri --version 2>/dev/null))"
  fi
fi

# ── runtime: system libraries ──────────────────────────────────────────────────
#
# Runtime shared libraries for the GUI. When the app is installed via the .deb,
# dpkg pulls these in automatically through the package's Depends; they are kept
# here so the raw `socks5proxy-desktop` binary also runs.

step 'Installing runtime libraries (GTK/WebKit)'
ensure_packages \
  libgtk-3-0 \
  libwebkit2gtk-4.1-0 \
  libjavascriptcoregtk-4.1-0 \
  libsoup-3.0-0 \
  libayatana-appindicator3-1

# ── runtime: tun2proxy ─────────────────────────────────────────────────────────
#
# Prefer the prebuilt release binary (no Rust needed); fall back to building from
# source with cargo if the download fails or no release matches this arch.

step 'Checking tun2proxy (required for TUN routing mode)'

TBIN='/usr/local/bin/tun2proxy-bin'
TUN2PROXY_FALLBACK_TAG='v0.8.2'  # pinned tag used if the latest cannot be resolved

# Download the prebuilt tun2proxy-bin from GitHub releases. Returns 1 on any
# failure so the caller can fall back to a source build.
install_tun2proxy_prebuilt() {
  local arch triple
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) triple='x86_64-unknown-linux-gnu' ;;
    aarch64|arm64) triple='aarch64-unknown-linux-gnu' ;;
    *) printf '    No prebuilt tun2proxy for arch %s.\n' "$arch" >&2; return 1 ;;
  esac

  ensure_packages curl unzip

  local tag url tmp
  # Resolve the latest tag via the releases/latest redirect (no API rate limit).
  tag="$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    https://github.com/tun2proxy/tun2proxy/releases/latest 2>/dev/null || true)"
  tag="${tag##*/}"
  [[ "$tag" == v* ]] || tag="$TUN2PROXY_FALLBACK_TAG"
  url="https://github.com/tun2proxy/tun2proxy/releases/download/$tag/tun2proxy-$triple.zip"

  tmp="$(mktemp -d)"
  if curl -fsSL -o "$tmp/t.zip" "$url" \
     && unzip -o -q "$tmp/t.zip" -d "$tmp" \
     && [[ -f "$tmp/tun2proxy-bin" ]]; then
    sudo rm -f "$TBIN"
    sudo install -m 0755 "$tmp/tun2proxy-bin" "$TBIN"
    rm -rf "$tmp"
    ok "tun2proxy-bin $tag installed from prebuilt release ($triple)"
    return 0
  fi
  rm -rf "$tmp"
  printf '    Prebuilt download failed (%s).\n' "$url" >&2
  return 1
}

# Build tun2proxy-bin from source with cargo and install it.
install_tun2proxy_from_source() {
  ensure_cargo
  if ! has tun2proxy-bin; then
    printf '    Building tun2proxy from source (this takes a few minutes)...\n'
    cargo install tun2proxy --bin tun2proxy-bin --locked
  fi
  # Copy the real binary (not a symlink) so setcap works.
  local cargo_bin="$HOME/.cargo/bin/tun2proxy-bin"
  if [[ -f "$cargo_bin" ]]; then
    if [[ -L "$TBIN" ]] || [[ ! -f "$TBIN" ]] || ! diff -q "$cargo_bin" "$TBIN" >/dev/null 2>&1; then
      sudo rm -f "$TBIN"
      sudo install -m 0755 "$cargo_bin" "$TBIN"
    fi
  fi
  ok "tun2proxy-bin installed from source"
}

if has tun2proxy-bin || [[ -x "$TBIN" ]]; then
  ok "tun2proxy-bin already installed ($TBIN)"
elif install_tun2proxy_prebuilt; then
  :
else
  printf '    Falling back to building tun2proxy from source.\n'
  install_tun2proxy_from_source
fi

# ── runtime: tun2proxy capabilities (preferred) + sudoers fallback ─────────────

step 'Granting tun2proxy-bin network privileges'

# File capabilities are still useful for low-level networking operations, but
# current Linux tun2proxy builds may still need full root privileges later in
# setup. The desktop app therefore prefers pkexec/sudo at runtime.
if has setcap && has getcap; then
  CURRENT_CAPS="$(getcap "$TBIN" 2>/dev/null || true)"
  WANT_CAPS="cap_net_admin,cap_net_raw=eip"
  if printf '%s' "$CURRENT_CAPS" | grep -q "cap_net_admin"; then
    ok "file capabilities already set ($CURRENT_CAPS)"
  else
    sudo setcap "$WANT_CAPS" "$TBIN"
    ok "file capabilities set on $TBIN (cap_net_admin,cap_net_raw)"
  fi
else
  printf '    setcap/getcap not found — falling back to sudoers rule\n'
fi

# Fallback: sudoers NOPASSWD rule for systems without libcap-utils or where
# setcap is unavailable.
SUDOERS_FILE='/etc/sudoers.d/tun2proxy-bin'
SUDOERS_RULE="$USER ALL=(ALL) NOPASSWD: /usr/local/bin/tun2proxy-bin"

if [[ -f "$SUDOERS_FILE" ]] && sudo grep -qF "$SUDOERS_RULE" "$SUDOERS_FILE" 2>/dev/null; then
  ok "sudoers fallback rule already in place ($SUDOERS_FILE)"
else
  printf '%s\n' "$SUDOERS_RULE" | sudo tee "$SUDOERS_FILE" > /dev/null
  sudo chmod 0440 "$SUDOERS_FILE"
  ok "sudoers fallback rule written ($SUDOERS_FILE)"
fi

# ── runtime: polkit policy ─────────────────────────────────────────────────────
#
# Lets the app spawn tun2proxy-bin via `pkexec` which shows the native system
# authentication dialog (GNOME/KDE) instead of a custom in-app prompt.
# auth_admin_keep means the user is only asked once per session.

step 'Installing polkit policy for tun2proxy-bin'

POLICY_DIR='/usr/share/polkit-1/actions'
POLICY_FILE="$POLICY_DIR/net.socks5proxy.tun2proxy.policy"

if [[ -f "$POLICY_FILE" ]]; then
  ok "polkit policy already installed ($POLICY_FILE)"
else
  sudo tee "$POLICY_FILE" > /dev/null << 'POLICY'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
  "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="net.socks5proxy.tun2proxy">
    <description>Create a TUN network interface for SOCKS5 routing</description>
    <message>Authentication is required to create a TUN network interface.</message>
    <icon_name>network-vpn</icon_name>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/local/bin/tun2proxy-bin</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">TRUE</annotate>
  </action>
</policyconfig>
POLICY
  ok "polkit policy installed ($POLICY_FILE)"
fi

# ── runtime: tun2proxy-stop cleanup helper ─────────────────────────────────────
#
# A narrow privileged script that kills any tun2proxy-bin process holding a
# given TUN device and removes the interface.  It only accepts device names
# matching the ^s5p[a-f0-9]+$ pattern so it cannot be abused as a generic kill.

step 'Installing tun2proxy-stop cleanup helper'

STOP_SCRIPT='/usr/local/bin/tun2proxy-stop'

# Write (or refresh) the script.
sudo tee "$STOP_SCRIPT" > /dev/null << 'SCRIPT'
#!/bin/bash
# Kill the tun2proxy-bin process that owns the given TUN device and remove
# the interface.  Only accepts our s5p<hex> device names.
TUN_DEV="${1:-}"
if [[ ! "$TUN_DEV" =~ ^s5p[a-f0-9]+$ ]]; then
  echo "tun2proxy-stop: invalid device name '${TUN_DEV}'" >&2
  exit 1
fi
pkill -TERM -f "tun2proxy-bin.*--tun ${TUN_DEV}" 2>/dev/null || true
sleep 0.5
pkill -KILL -f "tun2proxy-bin.*--tun ${TUN_DEV}" 2>/dev/null || true
ip link delete dev "${TUN_DEV}" 2>/dev/null || true
SCRIPT
sudo chmod 0755 "$STOP_SCRIPT"
ok "tun2proxy-stop written to $STOP_SCRIPT"

# Add the sudoers rule for the stop helper (append to the existing file).
STOP_RULE="$USER ALL=(ALL) NOPASSWD: $STOP_SCRIPT"
SUDOERS_FILE='/etc/sudoers.d/tun2proxy-bin'
if sudo grep -qF "$STOP_RULE" "$SUDOERS_FILE" 2>/dev/null; then
  ok "sudoers rule for tun2proxy-stop already in place"
else
  printf '\n%s\n' "$STOP_RULE" | sudo tee -a "$SUDOERS_FILE" > /dev/null
  ok "sudoers rule for tun2proxy-stop added"
fi

# ── done ─────────────────────────────────────────────────────────────────────

printf '\n\033[1;32mRuntime dependencies installed.\033[0m\n'
if [[ "$WITH_BUILD_DEPS" -eq 1 ]]; then
  printf 'Build dependencies installed too. You can now build with:\n'
  printf '  ./scripts/build-desktop-linux.sh build\n'
  printf '  ./scripts/build-desktop-linux.sh bundle\n'
  printf '  ./scripts/build-desktop-linux.sh install   # builds + installs the .deb\n'
else
  printf 'To build the app, re-run with build deps:\n'
  printf '  ./scripts/install-deps-linux.sh --with-build-deps\n'
fi
