#!/usr/bin/env bash
# Uninstall socks5proxy from a Debian/Ubuntu system.
#
# Removes the desktop package (which stops/disables the socks5proxyd daemon via
# its maintainer scripts) and the runtime artifacts that install-deps-linux.sh
# placed on the system (tun2proxy-bin, polkit policy, the tun2proxy-stop helper,
# sudoers rules). It also cleans up any legacy hand-installed daemon files.
#
# It does NOT remove system libraries (GTK/WebKit), the Rust toolchain, or the
# tun2proxy-bin in ~/.cargo/bin — those are general-purpose and may be shared.
# User configuration is kept unless you pass --purge.
#
# Safe to re-run — missing pieces are skipped.
set -euo pipefail

# ── helpers ──────────────────────────────────────────────────────────────────

has() { command -v "$1" >/dev/null 2>&1; }
step() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
ok() { printf '    \033[1;32m✓\033[0m %s\n' "$*"; }

usage() {
  cat <<'EOF'
Usage: scripts/uninstall-linux.sh [--purge]

  (no args)   Remove the app, daemon and runtime helpers. Keep user config.
  --purge     Additionally delete the user configuration directory.
  -h, --help  Show this help.
EOF
}

PURGE=0
case "${1:-}" in
  '') ;;
  --purge) PURGE=1 ;;
  -h|--help) usage; exit 0 ;;
  *) printf 'Unknown argument: %s\n\n' "$1" >&2; usage >&2; exit 1 ;;
esac

# Debian package name as derived by the Tauri bundler from the productName
# (it inserts a hyphen at the case boundary: "SOCKS5Proxy" -> "socks5-proxy").
PKG='socks5-proxy'
SERVICE='socks5proxyd.service'

# ── 1. stop and disable the daemon ─────────────────────────────────────────────

step 'Stopping socks5proxyd daemon'
if has systemctl; then
  sudo systemctl stop "$SERVICE" 2>/dev/null || true
  sudo systemctl disable "$SERVICE" 2>/dev/null || true
  ok 'daemon stopped and disabled'
else
  printf '    systemctl not found — skipping service stop\n'
fi

# ── 2. remove the desktop package ──────────────────────────────────────────────
#
# Its prerm/postrm also stop/disable the daemon and reload systemd.

step 'Removing the socks5proxy package'
if dpkg-query -W -f='${Status}' "$PKG" 2>/dev/null | grep -q 'install ok installed'; then
  sudo apt-get purge -y "$PKG"
  ok "package $PKG removed"
else
  printf '    package %s is not installed (skipping)\n' "$PKG"
fi

# ── 3. remove legacy hand-installed daemon files ───────────────────────────────
#
# Older install-deps-linux.sh versions placed these directly; the .deb now owns
# the daemon, but clean them up in case an old install left them behind.

step 'Removing legacy daemon files'
for f in /usr/local/bin/socks5proxyd /etc/systemd/system/"$SERVICE"; do
  if [[ -e "$f" ]]; then
    sudo rm -f "$f"
    ok "removed $f"
  fi
done
if has systemctl; then
  sudo systemctl daemon-reload 2>/dev/null || true
fi

# ── 4. remove tun2proxy runtime helpers ────────────────────────────────────────

step 'Removing tun2proxy helpers, polkit policy and sudoers rules'
for f in \
  /usr/local/bin/tun2proxy-bin \
  /usr/local/bin/tun2proxy-stop \
  /usr/share/polkit-1/actions/net.socks5proxy.tun2proxy.policy \
  /etc/sudoers.d/tun2proxy-bin
do
  if [[ -e "$f" ]]; then
    sudo rm -f "$f"
    ok "removed $f"
  fi
done

# ── 5. clean up ephemeral runtime state ────────────────────────────────────────

step 'Cleaning runtime state'
for f in /run/socks5proxyd.sock /run/socks5proxyd-tun-state.toml; do
  if [[ -e "$f" ]]; then
    sudo rm -f "$f"
    ok "removed $f"
  fi
done

# ── 6. optionally remove user configuration ────────────────────────────────────

CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/socks5proxy"
if [[ "$PURGE" -eq 1 ]]; then
  step 'Removing user configuration (--purge)'
  if [[ -d "$CONFIG_DIR" ]]; then
    rm -rf "$CONFIG_DIR"
    ok "removed $CONFIG_DIR"
  else
    printf '    no config directory at %s\n' "$CONFIG_DIR"
  fi
else
  if [[ -d "$CONFIG_DIR" ]]; then
    printf '\n    User config kept at %s (use --purge to remove it).\n' "$CONFIG_DIR"
  fi
fi

# ── done ───────────────────────────────────────────────────────────────────────

printf '\n\033[1;32msocks5proxy uninstalled.\033[0m\n'
printf 'Left untouched: system libraries (GTK/WebKit), the Rust toolchain, and\n'
printf 'the tun2proxy-bin in ~/.cargo/bin. Remove those manually if you want to.\n'
