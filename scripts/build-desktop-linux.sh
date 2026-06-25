#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/build-desktop-linux.sh <build|bundle|bundle-clean|install|install-clean>

Commands:
  build          Build the GUI and daemon release executables and copy them to
                 build-artifacts/linux/
  bundle         Build GUI + daemon, then produce a self-contained .deb that
                 ships the socks5proxyd daemon and (re)starts it on install
  bundle-clean   Same as bundle, then remove intermediate build directories
  install        Same as bundle, then install the .deb with `sudo dpkg -i`.
                 The package's own maintainer scripts stop/replace/restart the
                 daemon — no manual systemctl steps are needed.
  install-clean  Same as install, then remove all intermediate build artifacts
                 and caches (keeps executables and .deb in build-artifacts/linux/)

Outputs:
  build-artifacts/linux/socks5proxy-desktop
  build-artifacts/linux/socks5proxyd
  build-artifacts/linux/*.deb

Bundle/install modes require the Tauri CLI:
  cargo install tauri-cli --version 2.0.0
EOF
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf 'Missing required command: %s\n' "$1" >&2
    exit 1
  fi
}

copy_all_matches() {
  local pattern="$1"
  local destination_dir="$2"
  local found_any=0

  while IFS= read -r artifact; do
    [[ -n "$artifact" ]] || continue
    cp "$artifact" "$destination_dir/"
    found_any=1
  done < <(find "${BUNDLE_SEARCH_DIRS[@]}" -type f -name "$pattern" 2>/dev/null | sort -u || true)

  if [[ "$found_any" -eq 0 ]]; then
    printf 'No artifacts matching %s found.\n' "$pattern" >&2
    exit 1
  fi
}

# Post-process a Tauri-built .deb so it ships the socks5proxyd daemon and manages
# it through the package lifecycle. Tauri 2.0.0's deb config has no maintainer
# script hooks, so we unpack the .deb, drop the daemon binary + systemd unit in,
# inject postinst/prerm/postrm, and repack over the original file.
inject_daemon_into_deb() {
  local deb_path="$1"
  local daemon_bin="$2"
  local work
  work="$(mktemp -d)"

  dpkg-deb -R "$deb_path" "$work"  # ownership is restored to root via fakeroot below

  install -D -m 0755 "$daemon_bin" "$work/usr/bin/socks5proxyd"
  install -D -m 0644 "$ROOT_DIR/packaging/socks5proxyd.service" \
    "$work/usr/lib/systemd/system/socks5proxyd.service"

  # postinst: drop any stale hand-installed daemon/unit from old install-deps
  # runs, then (re)enable and (re)start the service on the new binary.
  cat > "$work/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  [ -e /usr/local/bin/socks5proxyd ] && rm -f /usr/local/bin/socks5proxyd || true
  [ -e /etc/systemd/system/socks5proxyd.service ] && rm -f /etc/systemd/system/socks5proxyd.service || true
  systemctl daemon-reload || true
  systemctl enable socks5proxyd.service || true
  systemctl restart socks5proxyd.service || true
fi
POSTINST

  # prerm: stop the daemon before its binary is swapped (upgrade) or removed,
  # and disable it on outright removal.
  cat > "$work/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
systemctl stop socks5proxyd.service || true
[ "$1" = "remove" ] && systemctl disable socks5proxyd.service || true
PRERM

  # postrm: reload systemd after the unit file is gone.
  cat > "$work/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
[ "$1" = "remove" ] && systemctl daemon-reload || true
POSTRM

  chmod 0755 "$work/DEBIAN/postinst" "$work/DEBIAN/prerm" "$work/DEBIAN/postrm"

  # Refresh md5sums so the repacked package stays consistent with `dpkg --verify`.
  if [[ -f "$work/DEBIAN/md5sums" ]]; then
    ( cd "$work" && find usr -type f -exec md5sum {} + > DEBIAN/md5sums )
  fi

  # Repack under fakeroot so every entry is owned by root:root. Extracting and
  # rebuilding as a normal user would otherwise ship the root-run daemon binary
  # owned by the build user.
  fakeroot bash -c 'chown -R root:root "$1" && dpkg-deb --build "$1" "$2"' _ "$work" "$deb_path"
  rm -rf "$work"
  printf 'Injected socks5proxyd daemon into %s\n' "$deb_path"
}

MODE="${1:-}"
if [[ -z "$MODE" ]]; then
  usage
  exit 1
fi

case "$MODE" in
  build|bundle|bundle-clean|install|install-clean) ;;
  *)
    usage
    exit 1
    ;;
esac

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT_DIR/apps/desktop"
OUTPUT_DIR="$ROOT_DIR/build-artifacts/linux"
TARGET_DIR="$ROOT_DIR/.build/desktop-linux-target"
BINARY_NAME="socks5proxy-desktop"
DAEMON_NAME="socks5proxyd"
BINARY_PATH="$TARGET_DIR/release/$BINARY_NAME"
DAEMON_PATH="$TARGET_DIR/release/$DAEMON_NAME"
BUNDLE_SEARCH_DIRS=(
  "$TARGET_DIR/release/bundle/deb"
  "$APP_DIR/src-tauri/target/release/bundle/deb"
)

require_command cargo

mkdir -p "$OUTPUT_DIR"

build_daemon() {
  printf 'Building socks5proxyd daemon...\n'
  (
    cd "$ROOT_DIR"
    CARGO_TARGET_DIR="$TARGET_DIR" cargo build -p socks5proxyd --release
  )
  if [[ ! -f "$DAEMON_PATH" ]]; then
    printf 'Expected daemon binary not found: %s\n' "$DAEMON_PATH" >&2
    exit 1
  fi
  cp "$DAEMON_PATH" "$OUTPUT_DIR/$DAEMON_NAME"
}

# Build GUI + daemon and produce a self-contained .deb in build-artifacts/linux/.
build_bundle() {
  require_command dpkg-deb
  require_command fakeroot

  # Tauri does not clean its bundle output dir, so stale .deb files from earlier
  # builds (e.g. a previous version or product name) would otherwise be copied
  # and shipped alongside the current one. Clear them first.
  for dir in "${BUNDLE_SEARCH_DIRS[@]}"; do
    rm -f "$dir"/*.deb 2>/dev/null || true
  done
  rm -f "$OUTPUT_DIR"/*.deb 2>/dev/null || true

  printf 'Building Debian bundle (GUI)...\n'
  (
    cd "$APP_DIR"
    CARGO_TARGET_DIR="$TARGET_DIR" cargo tauri build --bundles deb
  )

  build_daemon

  copy_all_matches '*.deb' "$OUTPUT_DIR"
  if [[ -f "$BINARY_PATH" ]]; then
    cp "$BINARY_PATH" "$OUTPUT_DIR/$BINARY_NAME"
  fi

  # Inject the daemon into every .deb we just collected.
  while IFS= read -r deb; do
    [[ -n "$deb" ]] || continue
    inject_daemon_into_deb "$deb" "$OUTPUT_DIR/$DAEMON_NAME"
  done < <(find "$OUTPUT_DIR" -maxdepth 1 -name '*.deb' | sort -u)
}

clean_build_dirs() {
  printf 'Cleaning intermediate build directories...\n'
  (cd "$ROOT_DIR" && CARGO_TARGET_DIR="$TARGET_DIR" cargo clean) || true
  rm -rf "$TARGET_DIR"
}

case "$MODE" in
  build)
    printf 'Building desktop release executable...\n'
    (
      cd "$ROOT_DIR"
      CARGO_TARGET_DIR="$TARGET_DIR" cargo build -p socks5proxy-desktop --release
    )
    if [[ ! -f "$BINARY_PATH" ]]; then
      printf 'Expected executable not found: %s\n' "$BINARY_PATH" >&2
      exit 1
    fi
    cp "$BINARY_PATH" "$OUTPUT_DIR/$BINARY_NAME"
    build_daemon
    ;;

  bundle|bundle-clean)
    build_bundle
    [[ "$MODE" == "bundle-clean" ]] && clean_build_dirs
    ;;

  install|install-clean)
    build_bundle

    printf 'Installing .deb package...\n'
    DEB_FILE="$(find "$OUTPUT_DIR" -maxdepth 1 -name '*.deb' | sort | tail -1)"
    if [[ -z "$DEB_FILE" ]]; then
      printf 'No .deb found in %s\n' "$OUTPUT_DIR" >&2
      exit 1
    fi
    # The package's maintainer scripts stop -> replace -> restart the daemon.
    sudo dpkg -i "$DEB_FILE"

    [[ "$MODE" == "install-clean" ]] && clean_build_dirs
    ;;
esac

printf 'Artifacts available in %s\n' "$OUTPUT_DIR"
