# SOCKS5 Proxy Router

Desktop tray app and CLI for routing system traffic through an upstream SOCKS5 proxy.

## Quick Start

On Debian/Ubuntu you can install the runtime dependencies at once:

```sh
# runtime deps only (to run the GUI + daemon)
./scripts/install-deps-linux.sh

# also install build deps (-dev libs, Rust, tauri-cli) to compile the project
./scripts/install-deps-linux.sh --with-build-deps
```

`install-deps-linux.sh` installs dependencies only — it no longer builds or
installs the `socks5proxyd` daemon. The daemon is shipped inside the `.deb`
produced by `build-desktop-linux.sh`, which (re)starts it automatically on
install. Or install manually as described below.

### Installing a prebuilt package (end users)

If you were given a prebuilt `.deb`, a target machine needs just two steps — no
Rust toolchain and no build:

```sh
# 1. one-time: runtime dependencies (prebuilt tun2proxy-bin, polkit policy,
#    GTK/WebKit runtime libraries)
./scripts/install-deps-linux.sh

# 2. install the package (apt resolves the GUI library dependencies)
sudo apt install ./SOCKS5Proxy_<version>_<arch>.deb
```

The package ships the `socks5proxyd` daemon plus its systemd unit and
enables/restarts it automatically on install. Notes:

- Run `install-deps-linux.sh` **as the user who will use the app** (it writes
  per-user `sudoers` rules) and with `sudo` available.
- Use `sudo apt install ./…deb` (not bare `dpkg -i`) so dependencies are
  resolved automatically; running `install-deps-linux.sh` first also satisfies
  them either way.
- `tun` / `namespace` routing additionally needs the `tun2proxy-bin` helper that
  `install-deps-linux.sh` installs — the `.deb` on its own is sufficient only for
  `system` routing.

To remove everything again — the package (which stops/disables the daemon), the
`tun2proxy-bin` helper, polkit policy and sudoers rules:

```sh
./scripts/uninstall-linux.sh           # keeps your config
./scripts/uninstall-linux.sh --purge   # also deletes ~/.config/socks5proxy
```

It leaves system libraries, the Rust toolchain and `~/.cargo/bin/tun2proxy-bin`
untouched.

### Rust and Cargo

The recommended way is [rustup](https://rustup.rs):

```sh
# Linux / macOS
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

```powershell
# Windows — download and run the rustup installer
winget install Rustlang.Rustup
```

Verify: `rustc --version` and `cargo --version`.

### System libraries (Debian/Ubuntu, desktop app only)

```sh
sudo apt install libglib2.0-dev libgtk-3-dev libwebkit2gtk-4.1-dev \
    libjavascriptcoregtk-4.1-dev libsoup-3.0-dev libayatana-appindicator3-dev
```

These are the GTK/WebKit development headers that Tauri requires on Linux.
`pkg-config` is used during the build to locate them — make sure it is
installed: `sudo apt install pkg-config`.

### tun2proxy and socks5proxyd (optional, `tun` / `namespace` routing)

Linux `tun` mode is managed by the `socks5proxyd` root daemon, which starts and
stops `tun2proxy-bin` on behalf of the desktop app. The daemon binary and its
systemd unit are shipped inside the `.deb` and enabled/started on install. The
`install-deps-linux.sh` script installs the `tun2proxy-bin` helper (downloading
the prebuilt release binary, building from source only as a fallback) and its
polkit policy — so the runtime install needs no Rust toolchain.

**Debian/Ubuntu — from the GitHub releases:**

```sh
# Replace <version> and <arch> with the current release values, e.g. v0.8.2 / x86_64
wget https://github.com/tun2proxy/tun2proxy/releases/download/<version>/tun2proxy-<arch>-unknown-linux-gnu.zip
unzip tun2proxy-*.zip
sudo install -m 0755 tun2proxy-bin /usr/local/bin/tun2proxy-bin
```

**From source:**

```sh
cargo install tun2proxy --bin tun2proxy-bin
```

Verify: `tun2proxy-bin --version`.

(`install-deps-linux.sh` does this for you — preferring the prebuilt binary and
only building from source as a fallback.)

### Tauri CLI (bundle mode only)

`bundle` mode (`.deb` / NSIS installer) requires the Tauri CLI as a Cargo subcommand:

```sh
cargo install tauri-cli --version '^2' --locked
```

Only needed when running `bundle`/`install` modes; plain `build` uses `cargo build` directly.

Build commands:

```sh
# Linux: GUI + daemon release executables
./scripts/build-desktop-linux.sh build

# Linux: GUI + daemon + self-contained .deb (ships and (re)starts the daemon)
./scripts/build-desktop-linux.sh bundle

# Linux: same as bundle, then clean intermediate build artifacts
./scripts/build-desktop-linux.sh bundle-clean

# Linux: build the .deb and install it (sudo dpkg -i); the package's maintainer
# scripts stop -> replace -> restart the daemon for you
./scripts/build-desktop-linux.sh install
```

On Windows 11, install the build dependencies once (run elevated — installs the
MSVC C++ Build Tools, Rust and tauri-cli via winget; WebView2 already ships with
Windows 11):

```powershell
.\scripts\install-deps-windows.ps1
```

```powershell
# Windows PowerShell: release executable
.\scripts\build-desktop-windows.ps1 build

# Windows PowerShell: release executable + installer .exe
.\scripts\build-desktop-windows.ps1 bundle

# Windows PowerShell: release executable + installer .exe, then clean intermediates
.\scripts\build-desktop-windows.ps1 bundle-clean
```

Final artifacts are written to:

- `build-artifacts/linux/`
- `build-artifacts/windows/`

## License

This project is licensed under the MIT License. See [`LICENSE`](./LICENSE).

## What Is Included

- `crates/proxy-core`: dependency-light Rust core for config parsing, validation,
  SOCKS5 URL generation, SOCKS5 handshake, `tun2proxy` argument generation,
  system-proxy manipulation, and shared filesystem helpers.
- `crates/proxy-cli`: standalone `socks5proxy` CLI for saving/showing config,
  testing the SOCKS5 handshake, printing TUN args, and starting system or TUN
  routing.
- `apps/desktop`: Tauri v2 tray app for Windows and Linux.
  - `system` mode sets OS proxy settings best-effort.
- `tun` mode on Linux is supervised by the privileged `socks5proxyd` daemon.
  - `namespace` mode talks to the privileged `socks5proxyd` daemon on Linux and
    launches selected apps inside an isolated network namespace.
  - DNS routing maps to `tun2proxy --dns virtual` when enabled.

For how traffic is captured into the TUN device and what data flows through the
tunnel, see [docs/tun-traffic-flow.md](docs/tun-traffic-flow.md).

## Config

The desktop app stores config here:

- Windows: `%APPDATA%/socks5proxy/config.toml`
- Linux: `${XDG_CONFIG_HOME:-~/.config}/socks5proxy/config.toml`

On Unix the file is written with mode `0600` (user-read/write only). Passwords
are stored in plain text by design for v1; see "Security notes" below.

Example:

```toml
version = 2
active_profile_id = "profile-default"

[tray_settings]
exit_ip_lookup_enabled = true
geo_lookup_enabled = true
display_mode = "flag"
ip_prefix_segments = 2
refresh_interval_secs = 300

[[profiles]]
id = "profile-default"
name = "Default"
routing_mode = "tun"
proxy_dns = true
vpn_awareness_enabled = false
startup_cleanup_enabled = true
bypass = ["127.0.0.1", "10.0.0.0/8"]

[profiles.target]
kind = "structured"
host = "proxy.example.com"
port = 1080
selected_credential_id = "cred-default"

[[profiles.target.credentials]]
id = "cred-default"
label = "Credential 1"
username = "user"
password = "secret"
```

## CLI usage

Avoid putting passwords on the command line — `--password PASS` is visible in
`ps` and your shell history. Prefer one of:

```sh
# Piped from stdin
printf '%s' "$MY_PASS" | socks5proxy save --host proxy.example.com --username alice --password-stdin

# From a 0600 file
socks5proxy save --host proxy.example.com --username alice --password-file ~/.secrets/socks5
```

Set `SOCKS5PROXY_LOG=debug` to enable structured logs (via `tracing`).

Namespace app launcher commands:

```sh
socks5proxy launch APP_ID_OR_LABEL
socks5proxy launch-manual -- /usr/bin/curl https://example.com
```

## Build And Test

Core tests (no system deps required):

```sh
cargo test -p proxy-core
```

CLI build:

```sh
cargo build -p socks5proxy --release
./target/release/socks5proxy --help
```

Desktop app (dev mode, requires Tauri CLI):

```sh
cargo install tauri-cli --version '^2'
cd apps/desktop
cargo tauri dev
```

Desktop build scripts:

```sh
# Linux: GUI + daemon release executables
./scripts/build-desktop-linux.sh build

# Linux: GUI + daemon + self-contained .deb
./scripts/build-desktop-linux.sh bundle

# Linux: same as bundle, then remove intermediate build dirs
./scripts/build-desktop-linux.sh bundle-clean

# Linux: build the .deb and install it (daemon stop/replace/restart handled by the package)
./scripts/build-desktop-linux.sh install
```

```powershell
# Windows PowerShell: release executable
.\scripts\build-desktop-windows.ps1 build

# Windows PowerShell: release executable + NSIS installer .exe
.\scripts\build-desktop-windows.ps1 bundle

# Windows PowerShell: release executable + installer .exe, then clean intermediates
.\scripts\build-desktop-windows.ps1 bundle-clean
```

Windows also has a small wrapper:

```bat
scripts\build-desktop-windows.cmd bundle
```

Final artifacts are copied to `build-artifacts/linux/` or `build-artifacts/windows/`.
The scripts use isolated target directories under `.build/` so that `bundle-clean`
can remove desktop intermediates without wiping unrelated workspace outputs.

Linux Tauri builds require the GTK/WebKit development packages listed in the
Quick Start section above. Windows bundle builds use Tauri's NSIS target, so a
working NSIS-capable Tauri toolchain is required on that machine.

The desktop app has no Node.js or npm dependency. The frontend is plain
HTML/CSS/JS served directly from `apps/desktop/` — no build step required.

## Runtime Notes

- `system` routing is best-effort because individual applications can ignore
  OS proxy settings.
- `system` routing on Linux currently supports **GNOME-compatible desktops
  only** (it shells out to `gsettings`). On Linux the desktop app now starts an
  embedded local SOCKS5 adapter on `127.0.0.1:1081` and points GNOME's system
  proxy settings at that adapter, which then authenticates to the configured
  upstream SOCKS5 proxy. KDE, XFCE and others will fail at `enable` with a
  clear error. Windows works with native `reg add` calls.
- `tun` routing is the strict host-wide mode. On Linux the desktop app delegates
  TUN start/stop/status to the `socks5proxyd` root daemon, so disconnect can
  terminate the root-owned `tun2proxy-bin` process reliably. After updating this
  code, rebuild and reinstall the `.deb` (`./scripts/build-desktop-linux.sh
  install`) so the installed `socks5proxyd.service` exposes the latest TUN RPCs.
- `namespace` routing is Linux-only in v1 and requires a running
  `socks5proxyd` system service. It is selective: connecting a namespace profile
  starts the namespace session, and only apps launched through the app launcher
  run inside it. Existing running processes are not moved into the namespace.
  The `.deb` ships that daemon and enables it under systemd on install.
- The desktop app persists the system-proxy snapshot it made on startup. If the
  app crashes before restoring, the snapshot is replayed on the next start so
  the OS proxy returns to its pre-app state.

## Security notes

- The config file contains credentials in clear text. On Unix it is written
  with mode 0600; on Windows it inherits the user-profile ACL.
- `tun2proxy` is invoked with the SOCKS5 URL (including credentials) as a CLI
  argument, which makes them visible via `/proc/<pid>/cmdline`. This is a
  limitation of the current `tun2proxy` interface.
- Host strings are whitelisted before being interpolated into platform
  commands (gvariant strings, `reg add /d ...`, PowerShell). Only ASCII letters,
  digits and `.-:_[]` are allowed in hostnames.
- Geo-IP lookups (`api.ipify.org`, `ipwho.is`, `ipapi.co`, `api.ipinfo.io`) are routed
  through the configured SOCKS5 proxy so the exit IP is not handed to the
  geolocation provider via the user's default route.
- The IPinfo API token (when configured) is sent in an HTTP
  `Authorization: Bearer ...` header rather than in the URL, so it does not
  appear in HTTP access logs.

### Roadmap

- **OS-Keyring credential storage**: an OS-keyring backend (Linux Secret
  Service / Windows Credential Manager / macOS Keychain) is on the roadmap.
  Until that ships, the config file is the credential store; protect it like
  any other credentials file (0600, full-disk encryption, etc.).

## MIT Notes

The MIT License is a permissive license. In practice this means:

- you may use, modify, and redistribute this project, including commercially;
- you must keep the copyright notice and license text with substantial copies
  of the software;
- the software is provided "as is", without warranty.
