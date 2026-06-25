# Install the build dependencies for socks5proxy on Windows 11.
#
# Windows needs build dependencies plus the runtime files used by TUN mode.
# The WebView2 runtime the app needs to run ships with Windows 11. This installs:
#   1. Visual Studio C++ Build Tools (the MSVC linker Rust needs)
#   2. Rust (MSVC toolchain) via rustup
#   3. tauri-cli (for the NSIS bundle)
#   4. tun2proxy-bin.exe + wintun.dll into runtime\windows
#
# Run from an elevated PowerShell - the Build Tools install needs admin.
# Safe to re-run; already-installed steps are skipped. Targets Windows 11
# (relies on winget, which ships with Win11).

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "    [ok] $m" -ForegroundColor Green }
function Have($name) { [bool](Get-Command $name -ErrorAction SilentlyContinue) }

# --- preflight ---------------------------------------------------------------
if (-not (Have 'winget')) {
  throw "winget not found. It ships with Windows 11 - install 'App Installer' from the Microsoft Store, then re-run."
}

$elevated = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $elevated) {
  Write-Warning "Not running as Administrator - installing the Visual Studio Build Tools may fail. Re-run in an elevated PowerShell if it does."
}

$wingetCommon = @(
  '-e', '--accept-source-agreements', '--accept-package-agreements'
)

# --- 1. Visual Studio C++ Build Tools (MSVC linker) --------------------------
Step 'Installing Visual Studio C++ Build Tools (MSVC)'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$haveVc = $false
if (Test-Path $vswhere) {
  $vc = & $vswhere -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
  if ($vc) { $haveVc = $true }
}
if ($haveVc) {
  Ok 'MSVC C++ build tools already installed'
} else {
  winget install --id Microsoft.VisualStudio.2022.BuildTools @wingetCommon `
    --override "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
  Ok 'Visual Studio C++ Build Tools installed'
}

# --- 2. Rust (MSVC toolchain) ------------------------------------------------
Step 'Installing Rust toolchain'
if (Have 'cargo') {
  Ok "cargo already available ($(cargo --version))"
} else {
  winget install --id Rustlang.Rustup @wingetCommon
  # rustup installs into %USERPROFILE%\.cargo\bin; add it to PATH for this session.
  $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
  if (Test-Path $cargoBin) { $env:Path = "$cargoBin;$env:Path" }
  if (Have 'rustup') { rustup default stable-x86_64-pc-windows-msvc | Out-Null }
  Ok 'Rust installed'
}

# --- 3. tauri-cli (for the NSIS bundle) --------------------------------------
Step 'Installing tauri-cli (required for bundle mode)'
if (-not (Have 'cargo')) {
  Write-Warning "cargo is not on PATH yet (Rust was just installed). Open a NEW PowerShell and re-run this script to finish installing tauri-cli."
} else {
  $tauriVersion = ''
  $probe = (cargo tauri --version 2>$null)
  if ($LASTEXITCODE -eq 0) { $tauriVersion = $probe }
  if ($tauriVersion -match '^tauri-cli 2') {
    Ok "tauri-cli already installed ($tauriVersion)"
  } else {
    # Any tauri-cli 2.x works with the 2.x tauri crate; install the latest 2.x.
    cargo install tauri-cli --version '^2' --locked
    Ok 'tauri-cli installed'
  }
}

# --- WebView2 ----------------------------------------------------------------
Step 'WebView2 runtime'
Ok 'Ships with Windows 11 - no action needed (only required to run the app).'

# --- 4. Runtime artifacts ----------------------------------------------------
Step 'Installing Windows TUN runtime artifacts'
powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'install-runtime-windows.ps1')
Ok 'Windows TUN runtime artifacts installed'

Write-Host "`nBuild dependencies installed." -ForegroundColor Green
Write-Host 'You can now build with:'
Write-Host '  .\scripts\build-desktop-windows.ps1 build     # GUI .exe'
Write-Host '  .\scripts\build-desktop-windows.ps1 bundle    # GUI + NSIS installer'
