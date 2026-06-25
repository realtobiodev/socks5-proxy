param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('build', 'bundle', 'bundle-clean')]
  [string]$Mode,
  [switch]$SkipRuntimeDownload
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (Test-Path $cargoBin) {
  $env:Path = "$cargoBin;$env:Path"
}

function Require-Command {
  param([string]$Name)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $Name"
  }
}

function Invoke-InDirectory {
  param(
    [string]$Path,
    [scriptblock]$Script
  )

  Push-Location $Path
  try {
    & $Script
  }
  finally {
    Pop-Location
  }
}

function Copy-AllMatches {
  param(
    [string[]]$Roots,
    [string]$Filter,
    [string]$Destination
  )

  $files = foreach ($root in $Roots) {
    if (Test-Path $root) {
      Get-ChildItem -Path $root -Filter $Filter -File -Recurse
    }
  }

  if (-not $files) {
    throw "No artifacts matching '$Filter' found."
  }

  foreach ($file in ($files | Sort-Object FullName -Unique)) {
    Copy-Item -Path $file.FullName -Destination (Join-Path $Destination $file.Name) -Force
  }
}

function Ensure-RuntimeArtifacts {
  if ($SkipRuntimeDownload) {
    return
  }
  $tun = Join-Path $RuntimeDir 'tun2proxy-bin.exe'
  $wintun = Join-Path $RuntimeDir 'wintun.dll'
  if ((Test-Path $tun) -and (Test-Path $wintun)) {
    return
  }
  powershell -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'install-runtime-windows.ps1') -Destination $RuntimeDir
}

function Copy-RuntimeArtifacts {
  param([string]$Destination)
  New-Item -ItemType Directory -Force -Path $Destination | Out-Null
  foreach ($name in @('tun2proxy-bin.exe', 'wintun.dll', 'versions.txt')) {
    $source = Join-Path $RuntimeDir $name
    if (Test-Path $source) {
      Copy-Item -Path $source -Destination (Join-Path $Destination $name) -Force
    }
  }
  foreach ($name in @(
    'restore-network-windows.ps1',
    'emergency-network-reset-windows.ps1',
    'emergency-network-reset-windows.cmd',
    'watch-tun-recovery-windows.ps1',
    'inspect-wfp-windows.ps1'
  )) {
    $source = Join-Path $PSScriptRoot $name
    if (Test-Path $source) {
      Copy-Item -Path $source -Destination (Join-Path $Destination $name) -Force
    }
  }
}

function Remove-StaleBundledRuntime {
  $releaseDir = Join-Path $TargetDir 'release'
  if (-not (Test-Path $releaseDir)) {
    return
  }
  Get-ChildItem -Path $releaseDir -Directory -Filter '_up_' -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force
}

$RootDir = Split-Path -Path $PSScriptRoot -Parent
$AppDir = Join-Path $RootDir 'apps\desktop'
$OutputDir = Join-Path $RootDir 'build-artifacts\windows'
$RuntimeDir = Join-Path $RootDir 'runtime\windows'
$AppRuntimeDir = Join-Path $AppDir 'src-tauri\runtime\windows'
$TargetDir = Join-Path $RootDir '.build\desktop-windows-target'
$BinaryName = 'socks5proxy-desktop.exe'
$BinaryPath = Join-Path $TargetDir "release\$BinaryName"
$BundleRoots = @(
  (Join-Path $TargetDir 'release\bundle\nsis'),
  (Join-Path $AppDir 'src-tauri\target\release\bundle\nsis')
)

Require-Command cargo

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$env:CARGO_TARGET_DIR = $TargetDir

if ($Mode -in @('bundle', 'bundle-clean')) {
  Ensure-RuntimeArtifacts
  Copy-RuntimeArtifacts -Destination $AppRuntimeDir
  Remove-StaleBundledRuntime
  Write-Host 'Building Windows bundle...'
  Invoke-InDirectory $AppDir { cargo tauri build --bundles nsis }
  Copy-AllMatches -Roots $BundleRoots -Filter '*.exe' -Destination $OutputDir
  $tauriBinary = Join-Path $TargetDir "release\$BinaryName"
  if (Test-Path $tauriBinary) {
    Copy-Item -Path $tauriBinary -Destination (Join-Path $OutputDir $BinaryName) -Force
  }
} else {
  Write-Host 'Building desktop release executable...'
  Invoke-InDirectory $RootDir { cargo build -p socks5proxy-desktop --release }

  if (-not (Test-Path $BinaryPath)) {
    throw "Expected executable not found: $BinaryPath"
  }

  Copy-Item -Path $BinaryPath -Destination (Join-Path $OutputDir $BinaryName) -Force
}

Copy-RuntimeArtifacts -Destination $OutputDir

if ($Mode -eq 'bundle-clean') {
  Write-Host 'Cleaning intermediate build directories...'
  # cargo clean here runs with $env:CARGO_TARGET_DIR = $TargetDir set, so it only
  # cleans the redirected bundle target; remove that directory explicitly too.
  Invoke-InDirectory $RootDir { cargo clean }
  if (Test-Path $TargetDir) {
    Remove-Item -Path $TargetDir -Recurse -Force
  }
  # Also clean the default top-level target/. The bundle never builds into it, but
  # it accumulates (often many GB) from direct cargo/clippy/rust-analyzer runs
  # outside this script, which bundle-clean would otherwise leave untouched.
  $DefaultTargetDir = Join-Path $RootDir 'target'
  if (Test-Path $DefaultTargetDir) {
    Write-Host "Cleaning default target directory $DefaultTargetDir..."
    Remove-Item -Path $DefaultTargetDir -Recurse -Force
  }
}

Write-Host "Artifacts available in $OutputDir"
