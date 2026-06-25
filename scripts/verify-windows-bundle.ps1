param(
  [string]$ArtifactDir,
  [switch]$RequireNsisStaging
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    [ok] $m" -ForegroundColor Green }

$RootDir = Split-Path -Path $PSScriptRoot -Parent
if (-not $ArtifactDir) {
  $ArtifactDir = Join-Path $RootDir 'build-artifacts\windows'
}

$RuntimeDir = Join-Path $RootDir 'runtime\windows'
$AppRuntimeDir = Join-Path $RootDir 'apps\desktop\src-tauri\runtime\windows'
$NsisDir = Join-Path $RootDir '.build\desktop-windows-target\release\bundle\nsis'

function Require-File {
  param(
    [string]$Path,
    [string]$Label
  )
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Missing $Label`: $Path"
  }
  $item = Get-Item -LiteralPath $Path
  if ($item.Length -le 0) {
    throw "$Label is empty: $Path"
  }
  Ok "$Label present: $($item.Name) ($($item.Length) bytes)"
  $item
}

function Compare-Hash {
  param(
    [string]$ExpectedPath,
    [string]$ActualPath,
    [string]$Label
  )
  $expected = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExpectedPath).Hash
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $ActualPath).Hash
  if ($expected -ne $actual) {
    throw "$Label hash mismatch. Expected $expected from $ExpectedPath, got $actual from $ActualPath"
  }
  Ok "$Label SHA256 matches runtime source."
}

Step 'Checking Windows output artifacts'
Require-File -Path (Join-Path $ArtifactDir 'socks5proxy-desktop.exe') -Label 'desktop executable' | Out-Null
$installer = Get-ChildItem -Path $ArtifactDir -Filter '*setup.exe' -File -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
if (-not $installer) {
  throw "Missing NSIS setup executable in $ArtifactDir"
}
if ($installer.Length -le 0) {
  throw "NSIS setup executable is empty: $($installer.FullName)"
}
Ok "NSIS setup executable present: $($installer.Name) ($($installer.Length) bytes)"

Step 'Checking runtime source artifacts'
foreach ($name in @('tun2proxy-bin.exe', 'wintun.dll', 'versions.txt')) {
  Require-File -Path (Join-Path $RuntimeDir $name) -Label "runtime source $name" | Out-Null
}
foreach ($name in @(
  'restore-network-windows.ps1',
  'emergency-network-reset-windows.ps1',
  'emergency-network-reset-windows.cmd',
  'watch-tun-recovery-windows.ps1',
  'inspect-wfp-windows.ps1'
)) {
  Require-File -Path (Join-Path $PSScriptRoot $name) -Label "recovery source $name" | Out-Null
}

Step 'Checking build-artifacts runtime copies'
foreach ($name in @('tun2proxy-bin.exe', 'wintun.dll', 'versions.txt')) {
  $source = Join-Path $RuntimeDir $name
  $copy = Join-Path $ArtifactDir $name
  Require-File -Path $copy -Label "output runtime $name" | Out-Null
  Compare-Hash -ExpectedPath $source -ActualPath $copy -Label "output runtime $name"
}
foreach ($name in @(
  'restore-network-windows.ps1',
  'emergency-network-reset-windows.ps1',
  'emergency-network-reset-windows.cmd',
  'watch-tun-recovery-windows.ps1',
  'inspect-wfp-windows.ps1'
)) {
  $source = Join-Path $PSScriptRoot $name
  $copy = Join-Path $ArtifactDir $name
  Require-File -Path $copy -Label "output recovery $name" | Out-Null
  Compare-Hash -ExpectedPath $source -ActualPath $copy -Label "output recovery $name"
}

Step 'Checking Tauri resource staging'
foreach ($name in @('tun2proxy-bin.exe', 'wintun.dll', 'versions.txt')) {
  $source = Join-Path $RuntimeDir $name
  $staged = Join-Path $AppRuntimeDir $name
  Require-File -Path $staged -Label "Tauri staged runtime $name" | Out-Null
  Compare-Hash -ExpectedPath $source -ActualPath $staged -Label "Tauri staged runtime $name"
}
foreach ($name in @(
  'restore-network-windows.ps1',
  'emergency-network-reset-windows.ps1',
  'emergency-network-reset-windows.cmd',
  'watch-tun-recovery-windows.ps1',
  'inspect-wfp-windows.ps1'
)) {
  $source = Join-Path $PSScriptRoot $name
  $staged = Join-Path $AppRuntimeDir $name
  Require-File -Path $staged -Label "Tauri staged recovery $name" | Out-Null
  Compare-Hash -ExpectedPath $source -ActualPath $staged -Label "Tauri staged recovery $name"
}

Step 'Checking runtime version metadata'
$versions = Get-Content -Path (Join-Path $RuntimeDir 'versions.txt')
foreach ($required in @('tun2proxy_tag=', 'tun2proxy_asset=', 'wintun_version=', 'wintun_sha256=')) {
  if (-not ($versions | Where-Object { $_.StartsWith($required) })) {
    throw "versions.txt is missing required metadata key $required"
  }
}
Ok 'versions.txt contains tun2proxy and Wintun metadata.'

if ($RequireNsisStaging) {
  Step 'Checking NSIS staging output'
  $stagedInstaller = Get-ChildItem -Path $NsisDir -Filter '*setup.exe' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
  if (-not $stagedInstaller) {
    throw "Missing NSIS staged setup executable in $NsisDir"
  }
  Compare-Hash -ExpectedPath $stagedInstaller.FullName -ActualPath $installer.FullName -Label 'copied NSIS setup executable'
}

Step 'Bundle verification complete'
Ok "Windows bundle artifacts verified in $ArtifactDir"
