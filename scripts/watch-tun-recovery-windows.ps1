param(
  [Parameter(Mandatory = $true)]
  [int]$ParentPid,
  [Parameter(Mandatory = $true)]
  [string]$CancelFile,
  [string[]]$TunAdapterName = @('s5pz2test'),
  [int]$PollSeconds = 2,
  [string]$LogPath
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

function Write-LogLine {
  param([string]$Message)
  if (-not $LogPath) { return }
  $directory = Split-Path -Path $LogPath -Parent
  if ($directory) {
    New-Item -ItemType Directory -Force -Path $directory -ErrorAction SilentlyContinue | Out-Null
  }
  "$(Get-Date -Format o) $Message" | Add-Content -Path $LogPath -Encoding UTF8
}

$resetScript = Join-Path $PSScriptRoot 'emergency-network-reset-windows.ps1'
if (-not (Test-Path -LiteralPath $resetScript)) {
  throw "Missing emergency recovery script: $resetScript"
}

Write-LogLine "armed for parent pid $ParentPid and adapter(s): $($TunAdapterName -join ', ')"

while ($true) {
  if (Test-Path -LiteralPath $CancelFile) {
    Write-LogLine 'cancel file detected; watchdog exiting without recovery.'
    exit 0
  }

  $parent = Get-Process -Id $ParentPid -ErrorAction SilentlyContinue
  if (-not $parent) {
    break
  }

  Start-Sleep -Seconds $PollSeconds
}

if (Test-Path -LiteralPath $CancelFile) {
  Write-LogLine 'cancel file detected after parent exit; watchdog exiting without recovery.'
  exit 0
}

Write-LogLine "parent pid $ParentPid disappeared; starting emergency network reset."

$arguments = @(
  '-NoProfile',
  '-ExecutionPolicy', 'Bypass',
  '-File', $resetScript,
  '-ResetDnsServers'
)
foreach ($name in $TunAdapterName) {
  $arguments += @('-TunAdapterName', $name)
}

Start-Process -FilePath 'powershell.exe' `
  -ArgumentList $arguments `
  -WindowStyle Hidden `
  -Wait

Write-LogLine 'emergency network reset finished.'
