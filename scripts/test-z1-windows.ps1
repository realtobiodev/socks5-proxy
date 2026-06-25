param(
  [string]$CredentialsPath,
  [int]$DurationSeconds = 15,
  [switch]$Live,
  [switch]$EmergencyCloseEdge
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Warning $m }

$RootDir = Split-Path -Path $PSScriptRoot -Parent
if (-not $CredentialsPath) {
  $CredentialsPath = Join-Path $RootDir 'testdata\proxy_creds.txt'
}
$LogDir = Join-Path $RootDir '.build\z1-live-test'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

function Read-FirstProxyEntry {
  param([string]$Path)
  if (-not (Test-Path $Path)) {
    throw "Credentials file not found: $Path"
  }
  Get-Content -Path $Path |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') } |
    Select-Object -First 1
}

function Parse-ProxyEntry {
  param([string]$Line)
  if ($Line -match '^(?<user>[^:]+):(?<pass>[^@]+)@(?<host>.+):(?<port>\d+)$') {
    return [PSCustomObject]@{
      Username = $Matches.user
      Password = $Matches.pass
      Host = $Matches.host
      Port = [int]$Matches.port
    }
  }
  $parts = $Line -split ':'
  if ($parts.Count -ge 4) {
    return [PSCustomObject]@{
      Username = $parts[0]
      Password = $parts[1]
      Host = ($parts[2..($parts.Count - 2)] -join ':')
      Port = [int]$parts[$parts.Count - 1]
    }
  }
  throw "Unsupported credentials line format. Expected user:pass@host:port or user:pass:host:port."
}

function Test-Socks5Handshake {
  param($Proxy)
  $client = New-Object System.Net.Sockets.TcpClient
  $async = $client.BeginConnect([string]$Proxy.Host, [int]$Proxy.Port, $null, $null)
  if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(8))) {
    $client.Close()
    throw 'Timed out connecting to SOCKS5 endpoint.'
  }
  $client.EndConnect($async)
  $stream = $client.GetStream()
  $stream.ReadTimeout = 8000
  $stream.WriteTimeout = 8000
  $greeting = [byte[]](0x05, 0x02, 0x00, 0x02)
  $stream.Write($greeting, 0, $greeting.Length)
  $response = New-Object byte[] 2
  [void]$stream.Read($response, 0, 2)
  if ($response[0] -ne 0x05) {
    throw 'Endpoint did not speak SOCKS5.'
  }
  if ($response[1] -eq 0xff) {
    throw 'Endpoint rejected all SOCKS5 authentication methods.'
  }
  if ($response[1] -eq 0x02) {
    $username = [Text.Encoding]::UTF8.GetBytes([string]$Proxy.Username)
    $password = [Text.Encoding]::UTF8.GetBytes([string]$Proxy.Password)
    if ($username.Length -gt 255 -or $password.Length -gt 255) {
      throw 'SOCKS5 username/password is too long.'
    }
    $auth = New-Object System.Collections.Generic.List[byte]
    $auth.Add(0x01)
    $auth.Add([byte]$username.Length)
    $auth.AddRange($username)
    $auth.Add([byte]$password.Length)
    $auth.AddRange($password)
    $bytes = $auth.ToArray()
    $stream.Write($bytes, 0, $bytes.Length)
    $authResponse = New-Object byte[] 2
    [void]$stream.Read($authResponse, 0, 2)
    if ($authResponse[0] -ne 0x01 -or $authResponse[1] -ne 0x00) {
      throw 'SOCKS5 username/password authentication failed.'
    }
  }
  $client.Close()
}

function Test-LocalAdapterPortFree {
  $listener = $null
  try {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 1081)
    $listener.Start()
    Ok 'Local system-proxy adapter port 127.0.0.1:1081 is available.'
  } finally {
    if ($listener) { $listener.Stop() }
  }
}

function Get-ExitIpViaLocalBridge {
  $curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
  if (-not $curl) {
    Warn 'curl.exe not found; skipping local bridge exit-IP lookup.'
    return $null
  }
  $text = & $curl.Source `
    --silent `
    --show-error `
    --fail `
    --max-time 12 `
    --socks5-hostname '127.0.0.1:1081' `
    'https://api.ipify.org?format=json' 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "Local bridge exit-IP lookup failed: $($text -join ' ')"
  }
  try {
    return (($text -join "`n") | ConvertFrom-Json).ip
  } catch {
    throw "Could not parse local bridge exit-IP response: $($text -join ' ')"
  }
}

function Start-EmergencyWatchdog {
  param(
    [string]$CancelFile,
    [int]$DelaySeconds
  )
  if (Test-Path -LiteralPath $CancelFile) {
    Remove-Item -LiteralPath $CancelFile -Force -ErrorAction SilentlyContinue
  }
  $watchdogScript = Join-Path $LogDir 'emergency-watchdog-z1.ps1'
  $watchdogLog = Join-Path $LogDir 'emergency-watchdog-z1.log'
  @'
param(
  [string]$ScriptRoot,
  [string]$CancelFile,
  [int]$DelaySeconds,
  [int]$CloseEdgeValue,
  [string]$LogPath
)

$ErrorActionPreference = 'Continue'
for ($i = 0; $i -lt $DelaySeconds; $i++) {
  if (Test-Path -LiteralPath $CancelFile) { exit 0 }
  Start-Sleep -Seconds 1
}
if (Test-Path -LiteralPath $CancelFile) { exit 0 }

$reset = Join-Path $ScriptRoot 'emergency-network-reset-windows.ps1'
$args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $reset)
if ($CloseEdgeValue -eq 1) { $args += '-CloseEdge' }
"$(Get-Date -Format o) emergency watchdog running Z1 reset" | Set-Content -Path $LogPath -Encoding UTF8
Start-Process -FilePath 'powershell.exe' -ArgumentList $args -WindowStyle Hidden -Wait
'@ | Set-Content -Path $watchdogScript -Encoding UTF8

  $closeEdgeValue = if ($EmergencyCloseEdge) { 1 } else { 0 }
  Start-Process -FilePath 'powershell.exe' `
    -ArgumentList @(
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-File', $watchdogScript,
      '-ScriptRoot', $PSScriptRoot,
      '-CancelFile', $CancelFile,
      '-DelaySeconds', $DelaySeconds,
      '-CloseEdgeValue', $closeEdgeValue,
      '-LogPath', $watchdogLog
    ) `
    -WindowStyle Hidden `
    -PassThru
}

function Restore-Network {
  param([string]$Snapshot)
  powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'restore-network-windows.ps1') `
    -SystemProxySnapshot $Snapshot `
    -VerifyCleanup | Out-Null
}

function Format-ProcessArgument {
  param([string]$Value)
  if ($Value -notmatch '[\s"]') {
    return $Value
  }
  '"' + ($Value -replace '\\(?=\\*")', '$0\' -replace '"', '\"') + '"'
}

Step 'Preflight'
$entry = Read-FirstProxyEntry -Path $CredentialsPath
$proxy = Parse-ProxyEntry -Line $entry
Ok 'Loaded proxy test entry without printing credentials.'
Test-Socks5Handshake -Proxy $proxy
Ok 'Upstream SOCKS5 handshake/auth succeeded.'
Test-LocalAdapterPortFree

if (-not $Live) {
  Warn 'Dry-run only. Re-run with -Live to temporarily enable the Windows system proxy. Fallback: scripts\emergency-network-reset-windows.ps1'
  return
}

Step 'Building CLI'
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
cargo build -p socks5proxy | Write-Host
$cli = Join-Path $RootDir 'target\debug\socks5proxy.exe'
if (-not (Test-Path $cli)) {
  throw "CLI binary not found after build: $cli"
}

Step 'Saving fallback snapshot'
$snapshot = powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'save-network-snapshot-windows.ps1')
Ok "Snapshot saved: $snapshot"
$emergencyCancel = Join-Path $LogDir 'emergency-watchdog.cancel'
$watchdog = Start-EmergencyWatchdog -CancelFile $emergencyCancel -DelaySeconds ($DurationSeconds + 20)
Ok "Emergency watchdog armed; cancel file: $emergencyCancel"

$process = $null
try {
  Step 'Starting CLI system-proxy session'
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = $cli
  $processArgs = @(
    'start',
    '--routing-mode', 'system',
    '--host', [string]$proxy.Host,
    '--port', [string]$proxy.Port,
    '--username', [string]$proxy.Username,
    '--password-stdin'
  )
  $psi.Arguments = (($processArgs | ForEach-Object { Format-ProcessArgument $_ }) -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  $process = [System.Diagnostics.Process]::Start($psi)
  $process.StandardInput.WriteLine([string]$proxy.Password)
  Start-Sleep -Seconds 3
  if ($process.HasExited) {
    throw "CLI exited early with code $($process.ExitCode): $($process.StandardError.ReadToEnd())"
  }

  $local = [PSCustomObject]@{
    Host = '127.0.0.1'
    Port = 1081
    Username = $null
    Password = $null
  }
  Test-Socks5Handshake -Proxy $local
  Ok 'Local SOCKS5 auth bridge is reachable without client credentials.'
  $bridgeExitIp = Get-ExitIpViaLocalBridge
  if ($bridgeExitIp) {
    Ok "Exit IP through local auth bridge: $bridgeExitIp"
  }

  $settings = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  if ([int]$settings.ProxyEnable -ne 1 -or [string]$settings.ProxyServer -ne 'socks=127.0.0.1:1081') {
    throw "Unexpected system proxy state: ProxyEnable=$($settings.ProxyEnable), ProxyServer=$($settings.ProxyServer)"
  }
  Ok 'Windows system proxy points at socks=127.0.0.1:1081.'

  Start-Sleep -Seconds $DurationSeconds
} finally {
  Step 'Restoring system proxy state'
  if ($process -and -not $process.HasExited) {
    try {
      $process.StandardInput.WriteLine('')
      if (-not $process.WaitForExit(8000)) {
        $process.Kill()
        $process.WaitForExit()
      }
    } catch {
      try { $process.Kill() } catch {}
    }
  }
  if ($snapshot) {
    Restore-Network -Snapshot $snapshot
    Ok 'Network/system proxy snapshot restored.'
  }
  if ($emergencyCancel) {
    New-Item -ItemType File -Force -Path $emergencyCancel | Out-Null
  }
  if ($watchdog -and -not $watchdog.HasExited) {
    try { $watchdog.Kill() } catch {}
  }
}
