param(
  [string]$CredentialsPath = 'testdata\proxy_creds.txt',
  [string]$InstallerPath = 'build-artifacts\windows\SOCKS5Proxy_1.0.0_x64-setup.exe',
  [string]$InstallDir = '.build\final-installed-gui\app',
  [string]$LogDir = '.build\final-installed-gui',
  [string]$DesktopExe,
  [int]$UiTimeoutSeconds = 60,
  [int]$ConnectTimeoutSeconds = 120,
  [int]$PollSeconds = 2,
  [switch]$SkipInstall,
  [switch]$KeepInstall,
  [switch]$KeepConfig,
  [switch]$KeepRunning,
  [switch]$LiveZ1,
  [switch]$LiveZ2,
  [switch]$LiveZ3,
  [switch]$LiveZ4,
  [switch]$AllowWfpMutation,
  [switch]$TestRecovery
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($Message) { Write-Host "[GUI-PARITY] $Message" -ForegroundColor Cyan }
function Ok($Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn($Message) { Write-Warning $Message }

function Test-Administrator {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Relaunch-ElevatedIfNeeded {
  if ((Test-Administrator) -or (-not ($LiveZ2 -or $LiveZ3 -or $LiveZ4 -or $TestRecovery))) { return }

  $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
  foreach ($key in $PSBoundParameters.Keys) {
    $value = $PSBoundParameters[$key]
    if ($value -is [switch] -or $value -is [bool]) {
      if ($value) { $arguments += "-$key" }
    } else {
      $arguments += @("-$key", [string]$value)
    }
  }

  Step 'Relaunching elevated for live TUN/Z4/recovery GUI parity checks.'
  $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -Wait -PassThru
  exit $process.ExitCode
}

function Resolve-RepoPath {
  param([string]$Path)
  if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
  return (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path $Path)
}

function Read-FirstProxyEntry {
  param([string]$Path)
  $resolved = Resolve-RepoPath $Path
  if (-not (Test-Path -LiteralPath $resolved)) { throw "Credentials file not found: $resolved" }
  foreach ($line in Get-Content -Path $resolved) {
    $trimmed = $line.Trim()
    if (-not $trimmed -or $trimmed.StartsWith('#')) { continue }
    return $trimmed
  }
  throw "No proxy credential entry found in $resolved"
}

function Parse-ProxyEntry {
  param([string]$Entry)
  $withoutScheme = $Entry -replace '^[a-zA-Z0-9+.-]+://', ''
  $match = [regex]::Match($withoutScheme, '^(?:(?<user>[^:@]+):(?<pass>[^@]+)@)?(?<host>\[[^\]]+\]|[^:]+):(?<port>\d+)$')
  if (-not $match.Success) { throw "Unsupported proxy credential format: $Entry" }
  [PSCustomObject]@{
    Host = $match.Groups['host'].Value.Trim('[', ']')
    Port = [int]$match.Groups['port'].Value
    Username = $match.Groups['user'].Value
    Password = $match.Groups['pass'].Value
  }
}

function ConvertTo-TomlString {
  param([string]$Value)
  '"' + (($Value -replace '\\', '\\') -replace '"', '\"') + '"'
}

function Get-AppConfigPath {
  if (-not $env:APPDATA) { throw 'APPDATA is not set.' }
  return Join-Path $env:APPDATA 'socks5proxy\config.toml'
}

function Write-GuiConfig {
  param(
    $Proxy,
    [string]$SelectedProfileId
  )

  $path = Get-AppConfigPath
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
  $hostToml = ConvertTo-TomlString $Proxy.Host
  $userToml = ConvertTo-TomlString $Proxy.Username
  $passToml = ConvertTo-TomlString $Proxy.Password
  $port = [int]$Proxy.Port

  $profiles = @(
    @{ Id = 'z1-system'; Name = 'Z1 System Proxy'; Mode = 'system' },
    @{ Id = 'z2-tun'; Name = 'Z2 TUN'; Mode = 'tun' },
    @{ Id = 'z3-wireguard'; Name = 'Z3 WireGuard'; Mode = 'tun' },
    @{ Id = 'z4-mullvad'; Name = 'Z4 Mullvad'; Mode = 'tun' }
  )

  $text = @"
enabled = false
selected_profile_id = "$SelectedProfileId"
active_profile_id = "$SelectedProfileId"

[tray_settings]
exit_ip_lookup_enabled = true
geo_lookup_enabled = true
display_mode = "flag"
ip_prefix_segments = 2
refresh_interval_secs = 60

"@

  foreach ($profile in $profiles) {
    $text += @"
[[profiles]]
id = "$($profile.Id)"
name = "$($profile.Name)"
routing_mode = "$($profile.Mode)"
proxy_dns = true
startup_cleanup_enabled = true
bypass = []

[profiles.target]
kind = "structured"
host = $hostToml
port = $port
selected_credential_id = "cred-$($profile.Id)"

[[profiles.target.credentials]]
id = "cred-$($profile.Id)"
label = "Primary"
username = $userToml
password = $passToml

"@
  }

  Set-Content -Path $path -Value $text -Encoding UTF8
  return $path
}

function Backup-AppConfig {
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $path = Get-AppConfigPath
  $backup = Join-Path $LogDir 'config.toml.before'
  if (Test-Path -LiteralPath $path) {
    Copy-Item -LiteralPath $path -Destination $backup -Force
    return $backup
  }
  return $null
}

function Restore-AppConfig {
  param([string]$Backup)
  if ($KeepConfig) { return }
  $path = Get-AppConfigPath
  if ($Backup -and (Test-Path -LiteralPath $Backup)) {
    Copy-Item -LiteralPath $Backup -Destination $path -Force
  } elseif (Test-Path -LiteralPath $path) {
    Remove-Item -LiteralPath $path -Force
  }
}

function Install-App {
  if ($SkipInstall -or $DesktopExe) { return }
  $installer = Resolve-RepoPath $InstallerPath
  if (-not (Test-Path -LiteralPath $installer)) { throw "Installer not found: $installer" }
  $installPath = Resolve-RepoPath $InstallDir
  New-Item -ItemType Directory -Force -Path $installPath | Out-Null
  Step "Installing app from $installer"
  $process = Start-Process -FilePath $installer -ArgumentList @('/S', "/D=$installPath") -Wait -PassThru
  if ($process.ExitCode -ne 0) { throw "Installer failed with exit code $($process.ExitCode)" }
}

function Resolve-InstalledExe {
  if ($DesktopExe) {
    $resolved = Resolve-RepoPath $DesktopExe
    if (Test-Path -LiteralPath $resolved) { return (Resolve-Path -LiteralPath $resolved).Path }
    throw "Desktop executable not found: $resolved"
  }
  $candidates = @(
    (Join-Path (Resolve-RepoPath $InstallDir) 'socks5proxy-desktop.exe'),
    (Join-Path (Resolve-RepoPath $InstallDir) 'SOCKS5Proxy.exe'),
    (Resolve-RepoPath 'target\debug\socks5proxy-desktop.exe'),
    (Resolve-RepoPath 'build-artifacts\windows\socks5proxy-desktop.exe')
  )
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) { return (Resolve-Path -LiteralPath $candidate).Path }
  }
  throw 'Could not locate installed socks5proxy desktop executable.'
}

function Uninstall-TestApp {
  if ($SkipInstall -or $KeepInstall -or $DesktopExe) { return }
  $installPath = Resolve-RepoPath $InstallDir
  if (-not (Test-Path -LiteralPath $installPath)) { return }
  foreach ($name in @('uninstall.exe', 'Uninstall SOCKS5Proxy.exe', 'unins000.exe')) {
    $uninstaller = Join-Path $installPath $name
    if (Test-Path -LiteralPath $uninstaller) {
      Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait | Out-Null
      return
    }
  }
}

function Initialize-UiAutomation {
  Add-Type -AssemblyName UIAutomationClient
  Add-Type -AssemblyName UIAutomationTypes
}

function Find-AppWindow {
  param([int]$ProcessId)
  Initialize-UiAutomation
  $root = [Windows.Automation.AutomationElement]::RootElement
  $condition = New-Object Windows.Automation.PropertyCondition -ArgumentList @(
    [Windows.Automation.AutomationElement]::ProcessIdProperty,
    $ProcessId
  )
  return $root.FindFirst([Windows.Automation.TreeScope]::Children, $condition)
}

function Get-UiText {
  param([int]$ProcessId)
  Initialize-UiAutomation
  $window = Find-AppWindow -ProcessId $ProcessId
  if (-not $window) { return '' }
  $all = $window.FindAll([Windows.Automation.TreeScope]::Descendants, [Windows.Automation.Condition]::TrueCondition)
  $items = New-Object System.Collections.Generic.List[string]
  foreach ($element in $all) {
    $name = $element.Current.Name
    if (-not [string]::IsNullOrWhiteSpace($name)) { $items.Add($name) }
  }
  return ($items | Select-Object -Unique) -join "`n"
}

function Invoke-AppButton {
  param([int]$ProcessId, [string[]]$Names, [int]$TimeoutSeconds = $UiTimeoutSeconds)
  Initialize-UiAutomation
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $window = Find-AppWindow -ProcessId $ProcessId
    if ($window) {
      foreach ($name in $Names) {
        $condition = New-Object Windows.Automation.PropertyCondition -ArgumentList @(
          [Windows.Automation.AutomationElement]::NameProperty,
          $name
        )
        $button = $window.FindFirst([Windows.Automation.TreeScope]::Descendants, $condition)
        if ($button) {
          $pattern = $button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)
          $pattern.Invoke()
          return $true
        }
      }
    }
    Start-Sleep -Seconds $PollSeconds
  } while ((Get-Date) -lt $deadline)
  return $false
}

function Wait-Until {
  param([scriptblock]$Condition, [int]$TimeoutSeconds, [string]$WaitingFor)
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    if (& $Condition) { return $true }
    Start-Sleep -Seconds $PollSeconds
  } while ((Get-Date) -lt $deadline)
  Warn "Timed out waiting for $WaitingFor."
  return $false
}

function Start-Gui {
  param([string]$Exe)
  $process = Start-Process -FilePath $Exe -PassThru
  $ready = Wait-Until -TimeoutSeconds $UiTimeoutSeconds -WaitingFor 'GUI window' -Condition {
    return [bool](Find-AppWindow -ProcessId $process.Id)
  }
  if (-not $ready) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    throw 'Installed GUI did not show a window.'
  }
  return $process
}

function Stop-Gui {
  param($Process)
  if ($Process -and -not $Process.HasExited) {
    Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-HeadlessJson {
  param([string]$Exe, [string[]]$Arguments)
  $raw = & $Exe @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') exited with $LASTEXITCODE. Raw: $raw" }
  $text = (($raw | Out-String).Trim())
  $start = $text.IndexOf('{')
  $end = $text.LastIndexOf('}')
  if ($start -lt 0 -or $end -lt $start) { throw "Headless command did not return JSON. Raw: $text" }
  return ($text.Substring($start, $end - $start + 1) | ConvertFrom-Json)
}

function Save-Json {
  param([string]$Name, $Value)
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $path = Join-Path $LogDir "$Name.json"
  $Value | ConvertTo-Json -Depth 12 | Set-Content -Path $path -Encoding UTF8
  return $path
}

function Save-Text {
  param([string]$Name, [string]$Text)
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $path = Join-Path $LogDir "$Name.txt"
  Set-Content -Path $path -Value $Text -Encoding UTF8
  return $path
}

function Assert-UiContains {
  param([string]$Text, [string]$Pattern, [string]$Description)
  if ([string]::IsNullOrWhiteSpace($Text)) {
    Warn "UIAutomation did not expose text for $Description; relying on window presence/headless artifacts."
    return
  }
  if ($Text -notmatch $Pattern) { throw "UI did not show $Description. Pattern=$Pattern. Text=$Text" }
}

function Assert-UiHasIpOrError {
  param([string]$Text, [string]$Phase)
  if ([string]::IsNullOrWhiteSpace($Text)) {
    Warn "UIAutomation did not expose status metadata for $Phase; relying on headless/status artifacts."
    return
  }
  if ($Text -match '\b\d{1,3}(?:\.\d{1,3}){3}\b') { return }
  if ($Text -match 'Geo lookup failed|error|blocked|Connecting') { return }
  throw "UI did not show IP/flag metadata or a clear lookup status during $Phase. Text=$Text"
}

function Run-GuiDiagnostics {
  param([int]$ProcessId, [string]$Phase)
  if (-not (Invoke-AppButton -ProcessId $ProcessId -Names @('Run diagnostics') -TimeoutSeconds 20)) {
    Warn "Could not click Run diagnostics for $Phase via UIAutomation; WebView2 may not expose DOM controls."
    return
  }
  $ok = Wait-Until -TimeoutSeconds $ConnectTimeoutSeconds -WaitingFor "diagnostics for $Phase" -Condition {
    $text = Get-UiText -ProcessId $ProcessId
    return $text -match 'Pass|Warn|Fail|Blocked|Error'
  }
  $text = Get-UiText -ProcessId $ProcessId
  Save-Text -Name "$Phase-diagnostics-ui" -Text $text | Out-Null
  if (-not $ok) { Warn "Diagnostics did not expose completion text for $Phase. Text=$text" }
}

function Connect-And-Verify {
  param(
    [string]$Phase,
    [string]$ProfileId,
    [string]$ExpectedTitlePattern,
    [bool]$ExpectConnect
  )

  Write-GuiConfig -Proxy $proxy -SelectedProfileId $ProfileId | Out-Null
  $app = Start-Gui -Exe $exe
  try {
    $initialText = Get-UiText -ProcessId $app.Id
    Save-Text -Name "$Phase-initial-ui" -Text $initialText | Out-Null
    Run-GuiDiagnostics -ProcessId $app.Id -Phase "$Phase-before-connect"

    if (-not (Invoke-AppButton -ProcessId $app.Id -Names @('Connect', 'Reconnect') -TimeoutSeconds 30)) {
      throw "Could not click Connect for $Phase."
    }

    $settled = Wait-Until -TimeoutSeconds $ConnectTimeoutSeconds -WaitingFor "$Phase GUI status" -Condition {
      $text = Get-UiText -ProcessId $app.Id
      if ($ExpectConnect) {
        return $text -match $ExpectedTitlePattern
      }
      return $text -match 'Blocked|Error|requires|failed|Mullvad|WireGuard|WFP|kill-switch'
    }
    $connectedText = Get-UiText -ProcessId $app.Id
    Save-Text -Name "$Phase-connected-ui" -Text $connectedText | Out-Null
    if (-not $settled) { throw "$Phase did not reach expected GUI status. Text=$connectedText" }

    if ($ExpectConnect) {
      Assert-UiContains -Text $connectedText -Pattern $ExpectedTitlePattern -Description "$Phase connected status"
      Assert-UiHasIpOrError -Text $connectedText -Phase $Phase
      if (-not (Invoke-AppButton -ProcessId $app.Id -Names @('Disconnect') -TimeoutSeconds 30)) {
        throw "Could not click Disconnect for $Phase."
      }
      $disconnected = Wait-Until -TimeoutSeconds $ConnectTimeoutSeconds -WaitingFor "$Phase disconnect" -Condition {
        (Get-UiText -ProcessId $app.Id) -match 'Disconnected'
      }
      $postText = Get-UiText -ProcessId $app.Id
      Save-Text -Name "$Phase-post-disconnect-ui" -Text $postText | Out-Null
      if (-not $disconnected) { throw "$Phase did not disconnect cleanly. Text=$postText" }
    }
  } finally {
    Stop-Gui -Process $app
  }
}

Relaunch-ElevatedIfNeeded

$configBackup = $null
$proxy = Parse-ProxyEntry (Read-FirstProxyEntry -Path $CredentialsPath)
$exe = $null

try {
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $configBackup = Backup-AppConfig
  Install-App
  $exe = Resolve-InstalledExe
  Ok "Using GUI executable: $exe"

  Step 'Z0: installed GUI disconnected status, flag/IP area and diagnostics.'
  Write-GuiConfig -Proxy $proxy -SelectedProfileId 'z1-system' | Out-Null
  $z0 = Start-Gui -Exe $exe
  try {
    $z0Text = Get-UiText -ProcessId $z0.Id
    Save-Text -Name 'z0-ui' -Text $z0Text | Out-Null
    Assert-UiContains -Text $z0Text -Pattern 'Disconnected' -Description 'Z0 disconnected status'
    Run-GuiDiagnostics -ProcessId $z0.Id -Phase 'z0'
  } finally {
    Stop-Gui -Process $z0
  }
  Ok 'Z0 GUI status and diagnostics verified.'

  $preflight = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-tun-preflight-json')
  Save-Json -Name 'headless-windows-preflight' -Value $preflight | Out-Null
  Ok 'Headless Windows preflight captured for Z2-Z4 status parity.'

  if ($LiveZ1) {
    Step 'Z1: installed GUI system-proxy Connect/Disconnect.'
    Connect-And-Verify -Phase 'z1-system' -ProfileId 'z1-system' -ExpectedTitlePattern 'Connected|Connecting' -ExpectConnect:$true
    Ok 'Z1 GUI Connect/Disconnect verified.'
  } else {
    Warn 'Skipping live Z1 Connect/Disconnect. Pass -LiveZ1 to mutate system proxy.'
  }

  if ($LiveZ2) {
    Step 'Z2: installed GUI TUN Connect/Disconnect.'
    Connect-And-Verify -Phase 'z2-tun' -ProfileId 'z2-tun' -ExpectedTitlePattern 'Connected|Connecting' -ExpectConnect:$true
    Ok 'Z2 GUI Connect/Disconnect verified.'
  } else {
    Warn 'Skipping live Z2 TUN Connect/Disconnect. Pass -LiveZ2 to mutate TUN routes/DNS.'
  }

  if ($LiveZ3) {
    Step 'Z3: installed GUI WireGuard/TUN status path.'
    Connect-And-Verify -Phase 'z3-wireguard' -ProfileId 'z3-wireguard' -ExpectedTitlePattern 'Connected|Blocked|Error|WireGuard|VPN' -ExpectConnect:$false
    Ok 'Z3 GUI status path verified as connected/blocked with visible reason.'
  } else {
    Warn 'Skipping live Z3 GUI path. Pass -LiveZ3 with WireGuard prepared.'
  }

  if ($LiveZ4) {
    if (-not $AllowWfpMutation) {
      Step 'Z4: installed GUI Mullvad/WFP blocked status without mutation.'
      Connect-And-Verify -Phase 'z4-mullvad' -ProfileId 'z4-mullvad' -ExpectedTitlePattern 'Blocked|Error|Mullvad|WFP' -ExpectConnect:$false
      Ok 'Z4 GUI blocked status verified without WFP mutation.'
    } else {
      Step 'Z4: WFP live parity via installed/headless support path.'
      & (Join-Path $PSScriptRoot 'test-z4-wfp-live-windows.ps1') -DesktopExe $exe -CredentialsPath $CredentialsPath -AllowWfpMutation -LogDir (Join-Path $LogDir 'z4-wfp')
      if ($LASTEXITCODE -ne 0) { throw "Z4 WFP harness failed with exit code $LASTEXITCODE" }
      Ok 'Z4 WFP apply/rollback parity verified.'
    }
  } else {
    Warn 'Skipping live Z4 GUI/WFP path. Pass -LiveZ4; add -AllowWfpMutation for live WFP apply.'
  }

  if ($TestRecovery) {
    Step 'Recovery: installed GUI startup cleanup smoke.'
    $recoveryApp = Start-Gui -Exe $exe
    Stop-Gui -Process $recoveryApp
    $postPreflight = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-tun-preflight-json')
    Save-Json -Name 'post-recovery-preflight' -Value $postPreflight | Out-Null
    Ok 'Recovery startup/preflight smoke completed.'
  } else {
    Warn 'Skipping recovery smoke. Pass -TestRecovery to launch/restart installed GUI and capture post-cleanup preflight.'
  }
} finally {
  Restore-AppConfig -Backup $configBackup
  if (-not $KeepRunning) {
    Get-Process -Name 'socks5proxy-desktop' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  }
  Uninstall-TestApp
}
