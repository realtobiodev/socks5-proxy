param(
  [string]$CredentialsPath = 'testdata\proxy_creds.txt',
  [string]$InstallerPath = 'build-artifacts\windows\SOCKS5Proxy_1.0.0_x64-setup.exe',
  [string]$InstallDir = '.build\z2-installed-gui\app',
  [string]$LogDir = '.build\z2-installed-gui',
  [string]$TunAdapterName = 's5pz2test',
  [int]$ActivationTimeoutSeconds = 90,
  [int]$RecoveryTimeoutSeconds = 90,
  [int]$PollSeconds = 2,
  [switch]$SkipInstall,
  [switch]$KeepInstall,
  [switch]$KeepConfig,
  [switch]$KeepRunning
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($Message) { Write-Host "[Z2-GUI] $Message" -ForegroundColor Cyan }
function Ok($Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn($Message) { Write-Warning $Message }

function Test-Administrator {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Relaunch-Elevated {
  if (Test-Administrator) { return }

  $script = $PSCommandPath
  $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script)
  foreach ($key in $PSBoundParameters.Keys) {
    $value = $PSBoundParameters[$key]
    if ($value -is [switch] -or $value -is [bool]) {
      if ($value) { $arguments += "-$key" }
    } else {
      $arguments += @("-$key", [string]$value)
    }
  }

  Step 'Relaunching elevated for installer + TUN GUI test.'
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
  if (-not (Test-Path -LiteralPath $resolved)) {
    throw "Credentials file not found: $resolved"
  }

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
  if (-not $match.Success) {
    throw "Unsupported proxy credential format: $Entry"
  }

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

function Write-Z2GuiConfig {
  param($Proxy)

  $path = Get-AppConfigPath
  $dir = Split-Path -Parent $path
  New-Item -ItemType Directory -Force -Path $dir | Out-Null

  $toml = @"
enabled = false
selected_profile_id = "z2-installed-gui"
active_profile_id = "z2-installed-gui"

[tray_settings]
exit_ip_lookup_enabled = true
geo_lookup_enabled = true
display_mode = "flag"
ip_prefix_segments = 2
refresh_interval_secs = 300

[[profiles]]
id = "z2-installed-gui"
name = "Z2 Installed GUI"
routing_mode = "tun"
proxy_dns = true
startup_cleanup_enabled = true
bypass = []

[profiles.target]
kind = "structured"
host = $(ConvertTo-TomlString $Proxy.Host)
port = $($Proxy.Port)
selected_credential_id = "cred-z2-installed-gui"

[[profiles.target.credentials]]
id = "cred-z2-installed-gui"
label = "Primary"
username = $(ConvertTo-TomlString $Proxy.Username)
password = $(ConvertTo-TomlString $Proxy.Password)
"@

  Set-Content -Path $path -Value $toml -Encoding UTF8
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
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
    Copy-Item -LiteralPath $Backup -Destination $path -Force
  } elseif (Test-Path -LiteralPath $path) {
    Remove-Item -LiteralPath $path -Force
  }
}

function Install-App {
  if ($SkipInstall) { return }

  $installer = Resolve-RepoPath $InstallerPath
  if (-not (Test-Path -LiteralPath $installer)) {
    throw "Installer not found: $installer"
  }

  $installPath = Resolve-RepoPath $InstallDir
  New-Item -ItemType Directory -Force -Path $installPath | Out-Null
  Step "Installing app from $installer"
  $process = Start-Process -FilePath $installer -ArgumentList @('/S', "/D=$installPath") -Wait -PassThru
  if ($process.ExitCode -ne 0) {
    throw "Installer failed with exit code $($process.ExitCode)"
  }
}

function Resolve-InstalledExe {
  $candidates = @(
    (Join-Path (Resolve-RepoPath $InstallDir) 'socks5proxy-desktop.exe'),
    (Join-Path (Resolve-RepoPath $InstallDir) 'SOCKS5Proxy.exe'),
    (Join-Path $env:LOCALAPPDATA 'Programs\SOCKS5Proxy\socks5proxy-desktop.exe'),
    (Join-Path $env:ProgramFiles 'SOCKS5Proxy\socks5proxy-desktop.exe'),
    (Resolve-RepoPath 'build-artifacts\windows\socks5proxy-desktop.exe')
  )

  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }

  throw "Could not locate installed socks5proxy desktop executable."
}

function Uninstall-TestApp {
  if ($SkipInstall -or $KeepInstall) { return }

  $installPath = Resolve-RepoPath $InstallDir
  if (-not (Test-Path -LiteralPath $installPath)) { return }

  $uninstallers = @(
    (Join-Path $installPath 'uninstall.exe'),
    (Join-Path $installPath 'Uninstall SOCKS5Proxy.exe'),
    (Join-Path $installPath 'unins000.exe')
  )

  foreach ($uninstaller in $uninstallers) {
    if (Test-Path -LiteralPath $uninstaller) {
      Step "Removing test install via $uninstaller"
      Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait | Out-Null
      return
    }
  }

  $buildRoot = (Resolve-Path (Resolve-RepoPath '.build')).Path
  $resolvedInstall = (Resolve-Path -LiteralPath $installPath).Path
  if ($resolvedInstall.StartsWith($buildRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    Remove-Item -LiteralPath $resolvedInstall -Recurse -Force
  } else {
    Warn "No uninstaller found and install dir is outside .build; leaving $resolvedInstall in place."
  }
}

function Get-SystemProxySnapshot {
  $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  $props = Get-ItemProperty -Path $path
  $snapshot = [ordered]@{}
  foreach ($name in @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')) {
    $snapshot[$name] = if ($props.PSObject.Properties.Name -contains $name) { $props.$name } else { $null }
  }
  [PSCustomObject]$snapshot
}

function Compare-SystemProxySnapshot {
  param($Expected, $Actual)
  $diffs = @()
  foreach ($name in $Expected.PSObject.Properties.Name) {
    if ([string]$Expected.$name -ne [string]$Actual.$name) {
      $diffs += "$name expected '$($Expected.$name)' but found '$($Actual.$name)'"
    }
  }
  return $diffs
}

function Save-NetworkSnapshot {
  param([string]$Name)

  $managedAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq $TunAdapterName -or $_.Name -match '^s5p' -or $_.InterfaceDescription -match 'tun2proxy|socks5proxy' } |
    Select-Object Name, InterfaceDescription, Status, ifIndex)

  $snapshot = [PSCustomObject]@{
    CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
    SystemProxy = Get-SystemProxySnapshot
    ManagedAdapters = $managedAdapters
    Routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceAlias -eq $TunAdapterName -or $_.InterfaceIndex -in @($managedAdapters | ForEach-Object { $_.ifIndex }) -or $_.DestinationPrefix -in @('0.0.0.0/0', '::/0') } |
      Select-Object DestinationPrefix, InterfaceAlias, InterfaceIndex, NextHop, RouteMetric, ifMetric)
    DnsServers = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
      Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses)
  }

  $path = Join-Path $LogDir "$Name-network-state.json"
  $snapshot | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
  return $snapshot
}

function Get-ManagedZ2Adapters {
  @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Name -eq $TunAdapterName -or
      $_.Name -match '^s5p' -or
      $_.InterfaceDescription -match 'tun2proxy|socks5proxy'
    })
}

function Test-Internet {
  try {
    [void][System.Net.Dns]::GetHostAddresses('example.com')
    $response = Invoke-WebRequest -Uri 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 12
    return -not [string]::IsNullOrWhiteSpace($response.Content)
  } catch {
    Warn "Internet probe failed: $($_.Exception.Message)"
    return $false
  }
}

function Test-ActiveZ2 {
  $adapters = @(Get-ManagedZ2Adapters | Where-Object { $_.Status -eq 'Up' })
  if ($adapters.Count -eq 0) { return $false }

  foreach ($adapter in $adapters) {
    $routes = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
      Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' })
    $dns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
      Where-Object { @($_.ServerAddresses).Count -gt 0 })

    if ($routes.Count -gt 0 -and $dns.Count -gt 0) {
      return $true
    }
  }

  return $false
}

function Test-RecoveredNetwork {
  param($BaselineProxy)

  $errors = New-Object System.Collections.Generic.List[string]
  if (-not (Test-Internet)) { $errors.Add('internet probe failed') }

  $managedAdapters = @(Get-ManagedZ2Adapters)
  $activeManaged = @($managedAdapters | Where-Object { $_.Status -eq 'Up' })
  if ($activeManaged.Count -gt 0) {
    $errors.Add("managed adapter still active: $(@($activeManaged | ForEach-Object { $_.Name }) -join ', ')")
  }

  $managedIfIndexes = @($managedAdapters | ForEach-Object { $_.ifIndex })
  if ($managedIfIndexes.Count -gt 0) {
    $routes = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -in $managedIfIndexes })
    if ($routes.Count -gt 0) {
      $errors.Add("managed routes still present: $(@($routes | ForEach-Object { $_.DestinationPrefix }) -join ', ')")
    }
    $dns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceIndex -in $managedIfIndexes -and @($_.ServerAddresses).Count -gt 0 })
    if ($dns.Count -gt 0) {
      $errors.Add("managed DNS servers still present: $(@($dns | ForEach-Object { $_.InterfaceAlias }) -join ', ')")
    }
  }

  foreach ($diff in @(Compare-SystemProxySnapshot -Expected $BaselineProxy -Actual (Get-SystemProxySnapshot))) {
    $errors.Add("system proxy not restored: $diff")
  }

  return $errors
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

function Initialize-UiAutomation {
  Add-Type -AssemblyName UIAutomationClient
  Add-Type -AssemblyName UIAutomationTypes
}

function Find-AppWindow {
  param([int]$ProcessId)

  $root = [Windows.Automation.AutomationElement]::RootElement
  $condition = New-Object Windows.Automation.PropertyCondition(
    [Windows.Automation.AutomationElement]::ProcessIdProperty,
    $ProcessId
  )
  return $root.FindFirst([Windows.Automation.TreeScope]::Children, $condition)
}

function Invoke-AppButton {
  param(
    [int]$ProcessId,
    [string[]]$Names,
    [int]$TimeoutSeconds
  )

  Initialize-UiAutomation
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $window = Find-AppWindow -ProcessId $ProcessId
    if ($window) {
      foreach ($name in $Names) {
        $nameCondition = New-Object Windows.Automation.PropertyCondition(
          [Windows.Automation.AutomationElement]::NameProperty,
          $name
        )
        $button = $window.FindFirst([Windows.Automation.TreeScope]::Descendants, $nameCondition)
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

Relaunch-Elevated

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$configBackup = $null
$app = $null

try {
  Step 'Capturing baseline network and app config.'
  $configBackup = Backup-AppConfig
  $baseline = Save-NetworkSnapshot -Name 'baseline'
  if (-not (Test-Internet)) {
    throw 'Baseline internet probe failed; refusing to start GUI test.'
  }

  $proxy = Parse-ProxyEntry (Read-FirstProxyEntry -Path $CredentialsPath)
  $configPath = Write-Z2GuiConfig -Proxy $proxy
  Ok "Wrote GUI test config to $configPath"

  Install-App
  $exe = Resolve-InstalledExe
  Ok "Using installed app executable: $exe"

  Step 'Launching installed GUI app.'
  $app = Start-Process -FilePath $exe -PassThru
  Ok "GUI process pid=$($app.Id)"

  Step 'Clicking Connect through the GUI.'
  if (-not (Invoke-AppButton -ProcessId $app.Id -Names @('Connect', 'Reconnect', 'Activate') -TimeoutSeconds 45)) {
    throw 'Could not find or invoke the GUI Connect button via Windows UI Automation.'
  }

  if (-not (Wait-Until -TimeoutSeconds $ActivationTimeoutSeconds -WaitingFor 'active Z2 state from installed GUI' -Condition { Test-ActiveZ2 })) {
    throw 'Installed GUI did not bring Z2 TUN routing up.'
  }
  Save-NetworkSnapshot -Name 'active' | Out-Null
  Ok 'Installed GUI brought Z2 TUN routing up.'

  Step 'Clicking Disconnect through the GUI.'
  if (-not (Invoke-AppButton -ProcessId $app.Id -Names @('Disconnect', 'Stop') -TimeoutSeconds 30)) {
    throw 'Could not find or invoke the GUI Disconnect button via Windows UI Automation.'
  }

  $recovered = Wait-Until -TimeoutSeconds $RecoveryTimeoutSeconds -WaitingFor 'restored network after GUI disconnect' -Condition {
    $errors = @(Test-RecoveredNetwork -BaselineProxy $baseline.SystemProxy)
    return $errors.Count -eq 0
  }
  Save-NetworkSnapshot -Name 'post-disconnect' | Out-Null

  if (-not $recovered) {
    $errors = @(Test-RecoveredNetwork -BaselineProxy $baseline.SystemProxy)
    throw "Installed GUI disconnect did not restore cleanly: $($errors -join '; ')"
  }

  Ok 'Installer + GUI Z2 path verified: connect and disconnect restore internet, routes, DNS, adapter and system proxy.'
} finally {
  Restore-AppConfig -Backup $configBackup
  if ($app -and -not $app.HasExited -and -not $KeepRunning) {
    Stop-Process -Id $app.Id -Force -ErrorAction SilentlyContinue
  }
  Uninstall-TestApp
}
