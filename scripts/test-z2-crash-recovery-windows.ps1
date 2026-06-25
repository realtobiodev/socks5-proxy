param(
  [string]$CredentialsPath,
  [int]$ActivationTimeoutSeconds = 90,
  [int]$RecoveryTimeoutSeconds = 90,
  [int]$PollSeconds = 2,
  [string]$TunAdapterName = 's5pz2test',
  [switch]$ProxyDns = $true,
  [switch]$AllowExperimentalMullvadTun,
  [switch]$TemporarilyDisconnectMullvad,
  [switch]$SkipDnsRouteCheck,
  [switch]$SkipDnsLeakProbe,
  [switch]$NoElevate,
  [string]$LogDir = '.build\z2-crash-recovery'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($Message) { Write-Host "[Z2-CRASH] $Message" -ForegroundColor Cyan }
function Ok($Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn($Message) { Write-Warning $Message }

function Test-Administrator {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Relaunch-Elevated {
  if ((Test-Administrator) -or $NoElevate) { return }

  $script = $PSCommandPath
  $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $script, '-NoElevate')
  foreach ($key in $PSBoundParameters.Keys) {
    if ($key -eq 'NoElevate') { continue }
    $value = $PSBoundParameters[$key]
    if ($value -is [switch] -or $value -is [bool]) {
      if ($value) { $arguments += "-$key" }
    } else {
      $arguments += @("-$key", [string]$value)
    }
  }

  Step 'Relaunching elevated for live network crash/recovery test.'
  $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -Wait -PassThru
  exit $process.ExitCode
}

function Resolve-RepoRoot {
  return (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
}

function Get-SystemProxySnapshot {
  $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  $props = Get-ItemProperty -Path $path
  $names = @('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')
  $snapshot = [ordered]@{}
  foreach ($name in $names) {
    $snapshot[$name] = if ($props.PSObject.Properties.Name -contains $name) { $props.$name } else { $null }
  }
  [PSCustomObject]$snapshot
}

function Compare-SystemProxySnapshot {
  param($Expected, $Actual)

  $diffs = @()
  foreach ($name in $Expected.PSObject.Properties.Name) {
    $expectedValue = $Expected.$name
    $actualValue = $Actual.$name
    if ([string]$expectedValue -ne [string]$actualValue) {
      $diffs += "$name expected '$expectedValue' but found '$actualValue'"
    }
  }
  return $diffs
}

function Get-NetworkSnapshot {
  param([string]$Name)

  $managedAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Name -eq $TunAdapterName -or
      $_.Name -match '^s5p' -or
      $_.InterfaceDescription -match 'tun2proxy|socks5proxy'
    } |
    Select-Object Name, InterfaceDescription, Status, ifIndex, MacAddress)

  $routes = @(Get-NetRoute -ErrorAction SilentlyContinue |
    Where-Object {
      $_.DestinationPrefix -eq '0.0.0.0/0' -or
      $_.DestinationPrefix -eq '::/0' -or
      $_.InterfaceAlias -eq $TunAdapterName -or
      $_.InterfaceIndex -in @($managedAdapters | ForEach-Object { $_.ifIndex })
    } |
    Select-Object DestinationPrefix, InterfaceAlias, InterfaceIndex, NextHop, RouteMetric, ifMetric)

  $dnsServers = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceAlias -ne 'Loopback Pseudo-Interface 1' } |
    Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ServerAddresses)

  [PSCustomObject]@{
    Name = $Name
    CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
    SystemProxy = Get-SystemProxySnapshot
    ManagedAdapters = $managedAdapters
    Routes = $routes
    DnsServers = $dnsServers
  }
}

function Save-Json {
  param(
    [string]$Name,
    $Value
  )

  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $path = Join-Path $LogDir "$Name.json"
  $Value | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
  return $path
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
  $adapter = Get-NetAdapter -Name $TunAdapterName -ErrorAction SilentlyContinue
  if (-not $adapter) { return $false }

  $hasTunRoute = @(Get-NetRoute -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' }).Count -gt 0

  $hasTunDns = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ErrorAction SilentlyContinue |
    Where-Object { @($_.ServerAddresses).Count -gt 0 }).Count -gt 0

  return ($adapter.Status -eq 'Up') -and $hasTunRoute -and $hasTunDns
}

function Test-RecoveredNetwork {
  param($Baseline)

  $errors = New-Object System.Collections.Generic.List[string]

  if (-not (Test-Internet)) {
    $errors.Add('internet probe failed after recovery')
  }

  try {
    [void][System.Net.Dns]::GetHostAddresses('example.com')
  } catch {
    $errors.Add("DNS resolution failed after recovery: $($_.Exception.Message)")
  }

  $managedAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Name -eq $TunAdapterName -or
      $_.Name -match '^s5p' -or
      $_.InterfaceDescription -match 'tun2proxy|socks5proxy'
    })
  $activeManagedAdapters = @($managedAdapters | Where-Object { $_.Status -eq 'Up' })
  if ($activeManagedAdapters.Count -gt 0) {
    $errors.Add("managed TUN adapter still active: $(@($activeManagedAdapters | ForEach-Object { $_.Name }) -join ', ')")
  }

  $managedIfIndexes = @($managedAdapters | ForEach-Object { $_.ifIndex })
  if ($managedIfIndexes.Count -gt 0) {
    $managedRoutes = @(Get-NetRoute -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceIndex -in $managedIfIndexes })
    if ($managedRoutes.Count -gt 0) {
      $errors.Add("routes still bound to managed adapter: $(@($managedRoutes | ForEach-Object { "$($_.DestinationPrefix) via if$($_.InterfaceIndex)" }) -join '; ')")
    }

    $managedDns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceIndex -in $managedIfIndexes -and @($_.ServerAddresses).Count -gt 0 })
    if ($managedDns.Count -gt 0) {
      $errors.Add("DNS servers still bound to managed adapter: $(@($managedDns | ForEach-Object { "$($_.InterfaceAlias) $($_.AddressFamily)=$($_.ServerAddresses -join ',')" }) -join '; ')")
    }
  }

  $proxyDiffs = @(Compare-SystemProxySnapshot -Expected $Baseline.SystemProxy -Actual (Get-SystemProxySnapshot))
  foreach ($diff in $proxyDiffs) {
    $errors.Add("system proxy not restored: $diff")
  }

  return $errors
}

function Wait-Until {
  param(
    [scriptblock]$Condition,
    [int]$TimeoutSeconds,
    [string]$WaitingFor
  )

  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    if (& $Condition) { return $true }
    Start-Sleep -Seconds $PollSeconds
  } while ((Get-Date) -lt $deadline)

  Warn "Timed out waiting for $WaitingFor."
  return $false
}

Relaunch-Elevated

$repoRoot = Resolve-RepoRoot
$z2Script = Join-Path $PSScriptRoot 'test-z2-windows.ps1'
if (-not (Test-Path -LiteralPath $z2Script)) {
  throw "Missing Z2 test script: $z2Script"
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

Step 'Capturing baseline network state.'
$baseline = Get-NetworkSnapshot -Name 'baseline'
$baselinePath = Save-Json -Name 'baseline-network-state' -Value $baseline
Ok "Baseline written to $baselinePath"

if (-not (Test-Internet)) {
  throw 'Baseline internet probe failed; refusing to start destructive crash test.'
}
Ok 'Baseline internet and DNS are reachable.'

$stdoutPath = Join-Path $LogDir 'z2-child.stdout.log'
$stderrPath = Join-Path $LogDir 'z2-child.stderr.log'
$arguments = @(
  '-NoProfile',
  '-ExecutionPolicy', 'Bypass',
  '-File', $z2Script,
  '-Live',
  '-NoElevate',
  '-TunAdapterName', $TunAdapterName,
  '-TimeoutSeconds', ([string]$ActivationTimeoutSeconds)
)

if ($CredentialsPath) { $arguments += @('-CredentialsPath', $CredentialsPath) }
if (-not $ProxyDns) { $arguments += '-ProxyDns:$false' }
if ($AllowExperimentalMullvadTun) { $arguments += '-AllowExperimentalMullvadTun' }
if ($TemporarilyDisconnectMullvad) { $arguments += '-TemporarilyDisconnectMullvad' }
if ($SkipDnsRouteCheck) { $arguments += '-SkipDnsRouteCheck' }
if ($SkipDnsLeakProbe) { $arguments += '-SkipDnsLeakProbe' }

Step 'Starting Z2 live session under child PowerShell.'
$child = Start-Process -FilePath 'powershell.exe' `
  -ArgumentList $arguments `
  -WorkingDirectory $repoRoot `
  -RedirectStandardOutput $stdoutPath `
  -RedirectStandardError $stderrPath `
  -PassThru `
  -WindowStyle Hidden

Ok "Child session pid=$($child.Id)"

try {
  Step 'Waiting for active Z2 TUN route and DNS state.'
  $activated = Wait-Until -TimeoutSeconds $ActivationTimeoutSeconds -WaitingFor 'Z2 active TUN state' -Condition {
    if ($child.HasExited) { return $false }
    return Test-ActiveZ2
  }

  if (-not $activated) {
    if (-not $child.HasExited) { Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
    throw "Z2 did not become active before crash injection. See $stdoutPath and $stderrPath."
  }

  $activePath = Save-Json -Name 'active-network-state' -Value (Get-NetworkSnapshot -Name 'active')
  Ok "Active Z2 state written to $activePath"

  Step 'Injecting crash by force-killing the Z2 PowerShell session.'
  Stop-Process -Id $child.Id -Force
  Ok "Killed child session pid=$($child.Id)"

  Step 'Waiting for watchdog/startup recovery to restore the network.'
  $recovered = Wait-Until -TimeoutSeconds $RecoveryTimeoutSeconds -WaitingFor 'clean recovered network state' -Condition {
    $errors = @(Test-RecoveredNetwork -Baseline $baseline)
    return $errors.Count -eq 0
  }

  $post = Get-NetworkSnapshot -Name 'post-recovery'
  $postPath = Save-Json -Name 'post-recovery-network-state' -Value $post

  if (-not $recovered) {
    $errors = @(Test-RecoveredNetwork -Baseline $baseline)
    throw "Z2 recovery did not complete cleanly: $($errors -join '; '). Post-state: $postPath"
  }

  Ok "Post-recovery state written to $postPath"
  Ok 'Z2 crash/recovery verified: internet, DNS, routes, managed adapter and system proxy are restored.'
} finally {
  if ($child -and -not $child.HasExited) {
    Warn "Cleaning up still-running child session pid=$($child.Id)."
    Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue
  }
}
