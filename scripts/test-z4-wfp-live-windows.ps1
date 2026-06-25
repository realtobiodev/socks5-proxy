param(
  [string]$CredentialsPath,
  [string]$DesktopExe,
  [string]$LogDir = '.build\z4-wfp-live',
  [switch]$AllowWfpMutation,
  [switch]$TestReconnect,
  [int]$ReconnectTimeoutSeconds = 120,
  [switch]$KeepApplied,
  [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($Message) { Write-Host "[Z4-WFP] $Message" -ForegroundColor Cyan }
function Ok($Message) { Write-Host "[OK] $Message" -ForegroundColor Green }
function Warn($Message) { Write-Warning $Message }

function Test-Administrator {
  return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Relaunch-Elevated {
  if ((Test-Administrator) -or $NoElevate) { return }

  $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-NoElevate')
  foreach ($key in $PSBoundParameters.Keys) {
    if ($key -eq 'NoElevate') { continue }
    $value = $PSBoundParameters[$key]
    if ($value -is [switch] -or $value -is [bool]) {
      if ($value) { $arguments += "-$key" }
    } else {
      $arguments += @("-$key", [string]$value)
    }
  }

  Step 'Relaunching elevated for guarded WFP mutation test.'
  $process = Start-Process -FilePath 'powershell.exe' -ArgumentList $arguments -Verb RunAs -Wait -PassThru
  exit $process.ExitCode
}

function Resolve-RepoPath {
  param([string]$Path)
  if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
  return (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path $Path)
}

function Resolve-DesktopExe {
  if ($DesktopExe) {
    $resolved = Resolve-RepoPath $DesktopExe
    if (Test-Path -LiteralPath $resolved) { return (Resolve-Path -LiteralPath $resolved).Path }
    throw "Desktop executable not found: $resolved"
  }

  $candidates = @(
    'target\debug\socks5proxy-desktop.exe',
    'target\release\socks5proxy-desktop.exe',
    'build-artifacts\windows\socks5proxy-desktop.exe'
  )
  foreach ($candidate in $candidates) {
    $path = Resolve-RepoPath $candidate
    if (Test-Path -LiteralPath $path) { return (Resolve-Path -LiteralPath $path).Path }
  }
  throw 'Could not locate socks5proxy-desktop.exe. Build or pass -DesktopExe.'
}

function Resolve-MullvadCli {
  $candidates = New-Object System.Collections.Generic.List[string]
  if ($env:MULLVAD_CLI) { $candidates.Add($env:MULLVAD_CLI) }
  if ($env:ProgramFiles) { $candidates.Add((Join-Path $env:ProgramFiles 'Mullvad VPN\resources\mullvad.exe')) }
  if (${env:ProgramFiles(x86)}) { $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'Mullvad VPN\resources\mullvad.exe')) }
  $command = Get-Command 'mullvad.exe' -ErrorAction SilentlyContinue
  if ($command) { $candidates.Add($command.Source) }

  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }
  return $null
}

function Read-FirstProxyEntry {
  param([string]$Path)

  $resolved = Resolve-RepoPath $(if ($Path) { $Path } else { 'testdata\proxy_creds.txt' })
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

function Resolve-ProxyIpv4 {
  param($Proxy)

  $addresses = [System.Net.Dns]::GetHostAddresses([string]$Proxy.Host) |
    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
    ForEach-Object { $_.IPAddressToString } |
    Select-Object -Unique
  if (@($addresses).Count -eq 0) {
    throw "Proxy host $($Proxy.Host) did not resolve to IPv4. Current WFP apply supports IPv4 conditions only."
  }
  return @($addresses)[0]
}

function Invoke-HeadlessJson {
  param(
    [string]$Exe,
    [string[]]$Arguments,
    [bool]$Mutation
  )

  $previous = [Environment]::GetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', 'Process')
  try {
    if ($Mutation) {
      [Environment]::SetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', '1', 'Process')
    } else {
      [Environment]::SetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', $null, 'Process')
    }
    $raw = & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) {
      throw "$Exe $($Arguments -join ' ') exited with $LASTEXITCODE. Raw: $raw"
    }
    $rawText = (($raw | Out-String).Trim())
    $start = $rawText.IndexOf('{')
    $end = $rawText.LastIndexOf('}')
    if ($start -lt 0 -or $end -lt $start) {
      throw "Headless command did not return JSON. Raw: $rawText"
    }
    return ($rawText.Substring($start, $end - $start + 1) | ConvertFrom-Json)
  } finally {
    [Environment]::SetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', $previous, 'Process')
  }
}

function Save-Json {
  param([string]$Name, $Value)
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $path = Join-Path $LogDir "$Name.json"
  $Value | ConvertTo-Json -Depth 12 | Set-Content -Path $path -Encoding UTF8
  return $path
}

function Get-MullvadEndpointKey {
  param($Preflight)
  $mullvad = $Preflight.mullvad
  @(
    [string]$mullvad.endpoint_address,
    [string]$mullvad.relay_hostname,
    [string]$mullvad.relay_ipv4,
    [string]$mullvad.tunnel_interface
  ) -join '|'
}

function Assert-MullvadConnected {
  param($Preflight)

  if (-not $Preflight.mullvad -or -not ([string]$Preflight.mullvad.state).ToLowerInvariant().StartsWith('connected')) {
    throw "Mullvad is not connected; Z4 WFP exception is not required. State: $($Preflight.mullvad.state)"
  }
  if ($Preflight.mullvad.mullvad_exit_ip -eq $false) {
    throw 'Mullvad does not report the visible IP as a Mullvad exit IP.'
  }
}

function Assert-WfpScope {
  param($Apply)

  $roleSpecs = if ($Apply.PSObject.Properties['apply_readiness_role_specs']) {
    @($Apply.apply_readiness_role_specs)
  } else {
    @()
  }
  if (@($roleSpecs).Count -gt 0) {
    $roles = @($roleSpecs | ForEach-Object { $_.role })
    foreach ($required in @('provider', 'sublayer', 'allow_tun2proxy', 'allow_controller', 'enforce_proxy_vpn_route', 'allow_mullvad_transport')) {
      if ($roles -notcontains $required) {
        throw "WFP apply readiness is missing role '$required'."
      }
    }

    foreach ($role in @('allow_tun2proxy', 'allow_controller', 'enforce_proxy_vpn_route', 'allow_mullvad_transport')) {
      $spec = @($roleSpecs | Where-Object { $_.role -eq $role })[0]
      if (-not $spec.ready) { throw "WFP role $role is not ready: $($spec.blockers -join '; ')" }
      if (@($spec.conditions).Count -eq 0) {
        throw "WFP role $role has no conditions; refusing broad allow."
      }
    }
  } else {
    Warn 'WFP apply readiness role summary is not present in this JSON payload; falling back to top-level readiness fields.'
    if (-not [bool]$Apply.apply_readiness_ready) {
      $fallbackBlockers = @($Apply.apply_readiness_blockers)
      throw "WFP apply readiness is not ready: $($fallbackBlockers -join '; ')"
    }
  }
  $context = $Apply.apply_readiness_context
  if (-not $context.proxy_ip -or $context.proxy_ip_error) {
    throw "WFP context has invalid proxy IP: $($context.proxy_ip_error)"
  }
  if (-not $context.app_path -or -not $context.tun2proxy_path) {
    throw 'WFP context does not include both controller and tun2proxy paths.'
  }
  if (-not $context.mullvad_tunnel_interface -or -not $context.mullvad_tunnel_interface_index) {
    throw 'WFP context does not include Mullvad tunnel interface/index.'
  }
  if (-not $context.mullvad_endpoint_ip -or $context.mullvad_endpoint_ip_error) {
    throw "WFP context has invalid Mullvad endpoint IP: $($context.mullvad_endpoint_ip_error)"
  }
}

function Assert-ApplyReport {
  param($Apply)

  if (-not $Apply.ok) {
    $raw = $Apply | ConvertTo-Json -Depth 8
    $errorText = if ($Apply.PSObject.Properties['error']) { [string]$Apply.error } else { '' }
    if ($errorText -like '*failed to open Windows Filtering Platform engine for apply: 0x00000032*') {
      throw "WFP apply could not open the Windows Filtering Platform engine (0x00000032). This is no longer a guard-session problem when reproduced under .\scripts\run-guarded-windows-live-test.ps1; it indicates the current WFP mutation path failed on this machine/build. Use the supported end-to-end guarded path if you have not tried it yet: powershell -ExecutionPolicy Bypass -File .\scripts\run-guarded-windows-live-test.ps1 -Name z4-wfp-reconnect -Command `"powershell -ExecutionPolicy Bypass -File .\scripts\test-z4-windows.ps1 -Live -AllowWfpMutation -TestReconnect`". Raw: $raw"
    }
    throw "WFP apply JSON reported ok=false: $raw"
  }
  if ($Apply.report.status -ne 'applied') {
    throw "WFP apply did not apply filters. Status=$($Apply.report.status); blockers=$($Apply.report.blockers -join '; '); errors=$($Apply.report.errors -join '; ')"
  }
  if (@($Apply.report.applied).Count -lt 4) {
    throw "WFP apply reported too few runtime filters: $(@($Apply.report.applied).Count)"
  }
}

function Assert-RollbackReport {
  param($Rollback)

  if (-not $Rollback.ok) { throw "WFP rollback JSON reported ok=false: $($Rollback | ConvertTo-Json -Depth 8)" }
  if ($Rollback.report.status -ne 'rolled_back') {
    throw "WFP rollback did not complete. Status=$($Rollback.report.status); blockers=$($Rollback.report.blockers -join '; '); errors=$($Rollback.report.errors -join '; ')"
  }
}

function Invoke-MullvadReconnect {
  param([string]$MullvadCli)

  if (-not $MullvadCli) { throw 'mullvad.exe was not found; cannot test reconnect/relay change.' }
  Step 'Requesting Mullvad reconnect.'
  $output = & $MullvadCli reconnect 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "mullvad reconnect failed: $($output -join ' ')"
  }
}

function Wait-MullvadReconnected {
  param(
    [string]$Exe,
    [string]$PreviousEndpointKey
  )

  $deadline = (Get-Date).AddSeconds($ReconnectTimeoutSeconds)
  $last = $null
  do {
    Start-Sleep -Seconds 3
    $last = Invoke-HeadlessJson -Exe $Exe -Arguments @('--windows-tun-preflight-json') -Mutation:$false
    if ($last.mullvad -and ([string]$last.mullvad.state).ToLowerInvariant().StartsWith('connected')) {
      $currentKey = Get-MullvadEndpointKey -Preflight $last
      if ($currentKey -ne $PreviousEndpointKey) {
        Ok "Mullvad endpoint changed: $PreviousEndpointKey -> $currentKey"
      } else {
        Warn 'Mullvad reconnected but reported the same endpoint; validating reapply/cleanup anyway.'
      }
      return $last
    }
  } while ((Get-Date) -lt $deadline)

  throw "Mullvad did not return to connected state within $ReconnectTimeoutSeconds seconds."
}

Relaunch-Elevated

$exe = Resolve-DesktopExe
$proxy = Parse-ProxyEntry (Read-FirstProxyEntry -Path $CredentialsPath)
$proxyIp = Resolve-ProxyIpv4 -Proxy $proxy

Step "Using desktop executable: $exe"
Step "Using proxy IPv4 for WFP conditions: $proxyIp"

$preflight = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-tun-preflight-json') -Mutation:$false
Save-Json -Name 'preflight' -Value $preflight | Out-Null
Assert-MullvadConnected -Preflight $preflight

if (-not $preflight.wfp_exception_plan.required) {
  throw 'WFP exception plan is not required while Mullvad is connected; refusing ambiguous Z4 apply.'
}
if (-not $preflight.wfp_operation_plan.required) {
  throw 'WFP operation plan is not required while Mullvad is connected; refusing ambiguous Z4 apply.'
}
Ok 'Mullvad is connected and WFP exception plan is required.'

$guard = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-wfp-apply-json', '--proxy-ip', $proxyIp) -Mutation:$false
Save-Json -Name 'apply-guard' -Value $guard | Out-Null
if ($guard.report.attempted -eq $true -or $guard.report.status -ne 'blocked') {
  throw 'WFP apply guard did not block mutation without SOCKS5PROXY_ENABLE_WFP_MUTATION=1.'
}
Ok 'WFP apply guard blocks mutation without explicit opt-in.'

if (-not $AllowWfpMutation) {
  throw 'Guarded dry-run complete. Re-run with -AllowWfpMutation to install and rollback the Z4 WFP exception.'
}

$apply = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-wfp-apply-json', '--proxy-ip', $proxyIp) -Mutation:$true
Save-Json -Name 'apply-live' -Value $apply | Out-Null
Assert-WfpScope -Apply $apply
Assert-ApplyReport -Apply $apply
Ok 'WFP exception applied with scoped process/IP/interface conditions.'

if ($KeepApplied) {
  Warn 'Leaving WFP filters applied because -KeepApplied was set.'
  return
}

$rollback = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-wfp-rollback-json') -Mutation:$true
Save-Json -Name 'rollback-live' -Value $rollback | Out-Null
Assert-RollbackReport -Rollback $rollback
Ok 'WFP exception rollback completed.'

$rollbackCheck = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-wfp-rollback-json') -Mutation:$true
Save-Json -Name 'rollback-live-idempotent' -Value $rollbackCheck | Out-Null
Assert-RollbackReport -Rollback $rollbackCheck
Ok 'WFP rollback is idempotent after cleanup.'

if ($TestReconnect) {
  $beforeReconnectKey = Get-MullvadEndpointKey -Preflight $preflight
  $mullvadCli = Resolve-MullvadCli
  Invoke-MullvadReconnect -MullvadCli $mullvadCli
  $afterReconnect = Wait-MullvadReconnected -Exe $exe -PreviousEndpointKey $beforeReconnectKey
  Save-Json -Name 'preflight-after-reconnect' -Value $afterReconnect | Out-Null
  Assert-MullvadConnected -Preflight $afterReconnect

  Step 'Re-applying WFP exception after Mullvad reconnect/relay refresh.'
  $reapply = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-wfp-apply-json', '--proxy-ip', $proxyIp) -Mutation:$true
  Save-Json -Name 'apply-after-reconnect' -Value $reapply | Out-Null
  Assert-WfpScope -Apply $reapply
  Assert-ApplyReport -Apply $reapply
  Ok 'WFP exception re-applied after Mullvad reconnect.'

  $rerollback = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-wfp-rollback-json') -Mutation:$true
  Save-Json -Name 'rollback-after-reconnect' -Value $rerollback | Out-Null
  Assert-RollbackReport -Rollback $rerollback
  Ok 'WFP cleanup after reconnect completed.'

  $rerollbackCheck = Invoke-HeadlessJson -Exe $exe -Arguments @('--windows-wfp-rollback-json') -Mutation:$true
  Save-Json -Name 'rollback-after-reconnect-idempotent' -Value $rerollbackCheck | Out-Null
  Assert-RollbackReport -Rollback $rerollbackCheck
  Ok 'WFP reconnect cleanup is idempotent.'
}
