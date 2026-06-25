param(
  [string]$SystemProxySnapshot,
  [switch]$DisableSystemProxy,
  [switch]$RestoreDnsServers,
  [switch]$RenewDhcp,
  [switch]$NoKillTun2Proxy,
  [string[]]$TunAdapterName = @('s5pz2test'),
  [switch]$RemoveTunRoutes,
  [switch]$DisableStaleTunAdapter,
  [switch]$VerifyCleanup
)

$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Warning $m }

function Notify-ProxyChanged {
  try {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class WinInetNotify {
  [DllImport("wininet.dll", SetLastError = true)]
  public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
}
'@ -ErrorAction SilentlyContinue | Out-Null
    [WinInetNotify]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
    [WinInetNotify]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
  } catch {
    Warn "Could not broadcast proxy change: $($_.Exception.Message)"
  }
}

function Restore-SystemProxySnapshot {
  param([string]$Path)
  if (-not (Test-Path $Path)) {
    Warn "System proxy snapshot not found: $Path"
    return
  }
  $snapshot = Get-Content -Raw -Path $Path | ConvertFrom-Json
  $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  if ($null -ne $snapshot.ProxyEnable) {
    Set-ItemProperty -Path $key -Name ProxyEnable -Type DWord -Value ([int]$snapshot.ProxyEnable)
  }
  if ($null -ne $snapshot.ProxyServer -and $snapshot.ProxyServer -ne '') {
    Set-ItemProperty -Path $key -Name ProxyServer -Type String -Value ([string]$snapshot.ProxyServer)
  } else {
    Remove-ItemProperty -Path $key -Name ProxyServer -ErrorAction SilentlyContinue
  }
  Notify-ProxyChanged
  Ok 'System proxy restored from snapshot.'
}

function Restore-DnsSnapshot {
  param([string]$Path)
  if (-not (Test-Path $Path)) {
    Warn "DNS snapshot not found: $Path"
    return
  }
  $snapshot = Get-Content -Raw -Path $Path | ConvertFrom-Json
  if (-not $snapshot.DnsClientServers) {
    Warn 'Snapshot does not contain DNS client server data.'
    return
  }
  foreach ($group in @($snapshot.DnsClientServers | Group-Object InterfaceIndex)) {
    try {
      $servers = @($group.Group | ForEach-Object { @($_.ServerAddresses) } | Where-Object { $_ })
      if ($servers.Count -gt 0) {
        Set-DnsClientServerAddress -InterfaceIndex ([int]$group.Name) -ServerAddresses $servers -ErrorAction Stop
      } else {
        Set-DnsClientServerAddress -InterfaceIndex ([int]$group.Name) -ResetServerAddresses -ErrorAction Stop
      }
    } catch {
      Warn "Could not restore DNS servers for interface index $($group.Name): $($_.Exception.Message)"
    }
  }
  Ok 'DNS server settings restored from snapshot.'
}

function Disable-SystemProxy {
  $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  Set-ItemProperty -Path $key -Name ProxyEnable -Type DWord -Value 0
  Notify-ProxyChanged
  Ok 'System proxy disabled.'
}

function Get-ManagedTunAdapters {
  foreach ($name in $TunAdapterName) {
    if (-not $name) { continue }
    Get-NetAdapter -Name $name -ErrorAction SilentlyContinue
  }
}

function Get-RuntimeStatePath {
  if (-not $env:APPDATA) { return $null }
  Join-Path $env:APPDATA 'socks5proxy\runtime-state.toml'
}

function Get-PinnedProxyRoutesFromRuntimeState {
  $path = Get-RuntimeStatePath
  if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
  $routes = New-Object System.Collections.Generic.List[object]
  $current = $null
  foreach ($line in Get-Content -LiteralPath $path -ErrorAction SilentlyContinue) {
    $trimmed = $line.Trim()
    if ($trimmed -eq '[[pinned_proxy_routes]]') {
      if ($current) { $routes.Add([pscustomobject]$current) }
      $current = @{}
      continue
    }
    if (-not $current) { continue }
    if ($trimmed -match '^destination_prefix\s*=\s*"([^"]+)"') {
      $current.DestinationPrefix = $Matches[1]
    } elseif ($trimmed -match '^interface_index\s*=\s*(\d+)') {
      $current.InterfaceIndex = [int]$Matches[1]
    } elseif ($trimmed -match '^next_hop\s*=\s*"([^"]*)"') {
      $current.NextHop = $Matches[1]
    }
  }
  if ($current) { $routes.Add([pscustomobject]$current) }
  @($routes | Where-Object {
    $_.DestinationPrefix -and $null -ne $_.InterfaceIndex -and $null -ne $_.NextHop
  })
}

function Remove-PinnedProxyRoutesFromRuntimeState {
  $routes = @(Get-PinnedProxyRoutesFromRuntimeState)
  if ($routes.Count -eq 0) {
    Ok 'No persisted pinned proxy routes found.'
    return
  }
  foreach ($route in $routes) {
    try {
      Remove-NetRoute `
        -DestinationPrefix ([string]$route.DestinationPrefix) `
        -InterfaceIndex ([int]$route.InterfaceIndex) `
        -NextHop ([string]$route.NextHop) `
        -Confirm:$false `
        -ErrorAction SilentlyContinue
    } catch {
      Warn "Could not remove pinned proxy route '$($route.DestinationPrefix)' on interface $($route.InterfaceIndex): $($_.Exception.Message)"
    }
  }
  Ok "Persisted pinned proxy route cleanup attempted for $($routes.Count) route(s)."
}

function Get-WfpFiltersFromRuntimeState {
  $path = Get-RuntimeStatePath
  if (-not $path -or -not (Test-Path -LiteralPath $path)) { return @() }
  $filters = New-Object System.Collections.Generic.List[object]
  $current = $null
  foreach ($line in Get-Content -LiteralPath $path -ErrorAction SilentlyContinue) {
    $trimmed = $line.Trim()
    if ($trimmed -eq '[[wfp_filters]]') {
      if ($current) { $filters.Add([pscustomobject]$current) }
      $current = @{}
      continue
    }
    if ($trimmed.StartsWith('[[') -and $trimmed -ne '[[wfp_filters]]') {
      if ($current) { $filters.Add([pscustomobject]$current); $current = $null }
      continue
    }
    if (-not $current) { continue }
    if ($trimmed -match '^filter_id\s*=\s*"([^"]+)"') {
      $current.FilterId = $Matches[1]
    } elseif ($trimmed -match '^layer\s*=\s*"([^"]*)"') {
      $current.Layer = $Matches[1]
    } elseif ($trimmed -match '^display_name\s*=\s*"([^"]*)"') {
      $current.DisplayName = $Matches[1]
    } elseif ($trimmed -match '^session_tag\s*=\s*"([^"]*)"') {
      $current.SessionTag = $Matches[1]
    }
  }
  if ($current) { $filters.Add([pscustomobject]$current) }
  @($filters | Where-Object { $_.FilterId -or $_.DisplayName -or $_.SessionTag })
}

function Report-PersistedWfpFilters {
  $filters = @(Get-WfpFiltersFromRuntimeState)
  if ($filters.Count -eq 0) {
    Ok 'No persisted WFP filter artifacts found.'
    return
  }
  Warn "Found $($filters.Count) persisted WFP filter artifact(s). Automatic WFP deletion is not implemented in this recovery script yet."
  foreach ($filter in $filters) {
    Warn "Persisted WFP filter: id=$($filter.FilterId); layer=$($filter.Layer); name=$($filter.DisplayName); tag=$($filter.SessionTag)"
  }
}

function Remove-ManagedTunRoutes {
  $adapters = @(Get-ManagedTunAdapters)
  if ($adapters.Count -eq 0) {
    Ok 'No managed TUN adapter found for route cleanup.'
    return
  }
  foreach ($adapter in $adapters) {
    try {
      $routes = @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex ([int]$adapter.ifIndex) -ErrorAction SilentlyContinue)
      foreach ($route in $routes) {
        Remove-NetRoute -AddressFamily IPv4 `
          -DestinationPrefix $route.DestinationPrefix `
          -InterfaceIndex ([int]$route.InterfaceIndex) `
          -NextHop $route.NextHop `
          -Confirm:$false `
          -ErrorAction SilentlyContinue
      }
      Ok "Route cleanup attempted for managed TUN adapter '$($adapter.Name)'."
    } catch {
      Warn "Could not clean routes for managed TUN adapter '$($adapter.Name)': $($_.Exception.Message)"
    }
  }
}

function Disable-StaleTunAdapters {
  $adapters = @(Get-ManagedTunAdapters)
  if ($adapters.Count -eq 0) {
    Ok 'No managed TUN adapter found to disable.'
    return
  }
  foreach ($adapter in $adapters) {
    try {
      Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
      Ok "Disabled stale managed TUN adapter '$($adapter.Name)'."
    } catch {
      Warn "Could not disable managed TUN adapter '$($adapter.Name)': $($_.Exception.Message)"
    }
  }
}

function Test-ManagedTunCleanup {
  $adapters = @(Get-ManagedTunAdapters)
  if ($adapters.Count -eq 0) {
    Ok 'Managed TUN adapter cleanup verified.'
    return
  }
  $leftoverRoutes = @()
  foreach ($adapter in $adapters) {
    $leftoverRoutes += @(Get-NetRoute -AddressFamily IPv4 -InterfaceIndex ([int]$adapter.ifIndex) -ErrorAction SilentlyContinue)
  }
  if ($leftoverRoutes.Count -gt 0) {
    $summary = ($leftoverRoutes | ForEach-Object { "$($_.DestinationPrefix) via $($_.NextHop) on ifIndex $($_.InterfaceIndex)" }) -join '; '
    throw "Managed TUN cleanup still sees $($leftoverRoutes.Count) IPv4 route(s): $summary"
  }
  throw "Managed TUN adapter still exists: $(@($adapters | ForEach-Object { $_.Name }) -join ', ')"
}

if (-not $NoKillTun2Proxy) {
  Step 'Stopping tun2proxy processes'
  Get-Process -Name 'tun2proxy-bin','tun2proxy' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Ok 'tun2proxy process cleanup attempted.'
}

if ($SystemProxySnapshot) {
  Step 'Restoring system proxy snapshot'
  Restore-SystemProxySnapshot -Path $SystemProxySnapshot
  if ($RestoreDnsServers) {
    Step 'Restoring DNS server settings'
    Restore-DnsSnapshot -Path $SystemProxySnapshot
  }
} elseif ($DisableSystemProxy) {
  Step 'Disabling system proxy'
  Disable-SystemProxy
}

Step 'Flushing DNS cache'
ipconfig /flushdns | Out-Null
Ok 'DNS cache flushed.'

if ($RenewDhcp) {
  Step 'Renewing DHCP leases'
  ipconfig /release | Out-Null
  ipconfig /renew | Out-Null
  Ok 'DHCP renew attempted.'
}

if ($RemoveTunRoutes) {
  Step 'Cleaning persisted pinned proxy routes'
  Remove-PinnedProxyRoutesFromRuntimeState

  Step 'Checking persisted WFP filter artifacts'
  Report-PersistedWfpFilters

  Step 'Cleaning managed TUN routes'
  Remove-ManagedTunRoutes
}

if ($DisableStaleTunAdapter) {
  Step 'Disabling stale managed TUN adapter'
  Disable-StaleTunAdapters
}

if ($VerifyCleanup) {
  Step 'Verifying managed TUN cleanup'
  Test-ManagedTunCleanup
}

Write-Host "`nNetwork restore finished." -ForegroundColor Green
