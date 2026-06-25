param(
  [string[]]$TunAdapterName = @('s5pz2test'),
  [switch]$CloseEdge,
  [switch]$ResetDnsServers,
  [switch]$RenewDhcp,
  [switch]$DisconnectMullvad
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

function Disable-SystemProxy {
  $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  Set-ItemProperty -Path $key -Name ProxyEnable -Type DWord -Value 0 -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path $key -Name ProxyServer -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path $key -Name AutoConfigURL -ErrorAction SilentlyContinue
  Notify-ProxyChanged
}

function Get-ManagedTunAdapters {
  $seen = @{}
  foreach ($name in $TunAdapterName) {
    if (-not $name) { continue }
    Get-NetAdapter -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
      $seen[[int]$_.ifIndex] = $_
    }
  }
  Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Name -like 's5p*' -or
      ($_.InterfaceDescription -match 'Wintun|tun2proxy|socks5proxy' -and $_.Name -notmatch 'Mullvad|WireGuard')
    } |
    ForEach-Object { $seen[[int]$_.ifIndex] = $_ }
  $seen.Values
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
  Warn "Found $($filters.Count) persisted WFP filter artifact(s). Automatic WFP deletion is not implemented in this emergency script yet."
  foreach ($filter in $filters) {
    Warn "Persisted WFP filter: id=$($filter.FilterId); layer=$($filter.Layer); name=$($filter.DisplayName); tag=$($filter.SessionTag)"
  }
}

function Remove-ManagedTunRoutes {
  $maxAttempts = 6
  for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    $adapters = @(Get-ManagedTunAdapters)
    if ($adapters.Count -eq 0) {
      Ok 'No managed socks5proxy TUN adapter found.'
      return
    }

    foreach ($adapter in $adapters) {
      try {
        foreach ($family in @('IPv4', 'IPv6')) {
          Get-NetRoute -AddressFamily $family -InterfaceIndex ([int]$adapter.ifIndex) -ErrorAction SilentlyContinue |
            ForEach-Object {
              Remove-NetRoute -AddressFamily $family `
                -DestinationPrefix $_.DestinationPrefix `
                -InterfaceIndex ([int]$_.InterfaceIndex) `
                -NextHop $_.NextHop `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
            }
        }

        Set-DnsClientServerAddress -InterfaceIndex ([int]$adapter.ifIndex) -ResetServerAddresses -ErrorAction SilentlyContinue
        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

        $adapterAfterDisable = Get-NetAdapter -InterfaceIndex ([int]$adapter.ifIndex) -ErrorAction SilentlyContinue
        if ($adapterAfterDisable -and $adapterAfterDisable.Status -eq 'Up') {
          netsh interface set interface name="$($adapter.Name)" admin=DISABLED | Out-Null
        }
      } catch {
        Warn "Could not clean managed TUN adapter '$($adapter.Name)': $($_.Exception.Message)"
      }
    }

    Start-Sleep -Seconds 2

    $remainingAdapters = @(Get-ManagedTunAdapters)
    $activeRemainingAdapters = @($remainingAdapters | Where-Object { $_.Status -eq 'Up' })
    $remainingIfIndexes = @($remainingAdapters | ForEach-Object { [int]$_.ifIndex })
    $remainingRoutes = @()
    $remainingDns = @()
    if ($remainingIfIndexes.Count -gt 0) {
      $remainingRoutes = @(Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceIndex -in $remainingIfIndexes })
      $remainingDns = @(Get-DnsClientServerAddress -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -in $remainingIfIndexes -and @($_.ServerAddresses).Count -gt 0 })
    }

    if ($activeRemainingAdapters.Count -eq 0 -and $remainingRoutes.Count -eq 0 -and $remainingDns.Count -eq 0) {
      Ok "Managed TUN cleanup completed after $attempt attempt(s)."
      return
    }

    $remainingBits = New-Object System.Collections.Generic.List[string]
    if ($activeRemainingAdapters.Count -gt 0) {
      $remainingBits.Add("active adapters: $(@($activeRemainingAdapters | ForEach-Object { $_.Name }) -join ', ')")
    }
    if ($remainingRoutes.Count -gt 0) {
      $remainingBits.Add("routes: $(@($remainingRoutes | Select-Object -First 6 | ForEach-Object { \"$($_.DestinationPrefix) via if$($_.InterfaceIndex)\" }) -join '; ')")
    }
    if ($remainingDns.Count -gt 0) {
      $remainingBits.Add("dns: $(@($remainingDns | Select-Object -First 4 | ForEach-Object { \"$($_.InterfaceAlias) $($_.AddressFamily)=$($_.ServerAddresses -join ',')\" }) -join '; ')")
    }
    Warn "Managed TUN cleanup attempt $attempt/$maxAttempts incomplete: $($remainingBits -join ' | ')"
  }

  Warn 'Managed TUN cleanup left residual adapter state after all retry attempts.'
}

function Stop-Tun2ProxyHelpers {
  $processes = @(Get-Process -Name 'tun2proxy-bin','tun2proxy' -ErrorAction SilentlyContinue)
  if ($processes.Count -eq 0) {
    Ok 'No tun2proxy helper processes found.'
    return
  }

  $processes | Stop-Process -Force -ErrorAction SilentlyContinue
  foreach ($process in $processes) {
    try {
      Wait-Process -Id $process.Id -Timeout 10 -ErrorAction SilentlyContinue
    } catch {
    }
  }
  Ok "tun2proxy process cleanup attempted for $($processes.Count) process(es)."
}

function Reset-WinHttpProxy {
  netsh winhttp reset proxy | Out-Null
}

function Find-MullvadCli {
  $candidates = @(
    "$env:ProgramFiles\Mullvad VPN\resources\mullvad.exe",
    "${env:ProgramFiles(x86)}\Mullvad VPN\resources\mullvad.exe"
  )
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path $candidate)) { return $candidate }
  }
  $command = Get-Command mullvad.exe -ErrorAction SilentlyContinue
  if ($command) { return $command.Source }
  $null
}

if ($CloseEdge) {
  Step 'Closing Microsoft Edge'
  Get-Process -Name msedge -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Ok 'Edge process cleanup attempted.'
}

Step 'Stopping socks5proxy TUN helpers'
Stop-Tun2ProxyHelpers

Step 'Disabling Windows system proxy'
Disable-SystemProxy
Ok 'Windows system proxy disabled and change broadcast attempted.'

Step 'Resetting WinHTTP proxy'
Reset-WinHttpProxy
Ok 'WinHTTP proxy reset to direct access.'

Step 'Cleaning managed socks5proxy TUN routes/adapters'
Remove-PinnedProxyRoutesFromRuntimeState
Report-PersistedWfpFilters
Remove-ManagedTunRoutes

if ($ResetDnsServers) {
  Step 'Resetting DNS server settings to DHCP defaults'
  Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    ForEach-Object {
      Set-DnsClientServerAddress -InterfaceIndex ([int]$_.InterfaceIndex) -ResetServerAddresses -ErrorAction SilentlyContinue
    }
  Ok 'DNS server reset attempted.'
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

if ($DisconnectMullvad) {
  Step 'Disconnecting Mullvad'
  $mullvad = Find-MullvadCli
  if ($mullvad) {
    & $mullvad disconnect | Out-Null
    Ok 'Mullvad disconnect attempted.'
  } else {
    Warn 'Mullvad CLI not found.'
  }
}

Step 'Connectivity probe'
try {
  $ip = (Invoke-WebRequest -Uri 'https://api.ipify.org' -TimeoutSec 10 -UseBasicParsing).Content.Trim()
  Ok "Internet reachable. Current visible IPv4: $ip"
} catch {
  Warn "Connectivity probe failed: $($_.Exception.Message)"
}

Write-Host "`nEmergency network reset finished." -ForegroundColor Green
