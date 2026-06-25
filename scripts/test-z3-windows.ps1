param(
  [string]$CredentialsPath,
  [switch]$Live,
  [string]$WireGuardTunnelName,
  [int]$ReconnectTimeoutSeconds = 90,
  [int]$PollSeconds = 2,
  [string]$LiveLogDir = '.build\z3-wireguard-live',
  [switch]$SkipReconnect
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Live) {
  $liveScript = Join-Path $PSScriptRoot 'test-z3-wireguard-live-windows.ps1'
  $arguments = @{
    CredentialsPath = $CredentialsPath
    ReconnectTimeoutSeconds = $ReconnectTimeoutSeconds
    PollSeconds = $PollSeconds
    LogDir = $LiveLogDir
  }
  if ($WireGuardTunnelName) { $arguments.WireGuardTunnelName = $WireGuardTunnelName }
  if ($SkipReconnect) { $arguments.SkipReconnect = $true }
  & $liveScript @arguments
  exit $LASTEXITCODE
}

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Warning $m }

$RootDir = Split-Path -Path $PSScriptRoot -Parent
if (-not $CredentialsPath) {
  $CredentialsPath = Join-Path $RootDir 'testdata\proxy_creds.txt'
}
$LogDir = Join-Path $RootDir '.build\z3-preflight'
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
  try {
    $async = $client.BeginConnect([string]$Proxy.Host, [int]$Proxy.Port, $null, $null)
    if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(8))) {
      throw 'Timed out connecting to upstream proxy.'
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
      throw 'Upstream did not speak SOCKS5.'
    }
    if ($response[1] -eq 0xff) {
      throw 'Upstream rejected all SOCKS5 authentication methods.'
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
  } finally {
    $client.Close()
  }
}

function Resolve-ProxyIps {
  param($Proxy)
  [System.Net.Dns]::GetHostAddresses([string]$Proxy.Host) |
    Where-Object {
      $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -or
      $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6
    } |
    ForEach-Object { $_.IPAddressToString } |
    Select-Object -Unique
}

function Resolve-WireGuardCli {
  $candidates = New-Object System.Collections.Generic.List[string]
  if (Test-Path Env:WG_CLI) {
    $candidates.Add($env:WG_CLI)
  }
  $candidates.Add((Join-Path $env:ProgramFiles 'WireGuard\wg.exe'))
  if (Test-Path 'Env:ProgramFiles(x86)') {
    $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'WireGuard\wg.exe'))
  }
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
      return $candidate
    }
  }
  $command = Get-Command 'wg.exe' -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }
  $null
}

function Get-WireGuardStatus {
  $wg = Resolve-WireGuardCli
  if (-not $wg) {
    return [PSCustomObject]@{
      CliPath = $null
      Interfaces = @()
      Endpoints = @()
      Error = 'wg.exe not found'
    }
  }

  try {
    $interfacesText = (& $wg show interfaces 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) {
      return [PSCustomObject]@{
        CliPath = $wg
        Interfaces = @()
        Endpoints = @()
        Error = "wg show interfaces failed: $interfacesText"
      }
    }
    $interfaces = @()
    if (-not [string]::IsNullOrWhiteSpace($interfacesText)) {
      $interfaces = @($interfacesText -split '\s+' | Where-Object { $_ })
    }
    $endpoints = @()
    foreach ($interface in $interfaces) {
      $endpointText = (& $wg show $interface endpoints 2>&1) -join "`n"
      if ($LASTEXITCODE -ne 0) {
        Warn "wg show $interface endpoints failed: $endpointText"
        continue
      }
      foreach ($line in ($endpointText -split "`r?`n")) {
        $trimmed = $line.Trim()
        if (-not $trimmed) { continue }
        $parts = $trimmed -split '\s+'
        if ($parts.Count -lt 2) { continue }
        $endpoint = $parts[1]
        $host = $endpoint
        if ($endpoint -match '^\[(?<ip>[^\]]+)\](?::(?<port>\d+))?$') {
          $host = $Matches.ip
        } elseif ($endpoint -match '^(?<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?<port>\d+))?$') {
          $host = $Matches.ip
        } elseif ($endpoint -match '^(?<host>[^:]+):(?<port>\d+)$') {
          $host = $Matches.host
        }
        $endpoints += [PSCustomObject]@{
          Interface = $interface
          Peer = $parts[0]
          Endpoint = $endpoint
          Host = $host
        }
      }
    }
    [PSCustomObject]@{
      CliPath = $wg
      Interfaces = $interfaces
      Endpoints = $endpoints
      Error = $null
    }
  } catch {
    [PSCustomObject]@{
      CliPath = $wg
      Interfaces = @()
      Endpoints = @()
      Error = $_.Exception.Message
    }
  }
}

function Get-ActiveVpnAdapters {
  Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Status -eq 'Up' -and
      (
        $_.Name -match 'wireguard|wg|vpn|tun|tap|wintun|tailscale|nordlynx|proton|warp' -or
        $_.InterfaceDescription -match 'wireguard|wg|vpn|tun|tap|wintun|tailscale|nordlynx|proton|warp'
      )
    } |
    Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress
}

function Get-RouteForIp {
  param([string]$Ip)
  $parsed = $null
  if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) {
    return $null
  }
  $route = Find-NetRoute -RemoteIPAddress $parsed.IPAddressToString -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if (-not $route) { return $null }
  $adapter = Get-NetAdapter -InterfaceIndex ([int]$route.InterfaceIndex) -ErrorAction SilentlyContinue
  $destinationPrefix = $null
  if ($route.PSObject.Properties['DestinationPrefix']) {
    $destinationPrefix = [string]$route.DestinationPrefix
  } elseif ($route.PSObject.Properties['IPAddress'] -and $route.PSObject.Properties['PrefixLength']) {
    $destinationPrefix = "$($route.IPAddress)/$($route.PrefixLength)"
  }

  $nextHop = $null
  if ($route.PSObject.Properties['NextHop']) {
    $nextHop = [string]$route.NextHop
  }

  $routeMetric = $null
  if ($route.PSObject.Properties['RouteMetric']) {
    $routeMetric = $route.RouteMetric
  }

  [PSCustomObject]@{
    Ip = $parsed.IPAddressToString
    InterfaceIndex = [int]$route.InterfaceIndex
    InterfaceAlias = if ($adapter) { [string]$adapter.Name } else { $null }
    InterfaceDescription = if ($adapter) { [string]$adapter.InterfaceDescription } else { $null }
    DestinationPrefix = $destinationPrefix
    NextHop = $nextHop
    RouteMetric = $routeMetric
  }
}

function New-ProxyRoutePlan {
  param(
    [string]$Ip,
    [int]$InterfaceIndex
  )
  $parsed = $null
  if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) {
    return $null
  }
  if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    $prefix = "$($parsed.IPAddressToString)/32"
    $nextHop = '0.0.0.0'
  } else {
    $prefix = "$($parsed.IPAddressToString)/128"
    $nextHop = '::'
  }
  [PSCustomObject]@{
    DestinationPrefix = $prefix
    InterfaceIndex = $InterfaceIndex
    NextHop = $nextHop
    AddCommand = "New-NetRoute -DestinationPrefix '$prefix' -InterfaceIndex $InterfaceIndex -NextHop '$nextHop' -RouteMetric 1"
    RemoveCommand = "Remove-NetRoute -DestinationPrefix '$prefix' -InterfaceIndex $InterfaceIndex -NextHop '$nextHop' -Confirm:`$false"
  }
}

function Resolve-MullvadCli {
  $candidates = New-Object System.Collections.Generic.List[string]
  if (Test-Path Env:MULLVAD_CLI) {
    $candidates.Add($env:MULLVAD_CLI)
  }
  $candidates.Add((Join-Path $env:ProgramFiles 'Mullvad VPN\resources\mullvad.exe'))
  if (Test-Path 'Env:ProgramFiles(x86)') {
    $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'Mullvad VPN\resources\mullvad.exe'))
  }
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) {
      return $candidate
    }
  }
  $command = Get-Command 'mullvad.exe' -ErrorAction SilentlyContinue
  if ($command) {
    return $command.Source
  }
  $null
}

function Get-MullvadRuntimeStatus {
  $mullvad = Resolve-MullvadCli
  if (-not $mullvad) { return $null }
  try {
    $statusText = & $mullvad status --json 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($statusText -join "`n"))) {
      return $null
    }
    ($statusText -join "`n") | ConvertFrom-Json
  } catch {
    Warn "Could not inspect Mullvad runtime status: $($_.Exception.Message)"
    $null
  }
}

if ($Live) {
  throw 'Live Z3 is intentionally not implemented in this harness yet. Use this script as a dry-run preflight only; route/TUN live tests must be run with an armed fallback.'
}

Step 'Proxy preflight'
$entry = Read-FirstProxyEntry -Path $CredentialsPath
$proxy = Parse-ProxyEntry -Line $entry
Ok 'Loaded proxy test entry without printing credentials.'
Test-Socks5Handshake -Proxy $proxy
Ok 'SOCKS5 handshake/auth succeeded.'
$proxyIps = @(Resolve-ProxyIps -Proxy $proxy)
if ($proxyIps.Count -eq 0) {
  throw "Could not resolve proxy host $($proxy.Host)."
}
Ok "Resolved proxy host to $($proxyIps.Count) IP address(es): $($proxyIps -join ', ')"

Step 'WireGuard preflight'
$wgStatus = Get-WireGuardStatus
if ($wgStatus.CliPath) {
  Ok "wg.exe found: $($wgStatus.CliPath)"
} else {
  Warn 'wg.exe was not found; standard WireGuard Z3 cannot be fully verified.'
}
if ($wgStatus.Error) {
  Warn $wgStatus.Error
}
if ($wgStatus.Interfaces.Count -gt 0) {
  Ok "WireGuard interface(s): $($wgStatus.Interfaces -join ', ')"
} else {
  Warn 'No active WireGuard interfaces were reported by wg.exe.'
}
if ($wgStatus.Endpoints.Count -gt 0) {
  Ok "WireGuard peer endpoint candidate(s): $($wgStatus.Endpoints.Count)"
} else {
  Warn 'No WireGuard peer endpoints were reported.'
}

Step 'VPN adapter and route preflight'
$vpnAdapters = @(Get-ActiveVpnAdapters)
$snapshotPath = Join-Path $LogDir 'z3-preflight.json'
$routes = @($proxyIps | ForEach-Object { Get-RouteForIp -Ip $_ } | Where-Object { $_ })
$activeVpnIndexes = @($vpnAdapters | ForEach-Object { [int]$_.ifIndex })
$preferredVpn = $null
if ($vpnAdapters.Count -gt 0) {
  $preferredVpn = $vpnAdapters | Where-Object {
    $_.Name -match 'wireguard|wg' -or $_.InterfaceDescription -match 'wireguard|wg'
  } | Select-Object -First 1
  if (-not $preferredVpn) {
    $preferredVpn = $vpnAdapters | Select-Object -First 1
  }
  Ok "Active VPN-like adapter(s): $($vpnAdapters.Count). Preferred: $($preferredVpn.Name) (#$($preferredVpn.ifIndex))"
} else {
  Warn 'No active VPN-like adapter found. Z3 would degrade/block until WireGuard is connected.'
}

$routePlans = @()
foreach ($ip in $proxyIps) {
  if ($preferredVpn) {
    $routePlans += New-ProxyRoutePlan -Ip $ip -InterfaceIndex ([int]$preferredVpn.ifIndex)
  }
}

foreach ($route in $routes) {
  if ($activeVpnIndexes -contains [int]$route.InterfaceIndex) {
    Ok "Current proxy route $($route.Ip) already uses VPN-like adapter $($route.InterfaceAlias) (#$($route.InterfaceIndex))."
  } elseif ($preferredVpn) {
    Warn "Current proxy route $($route.Ip) uses $($route.InterfaceAlias) (#$($route.InterfaceIndex)); Z3 needs a pinned host route via $($preferredVpn.Name) (#$($preferredVpn.ifIndex))."
  } else {
    Warn "Current proxy route $($route.Ip) uses $($route.InterfaceAlias) (#$($route.InterfaceIndex)); no VPN adapter is available for Z3."
  }
}

if ($routePlans.Count -gt 0) {
  Step 'Planned proxy host route(s)'
  foreach ($plan in $routePlans) {
    Write-Host "    add:    $($plan.AddCommand)"
    Write-Host "    remove: $($plan.RemoveCommand)"
  }
}

$mullvadStatus = Get-MullvadRuntimeStatus
if ($mullvadStatus -and $mullvadStatus.state -eq 'connected') {
  Warn 'Mullvad is connected. That is Z4, not standard Z3; the app currently blocks Windows TUN start until the Mullvad WFP kill-switch exception is implemented.'
}

[PSCustomObject]@{
  CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
  ProxyHost = $proxy.Host
  ProxyIps = $proxyIps
  WireGuard = $wgStatus
  VpnAdapters = $vpnAdapters
  ProxyRoutes = $routes
  PlannedProxyRoutes = $routePlans
  MullvadState = if ($mullvadStatus) { $mullvadStatus.state } else { $null }
} | ConvertTo-Json -Depth 8 | Set-Content -Path $snapshotPath -Encoding UTF8

Ok "Z3 preflight snapshot written: $snapshotPath"
Warn 'Dry-run only. No routes, adapters, DNS settings, Mullvad state, or system proxy settings were changed.'
