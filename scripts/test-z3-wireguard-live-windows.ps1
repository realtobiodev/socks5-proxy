param(
  [string]$CredentialsPath,
  [string]$WireGuardTunnelName,
  [int]$ReconnectTimeoutSeconds = 90,
  [int]$PollSeconds = 2,
  [string]$LogDir = '.build\z3-wireguard-live',
  [switch]$SkipReconnect,
  [switch]$NoElevate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($Message) { Write-Host "[Z3-WG] $Message" -ForegroundColor Cyan }
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

  Step 'Relaunching elevated for route mutation and WireGuard reconnect test.'
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

  $resolved = Resolve-RepoPath $(if ($Path) { $Path } else { 'testdata\proxy_creds.txt' })
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

function Read-Exact {
  param($Stream, [byte[]]$Buffer, [int]$Count)
  $offset = 0
  while ($offset -lt $Count) {
    $read = $Stream.Read($Buffer, $offset, $Count - $offset)
    if ($read -le 0) { throw 'SOCKS5 connection closed unexpectedly.' }
    $offset += $read
  }
}

function Test-Socks5Handshake {
  param($Proxy)

  $client = [System.Net.Sockets.TcpClient]::new()
  $client.ReceiveTimeout = 10000
  $client.SendTimeout = 10000
  $client.Connect($Proxy.Host, [int]$Proxy.Port)
  try {
    $stream = $client.GetStream()
    $methods = if ($Proxy.Username) { [byte[]](0x05, 0x01, 0x02) } else { [byte[]](0x05, 0x01, 0x00) }
    $stream.Write($methods, 0, $methods.Length)
    $response = New-Object byte[] 2
    Read-Exact $stream $response 2
    if ($response[0] -ne 0x05) { throw 'Invalid SOCKS5 version in method response.' }
    if ($Proxy.Username) {
      if ($response[1] -ne 0x02) { throw "SOCKS5 server did not select username/password auth (method=$($response[1]))." }
      $user = [Text.Encoding]::UTF8.GetBytes([string]$Proxy.Username)
      $pass = [Text.Encoding]::UTF8.GetBytes([string]$Proxy.Password)
      if ($user.Length -gt 255 -or $pass.Length -gt 255) { throw 'SOCKS5 credentials exceed 255 bytes.' }
      $auth = [byte[]](0x01, [byte]$user.Length) + $user + [byte[]]([byte]$pass.Length) + $pass
      $stream.Write($auth, 0, $auth.Length)
      $authResponse = New-Object byte[] 2
      Read-Exact $stream $authResponse 2
      if ($authResponse[1] -ne 0x00) { throw "SOCKS5 authentication failed (status=$($authResponse[1])). " }
    } elseif ($response[1] -ne 0x00) {
      throw "SOCKS5 server did not accept no-auth (method=$($response[1]))."
    }
  } finally {
    $client.Dispose()
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
  if ($env:WG_CLI) { $candidates.Add($env:WG_CLI) }
  if ($env:ProgramFiles) { $candidates.Add((Join-Path $env:ProgramFiles 'WireGuard\wg.exe')) }
  if (${env:ProgramFiles(x86)}) { $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'WireGuard\wg.exe')) }
  foreach ($candidate in $candidates) {
    if ($candidate -and (Test-Path -LiteralPath $candidate)) { return (Resolve-Path -LiteralPath $candidate).Path }
  }
  return $null
}

function Get-WireGuardInterfaces {
  param([string]$WgCli)
  if (-not $WgCli) { return @() }
  $text = & $WgCli show interfaces 2>$null
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($text -join "`n"))) { return @() }
  return @(($text -join ' ') -split '\s+' | Where-Object { $_ })
}

function Get-WireGuardEndpoints {
  param([string]$WgCli, [string[]]$Interfaces)

  $items = New-Object System.Collections.Generic.List[object]
  foreach ($iface in $Interfaces) {
    $endpointText = & $WgCli show $iface endpoints 2>$null
    if ($LASTEXITCODE -ne 0) { continue }
    $handshakeText = & $WgCli show $iface latest-handshakes 2>$null
    $handshakeByPeer = @{}
    if ($LASTEXITCODE -eq 0) {
      foreach ($line in @($handshakeText)) {
        $parts = "$line".Trim() -split '\s+'
        if ($parts.Count -ge 2) { $handshakeByPeer[$parts[0]] = [int64]$parts[1] }
      }
    }

    foreach ($line in @($endpointText)) {
      $parts = "$line".Trim() -split '\s+'
      if ($parts.Count -lt 2 -or $parts[1] -eq '(none)') { continue }
      $endpoint = $parts[1]
      $host = if ($endpoint.StartsWith('[')) {
        ($endpoint -split '\]')[0].TrimStart('[')
      } else {
        ($endpoint -split ':')[0]
      }
      $items.Add([PSCustomObject]@{
        Interface = $iface
        Peer = $parts[0]
        Endpoint = $endpoint
        EndpointHost = $host
        LatestHandshakeUnix = if ($handshakeByPeer.ContainsKey($parts[0])) { $handshakeByPeer[$parts[0]] } else { 0 }
      })
    }
  }
  return @($items)
}

function Get-WireGuardKillSwitchReason {
  $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
    Where-Object {
      ($_.DisplayName -match 'WireGuard' -or $_.Group -match 'WireGuard') -and
      $_.Action -eq 'Block' -and
      $_.Enabled -eq 'True'
    } |
    Select-Object -First 5 -ExpandProperty DisplayName)

  if ($rules.Count -eq 0) { return $null }
  return "WireGuard firewall block rule(s) active: $($rules -join '; ')"
}

function Get-WireGuardAdapter {
  param([string[]]$Interfaces)

  $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Status -eq 'Up' -and (
        ($WireGuardTunnelName -and $_.Name -eq $WireGuardTunnelName) -or
        ($Interfaces -contains $_.Name) -or
        $_.InterfaceDescription -match 'WireGuard|Wintun'
      )
    })
  if ($WireGuardTunnelName) {
    $named = @($adapters | Where-Object { $_.Name -eq $WireGuardTunnelName })
    if ($named.Count -gt 0) { return $named[0] }
  }
  if ($adapters.Count -eq 0) { return $null }
  return $adapters[0]
}

function New-HostRouteSpec {
  param([string]$Ip, [int]$InterfaceIndex)
  $parsed = [System.Net.IPAddress]::Parse($Ip)
  if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
    return [PSCustomObject]@{ DestinationPrefix = "$($parsed.IPAddressToString)/32"; NextHop = '0.0.0.0'; InterfaceIndex = $InterfaceIndex }
  }
  [PSCustomObject]@{ DestinationPrefix = "$($parsed.IPAddressToString)/128"; NextHop = '::'; InterfaceIndex = $InterfaceIndex }
}

function Add-PinnedProxyRoutes {
  param([string[]]$ProxyIps, $WireGuardAdapter)

  $added = New-Object System.Collections.Generic.List[object]
  foreach ($ip in $ProxyIps) {
    $spec = New-HostRouteSpec -Ip $ip -InterfaceIndex ([int]$WireGuardAdapter.ifIndex)
    $existing = @(Get-NetRoute -DestinationPrefix $spec.DestinationPrefix -InterfaceIndex $spec.InterfaceIndex -ErrorAction SilentlyContinue)
    if ($existing.Count -eq 0) {
      New-NetRoute -DestinationPrefix $spec.DestinationPrefix -InterfaceIndex $spec.InterfaceIndex -NextHop $spec.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
      $added.Add($spec)
    }
  }
  return @($added)
}

function Remove-PinnedProxyRoutes {
  param([object[]]$Routes)
  foreach ($route in @($Routes)) {
    Remove-NetRoute -DestinationPrefix $route.DestinationPrefix -InterfaceIndex $route.InterfaceIndex -NextHop $route.NextHop -Confirm:$false -ErrorAction SilentlyContinue
  }
}

function Find-RouteForIp {
  param([string]$Ip)
  try {
    Find-NetRoute -RemoteIPAddress $Ip -ErrorAction Stop | Select-Object -First 1
  } catch {
    $null
  }
}

function Assert-ProxyRoutesUseWireGuard {
  param([string[]]$ProxyIps, $WireGuardAdapter)
  foreach ($ip in $ProxyIps) {
    $route = Find-RouteForIp -Ip $ip
    if (-not $route) { throw "No route found for proxy IP $ip." }
    if ([int]$route.InterfaceIndex -ne [int]$WireGuardAdapter.ifIndex) {
      throw "Proxy IP $ip routes via $($route.InterfaceAlias) (#$($route.InterfaceIndex)); expected WireGuard $($WireGuardAdapter.Name) (#$($WireGuardAdapter.ifIndex))."
    }
  }
}

function Assert-KeepaliveBypassesProxyTun {
  param($Endpoints, [string[]]$ProxyIps)

  foreach ($endpoint in @($Endpoints)) {
    if ($ProxyIps -contains $endpoint.EndpointHost) {
      throw "WireGuard endpoint $($endpoint.EndpointHost) equals a proxy IP; keepalive bypass cannot be distinguished."
    }
    $route = Find-RouteForIp -Ip $endpoint.EndpointHost
    if (-not $route) {
      Warn "No route found for WireGuard endpoint $($endpoint.EndpointHost); endpoint may be hostname-only or temporarily unresolved."
      continue
    }
    if ([string]$route.InterfaceAlias -match '^s5p|tun2proxy|socks5proxy') {
      throw "WireGuard keepalive endpoint $($endpoint.EndpointHost) routes through proxy/TUN interface $($route.InterfaceAlias)."
    }
  }
}

function Resolve-WireGuardTunnelService {
  param([string[]]$Interfaces)

  $services = @(Get-Service -Name 'WireGuardTunnel$*' -ErrorAction SilentlyContinue)
  if ($WireGuardTunnelName) {
    $exact = @($services | Where-Object { $_.Name -eq "WireGuardTunnel`$$WireGuardTunnelName" -or $_.DisplayName -like "*$WireGuardTunnelName*" })
    if ($exact.Count -gt 0) { return $exact[0] }
  }
  foreach ($iface in @($Interfaces)) {
    $match = @($services | Where-Object { $_.Name -eq "WireGuardTunnel`$$iface" -or $_.DisplayName -like "*$iface*" })
    if ($match.Count -gt 0) { return $match[0] }
  }
  $running = @($services | Where-Object { $_.Status -eq 'Running' })
  if ($running.Count -eq 1) { return $running[0] }
  return $null
}

function Restart-WireGuardTunnel {
  param($Service)

  Step "Restarting WireGuard tunnel service $($Service.Name)."
  Restart-Service -Name $Service.Name -Force -ErrorAction Stop
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

function Save-Json {
  param([string]$Name, $Value)
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  $path = Join-Path $LogDir "$Name.json"
  $Value | ConvertTo-Json -Depth 8 | Set-Content -Path $path -Encoding UTF8
  return $path
}

Relaunch-Elevated

$addedRoutes = @()

try {
  New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

  Step 'Reading proxy credentials and WireGuard state.'
  $proxy = Parse-ProxyEntry (Read-FirstProxyEntry -Path $CredentialsPath)
  $proxyIps = @(Resolve-ProxyIps -Proxy $proxy)
  if ($proxyIps.Count -eq 0) { throw "Proxy host $($proxy.Host) did not resolve." }

  $wgCli = Resolve-WireGuardCli
  if (-not $wgCli) { throw 'wg.exe was not found. Install WireGuard for Windows or set WG_CLI.' }

  $interfaces = @(Get-WireGuardInterfaces -WgCli $wgCli)
  if ($interfaces.Count -eq 0) { throw 'wg.exe reported no WireGuard interfaces. Connect WireGuard with kill-switch off before running Z3 live.' }

  $killSwitchReason = Get-WireGuardKillSwitchReason
  if ($killSwitchReason) {
    throw "Windows Z3 with WireGuard kill-switch enabled is intentionally blocked in V1. Disable WireGuard's 'Block untunneled traffic' option for Z3, or use the future Z3b/Z4 WFP exception path. Detected: $killSwitchReason"
  }

  $endpoints = @(Get-WireGuardEndpoints -WgCli $wgCli -Interfaces $interfaces)
  if ($endpoints.Count -eq 0) { throw 'No WireGuard peer endpoints were visible; cannot verify keepalive bypass.' }

  $wgAdapter = Get-WireGuardAdapter -Interfaces $interfaces
  if (-not $wgAdapter) { throw 'No active WireGuard/Wintun adapter was found.' }
  Ok "WireGuard adapter: $($wgAdapter.Name) (#$($wgAdapter.ifIndex))"

  Save-Json -Name 'baseline' -Value ([PSCustomObject]@{
    CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
    ProxyHost = $proxy.Host
    ProxyIps = $proxyIps
    WireGuardCli = $wgCli
    WireGuardInterfaces = $interfaces
    WireGuardAdapter = $wgAdapter | Select-Object Name, InterfaceDescription, Status, ifIndex
    WireGuardEndpoints = $endpoints
  }) | Out-Null

  Step 'Checking SOCKS5 before route pinning.'
  Test-Socks5Handshake -Proxy $proxy
  Ok 'SOCKS5 handshake succeeded.'

  Step 'Pinning proxy host route(s) to WireGuard.'
  $addedRoutes = @(Add-PinnedProxyRoutes -ProxyIps $proxyIps -WireGuardAdapter $wgAdapter)
  Assert-ProxyRoutesUseWireGuard -ProxyIps $proxyIps -WireGuardAdapter $wgAdapter
  Ok "Proxy IP route(s) use WireGuard: $($proxyIps -join ', ')"

  Step 'Verifying WireGuard keepalive endpoint bypass.'
  Assert-KeepaliveBypassesProxyTun -Endpoints $endpoints -ProxyIps $proxyIps
  Ok 'WireGuard endpoint routes do not loop through proxy/TUN.'

  Step 'Checking SOCKS5 through pinned WireGuard route.'
  Test-Socks5Handshake -Proxy $proxy
  Ok 'SOCKS5 handshake still succeeds with proxy route pinned to WireGuard.'

  if (-not $SkipReconnect) {
    $service = Resolve-WireGuardTunnelService -Interfaces $interfaces
    if (-not $service) {
      throw 'Could not identify a WireGuardTunnel$ service for reconnect. Pass -WireGuardTunnelName or use -SkipReconnect.'
    }

    Restart-WireGuardTunnel -Service $service
    $reconnected = Wait-Until -TimeoutSeconds $ReconnectTimeoutSeconds -WaitingFor 'WireGuard reconnect and proxy route recovery' -Condition {
      $latestAdapter = Get-WireGuardAdapter -Interfaces $interfaces
      if (-not $latestAdapter -or $latestAdapter.Status -ne 'Up') { return $false }
      try {
        Assert-ProxyRoutesUseWireGuard -ProxyIps $proxyIps -WireGuardAdapter $latestAdapter
        Assert-KeepaliveBypassesProxyTun -Endpoints $endpoints -ProxyIps $proxyIps
        Test-Socks5Handshake -Proxy $proxy
        return $true
      } catch {
        return $false
      }
    }

    if (-not $reconnected) {
      throw 'WireGuard reconnect did not restore the Z3 proxy path in time.'
    }
    Ok 'WireGuard reconnect preserved/restored proxy path and keepalive bypass.'
  } else {
    Warn 'Reconnect test skipped by -SkipReconnect.'
  }

  Save-Json -Name 'post-check' -Value ([PSCustomObject]@{
    CapturedAt = (Get-Date).ToUniversalTime().ToString('o')
    ProxyRoutes = @($proxyIps | ForEach-Object { Find-RouteForIp -Ip $_ })
    WireGuardEndpoints = $endpoints
    AddedRoutes = $addedRoutes
  }) | Out-Null

  Ok 'Z3 WireGuard kill-switch-off path verified.'
} finally {
  if ($addedRoutes.Count -gt 0) {
    Step 'Cleaning up pinned proxy route(s).'
    Remove-PinnedProxyRoutes -Routes $addedRoutes
  }
}
