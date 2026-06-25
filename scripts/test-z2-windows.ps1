param(
  [string]$CredentialsPath,
  [int]$TimeoutSeconds = 45,
  [int]$StartupSeconds = 8,
  [switch]$Live,
  [switch]$ProxyDns = $true,
  [switch]$NoElevate,
  [string]$TunAdapterName = 's5pz2test',
  [switch]$NoEmergencyCloseEdge,
  [switch]$AllowExperimentalMullvadTun,
  [switch]$TemporarilyDisconnectMullvad,
  [switch]$SkipDnsRouteCheck,
  [switch]$SkipDnsLeakProbe
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

$RuntimeDir = Join-Path $RootDir 'runtime\windows'
$Tun2Proxy = Join-Path $RuntimeDir 'tun2proxy-bin.exe'
$Wintun = Join-Path $RuntimeDir 'wintun.dll'
$LogDir = Join-Path $RootDir '.build\z2-live-test'
$TunDnsServer = '10.0.0.1'
$BlockedIpv4DnsServer = '127.0.0.1'
$BlockedIpv6DnsServer = '::1'
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$TranscriptStarted = $false
try {
  Start-Transcript -Path (Join-Path $LogDir 'z2-test-transcript.log') -Append | Out-Null
  $TranscriptStarted = $true
} catch {
  $TranscriptStarted = $false
}

function Test-Administrator {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Relaunch-Elevated {
  $script = $PSCommandPath
  $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"")
  if ($CredentialsPath) { $args += @('-CredentialsPath', "`"$CredentialsPath`"") }
  $args += @('-TimeoutSeconds', $TimeoutSeconds, '-StartupSeconds', $StartupSeconds)
  if ($Live) { $args += '-Live' }
  if (-not $ProxyDns) { $args += @('-ProxyDns:$false') }
  if ($NoElevate) { $args += '-NoElevate' }
  if ($TunAdapterName) { $args += @('-TunAdapterName', "`"$TunAdapterName`"") }
  if ($NoEmergencyCloseEdge) { $args += '-NoEmergencyCloseEdge' }
  if ($AllowExperimentalMullvadTun) { $args += '-AllowExperimentalMullvadTun' }
  if ($TemporarilyDisconnectMullvad) { $args += '-TemporarilyDisconnectMullvad' }
  if ($SkipDnsRouteCheck) { $args += '-SkipDnsRouteCheck' }
  if ($SkipDnsLeakProbe) { $args += '-SkipDnsLeakProbe' }
  Start-Process -FilePath 'powershell.exe' -ArgumentList ($args -join ' ') -Verb RunAs | Out-Null
}

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

function New-Socks5Url {
  param($Proxy)
  $user = [Uri]::EscapeDataString([string]$Proxy.Username)
  $pass = [Uri]::EscapeDataString([string]$Proxy.Password)
  "socks5://$user`:$pass@$($Proxy.Host):$($Proxy.Port)"
}

function Test-Socks5Handshake {
  param($Proxy)
  $client = New-Object System.Net.Sockets.TcpClient
  $async = $client.BeginConnect([string]$Proxy.Host, [int]$Proxy.Port, $null, $null)
  if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(8))) {
    $client.Close()
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
  $client.Close()
}

function Read-Exact {
  param(
    [System.IO.Stream]$Stream,
    [int]$Length,
    [string]$Description
  )
  $buffer = New-Object byte[] $Length
  $offset = 0
  while ($offset -lt $Length) {
    $read = $Stream.Read($buffer, $offset, $Length - $offset)
    if ($read -le 0) {
      throw "SOCKS5 stream closed while reading $Description."
    }
    $offset += $read
  }
  $buffer
}

function Connect-Socks5Target {
  param(
    $Proxy,
    [string]$TargetHost,
    [int]$TargetPort
  )
  $client = New-Object System.Net.Sockets.TcpClient
  $async = $client.BeginConnect([string]$Proxy.Host, [int]$Proxy.Port, $null, $null)
  if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(10))) {
    $client.Close()
    throw 'Timed out connecting to upstream proxy.'
  }
  $client.EndConnect($async)
  $stream = $client.GetStream()
  $stream.ReadTimeout = 10000
  $stream.WriteTimeout = 10000

  try {
    $greeting = [byte[]](0x05, 0x02, 0x00, 0x02)
    $stream.Write($greeting, 0, $greeting.Length)
    $response = Read-Exact -Stream $stream -Length 2 -Description 'SOCKS5 greeting'
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
      $authResponse = Read-Exact -Stream $stream -Length 2 -Description 'SOCKS5 auth response'
      if ($authResponse[0] -ne 0x01 -or $authResponse[1] -ne 0x00) {
        throw 'SOCKS5 username/password authentication failed.'
      }
    } elseif ($response[1] -ne 0x00) {
      throw ("Upstream selected unsupported SOCKS5 auth method 0x{0:x2}." -f $response[1])
    }

    $hostBytes = [Text.Encoding]::ASCII.GetBytes($TargetHost)
    if ($hostBytes.Length -gt 255) {
      throw 'SOCKS5 target host is too long.'
    }
    $portHigh = [byte](($TargetPort -shr 8) -band 0xff)
    $portLow = [byte]($TargetPort -band 0xff)
    $request = New-Object System.Collections.Generic.List[byte]
    $request.Add(0x05)
    $request.Add(0x01)
    $request.Add(0x00)
    $request.Add(0x03)
    $request.Add([byte]$hostBytes.Length)
    $request.AddRange($hostBytes)
    $request.Add($portHigh)
    $request.Add($portLow)
    $bytes = $request.ToArray()
    $stream.Write($bytes, 0, $bytes.Length)

    $head = Read-Exact -Stream $stream -Length 4 -Description 'SOCKS5 CONNECT response'
    if ($head[0] -ne 0x05) {
      throw 'Proxy returned an invalid SOCKS5 response.'
    }
    if ($head[1] -ne 0x00) {
      throw ("SOCKS5 CONNECT failed with reply code 0x{0:x2}." -f $head[1])
    }
    switch ($head[3]) {
      0x01 { [void](Read-Exact -Stream $stream -Length 6 -Description 'SOCKS5 IPv4 bind address') }
      0x03 {
        $len = (Read-Exact -Stream $stream -Length 1 -Description 'SOCKS5 domain bind length')[0]
        [void](Read-Exact -Stream $stream -Length ($len + 2) -Description 'SOCKS5 domain bind address')
      }
      0x04 { [void](Read-Exact -Stream $stream -Length 18 -Description 'SOCKS5 IPv6 bind address') }
      default { throw ("SOCKS5 response used unsupported address type 0x{0:x2}." -f $head[3]) }
    }

    [PSCustomObject]@{
      Client = $client
      Stream = $stream
    }
  } catch {
    $client.Close()
    throw
  }
}

function Get-ProxyExitIp {
  param($Proxy)
  $connection = Connect-Socks5Target -Proxy $Proxy -TargetHost 'api.ipify.org' -TargetPort 443
  $ssl = $null
  try {
    $callback = { param($sender, $cert, $chain, $errors) return $true }
    $ssl = New-Object System.Net.Security.SslStream($connection.Stream, $false, $callback)
    $ssl.ReadTimeout = 10000
    $ssl.WriteTimeout = 10000
    $ssl.AuthenticateAsClient('api.ipify.org')
    $request = [Text.Encoding]::ASCII.GetBytes("GET /?format=json HTTP/1.1`r`nHost: api.ipify.org`r`nAccept: application/json`r`nConnection: close`r`n`r`n")
    $ssl.Write($request, 0, $request.Length)
    $buffer = New-Object byte[] 4096
    $memory = New-Object System.IO.MemoryStream
    while (($read = $ssl.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $memory.Write($buffer, 0, $read)
    }
    $text = [Text.Encoding]::UTF8.GetString($memory.ToArray())
    $body = ($text -split "`r`n`r`n", 2)[-1]
    $json = $body | ConvertFrom-Json
    if (-not $json.ip) {
      throw "Could not parse proxy exit-IP response: $body"
    }
    [string]$json.ip
  } finally {
    if ($ssl) { $ssl.Dispose() }
    if ($connection -and $connection.Client) { $connection.Client.Close() }
  }
}

function Add-UniqueIp {
  param(
    [System.Collections.Generic.List[string]]$List,
    [string]$Candidate
  )
  if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
  $parsed = $null
  if ([System.Net.IPAddress]::TryParse($Candidate.Trim(), [ref]$parsed)) {
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
      return
    }
    $normalized = $parsed.IPAddressToString
    if (-not $List.Contains($normalized)) {
      $List.Add($normalized)
    }
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

function Add-MullvadEndpointIp {
  param(
    [System.Collections.Generic.List[string]]$List,
    [string]$Address
  )
  if ([string]::IsNullOrWhiteSpace($Address)) { return }
  $trimmed = $Address.Trim()

  if ($trimmed -match '^\[(?<ip>[^\]]+)\](?::\d+)?$') {
    Add-UniqueIp -List $List -Candidate $Matches.ip
    return
  }
  if ($trimmed -match '^(?<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$') {
    Add-UniqueIp -List $List -Candidate $Matches.ip
    return
  }
  Add-UniqueIp -List $List -Candidate $trimmed
}

function Add-MullvadRelayIps {
  param(
    [System.Collections.Generic.List[string]]$List,
    [string]$RelayList,
    [string]$Hostname
  )
  if ([string]::IsNullOrWhiteSpace($RelayList) -or [string]::IsNullOrWhiteSpace($Hostname)) {
    return
  }

  $pattern = '(?m)^\s*' + [regex]::Escape($Hostname.Trim()) + '\s+\((?<ips>[^)]*)\)'
  $match = [regex]::Match($RelayList, $pattern)
  if (-not $match.Success) { return }

  foreach ($candidate in ($match.Groups['ips'].Value -split ',')) {
    Add-UniqueIp -List $List -Candidate $candidate
  }
}

function Get-MullvadTransportBypasses {
  $ips = New-Object System.Collections.Generic.List[string]
  $mullvad = Resolve-MullvadCli
  if (-not $mullvad) { return @() }

  try {
    $statusText = & $mullvad status --json 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace(($statusText -join "`n"))) {
      return @()
    }
    $status = ($statusText -join "`n") | ConvertFrom-Json
    if ($status.state -ne 'connected') {
      return @()
    }

    if ($status.details -and $status.details.endpoint -and $status.details.endpoint.address) {
      Add-MullvadEndpointIp -List $ips -Address ([string]$status.details.endpoint.address)
    }

    $hostnames = New-Object System.Collections.Generic.List[string]
    if ($status.details -and $status.details.location) {
      if ($status.details.location.hostname) { $hostnames.Add([string]$status.details.location.hostname) }
      if ($status.details.location.entry_hostname) { $hostnames.Add([string]$status.details.location.entry_hostname) }
    }

    if ($hostnames.Count -gt 0) {
      $relayText = (& $mullvad relay list 2>$null) -join "`n"
      if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($relayText)) {
        foreach ($hostname in ($hostnames | Select-Object -Unique)) {
          Add-MullvadRelayIps -List $ips -RelayList $relayText -Hostname $hostname
        }
      }
    }
  } catch {
    Warn "Could not inspect Mullvad transport bypasses: $($_.Exception.Message)"
  }

  @($ips | Select-Object -Unique)
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

function Wait-MullvadState {
  param(
    [string]$State,
    [int]$TimeoutSeconds = 30
  )
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $status = Get-MullvadRuntimeStatus
    if ($status -and $status.state -eq $State) {
      return $status
    }
    Start-Sleep -Seconds 1
  } while ((Get-Date) -lt $deadline)
  $null
}

function Disconnect-MullvadForZ2 {
  $mullvad = Resolve-MullvadCli
  if (-not $mullvad) {
    throw 'Cannot temporarily disconnect Mullvad: mullvad.exe was not found.'
  }
  Step 'Temporarily disconnecting Mullvad for guarded Z2 test'
  & $mullvad disconnect | Out-Null
  $status = Wait-MullvadState -State 'disconnected' -TimeoutSeconds 30
  if (-not $status) {
    throw 'Mullvad did not report disconnected within 30 seconds.'
  }
  Ok 'Mullvad is disconnected for this Z2 live test.'
}

function Reconnect-MullvadAfterZ2 {
  $mullvad = Resolve-MullvadCli
  if (-not $mullvad) {
    Warn 'Could not reconnect Mullvad: mullvad.exe was not found.'
    return
  }
  Step 'Reconnecting Mullvad after Z2 test'
  & $mullvad connect | Out-Null
  $status = Wait-MullvadState -State 'connected' -TimeoutSeconds 45
  if ($status) {
    Ok 'Mullvad reconnect reported connected.'
  } else {
    Warn 'Mullvad reconnect was attempted but did not report connected within 45 seconds.'
  }
}

function Get-MullvadTunBlockReason {
  param($Status)
  if (-not $Status -or $AllowExperimentalMullvadTun) { return $null }
  if ($Status.state -ne 'connected') { return $null }

  $endpoint = 'unknown endpoint'
  if ($Status.details) {
    $endpointProperty = $Status.details.PSObject.Properties['endpoint']
    $locationProperty = $Status.details.PSObject.Properties['location']
    if ($endpointProperty -and $endpointProperty.Value.PSObject.Properties['address']) {
      $endpoint = [string]$Status.details.endpoint.address
    } elseif ($locationProperty -and $locationProperty.Value.PSObject.Properties['hostname']) {
      $endpoint = [string]$Status.details.location.hostname
    }
  }
    "Mullvad is connected ($endpoint). Windows Z4 requires the scoped WFP kill-switch exception before TUN routing can start. Disconnect Mullvad to run Z2, or run the guarded Z4 WFP path with -Live -AllowWfpMutation."
}

function Get-CurrentExitIp {
  (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 10).ip
}

function Resolve-IpifyIpv4 {
  [System.Net.Dns]::GetHostAddresses('api.ipify.org') |
    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
    Select-Object -First 1 |
    ForEach-Object { $_.IPAddressToString }
}

function Get-CurrentExitIpViaAddress {
  param([string]$TargetIp)
  if ([string]::IsNullOrWhiteSpace($TargetIp)) {
    return Get-CurrentExitIp
  }
  $client = New-Object System.Net.Sockets.TcpClient
  $async = $client.BeginConnect($TargetIp, 443, $null, $null)
  if (-not $async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(10))) {
    $client.Close()
    throw "Timed out connecting to api.ipify.org address $TargetIp."
  }
  $client.EndConnect($async)
  $stream = $client.GetStream()
  $stream.ReadTimeout = 10000
  $stream.WriteTimeout = 10000
  $ssl = $null
  try {
    $callback = { param($sender, $cert, $chain, $errors) return $true }
    $ssl = New-Object System.Net.Security.SslStream($stream, $false, $callback)
    $ssl.ReadTimeout = 10000
    $ssl.WriteTimeout = 10000
    $ssl.AuthenticateAsClient('api.ipify.org')
    $request = [Text.Encoding]::ASCII.GetBytes("GET /?format=json HTTP/1.1`r`nHost: api.ipify.org`r`nAccept: application/json`r`nConnection: close`r`n`r`n")
    $ssl.Write($request, 0, $request.Length)
    $buffer = New-Object byte[] 4096
    $memory = New-Object System.IO.MemoryStream
    while (($read = $ssl.Read($buffer, 0, $buffer.Length)) -gt 0) {
      $memory.Write($buffer, 0, $read)
    }
    $text = [Text.Encoding]::UTF8.GetString($memory.ToArray())
    $body = ($text -split "`r`n`r`n", 2)[-1]
    $json = $body | ConvertFrom-Json
    if (-not $json.ip) {
      throw "Could not parse api.ipify.org response via $TargetIp`: $body"
    }
    [string]$json.ip
  } finally {
    if ($ssl) { $ssl.Dispose() }
    if ($client) { $client.Close() }
  }
}

function Clear-WindowsDnsCache {
  $output = & ipconfig /flushdns 2>&1
  if ($LASTEXITCODE -ne 0) {
    throw "ipconfig /flushdns failed: $($output -join ' ')"
  }
}

function Set-DnsServersForTun {
  if (-not $ProxyDns) {
    Warn 'DNS hardening skipped because -ProxyDns is disabled.'
    return
  }

  Step 'Hardening Windows DNS routes for TUN'
  $before = @(
    foreach ($family in @('IPv4', 'IPv6')) {
      Get-DnsClientServerAddress -AddressFamily $family -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, InterfaceIndex, @{Name = 'AddressFamily'; Expression = { $family } }, ServerAddresses
    }
  )
  $pathBefore = Join-Path $LogDir 'dns-servers-before-hardening.json'
  $before | ConvertTo-Json -Depth 5 | Set-Content -Path $pathBefore -Encoding UTF8

  $targets = @($before | Where-Object {
      $_.InterfaceAlias -and
      -not ([string]$_.InterfaceAlias).Equals($TunAdapterName, [System.StringComparison]::OrdinalIgnoreCase) -and
      -not ([string]$_.InterfaceAlias).Equals('Loopback Pseudo-Interface 1', [System.StringComparison]::OrdinalIgnoreCase) -and
      @($_.ServerAddresses | Where-Object { $_ -and ([string]$_) -notmatch '^fec0:0:0:ffff::[123]$' }).Count -gt 0
    })

  $targetGroups = @($targets | Group-Object InterfaceIndex)
  foreach ($group in $targetGroups) {
    $families = @($group.Group | ForEach-Object { [string]$_.AddressFamily } | Select-Object -Unique)
    $servers = @()
    if ($families -contains 'IPv4') { $servers += $BlockedIpv4DnsServer }
    if ($families -contains 'IPv6') { $servers += $BlockedIpv6DnsServer }
    if ($servers.Count -eq 0) { continue }
    Set-DnsClientServerAddress `
      -InterfaceIndex ([int]$group.Name) `
      -ServerAddresses @($servers) `
      -ErrorAction Stop
  }

  $after = @(
    foreach ($family in @('IPv4', 'IPv6')) {
      Get-DnsClientServerAddress -AddressFamily $family -ErrorAction SilentlyContinue |
        Select-Object InterfaceAlias, InterfaceIndex, @{Name = 'AddressFamily'; Expression = { $family } }, ServerAddresses
    }
  )
  $pathAfter = Join-Path $LogDir 'dns-servers-active.json'
  $after | ConvertTo-Json -Depth 5 | Set-Content -Path $pathAfter -Encoding UTF8
  Ok "Temporarily hardened $($targetGroups.Count) non-TUN interface DNS configuration(s): IPv4 to local blackhole $BlockedIpv4DnsServer, IPv6 to local blackhole $BlockedIpv6DnsServer. TUN DNS remains $TunDnsServer. Snapshots: $pathBefore, $pathAfter"
  Clear-WindowsDnsCache
  Ok 'Windows DNS cache flushed after DNS hardening.'
}

function Invoke-Pktmon {
  param(
    [string[]]$Arguments,
    [switch]$AllowFailure
  )
  $previousPreference = $ErrorActionPreference
  $output = @()
  $exitCode = 0
  try {
    $ErrorActionPreference = 'Continue'
    $output = & pktmon @Arguments 2>&1
    $exitCode = $LASTEXITCODE
  } catch {
    $output = @($_.Exception.Message)
    $exitCode = 1
  } finally {
    $ErrorActionPreference = $previousPreference
  }
  if ($exitCode -ne 0 -and -not $AllowFailure) {
    throw "pktmon $($Arguments -join ' ') failed: $($output -join ' ')"
  }
  $output
}

function Start-DnsLeakCapture {
  $pktmon = Get-Command 'pktmon.exe' -ErrorAction SilentlyContinue
  if (-not $pktmon) {
    throw 'pktmon.exe is required for the DNS leak probe but was not found.'
  }

  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $etl = Join-Path $LogDir "dns-leak-$stamp.etl"
  $txt = Join-Path $LogDir "dns-leak-$stamp.txt"
  Remove-Item -LiteralPath $etl, $txt -Force -ErrorAction SilentlyContinue

  Invoke-Pktmon -Arguments @('stop') -AllowFailure | Out-Null
  Invoke-Pktmon -Arguments @('filter', 'remove') -AllowFailure | Out-Null
  Invoke-Pktmon -Arguments @('filter', 'add', 'socks5proxy-dns', '-p', '53') | Out-Null
  Invoke-Pktmon -Arguments @('start', '--capture', '--pkt-size', '0', '--file-name', $etl) | Out-Null
  [PSCustomObject]@{
    Etl = $etl
    Txt = $txt
  }
}

function Stop-DnsLeakCapture {
  param($Capture)
  Invoke-Pktmon -Arguments @('stop') -AllowFailure | Out-Null
  Invoke-Pktmon -Arguments @('etl2txt', $Capture.Etl, '--out', $Capture.Txt, '--brief') | Out-Null
  Invoke-Pktmon -Arguments @('filter', 'remove') -AllowFailure | Out-Null
}

function Get-DnsLeakPacketLines {
  param([string]$TextPath)
  if (-not (Test-Path -LiteralPath $TextPath)) { return @() }
  Get-Content -Path $TextPath -ErrorAction SilentlyContinue |
    Where-Object {
      $_ -match '\b(UDP|TCP)\b' -and
      ($_ -match '(\.|:|\s)53(\s|,|:|$|->|<-)' -or $_ -match 'Port-[12]\s+53') -and
      $_ -notmatch 'ip:\s+10\.0\.0\.33\.\d+\s+>\s+10\.0\.0\.1\.53' -and
      $_ -notmatch 'ip:\s+10\.0\.0\.1\.53\s+>\s+10\.0\.0\.33\.\d+' -and
      $_ -notmatch '127\.0\.0\.1\.\d+\s+>\s+127\.0\.0\.1\.53' -and
      $_ -notmatch '127\.0\.0\.1\.53\s+>\s+127\.0\.0\.1\.\d+' -and
      $_ -notmatch '::1\.\d+\s+>\s+::1\.53' -and
      $_ -notmatch '::1\.53\s+>\s+::1\.\d+'
    }
}

function Invoke-DnsLeakProbe {
  if ($SkipDnsLeakProbe) {
    Warn 'DNS leak probe skipped by -SkipDnsLeakProbe.'
    return
  }
  if (-not $ProxyDns) {
    Warn 'DNS leak probe skipped because -ProxyDns is disabled.'
    return
  }

  Step 'Checking DNS leak with pktmon'
  $capture = Start-DnsLeakCapture
  try {
    Clear-WindowsDnsCache
    $probeName = "s5p-$([guid]::NewGuid().ToString('N')).example.com"
    Resolve-DnsName -Name $probeName -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null
  } finally {
    Stop-DnsLeakCapture -Capture $capture
  }

  $packetLines = @(Get-DnsLeakPacketLines -TextPath $capture.Txt)
  if ($packetLines.Count -gt 0) {
    $sample = ($packetLines | Select-Object -First 3) -join ' | '
    throw "DNS leak probe observed $($packetLines.Count) non-TUN packet line(s) matching TCP/UDP port 53 while TUN was active. Capture: $($capture.Txt). Sample: $sample"
  }
  Ok "No non-TUN TCP/UDP port 53 packets observed during DNS probe. Capture: $($capture.Txt)"
}

function Get-RouteInterfaceForIp {
  param([string]$Ip)
  $parsed = $null
  if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$parsed)) {
    return $null
  }
  $route = Find-NetRoute -RemoteIPAddress $parsed.IPAddressToString -ErrorAction SilentlyContinue |
    Select-Object -First 1
  if (-not $route) { return $null }
  $adapter = Get-NetAdapter -InterfaceIndex ([int]$route.InterfaceIndex) -ErrorAction SilentlyContinue
  if (-not $adapter) { return $null }
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
  } elseif ($route.PSObject.Properties['Metric']) {
    $routeMetric = $route.Metric
  }
  [PSCustomObject]@{
    Ip = $parsed.IPAddressToString
    InterfaceIndex = [int]$route.InterfaceIndex
    InterfaceAlias = [string]$adapter.Name
    DestinationPrefix = $destinationPrefix
    NextHop = $nextHop
    RouteMetric = $routeMetric
  }
}

function Get-TunAdapterSnapshot {
  Get-NetAdapter -Name $TunAdapterName -ErrorAction SilentlyContinue |
    Select-Object Name, InterfaceDescription, Status, ifIndex, MacAddress, InterfaceGuid
}

function Get-TunRouteSnapshot {
  Get-NetAdapter -Name $TunAdapterName -ErrorAction SilentlyContinue |
    ForEach-Object {
      Get-NetRoute -AddressFamily IPv4 -InterfaceIndex ([int]$_.ifIndex) -ErrorAction SilentlyContinue |
        Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, ifMetric, PolicyStore
    }
}

function Test-ProxyBypassRoutes {
  param([string[]]$ProxyIps)
  Step 'Checking proxy bypass routes'
  $routes = @($ProxyIps | Where-Object { $_ } | Select-Object -Unique |
    ForEach-Object { Get-RouteInterfaceForIp -Ip ([string]$_) } |
    Where-Object { $_ })
  $path = Join-Path $LogDir 'proxy-bypass-routes-active.json'
  $routes | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8

  if ($routes.Count -eq 0) {
    throw "No active route could be resolved for the upstream proxy IP(s). Snapshot: $path"
  }

  $loopRoutes = @($routes | Where-Object {
      ([string]$_.InterfaceAlias).Equals($TunAdapterName, [System.StringComparison]::OrdinalIgnoreCase)
    })
  if ($loopRoutes.Count -gt 0) {
    $summary = ($loopRoutes | ForEach-Object { "$($_.Ip) via $($_.InterfaceAlias) ($($_.DestinationPrefix))" }) -join '; '
    throw "Proxy bypass route(s) loop through active TUN adapter '$TunAdapterName': $summary. Snapshot: $path"
  }

  Ok "Proxy route(s) avoid active TUN adapter '$TunAdapterName'. Snapshot: $path"
}

function Test-DnsServerRoutesThroughTun {
  if ($SkipDnsRouteCheck) {
    Warn 'DNS server route check skipped by -SkipDnsRouteCheck.'
    return
  }
  if (-not $ProxyDns) {
    Warn 'DNS server route check skipped because -ProxyDns is disabled.'
    return
  }

  Step 'Checking DNS server routes'
  $servers = @(
    foreach ($family in @('IPv4', 'IPv6')) {
      Get-DnsClientServerAddress -AddressFamily $family -ErrorAction SilentlyContinue |
        ForEach-Object {
          $entry = $_
          @($entry.ServerAddresses) | Where-Object {
            $_ -and ([string]$_) -notmatch '^fec0:0:0:ffff::[123]$'
          } | ForEach-Object {
            [PSCustomObject]@{
              AddressFamily = $family
              ServerAddress = [string]$_
            }
          }
        }
    }
  ) | Sort-Object AddressFamily, ServerAddress -Unique

  if (-not $servers -or @($servers).Count -eq 0) {
    Warn 'No configured DNS servers were reported by Windows.'
    return
  }

  $routes = @($servers | ForEach-Object {
      $route = Get-RouteInterfaceForIp -Ip ([string]$_.ServerAddress)
      if ($route) {
        $route | Add-Member -NotePropertyName AddressFamily -NotePropertyValue ([string]$_.AddressFamily) -Force
        $route
      } else {
        [PSCustomObject]@{
          Ip = [string]$_.ServerAddress
          AddressFamily = [string]$_.AddressFamily
          InterfaceIndex = $null
          InterfaceAlias = $null
          DestinationPrefix = $null
          NextHop = $null
          RouteMetric = $null
        }
      }
    })
  $path = Join-Path $LogDir 'dns-server-routes-active.json'
  $routes | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8

  $leaks = @($routes | Where-Object {
      $ip = [string]$_.Ip
      if ($ip -eq $BlockedIpv4DnsServer -or $ip -eq $BlockedIpv6DnsServer) {
        $false
      } else {
        -not ([string]$_.InterfaceAlias).Equals($TunAdapterName, [System.StringComparison]::OrdinalIgnoreCase)
      }
    })
  if ($leaks.Count -gt 0) {
    $summary = ($leaks | ForEach-Object { "$($_.Ip) [$($_.AddressFamily)] via $($_.InterfaceAlias) ($($_.DestinationPrefix))" }) -join '; '
    throw "Configured DNS server route(s) do not use active TUN adapter '$TunAdapterName': $summary. Snapshot: $path"
  }

  Ok "Configured DNS server routes use active TUN adapter '$TunAdapterName' or local DNS blackholes '$BlockedIpv4DnsServer'/'$BlockedIpv6DnsServer'. Snapshot: $path"
}

function Save-ActiveTunProof {
  param(
    [int]$Tun2ProxyPid,
    [string[]]$ProxyIps,
    [string[]]$BypassIps,
    [string]$BaselineExitIp,
    [string]$ExpectedProxyExitIp,
    [string]$ObservedExitIp
  )
  $path = Join-Path $LogDir 'active-tun-proof.json'
  [PSCustomObject]@{
    CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    TunAdapterName = $TunAdapterName
    Tun2ProxyPid = $Tun2ProxyPid
    ProxyDns = [bool]$ProxyDns
    BaselineExitIp = $BaselineExitIp
    ExpectedProxyExitIp = $ExpectedProxyExitIp
    ObservedExitIp = $ObservedExitIp
    ProxyIps = @($ProxyIps)
    BypassIps = @($BypassIps)
    TunAdapters = @(Get-TunAdapterSnapshot)
    TunRoutes = @(Get-TunRouteSnapshot)
    ProxyBypassRoutes = @($ProxyIps | Where-Object { $_ } | Select-Object -Unique |
      ForEach-Object { Get-RouteInterfaceForIp -Ip ([string]$_) } |
      Where-Object { $_ })
    BypassRouteSnapshot = @($BypassIps | Where-Object { $_ } | Select-Object -Unique |
      ForEach-Object { Get-RouteInterfaceForIp -Ip ([string]$_) } |
      Where-Object { $_ })
    DefaultRoutes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
      Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, ifMetric, PolicyStore)
  } | ConvertTo-Json -Depth 6 | Set-Content -Path $path -Encoding UTF8
  $path
}

function Restore-Network {
  param([string]$Snapshot)
  powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'restore-network-windows.ps1') `
    -SystemProxySnapshot $Snapshot `
    -RestoreDnsServers `
    -TunAdapterName $TunAdapterName `
    -RemoveTunRoutes `
    -DisableStaleTunAdapter `
    -VerifyCleanup | Out-Null
}

function Start-RestoreWatchdog {
  param(
    [string]$Snapshot,
    [int]$DelaySeconds
  )
  Start-Job -ScriptBlock {
    param($ScriptRoot, $SnapshotPath, $Delay, $TunName)
    Start-Sleep -Seconds $Delay
    powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptRoot 'restore-network-windows.ps1') `
      -SystemProxySnapshot $SnapshotPath `
      -RestoreDnsServers `
      -TunAdapterName $TunName `
      -RemoveTunRoutes `
      -DisableStaleTunAdapter `
      -VerifyCleanup | Out-Null
  } -ArgumentList $PSScriptRoot, $Snapshot, $DelaySeconds, $TunAdapterName
}

function Start-EmergencyWatchdog {
  param(
    [string]$CancelFile,
    [int]$DelaySeconds,
    [int]$ParentProcessId
  )
  if (Test-Path -LiteralPath $CancelFile) {
    Remove-Item -LiteralPath $CancelFile -Force -ErrorAction SilentlyContinue
  }
  $watchdogScript = Join-Path $LogDir 'emergency-watchdog.ps1'
  $watchdogLog = Join-Path $LogDir 'emergency-watchdog.log'
  @'
param(
  [string]$ScriptRoot,
  [string]$CancelFile,
  [int]$DelaySeconds,
  [int]$ParentProcessId,
  [string]$TunAdapterName,
  [int]$CloseEdgeValue,
  [string]$LogPath
)

$ErrorActionPreference = 'Continue'
for ($i = 0; $i -lt $DelaySeconds; $i++) {
  if (Test-Path -LiteralPath $CancelFile) { exit 0 }
  Start-Sleep -Seconds 1
}
while ($true) {
  if (Test-Path -LiteralPath $CancelFile) { exit 0 }
  $parentAlive = $false
  try {
    $parentAlive = $null -ne (Get-Process -Id $ParentProcessId -ErrorAction SilentlyContinue)
  } catch {
    $parentAlive = $false
  }
  if (-not $parentAlive) { break }
  Start-Sleep -Seconds 2
}

$reset = Join-Path $ScriptRoot 'emergency-network-reset-windows.ps1'
$args = @(
  '-NoProfile',
  '-ExecutionPolicy', 'Bypass',
  '-File', $reset,
  '-TunAdapterName', $TunAdapterName,
  '-ResetDnsServers'
)
if ($CloseEdgeValue -eq 1) { $args += '-CloseEdge' }
$stdoutPath = [System.IO.Path]::ChangeExtension($LogPath, '.stdout.log')
$stderrPath = [System.IO.Path]::ChangeExtension($LogPath, '.stderr.log')
"$(Get-Date -Format o) emergency watchdog running reset" | Set-Content -Path $LogPath -Encoding UTF8
"stdout=$stdoutPath" | Add-Content -Path $LogPath -Encoding UTF8
"stderr=$stderrPath" | Add-Content -Path $LogPath -Encoding UTF8
$resetProcess = Start-Process -FilePath 'powershell.exe' `
  -ArgumentList $args `
  -RedirectStandardOutput $stdoutPath `
  -RedirectStandardError $stderrPath `
  -WindowStyle Hidden `
  -PassThru `
  -Wait
"$(Get-Date -Format o) emergency watchdog reset exit code=$($resetProcess.ExitCode)" | Add-Content -Path $LogPath -Encoding UTF8
'@ | Set-Content -Path $watchdogScript -Encoding UTF8

  $closeEdgeValue = if ($NoEmergencyCloseEdge) { 0 } else { 1 }
  Start-Process -FilePath 'powershell.exe' `
    -ArgumentList @(
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-File', $watchdogScript,
      '-ScriptRoot', $PSScriptRoot,
      '-CancelFile', $CancelFile,
      '-DelaySeconds', $DelaySeconds,
      '-ParentProcessId', $PID,
      '-TunAdapterName', $TunAdapterName,
      '-CloseEdgeValue', $closeEdgeValue,
      '-LogPath', $watchdogLog
    ) `
    -WindowStyle Hidden `
    -PassThru
}

function Save-TestNetworkState {
  param([string]$Name)
  $path = Join-Path $LogDir "$Name-network-state.json"
  [PSCustomObject]@{
    CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
    TunAdapterName = $TunAdapterName
    ManagedTunAdapters = @(Get-NetAdapter -Name $TunAdapterName -ErrorAction SilentlyContinue |
      Select-Object Name, InterfaceDescription, Status, ifIndex, MacAddress, InterfaceGuid)
    ManagedTunRoutes = @(Get-NetAdapter -Name $TunAdapterName -ErrorAction SilentlyContinue |
      ForEach-Object {
        Get-NetRoute -AddressFamily IPv4 -InterfaceIndex ([int]$_.ifIndex) -ErrorAction SilentlyContinue |
          Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, ifMetric, PolicyStore
      })
  } | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding UTF8
  $path
}

Step 'Preflight'
if (-not (Test-Path $Tun2Proxy)) { throw "Missing $Tun2Proxy. Run scripts\install-runtime-windows.ps1." }
if (-not (Test-Path $Wintun)) { throw "Missing $Wintun. Run scripts\install-runtime-windows.ps1." }
$entry = Read-FirstProxyEntry -Path $CredentialsPath
$proxy = Parse-ProxyEntry -Line $entry
Ok 'Loaded proxy test entry without printing credentials.'
$mullvadBypassIps = @(Get-MullvadTransportBypasses)
if ($mullvadBypassIps.Count -gt 0) {
  Ok "Detected $($mullvadBypassIps.Count) Mullvad transport bypass IP(s) for live TUN tests."
}
$mullvadStatus = Get-MullvadRuntimeStatus
$mullvadBlockReason = Get-MullvadTunBlockReason -Status $mullvadStatus
$mullvadDisconnectedForTest = $false
if ($mullvadBlockReason) {
  Warn $mullvadBlockReason
  if ($TemporarilyDisconnectMullvad) {
    Warn 'Live mode may temporarily disconnect Mullvad before preflight proxy probes, then reconnect it in cleanup.'
  }
}
if ($Live) {
  if ($mullvadBlockReason -and -not $TemporarilyDisconnectMullvad) {
    throw $mullvadBlockReason
  }
  if (-not (Test-Administrator)) {
    if ($NoElevate) {
      throw 'Live Z2 test requires administrator rights. Remove -NoElevate to allow a UAC relaunch.'
    }
    Warn 'Live Z2 test requires administrator rights. Relaunching with UAC.'
    Relaunch-Elevated
    return
  }
  if ($mullvadBlockReason -and $TemporarilyDisconnectMullvad) {
    $mullvadDisconnectedForTest = $true
    Disconnect-MullvadForZ2
  }
}
Test-Socks5Handshake -Proxy $proxy
Ok 'SOCKS5 handshake/auth succeeded.'
$baselineExitIp = $null
try {
  $baselineExitIp = Get-CurrentExitIp
  Ok "Baseline exit IP before TUN: $baselineExitIp"
} catch {
  Warn "Could not read baseline exit IP before TUN: $($_.Exception.Message)"
}
$expectedProxyExitIp = $null
try {
  $expectedProxyExitIp = Get-ProxyExitIp -Proxy $proxy
  Ok "Expected proxy exit IP via SOCKS5 remote-DNS probe: $expectedProxyExitIp"
} catch {
  Warn "Could not read expected proxy exit IP through SOCKS5: $($_.Exception.Message)"
}
$ipifyIp = $null
try {
  $ipifyIp = Resolve-IpifyIpv4
  if ($ipifyIp) {
    Ok "Resolved api.ipify.org IPv4 for TUN exit probe: $ipifyIp"
  }
} catch {
  Warn "Could not resolve api.ipify.org before TUN start: $($_.Exception.Message)"
}

if (-not $Live) {
  Warn 'Dry-run only. Re-run with -Live to start tun2proxy and modify host routing. Emergency fallback: scripts\emergency-network-reset-windows.ps1 -CloseEdge'
  return
}

Step 'Saving fallback snapshot'
$snapshot = powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'save-network-snapshot-windows.ps1')
Ok "Snapshot saved: $snapshot"
$preState = Save-TestNetworkState -Name 'before'
Ok "Pre-test managed TUN state saved: $preState"
$watchdog = Start-RestoreWatchdog -Snapshot $snapshot -DelaySeconds $TimeoutSeconds
$emergencyCancel = Join-Path $LogDir 'emergency-watchdog.cancel'
$emergencyWatchdog = Start-EmergencyWatchdog -CancelFile $emergencyCancel -DelaySeconds 8 -ParentProcessId $PID
Ok "Emergency watchdog armed; cancel file: $emergencyCancel"
$process = $null

try {
  if ($mullvadBlockReason -and $TemporarilyDisconnectMullvad -and -not $mullvadDisconnectedForTest) {
    $mullvadDisconnectedForTest = $true
    Disconnect-MullvadForZ2
    try {
      $baselineExitIp = Get-CurrentExitIp
      Ok "Baseline exit IP after temporary Mullvad disconnect: $baselineExitIp"
    } catch {
      Warn "Could not refresh baseline exit IP after Mullvad disconnect: $($_.Exception.Message)"
    }
  }

  Step 'Starting tun2proxy Z2 session'
  if ($ProxyDns) {
    Clear-WindowsDnsCache
    Ok 'Windows DNS cache flushed before TUN start.'
  } else {
    Warn 'Proxy DNS is disabled; this live run may allow direct system DNS lookups.'
  }
  $proxyIps = [System.Net.Dns]::GetHostAddresses([string]$proxy.Host) |
    Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
    ForEach-Object { $_.IPAddressToString } |
    Select-Object -Unique
  $bypassIps = @(@($proxyIps) + @($mullvadBypassIps) | Where-Object { $_ } | Select-Object -Unique)
  $arguments = @(
    '--tun', $TunAdapterName,
    '--setup',
    '--proxy', (New-Socks5Url -Proxy $proxy),
    '--dns', $(if ($ProxyDns) { 'virtual' } else { 'direct' }),
    '--verbosity', 'info'
  )
  foreach ($ip in $bypassIps) {
    $arguments += @('--bypass', $ip)
  }
  Ok "Configured $($bypassIps.Count) TUN bypass IP(s), including proxy and Mullvad transport candidates."
  $stdout = Join-Path $LogDir 'tun2proxy.stdout.log'
  $stderr = Join-Path $LogDir 'tun2proxy.stderr.log'
  $process = Start-Process -FilePath $Tun2Proxy `
    -ArgumentList $arguments `
    -WorkingDirectory $RuntimeDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -PassThru
  Start-Sleep -Seconds $StartupSeconds
  if ($process.HasExited) {
    throw "tun2proxy exited early with code $($process.ExitCode). See $stderr"
  }
  Ok "tun2proxy is running with pid $($process.Id)."

  Set-DnsServersForTun
  Test-ProxyBypassRoutes -ProxyIps $proxyIps

  Step 'Checking exit IP through TUN'
  $exitIp = Get-CurrentExitIpViaAddress -TargetIp $ipifyIp
  if ($baselineExitIp -and $exitIp -eq $baselineExitIp) {
    throw "Exit IP through active TUN is unchanged from baseline ($exitIp). Expected proxy TUN routing to change the observed exit IP."
  }
  if ($expectedProxyExitIp -and $exitIp -ne $expectedProxyExitIp) {
    throw "Exit IP through active TUN is $exitIp, but SOCKS5 proxy probe expected $expectedProxyExitIp."
  }
  Ok "Exit IP observed through active TUN: $exitIp"
  $activeProof = Save-ActiveTunProof `
    -Tun2ProxyPid $process.Id `
    -ProxyIps $proxyIps `
    -BypassIps $bypassIps `
    -BaselineExitIp $baselineExitIp `
    -ExpectedProxyExitIp $expectedProxyExitIp `
    -ObservedExitIp $exitIp
  Ok "Active TUN proof saved: $activeProof"

  Test-DnsServerRoutesThroughTun
  Invoke-DnsLeakProbe
} finally {
  Step 'Restoring network state'
  try {
    if ($process -and -not $process.HasExited) {
      Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    }
  } catch {
    Warn "Could not stop tun2proxy process cleanly: $($_.Exception.Message)"
  }
  try {
    Restore-Network -Snapshot $snapshot
  } catch {
    Warn "Network restore command failed: $($_.Exception.Message)"
  }
  try {
    $postState = Save-TestNetworkState -Name 'after'
    Ok "Post-test managed TUN state saved: $postState"
  } catch {
    Warn "Could not save post-test managed TUN state: $($_.Exception.Message)"
  }
  try {
    if ($watchdog) {
      Stop-Job -Job $watchdog -ErrorAction SilentlyContinue
      Remove-Job -Job $watchdog -Force -ErrorAction SilentlyContinue
    }
  } catch {
    Warn "Could not stop restore watchdog cleanly: $($_.Exception.Message)"
  }
  try {
    if ($emergencyCancel) {
      Set-Content -Path $emergencyCancel -Value (Get-Date -Format o) -Encoding UTF8
    }
    if ($emergencyWatchdog -and -not $emergencyWatchdog.HasExited) {
      Wait-Process -Id $emergencyWatchdog.Id -Timeout 5 -ErrorAction SilentlyContinue
    }
  } catch {
    Warn "Could not cancel emergency watchdog cleanly: $($_.Exception.Message)"
  }
  try {
    if ($mullvadDisconnectedForTest) {
      Reconnect-MullvadAfterZ2
    }
  } catch {
    Warn "Mullvad reconnect cleanup failed: $($_.Exception.Message)"
  }
  Ok 'Network restore attempted.'
  if ($TranscriptStarted) {
    try { Stop-Transcript | Out-Null } catch {}
  }
}
