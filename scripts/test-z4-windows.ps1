param(
  [string]$CredentialsPath,
  [switch]$Live,
  [string]$DesktopExe,
  [switch]$AllowWfpMutation,
  [switch]$TestReconnect,
  [switch]$KeepApplied,
  [switch]$NoElevate
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
$LogDir = Join-Path $RootDir '.build\z4-preflight'
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

function Get-Prop {
  param(
    $Object,
    [string]$Name
  )
  if (-not $Object) { return $null }
  $property = $Object.PSObject.Properties[$Name]
  if ($property) { return $property.Value }
  $null
}

function Add-UniqueIp {
  param(
    [System.Collections.Generic.List[string]]$List,
    [string]$Candidate
  )
  if ([string]::IsNullOrWhiteSpace($Candidate)) { return }
  $parsed = $null
  if ([System.Net.IPAddress]::TryParse($Candidate.Trim(), [ref]$parsed)) {
    $normalized = $parsed.IPAddressToString
    if (-not $List.Contains($normalized)) {
      $List.Add($normalized)
    }
  }
}

function Add-EndpointIp {
  param(
    [System.Collections.Generic.List[string]]$List,
    [string]$Address
  )
  if ([string]::IsNullOrWhiteSpace($Address)) { return }
  $trimmed = $Address.Trim()
  if ($trimmed -match '^\[(?<ip>[^\]]+)\](?::\d+)?$') {
    Add-UniqueIp -List $List -Candidate $Matches.ip
  } elseif ($trimmed -match '^(?<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$') {
    Add-UniqueIp -List $List -Candidate $Matches.ip
  } else {
    Add-UniqueIp -List $List -Candidate $trimmed
  }
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

function Get-MullvadStatus {
  $mullvad = Resolve-MullvadCli
  if (-not $mullvad) {
    return [PSCustomObject]@{
      CliPath = $null
      State = $null
      Raw = $null
      LockdownMode = $null
      Error = 'mullvad.exe was not found'
    }
  }

  $errorText = $null
  $status = $null
  try {
    $statusText = & $mullvad status --json 2>&1
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($statusText -join "`n"))) {
      $status = ($statusText -join "`n") | ConvertFrom-Json
    } else {
      $errorText = "mullvad status --json failed: $($statusText -join ' ')"
    }
  } catch {
    $errorText = $_.Exception.Message
  }

  $lockdown = $null
  try {
    $lockdownText = (& $mullvad lockdown-mode get 2>&1) -join "`n"
    if ($LASTEXITCODE -eq 0) {
      $lockdown = $lockdownText.Trim()
    }
  } catch {
    Warn "Could not inspect Mullvad lockdown-mode: $($_.Exception.Message)"
  }

  [PSCustomObject]@{
    CliPath = $mullvad
    State = if ($status) { [string](Get-Prop -Object $status -Name 'state') } else { $null }
    Raw = $status
    LockdownMode = $lockdown
    Error = $errorText
  }
}

function Get-MullvadTransportIps {
  param($MullvadStatus)
  $ips = New-Object System.Collections.Generic.List[string]
  $raw = $MullvadStatus.Raw
  $details = Get-Prop -Object $raw -Name 'details'
  $endpoint = Get-Prop -Object $details -Name 'endpoint'
  $location = Get-Prop -Object $details -Name 'location'
  Add-EndpointIp -List $ips -Address ([string](Get-Prop -Object $endpoint -Name 'address'))

  $hostnames = @()
  $relayHostname = Get-Prop -Object $location -Name 'hostname'
  $entryHostname = Get-Prop -Object $location -Name 'entry_hostname'
  if ($relayHostname) { $hostnames += $relayHostname }
  if ($entryHostname) { $hostnames += $entryHostname }
  if ($hostnames.Count -gt 0 -and $MullvadStatus.CliPath) {
    try {
      $relayText = (& $MullvadStatus.CliPath relay list 2>$null) -join "`n"
      if ($LASTEXITCODE -eq 0) {
        foreach ($hostname in ($hostnames | Select-Object -Unique)) {
          Add-MullvadRelayIps -List $ips -RelayList $relayText -Hostname ([string]$hostname)
        }
      }
    } catch {
      Warn "Could not inspect Mullvad relay list: $($_.Exception.Message)"
    }
  }
  @($ips | Select-Object -Unique)
}

function Get-ActiveVpnAdapters {
  Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Status -eq 'Up' -and
      (
        $_.Name -match 'mullvad|wireguard|wg|vpn|tun|tap|wintun' -or
        $_.InterfaceDescription -match 'mullvad|wireguard|wg|vpn|tun|tap|wintun'
      )
    } |
    Select-Object Name, InterfaceDescription, ifIndex, Status, MacAddress
}

function Test-Administrator {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Get-FirewallPreflight {
  $profiles = @()
  $matchingRules = @()
  $wfpStateAvailable = $false
  $wfpStateError = $null
  try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop |
      Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules)
  } catch {
    Warn "Could not inspect Windows Firewall profiles: $($_.Exception.Message)"
  }

  try {
    $matchingRules = @(Get-NetFirewallRule -ErrorAction Stop |
      Where-Object {
        $_.DisplayName -match 'Mullvad|WireGuard|socks5proxy|tun2proxy' -or
        $_.Group -match 'Mullvad|WireGuard|socks5proxy|tun2proxy'
      } |
      Select-Object DisplayName, Name, Enabled, Direction, Action, Profile, Group)
  } catch {
    Warn "Could not inspect Windows Firewall rules: $($_.Exception.Message)"
  }

  try {
    $wfpText = (& netsh wfp show state 2>&1) -join "`n"
    if ($LASTEXITCODE -eq 0) {
      $wfpStateAvailable = $true
    } else {
      $wfpStateError = $wfpText.Trim()
    }
  } catch {
    $wfpStateError = $_.Exception.Message
  }

  [PSCustomObject]@{
    Elevated = Test-Administrator
    Profiles = $profiles
    MatchingFirewallRules = $matchingRules
    MatchingFirewallRuleCount = $matchingRules.Count
    WfpStateAvailable = $wfpStateAvailable
    WfpStateError = $wfpStateError
  }
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
  [PSCustomObject]@{
    Ip = $parsed.IPAddressToString
    InterfaceIndex = [int]$route.InterfaceIndex
    InterfaceAlias = if ($adapter) { [string]$adapter.Name } else { $null }
    InterfaceDescription = if ($adapter) { [string]$adapter.InterfaceDescription } else { $null }
    DestinationPrefix = $destinationPrefix
    NextHop = if ($route.PSObject.Properties['NextHop']) { [string]$route.NextHop } else { $null }
  }
}

function Resolve-SupportFile {
  param(
    [string[]]$RelativePaths
  )
  foreach ($relative in $RelativePaths) {
    $candidate = Join-Path $RootDir $relative
    if (Test-Path -LiteralPath $candidate -PathType Leaf) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }
  $null
}

function Get-EndpointIpString {
  param([string]$Address)
  if ([string]::IsNullOrWhiteSpace($Address)) { return $null }
  $ips = New-Object System.Collections.Generic.List[string]
  Add-EndpointIp -List $ips -Address $Address
  if ($ips.Count -gt 0) { return $ips[0] }
  $null
}

function New-DeterministicWfpGuid {
  param(
    [string]$SessionTag,
    [string]$Role
  )
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [Text.Encoding]::UTF8.GetBytes("socks5proxy-windows-wfp-v1$SessionTag`:$Role")
    $hash = $sha.ComputeHash($bytes)
    $guidBytes = New-Object byte[] 16
    [Array]::Copy($hash, $guidBytes, 16)
    $guidBytes[6] = ($guidBytes[6] -band 0x0f) -bor 0x50
    $guidBytes[8] = ($guidBytes[8] -band 0x3f) -bor 0x80
    $hex = @($guidBytes | ForEach-Object { $_.ToString('x2') })
    '{' +
      ($hex[0..3] -join '') + '-' +
      ($hex[4..5] -join '') + '-' +
      ($hex[6..7] -join '') + '-' +
      ($hex[8..9] -join '') + '-' +
      ($hex[10..15] -join '') +
      '}'
  } finally {
    $sha.Dispose()
  }
}

function New-WfpFilterIdentities {
  param([string]$SessionTag)
  @(
    @{ Role = 'provider'; Layer = 'FWPM_PROVIDER'; DisplayName = 'SOCKS5Proxy Z4 WFP provider' },
    @{ Role = 'sublayer'; Layer = 'FWPM_SUBLAYER'; DisplayName = 'SOCKS5Proxy Z4 WFP sublayer' },
    @{ Role = 'allow_tun2proxy'; Layer = 'FWPM_LAYER_ALE_AUTH_CONNECT_V4'; DisplayName = 'SOCKS5Proxy Z4 allow tun2proxy' },
    @{ Role = 'allow_controller'; Layer = 'FWPM_LAYER_ALE_AUTH_CONNECT_V4'; DisplayName = 'SOCKS5Proxy Z4 allow controller' },
    @{ Role = 'enforce_proxy_vpn_route'; Layer = 'FWPM_LAYER_ALE_AUTH_CONNECT_V4'; DisplayName = 'SOCKS5Proxy Z4 enforce proxy via Mullvad' },
    @{ Role = 'allow_mullvad_transport'; Layer = 'FWPM_LAYER_ALE_AUTH_CONNECT_V4'; DisplayName = 'SOCKS5Proxy Z4 allow Mullvad transport' }
  ) | ForEach-Object {
    [PSCustomObject]@{
      Role = $_.Role
      Key = New-DeterministicWfpGuid -SessionTag $SessionTag -Role $_.Role
      DisplayName = $_.DisplayName
      Layer = $_.Layer
    }
  }
}

function New-WfpExceptionPlan {
  param(
    [bool]$Connected,
    $Firewall,
    [string]$TunnelInterface,
    [string]$EndpointAddress
  )

  $appPath = Resolve-SupportFile -RelativePaths @(
    'build-artifacts\windows\socks5proxy-desktop.exe',
    'target\debug\socks5proxy-desktop.exe'
  )
  $tun2proxyPath = Resolve-SupportFile -RelativePaths @(
    'runtime\windows\tun2proxy-bin.exe',
    'build-artifacts\windows\tun2proxy-bin.exe'
  )
  $endpointIp = Get-EndpointIpString -Address $EndpointAddress
  $blockers = New-Object System.Collections.Generic.List[string]
  $warnings = New-Object System.Collections.Generic.List[string]

  if ($Connected) {
    if (-not $Firewall.Elevated) {
      $blockers.Add('Administrator rights are required to inspect and install WFP filters.')
    }
    if (-not $Firewall.WfpStateAvailable) {
      if ($Firewall.WfpStateError) {
        $blockers.Add("WFP state is not readable in this session: $($Firewall.WfpStateError)")
      } else {
        $blockers.Add('WFP state is not readable in this session.')
      }
    }
    if (-not $appPath) {
      $blockers.Add('socks5proxy-desktop.exe could not be resolved for WFP scoping.')
    }
    if (-not $tun2proxyPath) {
      $blockers.Add('tun2proxy-bin.exe could not be resolved for WFP process scoping.')
    }
    if (-not $TunnelInterface) {
      $blockers.Add('Mullvad tunnel interface is unknown.')
    }
    if (-not $endpointIp) {
      $blockers.Add('Mullvad transport endpoint IP is unknown.')
    }
    if ($Firewall.MatchingFirewallRuleCount -eq 0) {
      $warnings.Add('No high-level Windows Firewall rules matching Mullvad/WireGuard/socks5proxy/tun2proxy were visible; the effective policy is likely in lower WFP layers.')
    }
  }

  $plannedAllows = @()
  $plannedCleanup = @()
  $plannedFilterIdentities = @()
  if ($Connected) {
    $plannedAllows = @(
      'Allow the managed tun2proxy process to exchange packets with the Wintun adapter while Mullvad is connected.',
      'Allow the socks5proxy desktop controller to manage the TUN session and local SOCKS bridge without opening unrelated outbound traffic.',
      'Keep the proxy server host route pinned through the Mullvad tunnel; do not allow proxy traffic to bypass Mullvad.',
      'Keep Mullvad relay/transport traffic outside the proxy TUN so VPN keepalives and rekeys cannot loop back into tun2proxy.'
    )
    $plannedCleanup = @(
      'Remove all socks5proxy-scoped WFP filters when the TUN session stops, fails to start, or is recovered after a crash.',
      'Remove stale socks5proxy-scoped WFP filters before installing a replacement session after Mullvad reconnects or changes relay.'
    )
    $plannedFilterIdentities = @(New-WfpFilterIdentities -SessionTag 'socks5proxy-z4')
  }

  $ready = $Connected -and $blockers.Count -eq 0
  $status = if (-not $Connected) { 'not_required' } elseif ($ready) { 'ready' } else { 'blocked' }

  [PSCustomObject]@{
    Required = [bool]$Connected
    Ready = [bool]$ready
    Status = $status
    Blockers = @($blockers)
    Warnings = @($warnings)
    AppPath = $appPath
    Tun2proxyPath = $tun2proxyPath
    MullvadTunnelInterface = $TunnelInterface
    MullvadEndpointIp = $endpointIp
    PlannedAllows = $plannedAllows
    PlannedCleanup = $plannedCleanup
    PlannedFilterIdentities = $plannedFilterIdentities
    SessionTag = 'socks5proxy-z4'
  }
}

function Get-WfpOperationScope {
  param([string]$Role)
  switch ($Role) {
    'provider' { 'create socks5proxy-owned WFP provider' }
    'sublayer' { 'create socks5proxy-owned WFP sublayer' }
    'allow_tun2proxy' { 'allow managed tun2proxy process traffic' }
    'allow_controller' { 'allow desktop controller management traffic' }
    'enforce_proxy_vpn_route' { 'enforce proxy server traffic through Mullvad tunnel' }
    'allow_mullvad_transport' { 'allow Mullvad relay transport outside proxy TUN' }
    default { 'unknown socks5proxy WFP identity' }
  }
}

function New-WfpOperation {
  param(
    [string]$Action,
    $Identity,
    [string]$Scope
  )
  [PSCustomObject]@{
    Action = $Action
    Role = [string]$Identity.Role
    Key = [string]$Identity.Key
    Layer = [string]$Identity.Layer
    DisplayName = [string]$Identity.DisplayName
    Scope = $Scope
  }
}

function New-WfpOperationPlan {
  param($WfpExceptionPlan)

  if (-not [bool]$WfpExceptionPlan.Required) {
    return [PSCustomObject]@{
      Required = $false
      Ready = $false
      Status = 'not_required'
      Blockers = @()
      SessionTag = [string]$WfpExceptionPlan.SessionTag
      CleanupBeforeApply = @()
      ApplyOperations = @()
      RollbackOperations = @()
      ExpectedRuntimeFilters = @()
    }
  }

  $identities = @($WfpExceptionPlan.PlannedFilterIdentities)
  $cleanupBeforeApply = @()
  for ($i = $identities.Count - 1; $i -ge 0; $i--) {
    $cleanupBeforeApply += New-WfpOperation -Action 'delete_stale' -Identity $identities[$i] -Scope 'session identity cleanup'
  }
  $applyOperations = @()
  foreach ($identity in $identities) {
    $applyOperations += New-WfpOperation -Action 'add' -Identity $identity -Scope (Get-WfpOperationScope -Role ([string]$identity.Role))
  }
  $rollbackOperations = @()
  for ($i = $identities.Count - 1; $i -ge 0; $i--) {
    $rollbackOperations += New-WfpOperation -Action 'delete' -Identity $identities[$i] -Scope 'session rollback'
  }
  $expectedRuntimeFilters = @()
  foreach ($identity in $identities) {
    if ([string]$identity.Layer -like 'FWPM_LAYER_*') {
      $expectedRuntimeFilters += [PSCustomObject]@{
        FilterId = [string]$identity.Key
        Layer = [string]$identity.Layer
        DisplayName = [string]$identity.DisplayName
        SessionTag = [string]$WfpExceptionPlan.SessionTag
      }
    }
  }

  [PSCustomObject]@{
    Required = $true
    Ready = [bool]$WfpExceptionPlan.Ready
    Status = if ([bool]$WfpExceptionPlan.Ready) { 'ready' } else { 'blocked' }
    Blockers = @($WfpExceptionPlan.Blockers)
    SessionTag = [string]$WfpExceptionPlan.SessionTag
    CleanupBeforeApply = $cleanupBeforeApply
    ApplyOperations = $applyOperations
    RollbackOperations = $rollbackOperations
    ExpectedRuntimeFilters = $expectedRuntimeFilters
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

if ($Live) {
  $liveScript = Join-Path $PSScriptRoot 'test-z4-wfp-live-windows.ps1'
  $arguments = @{
    CredentialsPath = $CredentialsPath
  }
  if ($DesktopExe) { $arguments.DesktopExe = $DesktopExe }
  if ($AllowWfpMutation) { $arguments.AllowWfpMutation = $true }
  if ($TestReconnect) { $arguments.TestReconnect = $true }
  if ($KeepApplied) { $arguments.KeepApplied = $true }
  if ($NoElevate) { $arguments.NoElevate = $true }
  & $liveScript @arguments
  exit $LASTEXITCODE
}

Step 'Proxy preflight'
$entry = Read-FirstProxyEntry -Path $CredentialsPath
$proxy = Parse-ProxyEntry -Line $entry
Ok 'Loaded proxy test entry without printing credentials.'
$proxyHandshakeSucceeded = $false
$proxyHandshakeError = $null
try {
  Test-Socks5Handshake -Proxy $proxy
  $proxyHandshakeSucceeded = $true
  Ok 'SOCKS5 handshake/auth succeeded.'
} catch {
  $proxyHandshakeError = $_.Exception.Message
}
$proxyIps = @(Resolve-ProxyIps -Proxy $proxy)
if ($proxyIps.Count -eq 0) {
  throw "Could not resolve proxy host $($proxy.Host)."
}
Ok "Resolved proxy host to $($proxyIps.Count) IP address(es): $($proxyIps -join ', ')"

Step 'Mullvad preflight'
$mullvad = Get-MullvadStatus
if ($mullvad.CliPath) {
  Ok "Mullvad CLI found: $($mullvad.CliPath)"
} else {
  Warn 'Mullvad CLI was not found; Z4 cannot be verified.'
}
if ($mullvad.Error) {
  Warn $mullvad.Error
}
$details = Get-Prop -Object $mullvad.Raw -Name 'details'
$endpoint = Get-Prop -Object $details -Name 'endpoint'
$location = Get-Prop -Object $details -Name 'location'
$endpointAddress = Get-Prop -Object $endpoint -Name 'address'
$tunnelInterface = Get-Prop -Object $endpoint -Name 'tunnel_interface'
$endpointProtocol = Get-Prop -Object $endpoint -Name 'protocol'
$tunnelType = Get-Prop -Object $endpoint -Name 'tunnel_type'
$relayHostname = Get-Prop -Object $location -Name 'hostname'
$visibleIpv4 = Get-Prop -Object $location -Name 'ipv4'
$mullvadExitIp = Get-Prop -Object $location -Name 'mullvad_exit_ip'

if ($mullvad.State) {
  Ok "Mullvad state: $($mullvad.State)"
} else {
  Warn 'Mullvad state is unavailable.'
}
if ($mullvad.LockdownMode) {
  Ok "Mullvad lockdown-mode: $($mullvad.LockdownMode)"
}
if ($endpointAddress) {
  Ok "Mullvad endpoint: $endpointAddress ($endpointProtocol/$tunnelType)"
}
if ($tunnelInterface) {
  Ok "Mullvad tunnel interface: $tunnelInterface"
}
if ($relayHostname) {
  Ok "Mullvad relay hostname: $relayHostname"
}
if ($visibleIpv4) {
  Ok "Mullvad visible IPv4: $visibleIpv4; Mullvad exit IP: $mullvadExitIp"
}

$transportIps = @(Get-MullvadTransportIps -MullvadStatus $mullvad)
if ($transportIps.Count -gt 0) {
  Ok "Detected Mullvad transport bypass IP(s): $($transportIps -join ', ')"
} else {
  Warn 'No Mullvad transport bypass IPs were detected.'
}

Step 'Route and guard preflight'
$vpnAdapters = @(Get-ActiveVpnAdapters)
$mullvadAdapter = $vpnAdapters | Where-Object {
  $_.Name -match 'mullvad' -or $_.InterfaceDescription -match 'mullvad'
} | Select-Object -First 1
if ($mullvadAdapter) {
  Ok "Active Mullvad adapter: $($mullvadAdapter.Name) (#$($mullvadAdapter.ifIndex))"
} elseif ($vpnAdapters.Count -gt 0) {
  Warn "No explicit Mullvad adapter found; first VPN-like adapter is $($vpnAdapters[0].Name) (#$($vpnAdapters[0].ifIndex))."
} else {
  Warn 'No active VPN-like adapter found.'
}

$preferredAdapter = if ($mullvadAdapter) { $mullvadAdapter } elseif ($vpnAdapters.Count -gt 0) { $vpnAdapters[0] } else { $null }
$routes = @($proxyIps | ForEach-Object { Get-RouteForIp -Ip $_ } | Where-Object { $_ })
$routePlans = @()
foreach ($ip in $proxyIps) {
  if ($preferredAdapter) {
    $routePlans += New-ProxyRoutePlan -Ip $ip -InterfaceIndex ([int]$preferredAdapter.ifIndex)
  }
}
foreach ($route in $routes) {
  if ($preferredAdapter -and [int]$route.InterfaceIndex -eq [int]$preferredAdapter.ifIndex) {
    Ok "Current proxy route $($route.Ip) already uses $($route.InterfaceAlias) (#$($route.InterfaceIndex))."
  } elseif ($preferredAdapter) {
    Warn "Current proxy route $($route.Ip) uses $($route.InterfaceAlias) (#$($route.InterfaceIndex)); Z4 needs a pinned route via $($preferredAdapter.Name) (#$($preferredAdapter.ifIndex))."
  } else {
    Warn "Current proxy route $($route.Ip) uses $($route.InterfaceAlias) (#$($route.InterfaceIndex)); no Mullvad route target is available."
  }
}
if ($routePlans.Count -gt 0) {
  Step 'Planned proxy host route(s)'
  foreach ($plan in $routePlans) {
    Write-Host "    add:    $($plan.AddCommand)"
    Write-Host "    remove: $($plan.RemoveCommand)"
  }
}

Step 'Firewall/WFP preflight'
$firewall = Get-FirewallPreflight
if ($firewall.Elevated) {
  Ok 'This shell is elevated; WFP state inspection is allowed when netsh succeeds.'
} else {
  Warn 'This shell is not elevated; WFP state inspection requires administrator rights.'
}
Ok "Windows Firewall profile(s) inspected: $($firewall.Profiles.Count)"
if ($firewall.MatchingFirewallRuleCount -gt 0) {
  Ok "Found $($firewall.MatchingFirewallRuleCount) visible firewall rule(s) matching Mullvad/WireGuard/socks5proxy/tun2proxy."
} else {
  Warn 'No visible Windows Firewall rules matching Mullvad/WireGuard/socks5proxy/tun2proxy were found via Get-NetFirewallRule.'
}
if ($firewall.WfpStateAvailable) {
  Ok 'netsh wfp show state succeeded.'
} elseif ($firewall.WfpStateError) {
  Warn "netsh wfp show state is not available in this shell: $($firewall.WfpStateError)"
}

$connected = $mullvad.State -and $mullvad.State.ToLowerInvariant().StartsWith('connected')
if (-not $proxyHandshakeSucceeded) {
  if ($connected) {
    Warn "SOCKS5 handshake/auth failed while Mullvad is connected: $proxyHandshakeError"
    Warn 'Dry-run continues because active Mullvad may block direct proxy reachability until the Z4 WFP exception path is applied.'
  } else {
    throw "SOCKS5 handshake/auth failed: $proxyHandshakeError"
  }
}
$wfpExceptionPlan = New-WfpExceptionPlan -Connected ([bool]$connected) -Firewall $firewall -TunnelInterface $tunnelInterface -EndpointAddress $endpointAddress
$wfpOperationPlan = New-WfpOperationPlan -WfpExceptionPlan $wfpExceptionPlan
Step 'Planned WFP exception'
if ($wfpExceptionPlan.Required) {
  Warn "WFP exception plan status: $($wfpExceptionPlan.Status)"
  foreach ($blocker in @($wfpExceptionPlan.Blockers)) {
    Warn "WFP plan blocker: $blocker"
  }
  Ok "Planned WFP allow responsibility count: $(@($wfpExceptionPlan.PlannedAllows).Count)"
  Ok "Planned WFP cleanup responsibility count: $(@($wfpExceptionPlan.PlannedCleanup).Count)"
  Ok "Planned WFP identity count: $(@($wfpExceptionPlan.PlannedFilterIdentities).Count)"
  Ok "Planned WFP apply operation count: $(@($wfpOperationPlan.ApplyOperations).Count)"
  Ok "Planned WFP rollback operation count: $(@($wfpOperationPlan.RollbackOperations).Count)"
  Ok "Expected WFP runtime filter count: $(@($wfpOperationPlan.ExpectedRuntimeFilters).Count)"
} else {
  Ok 'No connected Mullvad tunnel is active; no Z4 WFP exception is required for this dry-run.'
}

if ($connected) {
  Warn 'Z4 live start is blocked by design until the Mullvad WFP kill-switch exception is implemented.'
} else {
  Warn 'Mullvad is not connected; Z4 live verification cannot run until the Mullvad app is connected.'
}

$snapshotPath = Join-Path $LogDir 'z4-preflight.json'
[PSCustomObject]@{
  CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
  ProxyHost = $proxy.Host
  ProxyIps = $proxyIps
  ProxyHandshakeSucceeded = $proxyHandshakeSucceeded
  ProxyHandshakeError = $proxyHandshakeError
  Mullvad = [PSCustomObject]@{
    CliPath = $mullvad.CliPath
    State = $mullvad.State
    LockdownMode = $mullvad.LockdownMode
    Endpoint = $endpointAddress
    EndpointProtocol = $endpointProtocol
    TunnelType = $tunnelType
    TunnelInterface = $tunnelInterface
    RelayHostname = $relayHostname
    VisibleIpv4 = $visibleIpv4
    MullvadExitIp = $mullvadExitIp
    TransportIps = $transportIps
    Error = $mullvad.Error
  }
  VpnAdapters = $vpnAdapters
  ProxyRoutes = $routes
  PlannedProxyRoutes = $routePlans
  Firewall = $firewall
  WfpExceptionPlan = $wfpExceptionPlan
  WfpOperationPlan = $wfpOperationPlan
  Z4LiveBlockedReason = if ($connected) { 'Live WFP mutation requires explicit -Live -AllowWfpMutation in an elevated guarded session.' } else { 'Mullvad is not connected.' }
} | ConvertTo-Json -Depth 8 | Set-Content -Path $snapshotPath -Encoding UTF8

Ok "Z4 preflight snapshot written: $snapshotPath"
Warn 'Dry-run only. No routes, WFP rules, adapters, DNS settings, Mullvad state, or system proxy settings were changed.'
