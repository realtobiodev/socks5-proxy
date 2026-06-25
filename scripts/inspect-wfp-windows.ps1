param(
  [string]$OutputDir,
  [string]$ExistingStatePath,
  [switch]$Elevate,
  [switch]$RequireAdmin
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Warning $m }

$RootDir = Split-Path -Path $PSScriptRoot -Parent
if (-not $OutputDir) {
  $OutputDir = Join-Path $RootDir '.build\wfp-inspection'
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

function Test-Administrator {
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Relaunch-Elevated {
  $args = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', "`"$PSCommandPath`"",
    '-OutputDir', "`"$OutputDir`"",
    '-RequireAdmin'
  )
  Start-Process -FilePath 'powershell.exe' -ArgumentList ($args -join ' ') -Verb RunAs | Out-Null
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

function Get-MullvadSnapshot {
  $mullvad = Resolve-MullvadCli
  if (-not $mullvad) {
    return [PSCustomObject]@{
      CliPath = $null
      State = $null
      Endpoint = $null
      TunnelInterface = $null
      RelayHostname = $null
      VisibleIpv4 = $null
      Error = 'mullvad.exe was not found'
    }
  }

  try {
    $statusText = (& $mullvad status --json 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($statusText)) {
      return [PSCustomObject]@{
        CliPath = $mullvad
        State = $null
        Endpoint = $null
        TunnelInterface = $null
        RelayHostname = $null
        VisibleIpv4 = $null
        Error = "mullvad status --json failed: $statusText"
      }
    }
    $status = $statusText | ConvertFrom-Json
    [PSCustomObject]@{
      CliPath = $mullvad
      State = [string]$status.state
      Endpoint = [string]$status.details.endpoint.address
      TunnelInterface = [string]$status.details.endpoint.tunnel_interface
      RelayHostname = [string]$status.details.location.hostname
      VisibleIpv4 = [string]$status.details.location.ipv4
      Error = $null
    }
  } catch {
    [PSCustomObject]@{
      CliPath = $mullvad
      State = $null
      Endpoint = $null
      TunnelInterface = $null
      RelayHostname = $null
      VisibleIpv4 = $null
      Error = $_.Exception.Message
    }
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
  $trimmed = $Address.Trim()
  $candidate = $trimmed
  if ($trimmed -match '^\[(?<ip>[^\]]+)\](?::\d+)?$') {
    $candidate = $Matches.ip
  } elseif ($trimmed -match '^(?<ip>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$') {
    $candidate = $Matches.ip
  }
  $parsed = $null
  if ([System.Net.IPAddress]::TryParse($candidate, [ref]$parsed)) {
    return $parsed.IPAddressToString
  }
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
    $Mullvad,
    $Firewall,
    $Wfp,
    [bool]$Elevated
  )

  $connected = $Mullvad.State -and $Mullvad.State.ToLowerInvariant().StartsWith('connected')
  $appPath = Resolve-SupportFile -RelativePaths @(
    'build-artifacts\windows\socks5proxy-desktop.exe',
    'target\debug\socks5proxy-desktop.exe'
  )
  $tun2proxyPath = Resolve-SupportFile -RelativePaths @(
    'runtime\windows\tun2proxy-bin.exe',
    'build-artifacts\windows\tun2proxy-bin.exe'
  )
  $endpointIp = Get-EndpointIpString -Address $Mullvad.Endpoint
  $blockers = New-Object System.Collections.Generic.List[string]
  $warnings = New-Object System.Collections.Generic.List[string]

  if ($connected) {
    if (-not $Elevated) {
      $blockers.Add('Administrator rights are required to inspect and install WFP filters.')
    }
    if (-not $Wfp.StatePath) {
      $blockers.Add('WFP state is not readable in this session.')
    }
    if (-not $appPath) {
      $blockers.Add('socks5proxy-desktop.exe could not be resolved for WFP scoping.')
    }
    if (-not $tun2proxyPath) {
      $blockers.Add('tun2proxy-bin.exe could not be resolved for WFP process scoping.')
    }
    if (-not $Mullvad.TunnelInterface) {
      $blockers.Add('Mullvad tunnel interface is unknown.')
    }
    if (-not $endpointIp) {
      $blockers.Add('Mullvad transport endpoint IP is unknown.')
    }
    if ($Firewall.MatchingRuleCount -eq 0) {
      $warnings.Add('No high-level Windows Firewall rules matching Mullvad/WireGuard/socks5proxy/tun2proxy were visible; the effective policy is likely in lower WFP layers.')
    }
  }

  $plannedAllows = @()
  $plannedCleanup = @()
  $plannedFilterIdentities = @()
  if ($connected) {
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

  $ready = $connected -and $blockers.Count -eq 0
  $status = if (-not $connected) { 'not_required' } elseif ($ready) { 'ready' } else { 'blocked' }

  [PSCustomObject]@{
    Required = [bool]$connected
    Ready = [bool]$ready
    Status = $status
    Blockers = @($blockers)
    Warnings = @($warnings)
    AppPath = $appPath
    Tun2proxyPath = $tun2proxyPath
    MullvadTunnelInterface = $Mullvad.TunnelInterface
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

function Get-FirewallSnapshot {
  $terms = 'Mullvad|WireGuard|socks5proxy|tun2proxy'
  $profiles = @()
  $rules = @()
  $errorText = $null
  try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop |
      Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules)
  } catch {
    $errorText = "Profiles: $($_.Exception.Message)"
  }
  try {
    $rules = @(Get-NetFirewallRule -ErrorAction Stop |
      Where-Object { $_.DisplayName -match $terms -or $_.Group -match $terms } |
      Select-Object DisplayName, Name, Enabled, Direction, Action, Profile, Group)
  } catch {
    if ($errorText) {
      $errorText = "$errorText; Rules: $($_.Exception.Message)"
    } else {
      $errorText = "Rules: $($_.Exception.Message)"
    }
  }

  [PSCustomObject]@{
    Profiles = $profiles
    MatchingRules = $rules
    ProfileCount = $profiles.Count
    MatchingRuleCount = $rules.Count
    Error = $errorText
  }
}

function Invoke-WfpStateSnapshot {
  param(
    [string]$StatePath,
    [string[]]$Terms
  )

  $output = (& netsh wfp show state "file=$StatePath" 2>&1) -join "`n"
  $exitCode = $LASTEXITCODE
  New-WfpStateFileAnalysis -StatePath $StatePath -Terms $Terms -Output $output.Trim() -ExitCode $exitCode
}

function New-WfpStateFileAnalysis {
  param(
    [string]$StatePath,
    [string[]]$Terms,
    [string]$Output,
    $ExitCode
  )

  $exists = Test-Path -LiteralPath $StatePath -PathType Leaf
  $length = if ($exists) { (Get-Item -LiteralPath $StatePath).Length } else { 0 }
  $sha256 = if ($exists) { (Get-FileHash -Algorithm SHA256 -LiteralPath $StatePath).Hash } else { $null }
  $termHits = @()
  $termContexts = @()
  if ($exists) {
    foreach ($term in $Terms) {
      $matches = @(Select-String -LiteralPath $StatePath -Pattern $term -SimpleMatch -Context 2,2 -ErrorAction SilentlyContinue)
      $termHits += [PSCustomObject]@{
        Term = $term
        Count = $matches.Count
      }
      foreach ($match in ($matches | Select-Object -First 5)) {
        $before = @($match.Context.PreContext)
        $after = @($match.Context.PostContext)
        $termContexts += [PSCustomObject]@{
          Term = $term
          LineNumber = $match.LineNumber
          Line = $match.Line.Trim()
          Before = $before
          After = $after
        }
      }
    }
  }

  [PSCustomObject]@{
    ExitCode = $ExitCode
    Output = $Output
    StatePath = if ($exists) { $StatePath } else { $null }
    StateFileBytes = $length
    StateFileSha256 = $sha256
    TermHits = $termHits
    TermContexts = $termContexts
  }
}

function Import-WfpStateSnapshot {
  param(
    [string]$SourcePath,
    [string]$StatePath,
    [string[]]$Terms
  )

  if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) {
    throw "Existing WFP state file not found: $SourcePath"
  }
  $resolved = (Resolve-Path -LiteralPath $SourcePath).Path
  if ($resolved -ne $StatePath) {
    Copy-Item -LiteralPath $resolved -Destination $StatePath -Force
  }
  New-WfpStateFileAnalysis `
    -StatePath $StatePath `
    -Terms $Terms `
    -Output "Imported existing WFP state file: $resolved" `
    -ExitCode 0
}

function New-WfpInspectionAnalysis {
  param(
    $Mullvad,
    $Firewall,
    $Wfp,
    [bool]$Elevated
  )

  $connected = $Mullvad.State -and $Mullvad.State.ToLowerInvariant().StartsWith('connected')
  $termHitTotal = 0
  foreach ($hit in @($Wfp.TermHits)) {
    if ($hit.PSObject.Properties['Count']) {
      $termHitTotal += [int]$hit.Count
    }
  }
  $contextCount = @($Wfp.TermContexts).Count
  $blockers = @()
  $warnings = @()
  $nextActions = @()

  if (-not $connected) {
    $blockers += 'Mullvad is not connected; Z4 WFP analysis needs the Mullvad tunnel active.'
  }
  if (-not $Elevated -and -not $Wfp.StatePath) {
    $blockers += 'WFP state was not collected because the inspection did not run as administrator.'
    $nextActions += 'Re-run scripts\inspect-wfp-windows.ps1 from an Administrator PowerShell or with -Elevate.'
  }
  if ($Elevated -and -not $Wfp.StatePath) {
    $blockers += 'The elevated netsh WFP state file was not produced.'
  }
  if ($Elevated -and $Wfp.StatePath -and -not $Wfp.StateFileSha256) {
    $blockers += 'The WFP state file exists but no SHA256 was recorded.'
  }
  if ($Elevated -and $Wfp.StatePath -and $termHitTotal -eq 0) {
    $warnings += 'No Mullvad/WireGuard/socks5proxy/tun2proxy/Wintun terms were found in the WFP state file.'
  }
  if ($Firewall.MatchingRuleCount -eq 0) {
    $warnings += 'No matching high-level Windows Firewall rules were visible; Mullvad likely relies on lower-level WFP filters.'
  }
  if ($Elevated -and $termHitTotal -gt 0 -and $contextCount -eq 0) {
    $warnings += 'Term hits were counted but no context snippets were captured.'
  }
  if ($Elevated -and $connected -and $Wfp.StatePath) {
    $nextActions += 'Review TermContexts around Mullvad/WireGuard/Wintun filters before designing any CHAIN-4 exception.'
    $nextActions += 'Do not add WFP exceptions until the filter layer, conditions, and provider ownership are understood.'
  } elseif (-not $Elevated -and $connected -and $Wfp.StatePath) {
    $nextActions += 'Review the imported WFP state TermContexts, then re-run elevated only when live WFP Apply/Rollback is intentionally tested.'
  }

  $status = if ($blockers.Count -gt 0) {
    'blocked'
  } elseif ($warnings.Count -gt 0) {
    'ready_with_warnings'
  } else {
    'ready_for_manual_review'
  }

  [PSCustomObject]@{
    Status = $status
    MullvadConnected = [bool]$connected
    Elevated = $Elevated
    FirewallProfileCount = $Firewall.ProfileCount
    MatchingFirewallRuleCount = $Firewall.MatchingRuleCount
    WfpStateCollected = [bool]$Wfp.StatePath
    WfpStateSha256 = $Wfp.StateFileSha256
    WfpTermHitTotal = $termHitTotal
    WfpContextCount = $contextCount
    Blockers = $blockers
    Warnings = $warnings
    NextActions = $nextActions
  }
}

function Get-WfpTermHitCount {
  param(
    $Wfp,
    [string]$Term
  )
  foreach ($hit in @($Wfp.TermHits)) {
    if ([string]$hit.Term -eq $Term) {
      return [int]$hit.Count
    }
  }
  0
}

function New-WfpPlannedIdentityMatches {
  param(
    $Wfp,
    $WfpExceptionPlan
  )
  foreach ($identity in @($WfpExceptionPlan.PlannedFilterIdentities)) {
    $keyHits = Get-WfpTermHitCount -Wfp $Wfp -Term ([string]$identity.Key)
    $displayNameHits = Get-WfpTermHitCount -Wfp $Wfp -Term ([string]$identity.DisplayName)
    [PSCustomObject]@{
      Role = [string]$identity.Role
      Key = [string]$identity.Key
      DisplayName = [string]$identity.DisplayName
      Layer = [string]$identity.Layer
      KeyHits = $keyHits
      DisplayNameHits = $displayNameHits
      TotalHits = $keyHits + $displayNameHits
    }
  }
}

function Write-WfpInspectionSummary {
  param(
    $Snapshot,
    [string]$Path
  )

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add('# Windows WFP Inspection Summary')
  $lines.Add('')
  $lines.Add("- Created UTC: $($Snapshot.CreatedUtc)")
  $lines.Add("- Elevated: $($Snapshot.Elevated)")
  $lines.Add("- Analysis status: $($Snapshot.Analysis.Status)")
  $lines.Add("- Mullvad state: $($Snapshot.Mullvad.State)")
  $lines.Add("- Mullvad endpoint: $($Snapshot.Mullvad.Endpoint)")
  $lines.Add("- Mullvad interface: $($Snapshot.Mullvad.TunnelInterface)")
  $lines.Add("- Firewall profiles: $($Snapshot.Analysis.FirewallProfileCount)")
  $lines.Add("- Matching high-level firewall rules: $($Snapshot.Analysis.MatchingFirewallRuleCount)")
  $lines.Add("- WFP state collected: $($Snapshot.Analysis.WfpStateCollected)")
  $lines.Add("- WFP state SHA256: $($Snapshot.Analysis.WfpStateSha256)")
  $lines.Add("- WFP term hits: $($Snapshot.Analysis.WfpTermHitTotal)")
  $lines.Add("- WFP context snippets: $($Snapshot.Analysis.WfpContextCount)")
  $lines.Add("- WFP exception plan status: $($Snapshot.WfpExceptionPlan.Status)")
  $lines.Add("- WFP exception required: $($Snapshot.WfpExceptionPlan.Required)")
  $lines.Add("- WFP exception ready: $($Snapshot.WfpExceptionPlan.Ready)")
  $lines.Add("- Planned WFP allows: $(@($Snapshot.WfpExceptionPlan.PlannedAllows).Count)")
  $lines.Add("- Planned WFP cleanup steps: $(@($Snapshot.WfpExceptionPlan.PlannedCleanup).Count)")
  $lines.Add("- Planned WFP identities: $(@($Snapshot.WfpExceptionPlan.PlannedFilterIdentities).Count)")
  $lines.Add("- WFP operation plan status: $($Snapshot.WfpOperationPlan.Status)")
  $lines.Add("- WFP apply operations: $(@($Snapshot.WfpOperationPlan.ApplyOperations).Count)")
  $lines.Add("- WFP rollback operations: $(@($Snapshot.WfpOperationPlan.RollbackOperations).Count)")
  $lines.Add("- WFP expected runtime filters: $(@($Snapshot.WfpOperationPlan.ExpectedRuntimeFilters).Count)")
  $lines.Add("- Planned identity state hits: $((@($Snapshot.WfpPlannedIdentityMatches) | Measure-Object -Property TotalHits -Sum).Sum)")
  $lines.Add('')

  $lines.Add('## Blockers')
  $blockers = @($Snapshot.Analysis.Blockers)
  if ($blockers.Count -eq 0) {
    $lines.Add('- none')
  } else {
    foreach ($item in $blockers) { $lines.Add("- $item") }
  }
  $lines.Add('')

  $lines.Add('## Warnings')
  $warnings = @($Snapshot.Analysis.Warnings)
  if ($warnings.Count -eq 0) {
    $lines.Add('- none')
  } else {
    foreach ($item in $warnings) { $lines.Add("- $item") }
  }
  $lines.Add('')

  $lines.Add('## Next Actions')
  $actions = @($Snapshot.Analysis.NextActions)
  if ($actions.Count -eq 0) {
    $lines.Add('- none')
  } else {
    foreach ($item in $actions) { $lines.Add("- $item") }
  }
  $lines.Add('')
  $lines.Add('## WFP Exception Plan Blockers')
  $planBlockers = @($Snapshot.WfpExceptionPlan.Blockers)
  if ($planBlockers.Count -eq 0) {
    $lines.Add('- none')
  } else {
    foreach ($item in $planBlockers) { $lines.Add("- $item") }
  }
  $lines.Add('')
  $lines.Add('## WFP Planned Identities')
  $identities = @($Snapshot.WfpExceptionPlan.PlannedFilterIdentities)
  if ($identities.Count -eq 0) {
    $lines.Add('- none')
  } else {
    foreach ($identity in $identities) {
      $lines.Add("- $($identity.Role): $($identity.Key) [$($identity.Layer)] $($identity.DisplayName)")
    }
  }
  $lines.Add('')
  $lines.Add('## WFP Planned Identity Matches')
  $matches = @($Snapshot.WfpPlannedIdentityMatches)
  if ($matches.Count -eq 0) {
    $lines.Add('- none')
  } else {
    foreach ($match in $matches) {
      $lines.Add("- $($match.Role): key hits=$($match.KeyHits), display hits=$($match.DisplayNameHits), total=$($match.TotalHits)")
    }
  }
  $lines.Add('')
  $lines.Add('## WFP Operation Plan')
  $operations = @($Snapshot.WfpOperationPlan.ApplyOperations)
  if ($operations.Count -eq 0) {
    $lines.Add('- none')
  } else {
    foreach ($operation in $operations) {
      $lines.Add("- $($operation.Action) $($operation.Role): $($operation.Key) [$($operation.Layer)] $($operation.Scope)")
    }
  }
  $lines.Add('')
  $lines.Add('## Term Hits')
  $hits = @($Snapshot.Wfp.TermHits)
  if ($hits.Count -eq 0) {
    $lines.Add('- none')
  } else {
    foreach ($hit in $hits) {
      $lines.Add("- $($hit.Term): $($hit.Count)")
    }
  }

  $lines | Set-Content -Path $Path -Encoding UTF8
}

$isAdmin = Test-Administrator
if ($ExistingStatePath -and $Elevate) {
  throw '-ExistingStatePath and -Elevate cannot be combined; offline analysis does not need UAC.'
}
if ($Elevate -and -not $isAdmin) {
  Step 'Relaunching WFP inspection elevated'
  Relaunch-Elevated
  Ok 'UAC relaunch requested.'
  return
}

if ($RequireAdmin -and -not $isAdmin) {
  throw 'Administrator rights are required for WFP state inspection.'
}

Step 'Collecting read-only CHAIN-4 snapshot'
$mullvad = Get-MullvadSnapshot
$firewall = Get-FirewallSnapshot
$wfpTerms = @('Mullvad', 'WireGuard', 'socks5proxy', 'tun2proxy', 'Wintun')
$wfpStatePath = Join-Path $OutputDir 'wfp-state.xml'
$stateAnalysisTerms = @($wfpTerms)
$plannedIdentityTerms = @()
foreach ($identity in @(New-WfpFilterIdentities -SessionTag 'socks5proxy-z4')) {
  $plannedIdentityTerms += [string]$identity.Key
  $plannedIdentityTerms += [string]$identity.DisplayName
}
$stateAnalysisTerms += @($plannedIdentityTerms | Where-Object { $_ } | Select-Object -Unique)

$wfp = if ($ExistingStatePath) {
  Import-WfpStateSnapshot -SourcePath $ExistingStatePath -StatePath $wfpStatePath -Terms $stateAnalysisTerms
} elseif ($isAdmin) {
  Invoke-WfpStateSnapshot -StatePath $wfpStatePath -Terms $stateAnalysisTerms
} else {
  [PSCustomObject]@{
    ExitCode = $null
    Output = 'Administrator rights are required for netsh wfp show state.'
    StatePath = $null
    StateFileBytes = 0
    StateFileSha256 = $null
    TermHits = @()
    TermContexts = @()
  }
}
$analysis = New-WfpInspectionAnalysis -Mullvad $mullvad -Firewall $firewall -Wfp $wfp -Elevated $isAdmin
$wfpExceptionPlan = New-WfpExceptionPlan -Mullvad $mullvad -Firewall $firewall -Wfp $wfp -Elevated $isAdmin
$wfpOperationPlan = New-WfpOperationPlan -WfpExceptionPlan $wfpExceptionPlan
$wfpPlannedIdentityMatches = @(New-WfpPlannedIdentityMatches -Wfp $wfp -WfpExceptionPlan $wfpExceptionPlan)

$snapshot = [PSCustomObject]@{
  CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
  Elevated = $isAdmin
  Mullvad = $mullvad
  Firewall = $firewall
  Wfp = $wfp
  Analysis = $analysis
  WfpExceptionPlan = $wfpExceptionPlan
  WfpOperationPlan = $wfpOperationPlan
  WfpPlannedIdentityMatches = $wfpPlannedIdentityMatches
  ExistingStatePath = $ExistingStatePath
  Notes = @(
    'Read-only inspection only; no routes, firewall rules, WFP filters, DNS settings, system proxy settings, or Mullvad state are changed.',
    'If Elevated is false, re-run with -Elevate or from an Administrator PowerShell to collect netsh WFP state.'
  )
}

$snapshotPath = Join-Path $OutputDir 'wfp-inspection.json'
$summaryPath = Join-Path $OutputDir 'wfp-inspection-summary.md'
$snapshot | ConvertTo-Json -Depth 10 | Set-Content -Path $snapshotPath -Encoding UTF8
Write-WfpInspectionSummary -Snapshot $snapshot -Path $summaryPath

Ok "Snapshot written: $snapshotPath"
Ok "Summary written: $summaryPath"
Ok "Analysis status: $($analysis.Status)"
Ok "WFP exception plan status: $($wfpExceptionPlan.Status)"
if ($isAdmin) {
  Ok "WFP state path: $($wfp.StatePath)"
} elseif ($ExistingStatePath) {
  Ok "Imported WFP state path: $($wfp.StatePath)"
} else {
  Warn 'WFP state was not collected because this shell is not elevated.'
}
Warn 'Read-only inspection complete. No network or firewall state was changed.'
