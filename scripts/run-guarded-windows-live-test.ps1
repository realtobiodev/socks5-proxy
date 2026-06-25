param(
  [ValidatePattern('^[A-Za-z0-9_.-]+$')]
  [string]$Name,

  [string]$Command,

  [int]$TimeoutSeconds = 60,

  [string[]]$TunAdapterName = @('s5pz2test'),

  [string]$ArtifactRoot,

  [string]$DesktopExe,

  [string]$InvocationFile,

  [switch]$NoAutoElevate,

  [switch]$SkipEmergencyReset,

  [switch]$DisconnectMullvadOnEmergency
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Script:RootDir = Split-Path -Path $PSScriptRoot -Parent
if (-not $ArtifactRoot) {
  $ArtifactRoot = Join-Path $Script:RootDir '.build\guarded-live'
}

if ($InvocationFile) {
  $invocation = Get-Content -LiteralPath $InvocationFile -Raw | ConvertFrom-Json
  $Name = [string]$invocation.Name
  $Command = [string]$invocation.Command
  $TimeoutSeconds = [int]$invocation.TimeoutSeconds
  $TunAdapterName = @($invocation.TunAdapterName | ForEach-Object { [string]$_ })
  $ArtifactRoot = [string]$invocation.ArtifactRoot
  $DesktopExe = if ($invocation.DesktopExe) { [string]$invocation.DesktopExe } else { $null }
  $SkipEmergencyReset = [bool]$invocation.SkipEmergencyReset
  $DisconnectMullvadOnEmergency = [bool]$invocation.DisconnectMullvadOnEmergency
  $NoAutoElevate = $true
}

function Normalize-CommandText([string]$Value) {
  if ($null -eq $Value) {
    return $Value
  }

  $parts = @(
    ($Value -split "(`r`n|`n|`r)") |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ }
  )
  return ($parts -join ' ').Trim()
}

if (-not $Name) {
  throw '-Name is required.'
}
if (-not $Command) {
  throw '-Command is required.'
}
$Command = Normalize-CommandText $Command

function Write-Step([string]$Message) {
  Write-Host "[guard] $Message"
}

function Test-IsAdministrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Quote-Argument([string]$Value) {
  if ($null -eq $Value) {
    return '""'
  }
  return '"' + ($Value -replace '"', '\"') + '"'
}

function Join-ProcessArguments([string[]]$Values) {
  return (($Values | ForEach-Object { Quote-Argument ([string]$_) }) -join ' ')
}

function Restart-Elevated {
  $elevateDir = Join-Path $ArtifactRoot '_elevate'
  New-Item -ItemType Directory -Path $elevateDir -Force | Out-Null
  $invocationPath = Join-Path $elevateDir ("$Name-$PID.json")
  Save-JsonFile $invocationPath ([pscustomobject]@{
    Name = $Name
    Command = $Command
    TimeoutSeconds = $TimeoutSeconds
    TunAdapterName = $TunAdapterName
    ArtifactRoot = $ArtifactRoot
    DesktopExe = $DesktopExe
    SkipEmergencyReset = [bool]$SkipEmergencyReset
    DisconnectMullvadOnEmergency = [bool]$DisconnectMullvadOnEmergency
  })

  $args = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $PSCommandPath,
    '-InvocationFile', $invocationPath,
    '-NoAutoElevate'
  )

  Write-Step 'Adminrechte fehlen; starte denselben Guard per UAC neu.'
  $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList (Join-ProcessArguments $args) -Verb RunAs -PassThru -Wait
  exit $proc.ExitCode
}

function Save-JsonFile([string]$Path, [object]$Value) {
  $dir = Split-Path -Path $Path -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }
  $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Path -Encoding UTF8
}

function Read-SystemProxyState {
  $path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
  $props = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
  $proxyEnable = $null
  $proxyServer = $null
  $autoConfigUrl = $null

  if ($props) {
    $proxyEnableProp = $props.PSObject.Properties['ProxyEnable']
    $proxyServerProp = $props.PSObject.Properties['ProxyServer']
    $autoConfigUrlProp = $props.PSObject.Properties['AutoConfigURL']

    if ($proxyEnableProp -and $null -ne $proxyEnableProp.Value) {
      $proxyEnable = [int]$proxyEnableProp.Value
    }
    if ($proxyServerProp -and $null -ne $proxyServerProp.Value) {
      $proxyServer = [string]$proxyServerProp.Value
    }
    if ($autoConfigUrlProp -and $null -ne $autoConfigUrlProp.Value) {
      $autoConfigUrl = [string]$autoConfigUrlProp.Value
    }
  }

  [pscustomobject]@{
    ProxyEnable = $proxyEnable
    ProxyServer = $proxyServer
    AutoConfigURL = $autoConfigUrl
  }
}

function Get-NetworkProbe {
  $defaultRoutes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, InterfaceIndex, NextHop, RouteMetric, InterfaceMetric, PolicyStore)
  $managedAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object {
      $name = $_.Name
      $description = $_.InterfaceDescription
      ($TunAdapterName -contains $name) -or
        ($name -like 's5p*') -or
        ($description -match 'Wintun|tun2proxy|socks5proxy')
    } |
    Select-Object Name, InterfaceDescription, Status, InterfaceIndex, MacAddress, LinkSpeed)
  $dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, InterfaceIndex, ServerAddresses)

  $dnsOk = $false
  $dnsError = $null
  for ($attempt = 1; $attempt -le 3 -and -not $dnsOk; $attempt++) {
    try {
      Resolve-DnsName -Name 'example.com' -Type A -ErrorAction Stop | Out-Null
      $dnsOk = $true
      $dnsError = $null
    } catch {
      $dnsError = $_.Exception.Message
      if ($attempt -lt 3) {
        Start-Sleep -Seconds 2
      }
    }
  }

  $internetOk = $false
  $internetError = $null
  try {
    $tcp = Test-NetConnection -ComputerName '1.1.1.1' -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
    $internetOk = [bool]$tcp
  } catch {
    $internetError = $_.Exception.Message
  }

  [pscustomobject]@{
    Timestamp = (Get-Date).ToString('o')
    SystemProxy = Read-SystemProxyState
    DnsClientServers = $dns
    DefaultRoutes = $defaultRoutes
    ManagedAdapters = $managedAdapters
    DnsOk = $dnsOk
    DnsError = $dnsError
    InternetTcp443Ok = $internetOk
    InternetTcp443Error = $internetError
  }
}

function Test-CleanupProbe([object]$Before, [object]$After) {
  $issues = @()
  $warnings = @()

  if ($Before.DnsOk -and -not $After.DnsOk) {
    $issues += "DNS probe failed: $($After.DnsError)"
  } elseif (-not $Before.DnsOk -and -not $After.DnsOk) {
    $warnings += "DNS probe was already failing before the test: $($Before.DnsError)"
  }
  if ($Before.InternetTcp443Ok -and -not $After.InternetTcp443Ok) {
    $issues += "Internet TCP/443 probe failed: $($After.InternetTcp443Error)"
  } elseif (-not $Before.InternetTcp443Ok -and -not $After.InternetTcp443Ok) {
    $warnings += "Internet TCP/443 probe was already failing before the test: $($Before.InternetTcp443Error)"
  }

  if ($Before.SystemProxy.ProxyEnable -ne $After.SystemProxy.ProxyEnable) {
    $issues += "System proxy enable mismatch: before=$($Before.SystemProxy.ProxyEnable), after=$($After.SystemProxy.ProxyEnable)"
  }
  if (($Before.SystemProxy.ProxyServer | Out-String).Trim() -ne ($After.SystemProxy.ProxyServer | Out-String).Trim()) {
    $issues += 'System proxy server mismatch after cleanup.'
  }

  $activeManagedAdapters = @($After.ManagedAdapters | Where-Object { $_.Status -eq 'Up' })
  foreach ($adapter in $activeManagedAdapters) {
    $issues += "Managed adapter still Up after cleanup: $($adapter.Name)"
  }

  $managedRouteAliases = @($After.DefaultRoutes | Where-Object {
      ($TunAdapterName -contains $_.InterfaceAlias) -or ($_.InterfaceAlias -like 's5p*')
    })
  foreach ($route in $managedRouteAliases) {
    $issues += "Default route still points at managed adapter: $($route.InterfaceAlias)"
  }

  [pscustomobject]@{
    Healthy = ($issues.Count -eq 0)
    Issues = $issues
    Warnings = $warnings
  }
}

function Resolve-DesktopExe {
  if ($DesktopExe) {
    $resolved = Resolve-Path -LiteralPath $DesktopExe -ErrorAction SilentlyContinue
    if ($resolved) {
      return $resolved.Path
    }
    return $null
  }

  $candidates = @(
    (Join-Path $Script:RootDir 'target\debug\socks5proxy-desktop.exe'),
    (Join-Path $Script:RootDir 'target\release\socks5proxy-desktop.exe'),
    (Join-Path $Script:RootDir 'apps\desktop\src-tauri\target\debug\socks5proxy-desktop.exe'),
    (Join-Path $Script:RootDir 'apps\desktop\src-tauri\target\release\socks5proxy-desktop.exe')
  )
  foreach ($candidate in $candidates) {
    if (Test-Path -LiteralPath $candidate) {
      return (Resolve-Path -LiteralPath $candidate).Path
    }
  }
  return $null
}

function Invoke-WfpRollbackIfAvailable([string]$OutPath) {
  $exe = Resolve-DesktopExe
  if (-not $exe) {
    Save-JsonFile $OutPath ([pscustomobject]@{
      attempted = $false
      reason = 'socks5proxy-desktop.exe not found'
    })
    return
  }

  $stdout = [IO.Path]::ChangeExtension($OutPath, '.stdout.log')
  $stderr = [IO.Path]::ChangeExtension($OutPath, '.stderr.log')
  $previous = $env:SOCKS5PROXY_ENABLE_WFP_MUTATION
  $env:SOCKS5PROXY_ENABLE_WFP_MUTATION = '1'
  try {
    $proc = Start-Process -FilePath $exe `
      -ArgumentList (Join-ProcessArguments @('--windows-wfp-rollback-json')) `
      -WorkingDirectory $Script:RootDir `
      -RedirectStandardOutput $stdout `
      -RedirectStandardError $stderr `
      -WindowStyle Hidden `
      -PassThru `
      -Wait

    Save-JsonFile $OutPath ([pscustomobject]@{
      attempted = $true
      exe = $exe
      exitCode = $proc.ExitCode
      stdout = $stdout
      stderr = $stderr
    })
  } finally {
    if ($null -eq $previous) {
      Remove-Item Env:\SOCKS5PROXY_ENABLE_WFP_MUTATION -ErrorAction SilentlyContinue
    } else {
      $env:SOCKS5PROXY_ENABLE_WFP_MUTATION = $previous
    }
  }
}

function Stop-ProcessTree([int]$ProcessId) {
  $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcessId" -ErrorAction SilentlyContinue)
  foreach ($child in $children) {
    Stop-ProcessTree -ProcessId ([int]$child.ProcessId)
  }
  Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
}

function Start-LoggedPowerShellCommand([string]$CommandText, [string]$StdoutPath, [string]$StderrPath) {
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = 'powershell.exe'
  $psi.Arguments = Join-ProcessArguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', $CommandText)
  $psi.WorkingDirectory = $Script:RootDir
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true

  $proc = [System.Diagnostics.Process]::new()
  $proc.StartInfo = $psi
  $proc.EnableRaisingEvents = $false
  $null = $proc.Start()

  [pscustomobject]@{
    Process = $proc
    StdoutTask = $proc.StandardOutput.ReadToEndAsync()
    StderrTask = $proc.StandardError.ReadToEndAsync()
    StdoutPath = $StdoutPath
    StderrPath = $StderrPath
  }
}

function Complete-LoggedProcess([object]$Handle) {
  $stdout = $Handle.StdoutTask.GetAwaiter().GetResult()
  $stderr = $Handle.StderrTask.GetAwaiter().GetResult()
  Set-Content -LiteralPath $Handle.StdoutPath -Value $stdout -Encoding UTF8
  Set-Content -LiteralPath $Handle.StderrPath -Value $stderr -Encoding UTF8
}

function Invoke-Restore([string]$SnapshotPath, [string]$LogPath) {
  $restoreScript = Join-Path $PSScriptRoot 'restore-network-windows.ps1'
  $args = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $restoreScript,
    '-SystemProxySnapshot', $SnapshotPath,
    '-RestoreDnsServers',
    '-RenewDhcp',
    '-RemoveTunRoutes',
    '-DisableStaleTunAdapter',
    '-VerifyCleanup'
  )
  foreach ($adapter in $TunAdapterName) {
    $args += @('-TunAdapterName', $adapter)
  }
  & powershell.exe @args *> $LogPath
  return $LASTEXITCODE
}

function Invoke-EmergencyReset([string]$LogPath) {
  if ($SkipEmergencyReset) {
    "SkipEmergencyReset set; emergency reset was not executed." | Set-Content -LiteralPath $LogPath -Encoding UTF8
    return 0
  }

  $resetScript = Join-Path $PSScriptRoot 'emergency-network-reset-windows.ps1'
  $args = @(
    '-NoProfile',
    '-ExecutionPolicy', 'Bypass',
    '-File', $resetScript,
    '-ResetDnsServers',
    '-RenewDhcp'
  )
  foreach ($adapter in $TunAdapterName) {
    $args += @('-TunAdapterName', $adapter)
  }
  $shouldDisconnectMullvad = [bool]$DisconnectMullvadOnEmergency -or [bool]($Command -match '(^|\s)-TestReconnect(\s|$)')
  if ($shouldDisconnectMullvad) {
    $args += '-DisconnectMullvad'
  }
  & powershell.exe @args *> $LogPath
  return $LASTEXITCODE
}

if (-not (Test-IsAdministrator)) {
  if ($NoAutoElevate) {
    throw 'Guarded Windows live tests require an elevated PowerShell session.'
  }
  Restart-Elevated
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runDir = Join-Path $ArtifactRoot "$Name-$stamp"
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

$snapshotPath = Join-Path $runDir 'network-snapshot.json'
$beforePath = Join-Path $runDir 'probe-before.json'
$afterPath = Join-Path $runDir 'probe-after-cleanup.json'
$resultPath = Join-Path $runDir 'result.json'
$watchdogLog = Join-Path $runDir 'watchdog.log'
$restoreLog = Join-Path $runDir 'restore.log'
$emergencyLog = Join-Path $runDir 'emergency-reset.log'
$wfpRollbackPath = Join-Path $runDir 'wfp-rollback.json'
$childStdout = Join-Path $runDir 'child.stdout.log'
$childStderr = Join-Path $runDir 'child.stderr.log'
$cancelFile = Join-Path $runDir 'watchdog.cancel'

$watchdog = $null
$child = $null
$timedOut = $false
$childExitCode = $null
$restoreExitCode = $null
$emergencyExitCode = $null
$wfpRollbackAttempted = $false
$beforeProbe = $null
$afterProbe = $null
$cleanupCheck = [pscustomobject]@{
  Healthy = $false
  Issues = @('Cleanup check did not run.')
  Warnings = @()
}

try {
  Write-Step "Artefakte: $runDir"
  Write-Step 'Speichere Netzwerk-Snapshot und Vorher-Probe.'
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'save-network-snapshot-windows.ps1') -OutputPath $snapshotPath | Out-Null
  $beforeProbe = Get-NetworkProbe
  Save-JsonFile $beforePath $beforeProbe

  Write-Step 'Starte unabhaengigen Watchdog.'
  $watchdog = Start-Process -FilePath 'powershell.exe' `
    -ArgumentList (Join-ProcessArguments @(
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-File', (Join-Path $PSScriptRoot 'watch-tun-recovery-windows.ps1'),
      '-ParentPid', $PID,
      '-CancelFile', $cancelFile,
      '-TunAdapterName', $TunAdapterName,
      '-LogPath', $watchdogLog
    )) `
    -WindowStyle Hidden `
    -PassThru

  Write-Step "Starte Testkommando mit Timeout ${TimeoutSeconds}s."
  $childHandle = Start-LoggedPowerShellCommand -CommandText $Command -StdoutPath $childStdout -StderrPath $childStderr
  $child = $childHandle.Process

  $waitMs = [Math]::Max(1, $TimeoutSeconds) * 1000
  $exited = $child.WaitForExit([int]$waitMs)
  $child.Refresh()
  if (-not $exited -or -not $child.HasExited) {
    $timedOut = $true
    Write-Step 'Timeout erreicht; beende Test-Prozessbaum.'
    Stop-ProcessTree -ProcessId $child.Id
  } else {
    $child.WaitForExit()
    $child.Refresh()
    $childExitCode = $child.ExitCode
  }
  Complete-LoggedProcess -Handle $childHandle

  if ($timedOut -or ($childExitCode -ne 0)) {
    Write-Step 'Test fehlgeschlagen; versuche WFP-Rollback und Emergency-Reset.'
    $wfpRollbackAttempted = $true
    Invoke-WfpRollbackIfAvailable -OutPath $wfpRollbackPath
    $emergencyExitCode = Invoke-EmergencyReset -LogPath $emergencyLog
  } else {
    Write-Step 'Test erfolgreich; fuehre normalen Restore/Verify-Pfad aus.'
    $restoreExitCode = Invoke-Restore -SnapshotPath $snapshotPath -LogPath $restoreLog
  }

  $afterProbe = Get-NetworkProbe
  Save-JsonFile $afterPath $afterProbe
  $cleanupCheck = Test-CleanupProbe -Before $beforeProbe -After $afterProbe
} finally {
  New-Item -ItemType File -Path $cancelFile -Force | Out-Null
  if ($watchdog -and -not $watchdog.HasExited) {
    if (-not $watchdog.WaitForExit(5000)) {
      Stop-Process -Id $watchdog.Id -Force -ErrorAction SilentlyContinue
    }
  }

  $ok = (-not $timedOut) -and ($childExitCode -eq 0) -and $cleanupCheck.Healthy -and (
    ($null -ne $restoreExitCode -and $restoreExitCode -eq 0) -or
    ($null -ne $emergencyExitCode -and $emergencyExitCode -eq 0)
  )

  Save-JsonFile $resultPath ([pscustomobject]@{
    name = $Name
    command = $Command
    timedOut = $timedOut
    childExitCode = $childExitCode
    restoreExitCode = $restoreExitCode
    emergencyExitCode = $emergencyExitCode
    wfpRollbackAttempted = $wfpRollbackAttempted
    skipEmergencyReset = [bool]$SkipEmergencyReset
    artifactDir = $runDir
    snapshot = $snapshotPath
    probeBefore = $beforePath
    probeAfterCleanup = $afterPath
    childStdout = $childStdout
    childStderr = $childStderr
    restoreLog = $restoreLog
    emergencyResetLog = $emergencyLog
    watchdogLog = $watchdogLog
    cleanupHealthy = $cleanupCheck.Healthy
    cleanupIssues = $cleanupCheck.Issues
    cleanupWarnings = $cleanupCheck.Warnings
    ok = $ok
  })
}

Write-Step "Result: $resultPath"
if ($timedOut) {
  exit 124
}
if ($null -ne $childExitCode -and $childExitCode -ne 0) {
  exit $childExitCode
}
if ($null -ne $restoreExitCode -and $restoreExitCode -ne 0) {
  exit $restoreExitCode
}
if ($null -ne $emergencyExitCode -and $emergencyExitCode -ne 0) {
  exit $emergencyExitCode
}
if (-not $cleanupCheck.Healthy) {
  exit 70
}
exit 0
