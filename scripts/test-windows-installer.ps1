param(
  [string]$InstallerPath,
  [string]$InstallDir,
  [switch]$Live,
  [switch]$KeepInstall
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    [ok] $m" -ForegroundColor Green }
function Warn($m) { Write-Warning $m }

$RootDir = Split-Path -Path $PSScriptRoot -Parent
$ArtifactDir = Join-Path $RootDir 'build-artifacts\windows'
if (-not $InstallerPath) {
  $InstallerPath = Get-ChildItem -Path $ArtifactDir -Filter '*setup.exe' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 |
    ForEach-Object { $_.FullName }
}
if (-not $InstallDir) {
  $InstallDir = Join-Path $RootDir '.build\windows-installer-test\SOCKS5Proxy'
}

function Require-File {
  param(
    [string]$Path,
    [string]$Label
  )
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Missing $Label`: $Path"
  }
  $item = Get-Item -LiteralPath $Path
  if ($item.Length -le 0) {
    throw "$Label is empty: $Path"
  }
  Ok "$Label present: $($item.FullName) ($($item.Length) bytes)"
  $item
}

function Find-InstalledFile {
  param(
    [string]$Name,
    [switch]$Required
  )
  $matches = @(Get-ChildItem -Path $InstallDir -Filter $Name -File -Recurse -ErrorAction SilentlyContinue)
  if ($matches.Count -eq 0) {
    if ($Required) {
      throw "Installed file not found under $InstallDir`: $Name"
    }
    return $null
  }
  $matches | Sort-Object FullName | Select-Object -First 1
}

function Compare-SourceHash {
  param(
    [string]$InstalledPath,
    [string]$SourceName,
    [string]$SourceDir
  )
  if (-not $SourceDir) {
    $SourceDir = Join-Path $RootDir 'runtime\windows'
  }
  $source = Join-Path $SourceDir $SourceName
  Require-File -Path $source -Label "runtime source $SourceName" | Out-Null
  $expected = (Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $InstalledPath).Hash
  if ($expected -ne $actual) {
    throw "Installed $SourceName hash mismatch. Expected $expected, got $actual"
  }
  Ok "Installed $SourceName SHA256 matches runtime source."
}

function Assert-InstalledLayout {
  Step 'Checking installed app layout'
  Require-File -Path (Join-Path $InstallDir 'socks5proxy-desktop.exe') -Label 'installed desktop executable' | Out-Null
  foreach ($name in @('tun2proxy-bin.exe', 'wintun.dll', 'versions.txt')) {
    $installed = Find-InstalledFile -Name $name -Required
    Ok "Installed runtime $name found at $($installed.FullName)"
    Compare-SourceHash -InstalledPath $installed.FullName -SourceName $name
  }
  foreach ($name in @(
    'restore-network-windows.ps1',
    'emergency-network-reset-windows.ps1',
    'emergency-network-reset-windows.cmd',
    'watch-tun-recovery-windows.ps1',
    'inspect-wfp-windows.ps1'
  )) {
    $installed = Find-InstalledFile -Name $name -Required
    Ok "Installed recovery $name found at $($installed.FullName)"
    Compare-SourceHash -InstalledPath $installed.FullName -SourceName $name -SourceDir $PSScriptRoot
  }
}

function Assert-InstalledPreflight {
  Step 'Checking installed app headless TUN preflight'
  $exe = Join-Path $InstallDir 'socks5proxy-desktop.exe'
  $stdout = Join-Path (Split-Path -Path $InstallDir -Parent) 'installed-preflight.stdout.json'
  $stderr = Join-Path (Split-Path -Path $InstallDir -Parent) 'installed-preflight.stderr.txt'
  Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
  $process = Start-Process -FilePath $exe `
    -ArgumentList '--windows-tun-preflight-json' `
    -WorkingDirectory $InstallDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -Wait `
    -PassThru
  $raw = Get-Content -Raw -Path $stdout -ErrorAction SilentlyContinue
  $errorText = Get-Content -Raw -Path $stderr -ErrorAction SilentlyContinue
  if ($process.ExitCode -ne 0) {
    throw "Installed preflight command failed with exit code $($process.ExitCode): $errorText $raw"
  }
  try {
    $preflight = $raw | ConvertFrom-Json
  } catch {
    throw "Installed preflight did not return JSON: $raw $errorText"
  }

  foreach ($field in @('tun2proxy_path', 'wintun_path')) {
    $value = $preflight | Select-Object -ExpandProperty $field -ErrorAction SilentlyContinue
    if (-not $value) {
      $missingReasons = $preflight | Select-Object -ExpandProperty 'missing_reasons' -ErrorAction SilentlyContinue
      throw "Installed preflight did not report $field. Missing reasons: $($missingReasons -join '; '). Raw: $raw"
    }
    $reported = [string]$value
    if (-not (Test-Path -LiteralPath $reported -PathType Leaf)) {
      throw "Installed preflight reported missing file path for $field`: $reported"
    }
    if (-not $reported.StartsWith($InstallDir, [System.StringComparison]::OrdinalIgnoreCase)) {
      throw "Installed preflight $field is outside install dir. Path: $reported; install dir: $InstallDir"
    }
  }

  $nonAdminReasons = @($preflight.missing_reasons | Where-Object { $_ -ne 'Windows administrator rights are required.' })
  if ($nonAdminReasons.Count -gt 0) {
    throw "Installed preflight reported unexpected missing reason(s): $($nonAdminReasons -join '; ')"
  }
  if (-not ($preflight.PSObject.Properties['mullvad'])) {
    throw "Installed preflight did not include Mullvad status. Raw: $raw"
  }
  if (-not ($preflight.PSObject.Properties['wireguard'])) {
    throw "Installed preflight did not include WireGuard status. Raw: $raw"
  }
  if (-not ($preflight.PSObject.Properties['firewall'])) {
    throw "Installed preflight did not include Windows Firewall/WFP status. Raw: $raw"
  }
  foreach ($field in @('elevated', 'wfp_state_available')) {
    if (-not ($preflight.firewall.PSObject.Properties[$field])) {
      throw "Installed preflight firewall status is missing $field. Raw: $raw"
    }
  }
  if (-not ($preflight.firewall.PSObject.Properties['firewall_profiles_count'])) {
    throw "Installed preflight firewall status is missing firewall_profiles_count. Raw: $raw"
  }
  if (-not ($preflight.PSObject.Properties['wfp_exception_plan'])) {
    throw "Installed preflight did not include the WFP exception plan. Raw: $raw"
  }
  foreach ($field in @('required', 'ready', 'status', 'blockers', 'planned_allows', 'planned_cleanup', 'planned_filter_identities', 'session_tag')) {
    if (-not ($preflight.wfp_exception_plan.PSObject.Properties[$field])) {
      throw "Installed WFP exception plan is missing $field. Raw: $raw"
    }
  }
  if (-not ($preflight.PSObject.Properties['wfp_operation_plan'])) {
    throw "Installed preflight did not include the WFP operation plan. Raw: $raw"
  }
  foreach ($field in @('required', 'ready', 'status', 'blockers', 'cleanup_before_apply', 'apply_operations', 'rollback_operations', 'expected_runtime_filters', 'session_tag')) {
    if (-not ($preflight.wfp_operation_plan.PSObject.Properties[$field])) {
      throw "Installed WFP operation plan is missing $field. Raw: $raw"
    }
  }
  if (-not ($preflight.PSObject.Properties['wfp_apply_readiness'])) {
    throw "Installed preflight did not include WFP apply readiness. Raw: $raw"
  }
  foreach ($field in @('required', 'ready', 'status', 'blockers', 'role_specs')) {
    if (-not ($preflight.wfp_apply_readiness.PSObject.Properties[$field])) {
      throw "Installed WFP apply readiness is missing $field. Raw: $raw"
    }
  }
  if ($preflight.mullvad.state -eq 'connected') {
    if (-not [bool]$preflight.wfp_exception_plan.required) {
      throw "Installed WFP exception plan is not required while Mullvad is connected. Raw: $raw"
    }
    if ([string]$preflight.wfp_exception_plan.status -ne 'blocked' -and [string]$preflight.wfp_exception_plan.status -ne 'ready') {
      throw "Installed WFP exception plan has unexpected connected status. Raw: $raw"
    }
    if (@($preflight.wfp_exception_plan.planned_filter_identities).Count -lt 4) {
      throw "Installed WFP exception plan has too few planned filter identities. Raw: $raw"
    }
    if (-not [bool]$preflight.wfp_operation_plan.required) {
      throw "Installed WFP operation plan is not required while Mullvad is connected. Raw: $raw"
    }
    if (@($preflight.wfp_operation_plan.apply_operations).Count -lt 6 -or @($preflight.wfp_operation_plan.rollback_operations).Count -lt 6) {
      throw "Installed WFP operation plan has too few apply/rollback operations. Raw: $raw"
    }
    if (@($preflight.wfp_operation_plan.expected_runtime_filters).Count -ne 4) {
      throw "Installed WFP operation plan did not expose the four expected runtime filters. Raw: $raw"
    }
    if (-not [bool]$preflight.wfp_apply_readiness.required) {
      throw "Installed WFP apply readiness is not required while Mullvad is connected. Raw: $raw"
    }
    if ([string]$preflight.wfp_apply_readiness.status -ne 'blocked') {
      throw "Installed WFP apply readiness should remain blocked until live filter conditions are complete. Raw: $raw"
    }
  }
  if (-not ($preflight.PSObject.Properties['z4_guard'])) {
    throw "Installed preflight did not include Z4 guard status. Raw: $raw"
  }
  $guard = $preflight.z4_guard
  if (-not $guard.PSObject.Properties['status'] -or -not $guard.PSObject.Properties['blocked']) {
    throw "Installed preflight Z4 guard is missing required fields. Raw: $raw"
  }
  if ($preflight.mullvad.state -eq 'connected' -and -not [bool]$guard.blocked) {
    throw "Installed preflight did not block Z4 while Mullvad is connected. Raw: $raw"
  }
  Ok "Installed preflight resolved runtime files from $InstallDir."
}

function Assert-InstalledWfpRollbackBlocked {
  Step 'Checking installed app headless WFP rollback guard'
  $exe = Join-Path $InstallDir 'socks5proxy-desktop.exe'
  $stdout = Join-Path (Split-Path -Path $InstallDir -Parent) 'installed-wfp-rollback.stdout.json'
  $stderr = Join-Path (Split-Path -Path $InstallDir -Parent) 'installed-wfp-rollback.stderr.txt'
  Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
  $previousMutationEnv = [Environment]::GetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', 'Process')
  [Environment]::SetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', $null, 'Process')
  try {
    $process = Start-Process -FilePath $exe `
      -ArgumentList '--windows-wfp-rollback-json' `
      -WorkingDirectory $InstallDir `
      -WindowStyle Hidden `
      -RedirectStandardOutput $stdout `
      -RedirectStandardError $stderr `
      -Wait `
      -PassThru
  } finally {
    [Environment]::SetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', $previousMutationEnv, 'Process')
  }
  $raw = Get-Content -Raw -Path $stdout -ErrorAction SilentlyContinue
  $errorText = Get-Content -Raw -Path $stderr -ErrorAction SilentlyContinue
  if ($process.ExitCode -ne 0) {
    throw "Installed WFP rollback command failed with exit code $($process.ExitCode): $errorText $raw"
  }
  try {
    $rollback = $raw | ConvertFrom-Json
  } catch {
    throw "Installed WFP rollback command did not return JSON: $raw $errorText"
  }
  foreach ($field in @('ok', 'mutation_env', 'operation_plan_status', 'rollback_operation_count', 'expected_runtime_filter_count', 'apply_readiness_status', 'apply_readiness_ready', 'apply_readiness_blockers', 'report')) {
    if (-not ($rollback.PSObject.Properties[$field])) {
      throw "Installed WFP rollback JSON is missing $field. Raw: $raw"
    }
  }
  if ([string]$rollback.mutation_env -ne 'SOCKS5PROXY_ENABLE_WFP_MUTATION') {
    throw "Installed WFP rollback JSON reported unexpected mutation env. Raw: $raw"
  }
  if ($rollback.operation_plan_required -and @($rollback.report.blockers).Count -eq 0) {
    throw "Installed WFP rollback guard did not report a blocker while a rollback plan is required. Raw: $raw"
  }
  if ([bool]$rollback.report.attempted) {
    throw "Installed WFP rollback guard attempted mutation without SOCKS5PROXY_ENABLE_WFP_MUTATION. Raw: $raw"
  }
  if ($rollback.operation_plan_required -and [string]$rollback.report.status -ne 'blocked') {
    throw "Installed WFP rollback guard did not block required rollback without env gate. Raw: $raw"
  }
  if ($rollback.operation_plan_required -and [string]$rollback.apply_readiness_status -ne 'blocked') {
    throw "Installed WFP rollback JSON did not report blocked apply readiness. Raw: $raw"
  }
  Ok "Installed WFP rollback guard returned status $($rollback.report.status) without attempting mutation."
}

function Assert-InstalledWfpApplyBlocked {
  Step 'Checking installed app headless WFP apply guard'
  $exe = Join-Path $InstallDir 'socks5proxy-desktop.exe'
  $stdout = Join-Path (Split-Path -Path $InstallDir -Parent) 'installed-wfp-apply.stdout.json'
  $stderr = Join-Path (Split-Path -Path $InstallDir -Parent) 'installed-wfp-apply.stderr.txt'
  Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue
  $previousMutationEnv = [Environment]::GetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', 'Process')
  [Environment]::SetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', $null, 'Process')
  try {
    $process = Start-Process -FilePath $exe `
      -ArgumentList @('--windows-wfp-apply-json', '--proxy-ip', '198.51.100.10') `
      -WorkingDirectory $InstallDir `
      -WindowStyle Hidden `
      -RedirectStandardOutput $stdout `
      -RedirectStandardError $stderr `
      -Wait `
      -PassThru
  } finally {
    [Environment]::SetEnvironmentVariable('SOCKS5PROXY_ENABLE_WFP_MUTATION', $previousMutationEnv, 'Process')
  }
  $raw = Get-Content -Raw -Path $stdout -ErrorAction SilentlyContinue
  $errorText = Get-Content -Raw -Path $stderr -ErrorAction SilentlyContinue
  if ($process.ExitCode -ne 0) {
    throw "Installed WFP apply command failed with exit code $($process.ExitCode): $errorText $raw"
  }
  try {
    $apply = $raw | ConvertFrom-Json
  } catch {
    throw "Installed WFP apply command did not return JSON: $raw $errorText"
  }
  foreach ($field in @('ok', 'mutation_env', 'operation_plan_status', 'apply_operation_count', 'expected_runtime_filter_count', 'apply_readiness_status', 'apply_readiness_ready', 'apply_readiness_blockers', 'report')) {
    if (-not ($apply.PSObject.Properties[$field])) {
      throw "Installed WFP apply JSON is missing $field. Raw: $raw"
    }
  }
  if ([string]$apply.mutation_env -ne 'SOCKS5PROXY_ENABLE_WFP_MUTATION') {
    throw "Installed WFP apply JSON reported unexpected mutation env. Raw: $raw"
  }
  if ([bool]$apply.report.attempted) {
    throw "Installed WFP apply guard attempted mutation without SOCKS5PROXY_ENABLE_WFP_MUTATION. Raw: $raw"
  }
  if ($apply.PSObject.Properties['apply_readiness_context'] -and [string]$apply.apply_readiness_context.proxy_ip -ne '198.51.100.10') {
    throw "Installed WFP apply JSON did not preserve requested proxy IP. Raw: $raw"
  }
  if ($apply.operation_plan_required -and [string]$apply.report.status -ne 'blocked') {
    throw "Installed WFP apply guard did not block required apply without readiness/env gate. Raw: $raw"
  }
  Ok "Installed WFP apply guard returned status $($apply.report.status) without attempting mutation."
}

function Assert-InstalledWfpInspection {
  Step 'Checking installed WFP inspection script'
  $script = Find-InstalledFile -Name 'inspect-wfp-windows.ps1' -Required
  $outputDir = Join-Path (Split-Path -Path $InstallDir -Parent) 'installed-wfp-inspection'
  if (Test-Path -LiteralPath $outputDir) {
    Remove-Item -LiteralPath $outputDir -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

  $stdout = Join-Path $outputDir 'inspect-wfp.stdout.txt'
  $stderr = Join-Path $outputDir 'inspect-wfp.stderr.txt'
  $process = Start-Process -FilePath 'powershell.exe' `
    -ArgumentList @(
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-File', $script.FullName,
      '-OutputDir', $outputDir
    ) `
    -WorkingDirectory $InstallDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -Wait `
    -PassThru
  $outText = Get-Content -Raw -Path $stdout -ErrorAction SilentlyContinue
  $errText = Get-Content -Raw -Path $stderr -ErrorAction SilentlyContinue
  if ($process.ExitCode -ne 0) {
    throw "Installed WFP inspection failed with exit code $($process.ExitCode): $errText $outText"
  }

  $snapshotPath = Join-Path $outputDir 'wfp-inspection.json'
  $summaryPath = Join-Path $outputDir 'wfp-inspection-summary.md'
  Require-File -Path $snapshotPath -Label 'installed WFP inspection snapshot' | Out-Null
  Require-File -Path $summaryPath -Label 'installed WFP inspection summary' | Out-Null
  try {
    $snapshot = Get-Content -Raw -Path $snapshotPath | ConvertFrom-Json
  } catch {
    throw "Installed WFP inspection snapshot is not valid JSON: $snapshotPath"
  }
  foreach ($field in @('Elevated', 'Mullvad', 'Firewall', 'Wfp', 'Analysis', 'WfpExceptionPlan', 'WfpOperationPlan')) {
    if (-not ($snapshot.PSObject.Properties[$field])) {
      throw "Installed WFP inspection snapshot missing $field. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
  }
  if (-not ($snapshot.Firewall.PSObject.Properties['ProfileCount'])) {
    throw "Installed WFP inspection snapshot missing Firewall.ProfileCount. Raw: $(Get-Content -Raw -Path $snapshotPath)"
  }
  foreach ($field in @('StateFileBytes', 'StateFileSha256', 'TermHits', 'TermContexts')) {
    if (-not ($snapshot.Wfp.PSObject.Properties[$field])) {
      throw "Installed WFP inspection snapshot missing Wfp.$field. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
  }
  if ($snapshot.Elevated -and $snapshot.Wfp.StateFileBytes -gt 0 -and -not $snapshot.Wfp.StateFileSha256) {
    throw "Installed WFP inspection snapshot has a WFP state file without StateFileSha256. Raw: $(Get-Content -Raw -Path $snapshotPath)"
  }
  foreach ($field in @('Status', 'Blockers', 'Warnings', 'NextActions')) {
    if (-not ($snapshot.Analysis.PSObject.Properties[$field])) {
      throw "Installed WFP inspection snapshot missing Analysis.$field. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
  }
  foreach ($field in @('Required', 'Ready', 'Status', 'Blockers', 'Warnings', 'PlannedAllows', 'PlannedCleanup', 'PlannedFilterIdentities', 'SessionTag')) {
    if (-not ($snapshot.WfpExceptionPlan.PSObject.Properties[$field])) {
      throw "Installed WFP inspection snapshot missing WfpExceptionPlan.$field. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
  }
  foreach ($field in @('Required', 'Ready', 'Status', 'Blockers', 'CleanupBeforeApply', 'ApplyOperations', 'RollbackOperations', 'ExpectedRuntimeFilters', 'SessionTag')) {
    if (-not ($snapshot.WfpOperationPlan.PSObject.Properties[$field])) {
      throw "Installed WFP inspection snapshot missing WfpOperationPlan.$field. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
  }
  if ($snapshot.Mullvad.State -eq 'connected') {
    if (-not [bool]$snapshot.WfpExceptionPlan.Required) {
      throw "Installed WFP inspection plan is not required while Mullvad is connected. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
    if ([string]$snapshot.WfpExceptionPlan.Status -ne 'blocked' -and [string]$snapshot.WfpExceptionPlan.Status -ne 'ready') {
      throw "Installed WFP inspection plan has unexpected connected status. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
    if (@($snapshot.WfpExceptionPlan.PlannedFilterIdentities).Count -lt 4) {
      throw "Installed WFP inspection plan has too few planned filter identities. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
    if (-not [bool]$snapshot.WfpOperationPlan.Required) {
      throw "Installed WFP inspection operation plan is not required while Mullvad is connected. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
    if (@($snapshot.WfpOperationPlan.ApplyOperations).Count -lt 6 -or @($snapshot.WfpOperationPlan.RollbackOperations).Count -lt 6) {
      throw "Installed WFP inspection operation plan has too few apply/rollback operations. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
    if (@($snapshot.WfpOperationPlan.ExpectedRuntimeFilters).Count -ne 4) {
      throw "Installed WFP inspection operation plan did not expose four expected runtime filters. Raw: $(Get-Content -Raw -Path $snapshotPath)"
    }
  }
  $summary = Get-Content -Raw -Path $summaryPath
  if (
    $summary -notmatch '# Windows WFP Inspection Summary' -or
    $summary -notmatch [regex]::Escape("Analysis status: $($snapshot.Analysis.Status)") -or
    $summary -notmatch [regex]::Escape("WFP exception plan status: $($snapshot.WfpExceptionPlan.Status)") -or
    $summary -notmatch [regex]::Escape("WFP operation plan status: $($snapshot.WfpOperationPlan.Status)") -or
    $summary -notmatch [regex]::Escape("WFP expected runtime filters: $(@($snapshot.WfpOperationPlan.ExpectedRuntimeFilters).Count)") -or
    $summary -notmatch [regex]::Escape("Planned WFP identities: $(@($snapshot.WfpExceptionPlan.PlannedFilterIdentities).Count)")
  ) {
    throw "Installed WFP inspection summary does not match snapshot status. Summary: $summary"
  }
  Ok "Installed WFP inspection produced snapshot at $snapshotPath."

  Step 'Checking installed WFP inspection offline state import'
  $offlineDir = Join-Path (Split-Path -Path $InstallDir -Parent) 'installed-wfp-offline-inspection'
  if (Test-Path -LiteralPath $offlineDir) {
    Remove-Item -LiteralPath $offlineDir -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $offlineDir | Out-Null
  $statePath = Join-Path $offlineDir 'sample-wfp-state.xml'
  @'
<state>
  <provider>Mullvad</provider>
  <filter>{d601fd31-fe69-5e48-be03-a9ec0e4e4111}</filter>
  <name>SOCKS5Proxy Z4 WFP provider</name>
  <driver>Wintun</driver>
</state>
'@ | Set-Content -Path $statePath -Encoding UTF8

  $offlineStdout = Join-Path $offlineDir 'inspect-wfp-offline.stdout.txt'
  $offlineStderr = Join-Path $offlineDir 'inspect-wfp-offline.stderr.txt'
  $offlineProcess = Start-Process -FilePath 'powershell.exe' `
    -ArgumentList @(
      '-NoProfile',
      '-ExecutionPolicy', 'Bypass',
      '-File', $script.FullName,
      '-OutputDir', $offlineDir,
      '-ExistingStatePath', $statePath
    ) `
    -WorkingDirectory $InstallDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $offlineStdout `
    -RedirectStandardError $offlineStderr `
    -Wait `
    -PassThru
  $offlineOutText = Get-Content -Raw -Path $offlineStdout -ErrorAction SilentlyContinue
  $offlineErrText = Get-Content -Raw -Path $offlineStderr -ErrorAction SilentlyContinue
  if ($offlineProcess.ExitCode -ne 0) {
    throw "Installed WFP offline inspection failed with exit code $($offlineProcess.ExitCode): $offlineErrText $offlineOutText"
  }

  $offlineSnapshotPath = Join-Path $offlineDir 'wfp-inspection.json'
  $offlineSummaryPath = Join-Path $offlineDir 'wfp-inspection-summary.md'
  Require-File -Path $offlineSnapshotPath -Label 'installed offline WFP inspection snapshot' | Out-Null
  Require-File -Path $offlineSummaryPath -Label 'installed offline WFP inspection summary' | Out-Null
  $offlineSnapshot = Get-Content -Raw -Path $offlineSnapshotPath | ConvertFrom-Json
  if (-not $offlineSnapshot.ExistingStatePath) {
    throw "Installed offline WFP inspection did not record ExistingStatePath. Raw: $(Get-Content -Raw -Path $offlineSnapshotPath)"
  }
  if (-not [bool]$offlineSnapshot.Analysis.WfpStateCollected) {
    throw "Installed offline WFP inspection did not mark WFP state as collected. Raw: $(Get-Content -Raw -Path $offlineSnapshotPath)"
  }
  if ($offlineSnapshot.Wfp.StateFileBytes -le 0 -or -not $offlineSnapshot.Wfp.StateFileSha256) {
    throw "Installed offline WFP inspection did not record state file size/SHA256. Raw: $(Get-Content -Raw -Path $offlineSnapshotPath)"
  }
  if ([int]$offlineSnapshot.Analysis.WfpTermHitTotal -lt 2) {
    throw "Installed offline WFP inspection did not find expected terms. Raw: $(Get-Content -Raw -Path $offlineSnapshotPath)"
  }
  if (-not ($offlineSnapshot.PSObject.Properties['WfpPlannedIdentityMatches'])) {
    throw "Installed offline WFP inspection did not include planned identity matches. Raw: $(Get-Content -Raw -Path $offlineSnapshotPath)"
  }
  if (-not ($offlineSnapshot.PSObject.Properties['WfpOperationPlan'])) {
    throw "Installed offline WFP inspection did not include operation plan. Raw: $(Get-Content -Raw -Path $offlineSnapshotPath)"
  }
  if (@($offlineSnapshot.WfpOperationPlan.ExpectedRuntimeFilters).Count -ne 4) {
    throw "Installed offline WFP inspection operation plan did not expose four expected runtime filters. Raw: $(Get-Content -Raw -Path $offlineSnapshotPath)"
  }
  $providerMatch = @($offlineSnapshot.WfpPlannedIdentityMatches | Where-Object { $_.Role -eq 'provider' } | Select-Object -First 1)
  if ($providerMatch.Count -eq 0 -or [int]$providerMatch[0].KeyHits -lt 1 -or [int]$providerMatch[0].DisplayNameHits -lt 1) {
    throw "Installed offline WFP inspection did not correlate provider key/display name hits. Raw: $(Get-Content -Raw -Path $offlineSnapshotPath)"
  }
  $offlineSummary = Get-Content -Raw -Path $offlineSummaryPath
  if (
    $offlineSummary -notmatch [regex]::Escape('SOCKS5Proxy Z4 WFP provider') -or
    $offlineSummary -notmatch [regex]::Escape('provider: key hits=1, display hits=1, total=2') -or
    $offlineSummary -notmatch [regex]::Escape('WFP expected runtime filters: 4')
  ) {
    throw "Installed offline WFP inspection summary did not include planned identity matches. Summary: $offlineSummary"
  }
  Ok "Installed offline WFP inspection imported state from $statePath."
}

Step 'Preflight'
Require-File -Path $InstallerPath -Label 'NSIS setup executable' | Out-Null
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'verify-windows-bundle.ps1') -RequireNsisStaging | Write-Host
Ok 'Bundle verification succeeded before installer test.'

if (-not $Live) {
  Warn 'Dry-run only. Re-run with -Live to execute the NSIS installer into a test directory and uninstall it afterwards.'
  return
}

Step 'Preparing isolated install directory'
if (Test-Path -LiteralPath $InstallDir) {
  Remove-Item -LiteralPath $InstallDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path (Split-Path -Path $InstallDir -Parent) | Out-Null
Ok "Install target: $InstallDir"

$installerProcess = $null
try {
  Step 'Running NSIS silent installer'
  $installArg = "/D=$InstallDir"
  $installerProcess = Start-Process -FilePath $InstallerPath `
    -ArgumentList @('/S', $installArg) `
    -WindowStyle Hidden `
    -Wait `
    -PassThru
  if ($installerProcess.ExitCode -ne 0) {
    throw "Installer exited with code $($installerProcess.ExitCode)"
  }
  Ok 'Installer completed successfully.'

  Assert-InstalledLayout
  Assert-InstalledPreflight
  Assert-InstalledWfpRollbackBlocked
  Assert-InstalledWfpApplyBlocked
  Assert-InstalledWfpInspection
} finally {
  if (-not $KeepInstall) {
    Step 'Cleaning installed test app'
    $uninstallers = @(
      Find-InstalledFile -Name 'uninstall.exe'
      Find-InstalledFile -Name 'Uninstall.exe'
    ) | Where-Object { $_ }
    if ($uninstallers.Count -gt 0) {
      foreach ($uninstaller in $uninstallers | Select-Object -Unique) {
        $proc = Start-Process -FilePath $uninstaller.FullName `
          -ArgumentList '/S' `
          -WindowStyle Hidden `
          -Wait `
          -PassThru
        if ($proc.ExitCode -ne 0) {
          Warn "Uninstaller exited with code $($proc.ExitCode): $($uninstaller.FullName)"
        }
      }
    }
    if (Test-Path -LiteralPath $InstallDir) {
      Remove-Item -LiteralPath $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Ok 'Installer test cleanup completed.'
  } else {
    Warn "Keeping installed test app at $InstallDir"
  }
}
