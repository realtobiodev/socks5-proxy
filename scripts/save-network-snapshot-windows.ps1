param(
  [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RootDir = Split-Path -Path $PSScriptRoot -Parent
if (-not $OutputPath) {
  $SnapshotDir = Join-Path $RootDir '.build\windows-network-snapshots'
  New-Item -ItemType Directory -Force -Path $SnapshotDir | Out-Null
  $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
  $OutputPath = Join-Path $SnapshotDir "network-$stamp.json"
}

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$props = Get-ItemProperty -Path $key
$proxyEnableProp = $props.PSObject.Properties['ProxyEnable']
$proxyServerProp = $props.PSObject.Properties['ProxyServer']
$snapshot = [PSCustomObject]@{
  CreatedUtc = (Get-Date).ToUniversalTime().ToString('o')
  ProxyEnable = if ($null -ne $proxyEnableProp) { [int]$proxyEnableProp.Value } else { 0 }
  ProxyServer = if ($null -ne $proxyServerProp) { [string]$proxyServerProp.Value } else { '' }
  DnsClientServers = @(
    foreach ($family in @('IPv4', 'IPv6')) {
      Get-DnsClientServerAddress -AddressFamily $family |
        Select-Object InterfaceAlias, InterfaceIndex, @{Name = 'AddressFamily'; Expression = { $family } }, ServerAddresses
    }
  )
  Adapters = Get-NetAdapter |
    Select-Object Name, InterfaceDescription, Status, ifIndex, MacAddress, InterfaceGuid
  Routes = Get-NetRoute -AddressFamily IPv4 |
    Select-Object DestinationPrefix, NextHop, InterfaceIndex, RouteMetric, ifMetric, PolicyStore
}

$snapshot | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8
Write-Host $OutputPath
