param(
  [string]$Destination,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function Ok($m) { Write-Host "    [ok] $m" -ForegroundColor Green }

$RootDir = Split-Path -Path $PSScriptRoot -Parent
if (-not $Destination) {
  $Destination = Join-Path $RootDir 'runtime\windows'
}

$Destination = [System.IO.Path]::GetFullPath($Destination)
$TempRoot = Join-Path $RootDir '.build\windows-runtime-download'
$Tun2ProxyZip = Join-Path $TempRoot 'tun2proxy.zip'
$WintunZip = Join-Path $TempRoot 'wintun.zip'
$Tun2ProxyExe = Join-Path $Destination 'tun2proxy-bin.exe'
$WintunDll = Join-Path $Destination 'wintun.dll'
$Metadata = Join-Path $Destination 'versions.txt'

$WintunVersion = '0.14.1'
$WintunUrl = "https://www.wintun.net/builds/wintun-$WintunVersion.zip"
$WintunSha256 = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'

function Download-File {
  param(
    [string]$Url,
    [string]$Path
  )
  Write-Host "    downloading $Url"
  Invoke-WebRequest -Uri $Url -OutFile $Path -Headers @{ 'User-Agent' = 'socks5proxy-windows-runtime' }
}

function Expand-ZipClean {
  param(
    [string]$ZipPath,
    [string]$DestinationPath
  )
  if (Test-Path $DestinationPath) {
    Remove-Item -Path $DestinationPath -Recurse -Force
  }
  New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
  Expand-Archive -Path $ZipPath -DestinationPath $DestinationPath -Force
}

function Get-LatestTun2ProxyAsset {
  $release = Invoke-RestMethod `
    -Uri 'https://api.github.com/repos/tun2proxy/tun2proxy/releases/latest' `
    -Headers @{ 'User-Agent' = 'socks5proxy-windows-runtime' }
  $asset = $release.assets |
    Where-Object { $_.name -eq 'tun2proxy-x86_64-pc-windows-msvc.zip' } |
    Select-Object -First 1
  if (-not $asset) {
    throw 'Could not find tun2proxy-x86_64-pc-windows-msvc.zip in the latest tun2proxy release.'
  }
  [PSCustomObject]@{
    Tag = $release.tag_name
    Url = $asset.browser_download_url
    Name = $asset.name
  }
}

function Copy-FirstExisting {
  param(
    [string]$Root,
    [string[]]$Names,
    [string]$DestinationPath
  )
  foreach ($name in $Names) {
    $match = Get-ChildItem -Path $Root -Recurse -File -Filter $name | Select-Object -First 1
    if ($match) {
      Copy-Item -Path $match.FullName -Destination $DestinationPath -Force
      return $match.FullName
    }
  }
  throw "None of the expected files were found below ${Root}: $($Names -join ', ')"
}

New-Item -ItemType Directory -Force -Path $Destination | Out-Null
New-Item -ItemType Directory -Force -Path $TempRoot | Out-Null

if ((Test-Path $Tun2ProxyExe) -and (Test-Path $WintunDll) -and -not $Force) {
  Ok "Windows runtime artifacts already present in $Destination"
  return
}

Step 'Installing tun2proxy runtime'
$tun2proxy = Get-LatestTun2ProxyAsset
Download-File -Url $tun2proxy.Url -Path $Tun2ProxyZip
$TunExtract = Join-Path $TempRoot 'tun2proxy'
Expand-ZipClean -ZipPath $Tun2ProxyZip -DestinationPath $TunExtract
$tunSource = Copy-FirstExisting `
  -Root $TunExtract `
  -Names @('tun2proxy-bin.exe', 'tun2proxy.exe') `
  -DestinationPath $Tun2ProxyExe
Ok "tun2proxy $($tun2proxy.Tag) installed from $($tun2proxy.Name)"

Step 'Installing Wintun runtime'
Download-File -Url $WintunUrl -Path $WintunZip
$actualHash = (Get-FileHash -Path $WintunZip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $WintunSha256) {
  throw "Wintun SHA256 mismatch. Expected $WintunSha256, got $actualHash."
}
$WintunExtract = Join-Path $TempRoot 'wintun'
Expand-ZipClean -ZipPath $WintunZip -DestinationPath $WintunExtract
$wintunSource = Copy-FirstExisting `
  -Root (Join-Path $WintunExtract 'wintun\bin\amd64') `
  -Names @('wintun.dll') `
  -DestinationPath $WintunDll
Ok "Wintun $WintunVersion installed"

@(
  "tun2proxy_tag=$($tun2proxy.Tag)"
  "tun2proxy_asset=$($tun2proxy.Name)"
  "tun2proxy_source=$tunSource"
  "wintun_version=$WintunVersion"
  "wintun_sha256=$WintunSha256"
  "wintun_source=$wintunSource"
  "installed_utc=$((Get-Date).ToUniversalTime().ToString('o'))"
) | Set-Content -Path $Metadata -Encoding ASCII

Ok "Runtime artifacts available in $Destination"
