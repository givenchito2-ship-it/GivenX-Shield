[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$release = Join-Path $root 'release-r9'
$dist = Join-Path $root 'dist'
$staging = Join-Path $dist 'GivenX-Shield-1.6.2-R9'
$archive = Join-Path $dist 'GivenX_Shield_1_6_2_R9_Signed.zip'

foreach ($required in @(
    (Join-Path $release 'Agent\GivenX.Agent.exe'),
    (Join-Path $release 'UI\GivenX.UI.exe'),
    (Join-Path $release 'Installer\build-install.ps1'),
    (Join-Path $release 'trusted-build-artifacts.json'),
    (Join-Path $release 'release-metadata.json')
))
{
    if (-not (Test-Path $required)) { throw "La release firmada esta incompleta: $required" }
}

if (Test-Path $staging) { Remove-Item $staging -Recurse -Force }
New-Item -ItemType Directory -Path $staging -Force | Out-Null
Copy-Item $release $staging -Recurse -Force

$signedScripts = @('build-install.ps1', 'engine-setup.ps1', 'repair-current-alerts.ps1', 'rollback.ps1', 'uninstall.ps1')
foreach ($fileName in $signedScripts)
{
    Copy-Item (Join-Path (Join-Path $release 'Installer') $fileName) $staging -Force
}

$rootFiles = @(
    'INSTALAR-GIVENX.cmd',
    'RECUPERAR-GIVENX.cmd',
    'engine-setup.cmd',
    'REPARAR-ALERTAS-ACTUALES.cmd',
    'sysmon-config.xml',
    'LEEME-PRIMERO.txt',
    'README.md',
    'LICENSE',
    'NOTICE.md',
    'SECURITY.md'
)
foreach ($fileName in $rootFiles)
{
    Copy-Item (Join-Path $root $fileName) $staging -Force
}
Copy-Item (Join-Path $root 'rules') $staging -Recurse -Force

$checksums = Get-ChildItem $staging -File -Recurse | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($staging.Length + 1).Replace('\', '/')
    "$(Get-FileHash $_.FullName -Algorithm SHA256 | Select-Object -ExpandProperty Hash)  $relative"
}
$checksums | Set-Content (Join-Path $staging 'SHA256SUMS.txt') -Encoding ASCII

if (Test-Path $archive) { Remove-Item $archive -Force }
Compress-Archive -Path $staging -DestinationPath $archive -CompressionLevel Optimal
Write-Host "PAQUETE FIRMADO CREADO: $archive" -ForegroundColor Green
Write-Host "SHA-256: $((Get-FileHash $archive -Algorithm SHA256).Hash)" -ForegroundColor Green
