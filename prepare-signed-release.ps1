[CmdletBinding()]
param(
    [string]$SignedRoot,
    [string]$OutputRoot
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
if ([string]::IsNullOrWhiteSpace($SignedRoot)) { $SignedRoot = Join-Path $root 'signpath-output' }
if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path $root 'release-r9' }
$version = '1.6.2-R9'

function Normalize-Thumbprint([string]$Value)
{
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return ($Value -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
}

function Get-SignedItem([string]$Path, [string]$Label)
{
    if (-not (Test-Path $Path)) { throw "No existe $Label en la salida de SignPath: $Path" }
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate)
    {
        throw "$Label no tiene una firma Authenticode valida. Estado: $($signature.Status)"
    }
    return $signature
}

$agentSource = Join-Path $SignedRoot 'Agent\GivenX.Agent.exe'
$uiSource = Join-Path $SignedRoot 'UI\GivenX.UI.exe'
$agentSignature = Get-SignedItem $agentSource 'GivenX.Agent.exe'
$uiSignature = Get-SignedItem $uiSource 'GivenX.UI.exe'
$publisherThumbprint = Normalize-Thumbprint $agentSignature.SignerCertificate.Thumbprint
if ($publisherThumbprint -ne (Normalize-Thumbprint $uiSignature.SignerCertificate.Thumbprint))
{
    throw 'SignPath devolvio el agente y la interfaz con certificados distintos.'
}

$installerScripts = @(
    'build-install.ps1',
    'engine-setup.ps1',
    'repair-current-alerts.ps1',
    'rollback.ps1',
    'uninstall.ps1'
)
foreach ($fileName in $installerScripts)
{
    $signature = Get-SignedItem (Join-Path (Join-Path $SignedRoot 'Installer') $fileName) $fileName
    if ((Normalize-Thumbprint $signature.SignerCertificate.Thumbprint) -ne $publisherThumbprint)
    {
        throw "$fileName fue firmado por un certificado diferente."
    }
}

if (Test-Path $OutputRoot) { Remove-Item $OutputRoot -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $OutputRoot 'Agent') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $OutputRoot 'UI') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $OutputRoot 'Installer') -Force | Out-Null
Copy-Item (Join-Path $SignedRoot 'Agent\*') (Join-Path $OutputRoot 'Agent') -Recurse -Force
Copy-Item (Join-Path $SignedRoot 'UI\*') (Join-Path $OutputRoot 'UI') -Recurse -Force
Copy-Item (Join-Path $SignedRoot 'Installer\*') (Join-Path $OutputRoot 'Installer') -Recurse -Force

$monitoredExtensions = @('.exe', '.dll', '.scr', '.msi', '.ps1', '.bat', '.cmd', '.vbs', '.js')
$knownRootScripts = @(
    'INSTALAR-GIVENX.cmd',
    'RECUPERAR-GIVENX.cmd',
    'engine-setup.cmd',
    'REPARAR-ALERTAS-ACTUALES.cmd'
)
$artifactRows = Get-ChildItem $root -File -Recurse |
    Where-Object {
        $relative = $_.FullName.Substring($root.Length + 1).Replace('/', '\')
        $isKnownRootScript = -not $relative.Contains('\') -and $knownRootScripts -contains $_.Name
        $isSignedReleaseOutput = $relative -match '^release-r9\\(?:Agent|UI|Installer)\\'
        ($isKnownRootScript -or $isSignedReleaseOutput) -and $monitoredExtensions -contains $_.Extension.ToLowerInvariant()
    } |
    ForEach-Object {
        [pscustomobject]@{
            Sha256 = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
            FileName = $_.Name
            RelativePath = $_.FullName.Substring($root.Length + 1)
            Length = $_.Length
        }
    }
$trustedArtifacts = @($artifactRows | Group-Object Sha256 | ForEach-Object { $_.Group | Select-Object -First 1 })
$agentTarget = Join-Path $OutputRoot 'Agent\GivenX.Agent.exe'
$uiTarget = Join-Path $OutputRoot 'UI\GivenX.UI.exe'
$verification = [pscustomobject]@{
    Version = $version
    VerifiedAt = [DateTimeOffset]::Now.ToString('O')
    AgentSha256 = (Get-FileHash $agentTarget -Algorithm SHA256).Hash
    UiSha256 = (Get-FileHash $uiTarget -Algorithm SHA256).Hash
    AgentSignerThumbprint = $publisherThumbprint
    UiSignerThumbprint = $publisherThumbprint
    Artifacts = $trustedArtifacts
}
$verification | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputRoot 'trusted-build-artifacts.json') -Encoding UTF8

$metadata = [pscustomobject]@{
    Product = 'GivenX Shield'
    Version = $version
    Publisher = $agentSignature.SignerCertificate.Subject
    PublisherThumbprint = $publisherThumbprint
    PreparedAt = [DateTimeOffset]::Now.ToString('O')
    AgentSha256 = $verification.AgentSha256
    UiSha256 = $verification.UiSha256
}
$metadata | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $OutputRoot 'release-metadata.json') -Encoding UTF8

Write-Host "RELEASE FIRMADA VERIFICADA: $($agentSignature.SignerCertificate.Subject)" -ForegroundColor Green
Write-Host "Huella del editor: $publisherThumbprint" -ForegroundColor DarkGray
