[CmdletBinding()]
param(
    [switch]$RequireSignature
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$version = '1.6.2-R9'
$publish = Join-Path $root 'publish-r9'
$signingConfigurationPath = Join-Path $root 'signing-config.json'
$dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue

function Normalize-Thumbprint([string]$Value)
{
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return ($Value -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
}

function Get-SigningConfiguration
{
    $thumbprint = Normalize-Thumbprint $env:GIVENX_SIGNING_THUMBPRINT
    $timestampServer = [string]$env:GIVENX_TIMESTAMP_SERVER
    if (Test-Path $signingConfigurationPath)
    {
        try
        {
            $saved = Get-Content $signingConfigurationPath -Raw | ConvertFrom-Json
            if ([string]::IsNullOrWhiteSpace($thumbprint)) { $thumbprint = Normalize-Thumbprint ([string]$saved.Thumbprint) }
            if ([string]::IsNullOrWhiteSpace($timestampServer)) { $timestampServer = [string]$saved.TimestampServer }
        }
        catch
        {
            throw "signing-config.json no es valido: $($_.Exception.Message)"
        }
    }
    if ([string]::IsNullOrWhiteSpace($timestampServer)) { $timestampServer = 'http://timestamp.digicert.com' }
    return [pscustomobject]@{ Thumbprint = $thumbprint; TimestampServer = $timestampServer }
}

function Get-CodeSigningCertificate([string]$Thumbprint)
{
    if ($Thumbprint -notmatch '^[A-F0-9]{40,64}$')
    {
        throw 'La huella del certificado de firma no tiene un formato valido.'
    }
    foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My'))
    {
        try
        {
            $certificate = Get-ChildItem $store -ErrorAction Stop |
                Where-Object {
                    (Normalize-Thumbprint $_.Thumbprint) -eq $Thumbprint -and
                    $_.HasPrivateKey -and $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date) -and
                    @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value }) -contains '1.3.6.1.5.5.7.3.3'
                } |
                Select-Object -First 1
            if ($certificate) { return $certificate }
        }
        catch { }
    }
    throw "No se encontro un certificado de firma de codigo vigente, con clave privada, para la huella $Thumbprint."
}

function Sign-And-VerifyExecutable([string]$Path, $Certificate, [string]$TimestampServer)
{
    Write-Host "Firmando $([IO.Path]::GetFileName($Path)) como $($Certificate.Subject)..." -ForegroundColor Cyan
    $signature = Set-AuthenticodeSignature -FilePath $Path -Certificate $Certificate -HashAlgorithm SHA256 -IncludeChain All -TimestampServer $TimestampServer
    if ($signature.Status -ne 'Valid')
    {
        throw "La firma de $Path no quedo valida. Estado: $($signature.Status). Mensaje: $($signature.StatusMessage)"
    }
    $verified = Get-AuthenticodeSignature -FilePath $Path
    if ($verified.Status -ne 'Valid' -or $null -eq $verified.SignerCertificate -or
        (Normalize-Thumbprint $verified.SignerCertificate.Thumbprint) -ne (Normalize-Thumbprint $Certificate.Thumbprint))
    {
        throw "La comprobacion Authenticode posterior fallo para $Path."
    }
    return $verified
}

$signing = Get-SigningConfiguration
$signingCertificate = $null
if (-not [string]::IsNullOrWhiteSpace($signing.Thumbprint))
{
    $signingCertificate = Get-CodeSigningCertificate $signing.Thumbprint
}
elseif ($RequireSignature)
{
    throw 'R9 no se puede instalar desde una compilacion local sin firma. Usa una release firmada por SignPath o configura un certificado local valido. No desactives Control inteligente de aplicaciones.'
}

if (-not $dotnetCommand)
{
    throw 'Falta .NET 8 SDK. La instalacion actual no se modifico.'
}

if (Test-Path $publish) { Remove-Item $publish -Recurse -Force }
New-Item -ItemType Directory -Path $publish -Force | Out-Null

$agentProject = Join-Path $root 'src\GivenX.Agent\GivenX.Agent.csproj'
$uiProject = Join-Path $root 'src\GivenX.UI\GivenX.UI.csproj'

Write-Host 'Compilando el agente en una carpeta aislada...' -ForegroundColor Cyan
& $dotnetCommand.Source publish $agentProject -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:RestoreIgnoreFailedSources=true -o (Join-Path $publish 'Agent')
$agentExitCode = $LASTEXITCODE
if ($agentExitCode -ne 0)
{
    throw "La compilacion del agente fallo con el codigo $agentExitCode. La instalacion actual no se modifico."
}

Write-Host 'Compilando la interfaz en una carpeta aislada...' -ForegroundColor Cyan
& $dotnetCommand.Source publish $uiProject -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:RestoreIgnoreFailedSources=true -o (Join-Path $publish 'UI')
$uiExitCode = $LASTEXITCODE
if ($uiExitCode -ne 0)
{
    throw "La compilacion de la interfaz fallo con el codigo $uiExitCode. La instalacion actual no se modifico."
}

$agent = Join-Path $publish 'Agent\GivenX.Agent.exe'
$ui = Join-Path $publish 'UI\GivenX.UI.exe'
foreach ($executable in @($agent, $ui))
{
    if (-not (Test-Path $executable))
    {
        throw "No se produjo el ejecutable esperado: $executable"
    }
    if ((Get-Item $executable).Length -lt 1MB)
    {
        throw "El ejecutable parece incompleto: $executable"
    }
}

$installerScripts = @(
    'build-install.ps1',
    'engine-setup.ps1',
    'repair-current-alerts.ps1',
    'rollback.ps1',
    'uninstall.ps1'
)
$installerPublish = Join-Path $publish 'Installer'
New-Item -ItemType Directory -Path $installerPublish -Force | Out-Null
foreach ($fileName in $installerScripts)
{
    Copy-Item (Join-Path $root $fileName) $installerPublish -Force
}

$agentSignature = $null
$uiSignature = $null
$installerSignatures = @()
if ($signingCertificate)
{
    $agentSignature = Sign-And-VerifyExecutable $agent $signingCertificate $signing.TimestampServer
    $uiSignature = Sign-And-VerifyExecutable $ui $signingCertificate $signing.TimestampServer
    foreach ($fileName in $installerScripts)
    {
        $installerSignatures += @(Sign-And-VerifyExecutable (Join-Path $installerPublish $fileName) $signingCertificate $signing.TimestampServer)
    }
    Write-Host "FIRMA VERIFICADA: $($signingCertificate.Subject)" -ForegroundColor Green
    Write-Host "Huella: $(Normalize-Thumbprint $signingCertificate.Thumbprint)" -ForegroundColor DarkGray
}
else
{
    Write-Warning 'COMPILACION SIN FIRMA. Es valida para revisar el codigo y para enviarla a SignPath, pero no para instalarla directamente.'
    Write-Warning 'La release publica debe regresar firmada por SignPath; no desactives Control inteligente de aplicaciones.'
}

$monitoredExtensions = @('.exe', '.dll', '.scr', '.msi', '.ps1', '.bat', '.cmd', '.vbs', '.js')
$knownPackageScripts = @(
    'CONFIGURAR-FIRMA.cmd',
    'configure-signing.ps1',
    'INSTALAR-GIVENX.cmd',
    'RECUPERAR-GIVENX.cmd',
    'VERIFICAR-COMPILACION.cmd',
    'build-install.ps1',
    'engine-setup.cmd',
    'engine-setup.ps1',
    'REPARAR-ALERTAS-ACTUALES.cmd',
    'repair-current-alerts.ps1',
    'rollback.ps1',
    'uninstall.ps1',
    'verify-build.ps1',
    'prepare-signing-input.ps1',
    'prepare-signed-release.ps1',
    'package-signed-release.ps1'
)
$artifactRows = Get-ChildItem $root -File -Recurse |
    Where-Object {
        $relative = $_.FullName.Substring($root.Length + 1).Replace('/', '\')
        $isKnownRootScript = -not $relative.Contains('\') -and $knownPackageScripts -contains $_.Name
        $isGeneratedBuildOutput = $relative -match '^(publish-r9\\(?:Agent|UI|Installer)|src\\GivenX\.(?:Agent|UI|Shared)\\(?:bin|obj))\\'
        ($isKnownRootScript -or $isGeneratedBuildOutput) -and $monitoredExtensions -contains $_.Extension.ToLowerInvariant()
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
$agentSignerThumbprint = $null
$uiSignerThumbprint = $null
if ($agentSignature) { $agentSignerThumbprint = Normalize-Thumbprint $agentSignature.SignerCertificate.Thumbprint }
if ($uiSignature) { $uiSignerThumbprint = Normalize-Thumbprint $uiSignature.SignerCertificate.Thumbprint }

$verification = [pscustomobject]@{
    Version = $version
    VerifiedAt = [DateTimeOffset]::Now.ToString('O')
    AgentSha256 = (Get-FileHash $agent -Algorithm SHA256).Hash
    UiSha256 = (Get-FileHash $ui -Algorithm SHA256).Hash
    AgentSignerThumbprint = $agentSignerThumbprint
    UiSignerThumbprint = $uiSignerThumbprint
    Artifacts = $trustedArtifacts
}
$verification | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $publish 'trusted-build-artifacts.json') -Encoding UTF8

Write-Host ''
Write-Host 'COMPILACION VERIFICADA: agente e interfaz creados correctamente.' -ForegroundColor Green
Write-Host "$($trustedArtifacts.Count) hashes propios fueron registrados para evitar falsos positivos." -ForegroundColor Green
if ($agentSignature -and $uiSignature -and $installerSignatures.Count -eq $installerScripts.Count)
{
    Write-Host 'LISTA PARA INSTALAR: ejecutables y scripts tienen firma Authenticode valida.' -ForegroundColor Green
}
else
{
    Write-Host 'LISTA PARA GITHUB/SIGNPATH: compilacion limpia, aun no instalable.' -ForegroundColor Yellow
}
Write-Host 'No se modificaron tareas, procesos ni archivos instalados.' -ForegroundColor Green
