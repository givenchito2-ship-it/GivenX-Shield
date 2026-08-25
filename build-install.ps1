#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$version = '1.6.2-R9'
$install = Join-Path $env:ProgramFiles 'GivenX Shield'
$candidate = Join-Path $env:ProgramFiles 'GivenX Shield.candidate'
$rollbackDirectory = Join-Path $env:ProgramFiles 'GivenX Shield.rollback'
$publish = Join-Path $root 'publish-r9'
$signedRelease = Join-Path $root 'release-r9'
$backup = Join-Path $env:ProgramData 'GivenXShield\PreviousVersion'
$backupCandidate = Join-Path $env:ProgramData 'GivenXShield\PreviousVersion.new'
$backupPrevious = Join-Path $env:ProgramData 'GivenXShield\PreviousVersion.previous'
$diagnosticRoot = Join-Path $env:ProgramData 'GivenXShield\Diagnostics'
$failureLog = Join-Path $diagnosticRoot 'last-install-failure.txt'

$tasksStopped = $false
$oldMoved = $false
$newPlaced = $false

function Test-CompleteInstallation([string]$Path)
{
    $agentPath = Join-Path $Path 'GivenX.Agent.exe'
    $uiPath = Join-Path $Path 'GivenX.UI.exe'
    if (-not (Test-Path $agentPath) -or -not (Test-Path $uiPath)) { return $false }
    return ((Get-Item $agentPath).Length -gt 1MB) -and ((Get-Item $uiPath).Length -gt 1MB)
}

function Remove-WithRetries([string]$Path)
{
    if (-not (Test-Path $Path)) { return }
    for ($attempt = 1; $attempt -le 10; $attempt++)
    {
        try
        {
            Remove-Item $Path -Recurse -Force -ErrorAction Stop
            if (-not (Test-Path $Path)) { return }
        }
        catch
        {
            if ($attempt -eq 10) { throw }
        }
        Start-Sleep -Milliseconds 500
    }
    throw "Windows no permitió retirar la carpeta: $Path"
}

function Copy-DirectoryContent([string]$Source, [string]$Destination)
{
    if (-not (Test-Path $Source)) { throw "No existe la carpeta de origen: $Source" }
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Copy-Item (Join-Path $Source '*') $Destination -Recurse -Force
}

function Get-ValidSignerThumbprint([string]$Path, [string]$Component)
{
    if (-not (Test-Path $Path)) { throw "No existe $Component para comprobar su firma: $Path" }
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate)
    {
        throw "R9 rechazo $Component antes de tocar la instalacion actual: no tiene una firma Authenticode valida y confiable. Estado: $($signature.Status). Descarga una release oficial firmada o configura un certificado local valido. No desactives Control inteligente de aplicaciones."
    }
    return (($signature.SignerCertificate.Thumbprint -replace '[^A-Fa-f0-9]', '').ToUpperInvariant())
}

function Repair-OfficialYaraTrust([string]$Path)
{
    $expected = @{
        'yara64.exe' = '1C45EB279D820ABA81FD41C22384428EBE44037CF5793BE4B52A9D3B3DF62B33'
        'yarac64.exe' = '5B6705B9A8DABF496BCCF163A65887574290C97F8B999C8CB73DF5417B04BBD7'
    }
    $store = Join-Path $Path 'trusted-engine-hashes.json'
    $trusted = @()
    try { if (Test-Path $store) { $trusted += @(Get-Content $store -Raw | ConvertFrom-Json) } } catch { }
    $added = 0
    foreach ($name in $expected.Keys)
    {
        $engine = Join-Path $Path (Join-Path 'engines\yara' $name)
        if (-not (Test-Path $engine)) { continue }
        $actual = (Get-FileHash $engine -Algorithm SHA256).Hash.ToUpperInvariant()
        if ($actual -eq $expected[$name])
        {
            if ($trusted -notcontains $actual) { $trusted += $actual; $added++ }
        }
        else
        {
            Write-Warning "$name no coincide con YARA 4.5.5 oficial y no se marcara como confiable."
        }
    }
    if ($added -gt 0 -or -not (Test-Path $store))
    {
        $trusted = @($trusted | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Sort-Object -Unique)
        ConvertTo-Json -InputObject $trusted | Set-Content $store -Encoding UTF8
        Write-Host "$added hash(es) oficiales de YARA fueron reconciliados en la candidata." -ForegroundColor Green
    }
}

function Get-AppControlFileName($EventRecord)
{
    try
    {
        [xml]$xml = $EventRecord.ToXml()
        foreach ($item in @($xml.Event.EventData.Data))
        {
            if ([string]$item.Name -in @('FileName', 'File Name', 'FilePath', 'Path'))
            {
                $value = [string]$item.'#text'
                if (-not [string]::IsNullOrWhiteSpace($value)) { return $value }
            }
        }
    }
    catch { }
    return $null
}

function Write-AppControlDiagnostics([string]$Stage, [string]$Target, [datetime]$Since)
{
    New-Item -ItemType Directory -Path $diagnosticRoot -Force | Out-Null
    $rows = @()
    foreach ($query in @(
        @{ LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; Id = @(3033, 3077, 3079, 3081, 3089, 3114) },
        @{ LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'; Id = @(8004, 8022) },
        @{ LogName = 'Microsoft-Windows-AppLocker/MSI and Script'; Id = @(8029, 8036) }
    ))
    {
        try
        {
            $rows += @(Get-WinEvent -FilterHashtable @{ LogName = $query.LogName; StartTime = $Since } -ErrorAction Stop |
                Where-Object { $query.Id -contains $_.Id } |
                Select-Object -First 20)
        }
        catch { }
    }

    $lines = @(
        "GivenX Shield $version - diagnóstico de instalación",
        "Fecha: $([DateTimeOffset]::Now.ToString('O'))",
        "Etapa: $Stage",
        "Objetivo: $Target",
        ''
    )
    if ($rows.Count -eq 0)
    {
        $lines += 'Windows no devolvió eventos recientes de Code Integrity o AppLocker.'
    }
    else
    {
        foreach ($row in $rows | Sort-Object TimeCreated -Descending)
        {
            $lines += "[$($row.TimeCreated.ToString('O'))] $($row.LogName) / evento $($row.Id)"
            $lines += ($row.Message -replace "`0", '')
            $lines += ''
        }
    }
    Set-Content -Path $failureLog -Value $lines -Encoding UTF8

    $blockedFiles = @($rows | ForEach-Object { Get-AppControlFileName $_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
    foreach ($blockedFile in $blockedFiles)
    {
        Write-Host "Windows registró como bloqueado: $blockedFile" -ForegroundColor Yellow
    }
    Write-Host "Diagnóstico guardado en: $failureLog" -ForegroundColor Yellow
}

function Test-CandidateExecutable([string]$Path, [string]$Component)
{
    $started = (Get-Date).AddSeconds(-2)
    try
    {
        $process = Start-Process -FilePath $Path -ArgumentList '--givenx-preflight' -PassThru -Wait -WindowStyle Hidden -ErrorAction Stop
        if ($process.ExitCode -ne 0) { throw "$Component devolvió el código $($process.ExitCode)." }
    }
    catch
    {
        Write-AppControlDiagnostics "Prueba previa de $Component" $Path $started
        throw "Windows no permitió ejecutar $Component durante la prueba previa. La instalación actual NO fue modificada. Archivo: $Path. Detalle: $($_.Exception.Message)"
    }
}

function Start-InstalledComponent([string]$Path, [string]$Component, [string[]]$Arguments = @())
{
    $started = (Get-Date).AddSeconds(-2)
    try
    {
        $startParameters = @{ FilePath = $Path; PassThru = $true; ErrorAction = 'Stop' }
        if ($Arguments.Count -gt 0) { $startParameters.ArgumentList = $Arguments }
        $process = Start-Process @startParameters
        Start-Sleep -Seconds 2
        if ($process.HasExited) { throw "$Component se cerró durante la comprobación de arranque (código $($process.ExitCode))." }
        return $process
    }
    catch
    {
        Write-AppControlDiagnostics "Arranque instalado de $Component" $Path $started
        throw "Windows no permitió iniciar $Component después del cambio. Archivo: $Path. Detalle: $($_.Exception.Message)"
    }
}

function Stop-GivenX
{
    foreach ($taskName in @('GivenX Shield Agent', 'GivenX Shield UI', 'GivenX Shield Watchdog'))
    {
        Disable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    Unregister-ScheduledTask -TaskName 'GivenX Shield Watchdog' -Confirm:$false -ErrorAction SilentlyContinue

    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do
    {
        Get-Process 'GivenX.Agent', 'GivenX.UI' -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 350
        $running = Get-Process 'GivenX.Agent', 'GivenX.UI' -ErrorAction SilentlyContinue
    }
    while ($running -and [DateTime]::UtcNow -lt $deadline)

    if ($running)
    {
        throw 'Windows no permitió cerrar GivenX. La instalación actual no se reemplazó.'
    }
}

function Enable-ExistingGivenX([string]$Path)
{
    if (-not (Test-CompleteInstallation $Path)) { return }
    foreach ($taskName in @('GivenX Shield Agent', 'GivenX Shield UI'))
    {
        Enable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
    }
    Start-Process (Join-Path $Path 'GivenX.Agent.exe') -ErrorAction SilentlyContinue
    Start-Process (Join-Path $Path 'GivenX.UI.exe') -ErrorAction SilentlyContinue
}

function Register-GivenXTasks([string]$Path)
{
    $agent = Join-Path $Path 'GivenX.Agent.exe'
    $ui = Join-Path $Path 'GivenX.UI.exe'
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest

    $agentAction = New-ScheduledTaskAction -Execute $agent
    $agentSettings = New-ScheduledTaskSettingsSet -RestartCount 100 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'GivenX Shield Agent' -Action $agentAction -Trigger $trigger -Principal $principal -Settings $agentSettings -Force | Out-Null

    $uiAction = New-ScheduledTaskAction -Execute $ui -Argument '--background'
    $uiSettings = New-ScheduledTaskSettingsSet -RestartCount 20 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'GivenX Shield UI' -Action $uiAction -Trigger $trigger -Principal $principal -Settings $uiSettings -Force | Out-Null
}

try
{
    $hasSignedRelease = (Test-Path (Join-Path $signedRelease 'Agent\GivenX.Agent.exe')) -and
        (Test-Path (Join-Path $signedRelease 'UI\GivenX.UI.exe')) -and
        (Test-Path (Join-Path $signedRelease 'trusted-build-artifacts.json'))
    if ($hasSignedRelease)
    {
        $publish = $signedRelease
        Write-Host '[1/7] Verificando la release firmada sin recompilarla...' -ForegroundColor Cyan
    }
    else
    {
        $hasLocalSigning = -not [string]::IsNullOrWhiteSpace($env:GIVENX_SIGNING_THUMBPRINT) -or
            (Test-Path (Join-Path $root 'signing-config.json'))
        if (-not $hasLocalSigning)
        {
            throw 'Este es el paquete de codigo fuente de R9 y no contiene una release firmada. No se modifico la instalacion actual. Usa el ZIP firmado producido por GitHub/SignPath o configura un certificado local valido.'
        }
        Write-Host '[1/7] Compilando y firmando localmente sin tocar la instalación actual...' -ForegroundColor Cyan
        & (Join-Path $root 'verify-build.ps1') -RequireSignature
    }
    if (-not (Test-Path (Join-Path $publish 'Agent\GivenX.Agent.exe')) -or
        -not (Test-Path (Join-Path $publish 'UI\GivenX.UI.exe')) -or
        -not (Test-Path (Join-Path $publish 'trusted-build-artifacts.json')))
    {
        throw 'La verificación no produjo ambos ejecutables y su manifiesto de confianza.'
    }

    $agentSigner = Get-ValidSignerThumbprint (Join-Path $publish 'Agent\GivenX.Agent.exe') 'el agente nuevo'
    $uiSigner = Get-ValidSignerThumbprint (Join-Path $publish 'UI\GivenX.UI.exe') 'la interfaz nueva'
    if ($agentSigner -ne $uiSigner)
    {
        throw 'El agente y la interfaz fueron firmados por certificados distintos. La instalacion actual no se modifico.'
    }
    foreach ($fileName in @('build-install.ps1', 'engine-setup.ps1', 'repair-current-alerts.ps1', 'rollback.ps1', 'uninstall.ps1'))
    {
        $installerPath = Join-Path (Join-Path $publish 'Installer') $fileName
        $installerSigner = Get-ValidSignerThumbprint $installerPath $fileName
        if ($installerSigner -ne $agentSigner)
        {
            throw "$fileName fue firmado por un certificado diferente. La instalacion actual no se modifico."
        }
    }
    Write-Host "Firma Authenticode validada. Huella del editor: $agentSigner" -ForegroundColor Green

    Write-Host '[2/7] Preparando una instalación candidata aislada...' -ForegroundColor Cyan
    Remove-WithRetries $candidate
    New-Item -ItemType Directory -Path $candidate -Force | Out-Null
    Copy-DirectoryContent (Join-Path $publish 'Agent') $candidate
    Copy-DirectoryContent (Join-Path $publish 'UI') $candidate
    Copy-Item (Join-Path $publish 'trusted-build-artifacts.json') $candidate -Force

    foreach ($fileName in @(
        'uninstall.ps1',
        'sysmon-config.xml',
        'rollback.ps1',
        'RECUPERAR-GIVENX.cmd',
        'engine-setup.ps1',
        'engine-setup.cmd',
        'repair-current-alerts.ps1',
        'REPARAR-ALERTAS-ACTUALES.cmd'
    ))
    {
        $signedInstallerFile = Join-Path (Join-Path $publish 'Installer') $fileName
        $sourceFile = if (Test-Path $signedInstallerFile) { $signedInstallerFile } else { Join-Path $root $fileName }
        Copy-Item $sourceFile $candidate -Force
    }
    Copy-Item (Join-Path $root 'rules') $candidate -Recurse -Force

    $preservationSource = if (Test-CompleteInstallation $install) { $install } elseif (Test-CompleteInstallation $backup) { $backup } else { $null }
    if ($preservationSource)
    {
        if (Test-Path (Join-Path $preservationSource 'engines'))
        {
            Copy-Item (Join-Path $preservationSource 'engines') $candidate -Recurse -Force
        }
        if (Test-Path (Join-Path $preservationSource 'trusted-engine-hashes.json'))
        {
            Copy-Item (Join-Path $preservationSource 'trusted-engine-hashes.json') $candidate -Force
        }
    }

    Repair-OfficialYaraTrust $candidate

    Set-Content (Join-Path $candidate 'version.txt') "GivenX Shield $version" -Encoding UTF8
    $manifest = Get-ChildItem $candidate -File -Recurse |
        Where-Object {
            $relative = $_.FullName.Substring($candidate.Length + 1)
            $_.Name -ne 'install-manifest.json' -and
            $_.Name -ne 'trusted-engine-hashes.json' -and
            -not $relative.StartsWith('engines\', [StringComparison]::OrdinalIgnoreCase)
        } |
        ForEach-Object {
            [pscustomobject]@{
                Path = $_.FullName.Substring($candidate.Length + 1)
                Hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
            }
        }
    $manifest | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $candidate 'install-manifest.json') -Encoding UTF8
    if (-not (Test-CompleteInstallation $candidate))
    {
        throw 'La instalación candidata está incompleta. La versión actual no se modificó.'
    }

    Write-Host '[3/7] Comprobando que Windows permite ejecutar la versión candidata...' -ForegroundColor Cyan
    $candidateAgentSigner = Get-ValidSignerThumbprint (Join-Path $candidate 'GivenX.Agent.exe') 'el agente candidato'
    $candidateUiSigner = Get-ValidSignerThumbprint (Join-Path $candidate 'GivenX.UI.exe') 'la interfaz candidata'
    if ($candidateAgentSigner -ne $agentSigner -or $candidateUiSigner -ne $uiSigner)
    {
        throw 'La firma cambio durante la preparacion de la candidata. La instalacion actual no se modifico.'
    }
    Test-CandidateExecutable (Join-Path $candidate 'GivenX.Agent.exe') 'el agente nuevo'
    Test-CandidateExecutable (Join-Path $candidate 'GivenX.UI.exe') 'la interfaz nueva'
    Write-Host 'Prueba previa superada. La instalación actual aún no ha sido modificada.' -ForegroundColor Green

    Write-Host '[4/7] Deteniendo de forma controlada el radar...' -ForegroundColor Cyan
    $tasksStopped = $true
    Stop-GivenX

    Write-Host '[5/7] Creando y verificando el respaldo anterior...' -ForegroundColor Cyan
    if (Test-CompleteInstallation $install)
    {
        Remove-WithRetries $backupCandidate
        New-Item -ItemType Directory -Path $backupCandidate -Force | Out-Null
        Copy-DirectoryContent $install $backupCandidate
        if (-not (Test-CompleteInstallation $backupCandidate))
        {
            throw 'El respaldo nuevo no superó la verificación. La instalación actual no se reemplazó.'
        }
        Remove-WithRetries $backupPrevious
        if (Test-Path $backup) { Move-Item $backup $backupPrevious }
        try
        {
            Move-Item $backupCandidate $backup
        }
        catch
        {
            if ((Test-Path $backupPrevious) -and -not (Test-Path $backup))
            {
                Move-Item $backupPrevious $backup
            }
            throw
        }
        Remove-WithRetries $backupPrevious
    }
    elseif (-not (Test-CompleteInstallation $backup))
    {
        Write-Warning 'No existe una versión anterior completa; se continuará como instalación nueva.'
    }

    Write-Host '[6/7] Cambiando de versión de forma transaccional...' -ForegroundColor Cyan
    Remove-WithRetries $rollbackDirectory
    if (Test-Path $install)
    {
        Move-Item $install $rollbackDirectory
        $oldMoved = $true
    }
    Move-Item $candidate $install
    $newPlaced = $true
    if (-not (Test-CompleteInstallation $install))
    {
        throw 'La nueva versión no contiene ambos ejecutables después del cambio.'
    }

    Write-Host '[7/7] Iniciando y comprobando GivenX Shield...' -ForegroundColor Cyan
    $agentProcess = Start-InstalledComponent (Join-Path $install 'GivenX.Agent.exe') 'el agente instalado'
    $uiProcess = Start-InstalledComponent (Join-Path $install 'GivenX.UI.exe') 'la interfaz instalada'

    Register-GivenXTasks $install
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'GivenX Shield.lnk'))
    $shortcut.TargetPath = Join-Path $install 'GivenX.UI.exe'
    $shortcut.WorkingDirectory = $install
    $shortcut.Save()

    $tasksStopped = $false
    Remove-WithRetries $rollbackDirectory
    Remove-Item $failureLog -Force -ErrorAction SilentlyContinue
    Write-Host "GivenX Shield $version fue instalado y su arranque quedó comprobado." -ForegroundColor Green
}
catch
{
    $originalError = $_
    $failure = $originalError.Exception.Message
    Write-Host "La instalación no se completó: $failure" -ForegroundColor Red

    if (-not $tasksStopped -and -not $oldMoved -and -not $newPlaced)
    {
        try { Remove-WithRetries $candidate } catch { Write-Warning "No se pudo retirar la candidata: $($_.Exception.Message)" }
    }

    if ($tasksStopped -or $oldMoved -or $newPlaced)
    {
        try
        {
            foreach ($taskName in @('GivenX Shield Agent', 'GivenX Shield UI', 'GivenX Shield Watchdog'))
            {
                Disable-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | Out-Null
                Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            }
            Get-Process 'GivenX.Agent', 'GivenX.UI' -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1

            if ($newPlaced -and (Test-Path $install)) { Remove-WithRetries $install }
            if ($oldMoved -and (Test-Path $rollbackDirectory))
            {
                Move-Item $rollbackDirectory $install
            }
            elseif (-not (Test-CompleteInstallation $install) -and (Test-CompleteInstallation $backup))
            {
                Remove-WithRetries $install
                New-Item -ItemType Directory -Path $install -Force | Out-Null
                Copy-DirectoryContent $backup $install
            }

            if (Test-CompleteInstallation $install)
            {
                Register-GivenXTasks $install
                Enable-ExistingGivenX $install
                Write-Host 'La versión anterior fue restaurada y reactivada.' -ForegroundColor Yellow
            }
            else
            {
                Write-Host 'No existe una instalación completa para reactivar. Ejecuta RECUPERAR-GIVENX.cmd.' -ForegroundColor Red
            }
        }
        catch
        {
            Write-Host "La recuperación automática falló: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host 'Ejecuta RECUPERAR-GIVENX.cmd como administrador.' -ForegroundColor Red
        }
    }

    Write-Host 'La instalación terminó de forma segura con código 1.' -ForegroundColor Red
    exit 1
}
