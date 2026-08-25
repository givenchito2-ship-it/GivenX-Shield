#Requires -RunAsAdministrator
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$install = Split-Path -Parent $PSCommandPath
$logRoot = Join-Path $env:ProgramData 'GivenXShield'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$log = Join-Path $logRoot 'engine-setup.log'
$exitCode = 0
try { Start-Transcript -Path $log -Append -Force | Out-Null } catch { }
$temp = Join-Path $env:TEMP ("GivenX-Engines-" + [Guid]::NewGuid().ToString('N'))
$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$yaraVersion = '4.5.5'
$yaraUrl = 'https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip'
$yaraSha256 = '352396C8A3D9B31B157A4820ABD3B9347FC934A2314CDDA8A4F566A5570163E4'
$agentTaskExists = $false
$agentWasRunning = $false

function Step([string]$message) { Write-Host "`n[GivenX] $message" -ForegroundColor Cyan }
function Download([string]$uri, [string]$destination) {
    Invoke-WebRequest -Uri $uri -OutFile $destination -UseBasicParsing
    if (-not (Test-Path $destination) -or (Get-Item $destination).Length -lt 1024) { throw "La descarga oficial no llego completa: $uri" }
}
function Trust-EngineFiles([string[]]$paths) {
    $store = Join-Path $install 'trusted-engine-hashes.json'
    $trusted = @()
    try { if (Test-Path $store) { $trusted += @(Get-Content $store -Raw | ConvertFrom-Json) } } catch { }
    foreach ($path in $paths) { if (Test-Path $path) { $trusted += (Get-FileHash $path -Algorithm SHA256).Hash } }
    $trusted = @($trusted | Where-Object { $_ -match '^[A-Fa-f0-9]{64}$' } | Sort-Object -Unique)
    ConvertTo-Json -InputObject $trusted | Set-Content $store -Encoding UTF8
}

Clear-Host
Write-Host 'GivenX Shield 1.6.2-R9 - Instalacion asistida de motores' -ForegroundColor Green
Write-Host 'Se descargaran Sysmon desde Microsoft y YARA desde VirusTotal/GitHub.'
Write-Host 'Sysmon instala un servicio y controlador de Microsoft. La opcion -accepteula acepta su licencia.' -ForegroundColor Yellow
$answer = Read-Host 'Escribe SI para instalar o reparar ambos motores'
if ($answer.Trim().ToUpperInvariant() -ne 'SI') { Write-Host 'Operacion cancelada. No se hizo ningun cambio.'; try { Stop-Transcript | Out-Null } catch { }; exit 0 }

try {
    Step 'Pausando temporalmente el radar de GivenX...'
    $agentTaskExists = $null -ne (Get-ScheduledTask -TaskName 'GivenX Shield Agent' -ErrorAction SilentlyContinue)
    $agentWasRunning = $null -ne (Get-Process 'GivenX.Agent' -ErrorAction SilentlyContinue)
    if ($agentTaskExists) { Stop-ScheduledTask -TaskName 'GivenX Shield Agent' -ErrorAction SilentlyContinue }
    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        Get-Process 'GivenX.Agent' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 250
        $runningAgent = Get-Process 'GivenX.Agent' -ErrorAction SilentlyContinue
    } while ($runningAgent -and [DateTime]::UtcNow -lt $deadline)
    if ($runningAgent) { throw 'Windows no permitio pausar el radar. No se modificaron los motores.' }
    Write-Host 'Radar GivenX pausado. Microsoft Defender y tu antivirus principal siguen activos.' -ForegroundColor Yellow

    New-Item -ItemType Directory -Path $temp -Force | Out-Null

    Step 'Descargando y verificando Sysmon oficial...'
    $sysmonZip = Join-Path $temp 'Sysmon.zip'
    $sysmonExtract = Join-Path $temp 'Sysmon'
    Download $sysmonUrl $sysmonZip
    Expand-Archive -LiteralPath $sysmonZip -DestinationPath $sysmonExtract -Force
    $sysmonExe = Get-ChildItem $sysmonExtract -Filter 'Sysmon64.exe' -File -Recurse | Select-Object -First 1
    if (-not $sysmonExe) { throw 'El paquete oficial de Sysmon no contenia Sysmon64.exe.' }
    $signature = Get-AuthenticodeSignature $sysmonExe.FullName
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
        throw 'La firma digital de Microsoft en Sysmon no es valida. No se instalara.'
    }
    $sysmonDest = Join-Path $install 'engines\sysmon'
    New-Item -ItemType Directory -Path $sysmonDest -Force | Out-Null
    Copy-Item $sysmonExe.FullName (Join-Path $sysmonDest 'Sysmon64.exe') -Force
    $installedSysmon = Join-Path $sysmonDest 'Sysmon64.exe'
    Trust-EngineFiles @($installedSysmon)
    $service = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($service) { & $installedSysmon -accepteula -c (Join-Path $install 'sysmon-config.xml') | Out-Host }
    else {
        & $installedSysmon -accepteula -i (Join-Path $install 'sysmon-config.xml') | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'El primer registro de Sysmon fallo. Reintentando una vez...' -ForegroundColor Yellow
            Start-Sleep -Seconds 3
            & $installedSysmon -accepteula -i (Join-Path $install 'sysmon-config.xml') | Out-Host
        }
    }
    if ($LASTEXITCODE -ne 0) { throw "Sysmon devolvio el codigo $LASTEXITCODE." }
    if (-not $service) { Set-Content (Join-Path $sysmonDest 'installed-by-givenx.txt') 'GivenX Shield instalo esta instancia de Sysmon.' -Encoding UTF8 }
    Write-Host 'Sysmon instalado y configurado.' -ForegroundColor Green

    Step "Descargando y verificando YARA $yaraVersion oficial..."
    $yaraZip = Join-Path $temp 'YARA.zip'
    $yaraExtract = Join-Path $temp 'YARA'
    Download $yaraUrl $yaraZip
    $actualHash = (Get-FileHash $yaraZip -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actualHash -ne $yaraSha256) { throw 'El hash SHA-256 de YARA no coincide. No se instalara.' }
    Expand-Archive -LiteralPath $yaraZip -DestinationPath $yaraExtract -Force
    $yaraExe = Get-ChildItem $yaraExtract -Filter 'yara64.exe' -File -Recurse | Select-Object -First 1
    if (-not $yaraExe) { throw 'El paquete oficial de YARA no contenia yara64.exe.' }
    $yaraSource = $yaraExe.DirectoryName
    $yaraSourceFiles = @(Get-ChildItem $yaraSource -File -Recurse | Where-Object { $_.Extension -in '.exe','.dll' })
    $yaraDest = Join-Path $install 'engines\yara'
    New-Item -ItemType Directory -Path $yaraDest -Force | Out-Null
    Copy-Item (Join-Path $yaraSource '*') $yaraDest -Recurse -Force
    $installedYaraFiles = @()
    foreach ($sourceFile in $yaraSourceFiles) {
        $relative = $sourceFile.FullName.Substring($yaraSource.Length).TrimStart([IO.Path]::DirectorySeparatorChar)
        $installedFile = Join-Path $yaraDest $relative
        if (-not (Test-Path $installedFile)) { throw "Falta un archivo de YARA despues de copiarlo: $relative" }
        $sourceHash = (Get-FileHash $sourceFile.FullName -Algorithm SHA256).Hash
        $installedHash = (Get-FileHash $installedFile -Algorithm SHA256).Hash
        if ($sourceHash -ne $installedHash) { throw "YARA cambio durante la copia: $relative" }
        $installedYaraFiles += $installedFile
    }
    Trust-EngineFiles $installedYaraFiles
    $reportedVersion = & (Join-Path $yaraDest 'yara64.exe') --version
    if ($LASTEXITCODE -ne 0) { throw 'YARA no pudo iniciarse despues de la instalacion.' }
    Write-Host "YARA $reportedVersion instalado." -ForegroundColor Green

    Write-Host 'MOTORES INSTALADOS. Abre Estado de motores en GivenX Shield.' -ForegroundColor Green
}
catch {
    $exitCode = 1
    Write-Host "`nNO SE COMPLETO: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'No se desactivo Microsoft Defender ni se anadieron exclusiones.' -ForegroundColor Yellow
}
finally {
    if (Test-Path $temp) { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
    try {
        Step 'Reactivando el radar de GivenX...'
        if ($agentTaskExists) { Start-ScheduledTask -TaskName 'GivenX Shield Agent' -ErrorAction Stop }
        elseif ($agentWasRunning -and (Test-Path (Join-Path $install 'GivenX.Agent.exe'))) { Start-Process (Join-Path $install 'GivenX.Agent.exe') }
        if ($agentTaskExists -or $agentWasRunning) {
            $restartDeadline = [DateTime]::UtcNow.AddSeconds(10)
            do {
                Start-Sleep -Milliseconds 300
                $restartedAgent = Get-Process 'GivenX.Agent' -ErrorAction SilentlyContinue
            } while (-not $restartedAgent -and [DateTime]::UtcNow -lt $restartDeadline)
            if (-not $restartedAgent) { throw 'La tarea no volvio a iniciar GivenX.Agent.exe.' }
            Write-Host 'Radar GivenX reactivado y comprobado.' -ForegroundColor Green
        }
        else { Write-Host 'No habia un radar activo antes de esta operacion; no se inicio uno nuevo.' -ForegroundColor Yellow }
    }
    catch {
        $exitCode = 1
        Write-Host "No se pudo reactivar el radar: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Microsoft Defender no fue desactivado. Reinicia Windows o ejecuta GivenX.Agent.exe como administrador.' -ForegroundColor Yellow
    }
}
try { Stop-Transcript | Out-Null } catch { }
Write-Host "Registro: $log" -ForegroundColor DarkGray
exit $exitCode
