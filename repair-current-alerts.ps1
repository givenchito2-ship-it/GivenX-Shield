#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$install = Join-Path $env:ProgramFiles 'GivenX Shield'
$dataRoot = Join-Path $env:ProgramData 'GivenXShield'
$trustPath = Join-Path $install 'trusted-engine-hashes.json'
$eventsPath = Join-Path $dataRoot 'events.jsonl'
$resolvedPath = Join-Path $dataRoot 'resolved-events.json'
$backupRoot = Join-Path $dataRoot ("RepairBackups\" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$expectedYara = @{
    'yara64.exe' = '1C45EB279D820ABA81FD41C22384428EBE44037CF5793BE4B52A9D3B3DF62B33'
    'yarac64.exe' = '5B6705B9A8DABF496BCCF163A65887574290C97F8B999C8CB73DF5417B04BBD7'
}

function Write-JsonSet([string]$Path, [System.Collections.Generic.HashSet[string]]$Values)
{
    $parent = Split-Path -Parent $Path
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $temporary = $Path + '.givenx-repair.tmp'
    ConvertTo-Json -InputObject @($Values | Sort-Object) | Set-Content $temporary -Encoding UTF8
    Move-Item $temporary $Path -Force
}

function Read-JsonSet([string]$Path)
{
    $values = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    try
    {
        if (Test-Path $Path)
        {
            $raw = Get-Content $Path -Raw
            foreach ($match in [regex]::Matches($raw, '(?i)(?<![A-F0-9])[A-F0-9]{64}(?![A-F0-9])'))
            {
                [void]$values.Add($match.Value.ToUpperInvariant())
            }
        }
    }
    catch { }
    return ,$values
}

function Test-OfficialOneDriveComponent([string]$Path)
{
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    try
    {
        $allowed = @('OneDrive.exe', 'FileCoAuth.exe', 'OneDrive.Sync.Service.exe', 'Microsoft.SharePoint.exe')
        $root = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'Microsoft\OneDrive')).TrimEnd('\') + '\'
        $actual = [IO.Path]::GetFullPath($Path.Trim().Trim('"'))
        if (-not $actual.StartsWith($root, [StringComparison]::OrdinalIgnoreCase) -or
            $allowed -notcontains [IO.Path]::GetFileName($actual)) { return $false }
        $signature = Get-AuthenticodeSignature -FilePath $actual
        if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate) { return $false }
        return $signature.SignerCertificate.Subject -match '(?i)(?:^|,\s*)(?:CN|O)=Microsoft Corporation(?:,|$)'
    }
    catch { return $false }
}

if (-not (Test-Path (Join-Path $install 'GivenX.Agent.exe')))
{
    throw "No se encontró una instalación activa en $install"
}

New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
foreach ($path in @($trustPath, $resolvedPath))
{
    if (Test-Path $path) { Copy-Item $path $backupRoot -Force }
}

Write-Host '[1/3] Verificando los motores YARA oficiales instalados...' -ForegroundColor Cyan
$trusted = Read-JsonSet $trustPath
$verifiedNames = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($name in $expectedYara.Keys)
{
    $path = Join-Path $install (Join-Path 'engines\yara' $name)
    if (-not (Test-Path $path))
    {
        Write-Warning "No está instalado: $name"
        continue
    }
    $actual = (Get-FileHash $path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actual -ne $expectedYara[$name])
    {
        Write-Warning "$name no coincide con YARA 4.5.5 oficial. No se confió ni se ocultó su alerta."
        continue
    }
    [void]$trusted.Add($actual)
    [void]$verifiedNames.Add($name)
    Write-Host "${name}: SHA-256 oficial verificado." -ForegroundColor Green
}
if ($verifiedNames.Count -gt 0) { Write-JsonSet $trustPath $trusted }

Write-Host '[2/3] Resolviendo únicamente eventos cuya evidencia puede volver a verificarse...' -ForegroundColor Cyan
$resolved = Read-JsonSet $resolvedPath
$newlyResolved = 0
if (Test-Path $eventsPath)
{
    foreach ($line in Get-Content $eventsPath)
    {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $event = $line | ConvertFrom-Json } catch { continue }
        $fingerprint = [string]$event.Fingerprint
        $title = [string]$event.Title
        $evidence = [string]$event.Evidence
        if ([string]::IsNullOrWhiteSpace($fingerprint)) { continue }

        $safe = $false
        if ($title.Equals('Motor local no confiable', [StringComparison]::OrdinalIgnoreCase))
        {
            $match = [regex]::Match($evidence, '(?i)engines\\yara\\(?<name>yara64|yarac64)\.exe\s*$')
            $safe = $match.Success -and $verifiedNames.Contains($match.Groups['name'].Value + '.exe')
        }
        elseif ($title.Equals('Conexión desde programa de carpeta sensible', [StringComparison]::OrdinalIgnoreCase) -and
                $evidence -match '(?i)Regla:\s*GX-USERPATH-NETWORK')
        {
            $match = [regex]::Match($evidence, '(?im)^Proceso:\s*(?<path>[A-Z]:\\[^\r\n]+)\s*$')
            $safe = $match.Success -and (Test-OfficialOneDriveComponent $match.Groups['path'].Value)
        }

        if ($safe -and $resolved.Add($fingerprint)) { $newlyResolved++ }
    }
}
Write-JsonSet $resolvedPath $resolved

Write-Host '[3/3] Reactivando la actualización del panel...' -ForegroundColor Cyan
$task = Get-ScheduledTask -TaskName 'GivenX Shield Agent' -ErrorAction SilentlyContinue
if ($task)
{
    Stop-ScheduledTask -TaskName 'GivenX Shield Agent' -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Start-ScheduledTask -TaskName 'GivenX Shield Agent' -ErrorAction Stop
}
elseif (-not (Get-Process 'GivenX.Agent' -ErrorAction SilentlyContinue))
{
    Start-Process (Join-Path $install 'GivenX.Agent.exe')
}

Write-Host ''
Write-Host "Reparación terminada: $($verifiedNames.Count) motor(es) verificado(s), $newlyResolved evento(s) conocido(s) resuelto(s)." -ForegroundColor Green
Write-Host "Respaldo: $backupRoot" -ForegroundColor DarkGray
Write-Host 'No se permitieron carpetas, no se desactivó Defender y no se modificó Control de aplicaciones.' -ForegroundColor Green
