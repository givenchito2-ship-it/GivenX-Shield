[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$publish = Join-Path $root 'publish-r9'
$output = Join-Path $root 'signpath-input'

Write-Host 'Compilando GivenX Shield 1.6.2-R9 para SignPath...' -ForegroundColor Cyan
& (Join-Path $root 'verify-build.ps1')
if ($LASTEXITCODE -ne 0) { throw "La compilacion devolvio el codigo $LASTEXITCODE." }

if (Test-Path $output) { Remove-Item $output -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $output 'Agent') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $output 'UI') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $output 'Installer') -Force | Out-Null

Copy-Item (Join-Path $publish 'Agent\*') (Join-Path $output 'Agent') -Recurse -Force
Copy-Item (Join-Path $publish 'UI\*') (Join-Path $output 'UI') -Recurse -Force

Copy-Item (Join-Path $publish 'Installer\*') (Join-Path $output 'Installer') -Recurse -Force

foreach ($required in @(
    (Join-Path $output 'Agent\GivenX.Agent.exe'),
    (Join-Path $output 'UI\GivenX.UI.exe'),
    (Join-Path $output 'Installer\build-install.ps1')
))
{
    if (-not (Test-Path $required)) { throw "Falta el artefacto requerido: $required" }
}

Write-Host 'ENTRADA SIGNPATH PREPARADA: signpath-input' -ForegroundColor Green
Write-Host 'No se modificaron tareas, procesos ni archivos instalados.' -ForegroundColor Green
