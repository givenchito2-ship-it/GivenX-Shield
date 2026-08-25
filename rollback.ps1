#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$recovery = Join-Path (Split-Path -Parent $PSCommandPath) 'RECUPERAR-GIVENX.cmd'
if (-not (Test-Path $recovery))
{
    throw 'No se encontró RECUPERAR-GIVENX.cmd.'
}

& $env:ComSpec /d /c "`"$recovery`""
exit $LASTEXITCODE
