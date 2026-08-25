[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSCommandPath
$configurationPath = Join-Path $root 'signing-config.json'
$codeSigningOid = '1.3.6.1.5.5.7.3.3'

function Normalize-Thumbprint([string]$Value)
{
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return ($Value -replace '[^A-Fa-f0-9]', '').ToUpperInvariant()
}

$certificates = @()
foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My'))
{
    try
    {
        $certificates += @(Get-ChildItem $store -ErrorAction Stop |
            Where-Object {
                $_.HasPrivateKey -and $_.NotBefore -le (Get-Date) -and $_.NotAfter -gt (Get-Date) -and
                @($_.EnhancedKeyUsageList | ForEach-Object { $_.ObjectId.Value }) -contains $codeSigningOid
            } |
            ForEach-Object {
                [pscustomobject]@{
                    Certificate = $_
                    Store = $store
                    Subject = $_.Subject
                    Expires = $_.NotAfter
                    Thumbprint = Normalize-Thumbprint $_.Thumbprint
                }
            })
    }
    catch { }
}
$certificates = @($certificates | Sort-Object Thumbprint -Unique)

Write-Host 'GivenX Shield 1.6.2-R9 - Configuracion de firma local opcional' -ForegroundColor Cyan
Write-Host 'Este asistente guarda solamente la huella publica del certificado. Nunca copia la clave privada.' -ForegroundColor Gray
Write-Host ''
if ($certificates.Count -eq 0)
{
    Write-Host 'No se encontro un certificado de firma de codigo vigente con clave privada.' -ForegroundColor Yellow
    Write-Host 'Esta opcion es solo para desarrolladores con certificado propio. La distribucion publica usara SignPath.' -ForegroundColor Yellow
    exit 2
}

for ($index = 0; $index -lt $certificates.Count; $index++)
{
    $row = $certificates[$index]
    Write-Host "[$($index + 1)] $($row.Subject)" -ForegroundColor White
    Write-Host "    Vence: $($row.Expires.ToString('yyyy-MM-dd')) | Almacen: $($row.Store)" -ForegroundColor DarkGray
    Write-Host "    Huella: $($row.Thumbprint)" -ForegroundColor DarkGray
}

$selectionText = Read-Host 'Escribe el numero del certificado que usaras'
$selection = 0
if (-not [int]::TryParse($selectionText, [ref]$selection) -or $selection -lt 1 -or $selection -gt $certificates.Count)
{
    throw 'La seleccion no es valida. No se guardo ningun cambio.'
}
$selected = $certificates[$selection - 1]
$timestamp = Read-Host 'Servidor de sello de tiempo [http://timestamp.digicert.com]'
if ([string]::IsNullOrWhiteSpace($timestamp)) { $timestamp = 'http://timestamp.digicert.com' }

[pscustomobject]@{
    Version = 1
    Thumbprint = $selected.Thumbprint
    TimestampServer = $timestamp.Trim()
} | ConvertTo-Json | Set-Content $configurationPath -Encoding UTF8

Write-Host ''
Write-Host "Configuracion guardada para: $($selected.Subject)" -ForegroundColor Green
Write-Host 'Ahora ejecuta VERIFICAR-COMPILACION.cmd. Windows puede pedir permiso para usar la clave privada.' -ForegroundColor Green
