# Cadena de lanzamiento R9

## Fuente pública

El repositorio contiene únicamente código, reglas, configuración y documentación. No contiene claves, datos DPAPI, certificados, motores descargados ni binarios de release.

## Artefacto sin firma

`prepare-signing-input.ps1` compila `GivenX.Agent.exe` y `GivenX.UI.exe` como archivos únicos y reúne cinco scripts PowerShell. El resultado `signpath-input` se genera en un runner alojado por GitHub.

## Firma

SignPath recibe el artefacto registrado por GitHub Actions. La configuración `givenx-windows` permite firmar únicamente:

- `Agent/GivenX.Agent.exe`;
- `UI/GivenX.UI.exe`;
- cinco archivos `Installer/*.ps1`.

El flujo no firma archivos con nombres o cantidades diferentes.

## Verificación posterior

`prepare-signed-release.ps1` exige una firma Authenticode válida y el mismo certificado en todos los componentes. Luego calcula SHA-256 y crea `release-metadata.json` y `trusted-build-artifacts.json`.

## Instalación

`build-install.ps1` prefiere `release-r9`. No ejecuta `dotnet publish` cuando la release firmada existe, por lo que no destruye las firmas. Antes de detener el radar prueba ambos ejecutables candidatos. El cambio de carpetas es transaccional y conserva o restaura la versión anterior si algo falla.

El paquete de código fuente no contiene `release-r9`; al intentar instalarlo sin certificado local, se detiene sin modificar la instalación actual.
