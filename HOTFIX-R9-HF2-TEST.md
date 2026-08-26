# GivenX Shield 1.6.2-R9 HF2 TEST

Modo controlado para probar la instalación residente de R9 HF2 antes de que SignPath entregue la firma pública.

## Objetivo

Este modo no reemplaza la firma oficial. Solo permite que el instalador de pruebas acepte el artifact `unsigned` generado por GitHub Actions, después de validar:

- que el paquete contiene `Agent`, `UI` y `trusted-build-artifacts.json`;
- que el manifiesto corresponde a `1.6.2-R9`;
- que el manifiesto incluye el commit de GitHub Actions (`SourceCommit`);
- que los SHA-256 de `GivenX.Agent.exe` y `GivenX.UI.exe` coinciden con el manifiesto;
- que Microsoft Defender en tiempo real continúa activado.

El cambio de versión sigue siendo transaccional: prepara una candidata, prueba que Windows permite ejecutar Agent/UI, respalda la versión residente, cambia de versión y revierte a la anterior si algo falla.

## Smart App Control

Este instalador solo omite la barrera de firma propia de GivenX. No puede ni intenta saltarse Smart App Control de Windows.

Si Smart App Control bloquea los ejecutables unsigned, la prueba previa aborta antes de retirar la instalación residente. Para una prueba temporal puede ser necesario desactivar Smart App Control desde la interfaz oficial de Seguridad de Windows y volverlo a activar inmediatamente al terminar. Microsoft Defender y Firewall deben permanecer activos.

## Artifact de GitHub Actions

`verify-build.ps1` agrega una carpeta `DevTest` únicamente al artifact unsigned. La entrada que se envía a SignPath sigue copiando solo `Agent`, `UI` e `Installer`, de modo que el instalador de prueba no forma parte de la release pública firmada.

## Ejecución

Desde PowerShell como administrador, ubicado dentro de la carpeta `DevTest` del artifact:

```powershell
.\install-test-unsigned.ps1 -IUnderstandUnsignedTestBuild
```

No usar este modo para distribución pública.
