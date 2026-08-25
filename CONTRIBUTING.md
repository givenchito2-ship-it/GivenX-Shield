# Contribuir a GivenX Shield

Gracias por ayudar a mejorar el proyecto.

1. Crea una rama desde `main`.
2. Mantén los cambios pequeños y explicables.
3. Ejecuta `./verify-build.ps1` en Windows con .NET 8 SDK.
4. Documenta cómo probaste el cambio y sus posibles falsos positivos.
5. Abre un pull request. No modifiques `.signpath/`, los flujos de release, la cuarentena o la gestión de secretos sin una revisión adicional.

No se aceptan funciones ofensivas, captura de credenciales, evasión de seguridad, persistencia encubierta, descarga de malware ni código que desactive protecciones de Windows.

Nunca confirmes claves API, certificados, archivos PFX, datos DPAPI, registros privados, binarios compilados, `signing-config.json`, carpetas `release-*` o archivos de cuarentena. `.gitignore` cubre estos casos, pero debes revisar `git status` antes de publicar.

Al contribuir aceptas que tu cambio se distribuya bajo GPL-3.0-or-later.
