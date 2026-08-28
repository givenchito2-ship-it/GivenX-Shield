# GivenX Shield 1.6.2-R9 HF6

Hotfix para reducir dos falsos positivos observados en HF5 sin convertir `AppData` ni las carpetas temporales en zonas confiables.

## Qué corrige

- **GitHub Desktop / Git for Windows:** `git-remote-https.exe` deja de generar `GX-USERPATH-NETWORK` únicamente cuando está dentro de `GitHubDesktop\app-*\resources\app\git\mingw64\bin`, su firma Authenticode es válida para **Johannes Schindelin** y el `GitHubDesktop.exe` de esa misma versión conserva una firma válida de **GitHub, Inc.**
- **OneDrive:** `OneDriveSetup.exe` deja de generar `GX-REGISTRY-PERSISTENCE` únicamente durante su actualización normal, desde `%LOCALAPPDATA%\Microsoft\OneDrive\Update\OneDriveSetup.exe`, con firma válida de Microsoft y una entrada `Run` relacionada con OneDrive.
- **Evento heredado de OneDrive:** como `OneDriveSetup.exe` es temporal y puede borrarse al terminar la actualización, HF6 puede resolver un evento de hasta 48 horas de antigüedad solo si la ruta del actualizador era exactamente la oficial, la entrada `Run` es de OneDrive y la instalación actual de `OneDrive.exe` sigue firmada por Microsoft.
- **Eventos heredados de GitHub:** los eventos recientes de `git-remote-https.exe` se reevalúan con las mismas comprobaciones estrictas y dejan de mantener el puntaje si siguen siendo verificables.
- La versión reportada por Agent/UI pasa a `1.6.2-R9-HF6`.

## Qué no cambia

- No se confía globalmente en `%LOCALAPPDATA%`, `AppData`, `Temp` ni `Downloads`.
- Un `git-remote-https.exe` copiado fuera del árbol oficial de GitHub Desktop, sin firma válida o sin un `GitHubDesktop.exe` firmado por GitHub en la misma versión sigue alertando.
- Un `OneDriveSetup.exe` fuera de la ruta oficial, sin firma válida de Microsoft o que modifique ubicaciones de persistencia críticas sigue alertando.
- Defender, Smart App Control, YARA y las reglas de IOC permanecen activos.
