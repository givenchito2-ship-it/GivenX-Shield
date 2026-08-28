# GivenX Shield 1.6.2-R9 HF4

Hotfix para reducir falsos positivos observados en HF3 sin convertir rutas de usuario en zonas confiables.

## Qué corrige

- Microsoft Edge: su entrada normal `MicrosoftEdgeAutoLaunch_*` en `CurrentVersion\Run` deja de generar `GX-REGISTRY-PERSISTENCE` únicamente cuando `msedge.exe` está en Program Files, tiene firma Authenticode válida de Microsoft y el detalle contiene `--win-session-start`.
- GitHub Desktop: `GX-USERPATH-NETWORK` deja de dispararse para `GitHubDesktop.exe` únicamente cuando está en `%LOCALAPPDATA%\GitHubDesktop\app-*\GitHubDesktop.exe` y conserva una firma Authenticode válida de GitHub, Inc.
- Los eventos heredados de Edge y GitHub Desktop que cumplan esas comprobaciones se resuelven automáticamente.
- La versión reportada por Agent/UI pasa a `1.6.2-R9-HF4`.

## Qué NO se permite

- No se confía globalmente en `AppData`, `Downloads` ni otras carpetas modificables por el usuario.
- Un `msedge.exe` fuera de Program Files, sin firma válida, o que toque Winlogon, Policies, IFEO o SilentProcessExit sigue alertando.
- Un `GitHubDesktop.exe` fuera de su ruta oficial o sin firma válida de GitHub sigue alertando.
