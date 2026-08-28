# GivenX Shield 1.6.2-R9 HF10 — corrección múltiple

HF10 cambia el enfoque de hotfix uno-a-uno y agrupa varios falsos positivos ya observados durante las pruebas de R9.

## Qué corrige de una vez

1. **Microsoft Edge — limpieza RunOnce**
   - Reconoce únicamente `Microsoft\\Edge\\Application\\<versión>\\Installer\\setup.exe`.
   - Exige firma válida de Microsoft.
   - El objetivo debe ser exactamente `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\msedge_cleanup_{GUID}`.
   - El comando debe incluir `--msedge`, `--channel=stable`, `--delete-old-versions`, `--system-level` y `--on-logon`.
   - También resuelve el evento heredado si el instalador de la versión anterior ya fue eliminado pero Edge instalado sigue firmado por Microsoft.

2. **OneDrive — componentes oficiales con red**
   - Añade `OneDriveLauncher.exe` y `OneDriveStandaloneUpdater.exe` a los componentes conocidos.
   - Solo se aceptan bajo `%LOCALAPPDATA%\\Microsoft\\OneDrive` y con firma válida de Microsoft.

3. **Discord — conexiones normales desde AppData**
   - Reconoce `Discord.exe` únicamente bajo `%LOCALAPPDATA%\\Discord\\app-*\\Discord.exe`.
   - Exige firma válida de Discord Inc.
   - Una copia con el mismo nombre fuera de esa ruta o sin firma sigue generando `GX-USERPATH-NETWORK`.

4. **Instaladores temporales ya terminados**
   - Eventos `Archivo nuevo que requiere revisión` de patrones temporales típicos de instaladores (`~nsu*.tmp`, `_iu*.tmp`, `is-*.tmp/_isetup`) se resuelven solo cuando:
     - han pasado al menos 10 minutos;
     - el archivo ya no existe;
     - Microsoft Defender informó `Clean`;
     - VirusTotal informó `Clean (0 detecciones)`;
     - no existe ningún veredicto `Malicious` o `Suspicious`.
   - No se confía globalmente en `%TEMP%`.

5. **Limpieza del historial**
   - Los eventos históricos que cumplen exactamente las validaciones anteriores pasan al almacén de resueltos y dejan de determinar la puntuación actual.

## Qué NO se relaja

- `Downloads`, `Temp` y `AppData` siguen considerándose ubicaciones modificables por el usuario.
- TURMO u otros binarios no verificados no se permiten automáticamente.
- Persistencia en `Winlogon`, `Policies`, IFEO o `SilentProcessExit` sigue alertando.
- Un Edge/OneDrive/Discord sin firma válida o fuera de su ruta oficial sigue alertando.
- IOC confirmados, inyección, manipulación de defensas y reglas de alta severidad no cambian.

## Objetivo de la prueba

Después de instalar HF10 deben desaparecer de los eventos activos los falsos positivos ya verificados de Edge cleanup, OneDrive Launcher/Standalone Updater, Discord firmado y archivos temporales de instaladores ya finalizados. Los eventos que no puedan verificarse de forma fuerte seguirán apareciendo como `REVISAR`.
