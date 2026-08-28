# GivenX Shield 1.6.2-R9 HF7

Hotfix enfocado en el falso positivo heredado de OneDrive mostrado como `GX-REGISTRY-PERSISTENCE` con puntuación 62/100.

## Qué corrige

- Reconoce la entrada exacta de Microsoft OneDrive `CurrentVersion\RunOnce\Delete Cached Standalone Update Binary` cuando fue creada por el `OneDriveSetup.exe` oficial y firmado por Microsoft.
- Como `OneDriveSetup.exe` se elimina al terminar la actualización, un evento histórico de esa entrada exacta puede resolverse durante 14 días únicamente si la ruta registrada era `%LOCALAPPDATA%\Microsoft\OneDrive\Update\OneDriveSetup.exe` y el `OneDrive.exe` actualmente instalado conserva una firma válida de Microsoft.
- Los eventos ordinarios de OneDrive mantienen la ventana corta anterior; la ampliación solo aplica al nombre exacto de limpieza `Delete Cached Standalone Update Binary`.
- La versión reportada por Agent/UI pasa a `1.6.2-R9-HF7`.

## Qué NO cambia

- No se confía globalmente en `RunOnce`, `AppData` ni en cualquier archivo llamado `OneDriveSetup.exe`.
- Un ejecutable fuera de la ruta oficial, no firmado por Microsoft, o que escriba otra entrada de persistencia sigue generando alerta.
- Las ubicaciones críticas como Winlogon, Policies, IFEO y SilentProcessExit siguen sin excepciones.
