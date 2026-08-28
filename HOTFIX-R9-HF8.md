# GivenX Shield 1.6.2-R9 HF8

Hotfix puntual para el evento real observado de OneDrive `RunOnce`.

## Qué ocurrió

HF7 reconocía la variante `Delete Cached Standalone Update Binary`, pero en este equipo OneDrive creó la variante igualmente legítima `Delete Cached Update Binary`. Al no coincidir el nombre exacto, el evento heredado seguía manteniendo `62/100`.

## Qué corrige

- Reconoce **solo** estas dos entradas exactas de limpieza de OneDrive bajo `CurrentVersion\RunOnce`:
  - `Delete Cached Standalone Update Binary`
  - `Delete Cached Update Binary`
- Mantiene las mismas comprobaciones de HF7: ruta oficial de `OneDriveSetup.exe` y, para eventos históricos cuyo instalador temporal ya desapareció, exige que `OneDrive.exe` actual siga presente y firmado por Microsoft.
- No confía globalmente en `RunOnce`, `AppData`, `OneDriveSetup.exe` ni en nombres parecidos.
- La versión reportada por Agent/UI pasa a `1.6.2-R9-HF8`.

## Qué no cambia

- Cualquier otra entrada `RunOnce` sigue alertando.
- Un `OneDriveSetup.exe` fuera de la ruta oficial o una instalación actual de OneDrive sin firma válida de Microsoft sigue considerándose sospechosa.
