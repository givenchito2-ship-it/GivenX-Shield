# GivenX Shield 1.6.2-R9 HF2

Hotfix para reducir ruido observado al iniciar Windows sin convertir carpetas de usuario en zonas confiables.

## Qué corrige

- Chrome: una copia auténtica y firmada por Google, instalada en `Program Files`, ya no genera `GX-REGISTRY-PERSISTENCE` únicamente por escribir su entrada normal de `CurrentVersion\Run`. Las ubicaciones críticas (Winlogon, Policies, IFEO y SilentProcessExit) siguen alertando siempre.
- Eventos heredados de Chrome que cumplan esa misma verificación se resuelven automáticamente en el panel HF2.
- `GX-UNTRUSTED-DLL` ahora muestra la ruta exacta de la biblioteca (`Biblioteca:`) y los detalles de Sysmon, en vez de enseñar solo el proceso que la cargó.
- Si el usuario permite el hash exacto de una DLL revisada, futuros eventos de esa misma biblioteca dejan de repetirse; cualquier cambio de hash vuelve a revisarse.
- El detalle de evento prioriza la DLL real al usar `PERMITIR HASH`, evitando autorizar accidentalmente el ejecutable host.
- Se conserva el HF1: OneDrive firmado por Microsoft, Sysmon oficial firmado, deduplicación de conexiones y versión del agente residente.

## TURMO y otros programas en Downloads

No se agrega una excepción global para `Downloads`. Un programa reconocido como TURMO puede autorizarse con `VER` -> `PERMITIR HASH`; la excepción queda ligada al SHA-256 exacto y deja de servir si el archivo cambia.

## Steam / hardwareupdater

No se oculta automáticamente. HF2 muestra la DLL exacta que disparó la alerta. Solo después de verificar esa DLL debe usarse `PERMITIR HASH` si corresponde.

## Nota de migración

Si el título de la ventana sigue diciendo `1.6.2-R5`, Windows todavía está iniciando la instalación residente antigua. HF2 no modifica esa copia hasta instalar una release nueva completa.
