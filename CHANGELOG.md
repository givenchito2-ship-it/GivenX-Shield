# Historial de cambios

## 1.6.2-R9 — 2026-08-25

### Correcciones finales de R9

- Las alertas de integridad vuelven a activarse si una condición que estaba sana se degrada después; una resolución automática antigua ya no puede ocultar una nueva alteración.
- La cancelación de análisis se propaga correctamente y ya no se convierte en un falso error de motor.
- Las actividades verificadas como confiables se reconcilian durante la ejecución, sin obligar a reiniciar el agente para limpiar falsos positivos conocidos.
- El análisis de archivos nuevos ahora deduplica rutas pendientes y limita la concurrencia para evitar picos durante compilaciones, instalaciones o ráfagas de archivos.
- El monitor de archivos aumenta su búfer y avisa si Windows reporta pérdida de eventos.
- Workflows de GitHub actualizados para usar las generaciones actuales de `checkout` y `setup-dotnet`.

### Publicación y firma

- Preparación completa del repositorio público.
- Licencia GPL-3.0-or-later y políticas de seguridad/contribución.
- Compilación automática en GitHub Actions.
- Flujo manual de release firmado mediante SignPath.
- Firma anidada del agente, interfaz y scripts PowerShell.
- Instalación de binarios precompilados sin destruir sus firmas.
- Manifiesto de confianza regenerado después de la firma.
- Rechazo seguro del paquete fuente cuando no existe una release firmada.
- Exclusión explícita de secretos, certificados, motores descargados y datos locales.
