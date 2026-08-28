# GivenX Shield 1.6.2-R9 HF5

Hotfix para evitar que GivenX marque su propio instalador de pruebas como una amenaza de manipulación.

## Qué ocurrió

`install-test-unsigned.ps1` contiene instrucciones administrativas reales para respaldar, detener y volver a registrar componentes de GivenX. La regla YARA `GivenX_Possible_Security_Tampering` detectó correctamente esas cadenas, pero el Agent no reconocía el script como un artefacto propio generado por GitHub Actions. El resultado era un falso `REVISAR 82/100`.

## Qué corrige

- `verify-build.ps1` incorpora el SHA-256 exacto de `install-test-unsigned.ps1` al manifiesto `trusted-build-artifacts.json`.
- `BuildArtifactTrustStore` acepta ese nombre únicamente cuando el hash exacto está presente en el manifiesto verificado que corresponde al Agent/UI instalados.
- Un archivo distinto, modificado o simplemente renombrado a `install-test-unsigned.ps1` **no** obtiene confianza.
- Los eventos antiguos del instalador se resuelven automáticamente después de instalar HF5, porque su SHA-256 queda reconocido por el manifiesto del build.
- La versión reportada por Agent/UI pasa a `1.6.2-R9-HF5`.

## Qué no cambia

- La regla YARA de manipulación permanece activa.
- No se agrega una exclusión para `Downloads`, `DevTest` ni PowerShell en general.
- Defender y Smart App Control no se desactivan desde GivenX.

## Nota de prueba

Mientras HF4 siga instalado puede volver a mostrar la alerta al descargar HF5, porque HF4 aún no conoce el hash del script de pruebas. Tras instalar HF5, el evento debe resolverse automáticamente.
