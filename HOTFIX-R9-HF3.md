# GivenX Shield 1.6.2-R9 HF3

Hotfix basado en las pruebas de la instalación residente HF2.

## Qué corrige

- El chequeo de tareas programadas ahora analiza el XML real de Task Scheduler en vez de buscar texto de forma frágil. Evita falsos avisos de `GivenX Shield Agent` y `GivenX Shield UI` cuando ambas tareas existen y apuntan a `C:\Program Files\GivenX Shield`.
- `EngineTrustStore` tolera y recupera almacenes `trusted-engine-hashes.json` heredados/malformados, extrayendo únicamente SHA-256 válidos.
- El instalador normaliza siempre el almacén de hashes YARA, aunque los hashes oficiales ya estuvieran presentes dentro de una estructura heredada.
- `repair-current-alerts.ps1` también recupera hashes válidos de formatos heredados y vuelve a escribir un JSON limpio.
- La versión reportada por Agent/UI pasa a `1.6.2-R9-HF3`.

## Hallazgos de la prueba HF2

- `GivenX Shield UI` devolvió `LastTaskResult = 0` y se ejecutaba desde la ruta correcta.
- `GivenX.Agent.exe` y `GivenX.UI.exe` estaban activos desde `C:\Program Files\GivenX Shield`.
- `yarac64.exe` tenía SHA-256 `5B6705B9A8DABF496BCCF163A65887574290C97F8B999C8CB73DF5417B04BBD7`, que coincide con el hash oficial esperado por GivenX; la alerta 95/100 provenía del formato heredado del almacén de confianza, no de un cambio del binario.
