# GivenX Shield 1.6.2-R9 HF8 FIX

Corrige un error de compilación introducido en HF8.

## Error

`KnownBenignActivity.cs` todavía llamaba al nombre antiguo:

`IsOneDriveStandaloneUpdateCleanupTarget(target)`

La función actual se llama:

`IsOneDriveCachedUpdateCleanupTarget(target)`

## Cambio

Se reemplaza únicamente esa referencia obsoleta. No cambia la lógica de seguridad ni se agregan nuevas excepciones.
