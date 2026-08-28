# GivenX Shield 1.6.2-R9 HF9

Hotfix para eliminar un falso positivo de `GX-UNTRUSTED-DLL` observado con instaladores/desinstaladores temporales.

## Qué ocurrió

Sysmon puede emitir un evento de carga de imagen donde `Image` e `ImageLoaded` apuntan al mismo ejecutable. HF8 trataba ese caso como si el proceso hubiera cargado una biblioteca externa no verificada.

## Qué corrige

- `GX-UNTRUSTED-DLL` deja de dispararse cuando las rutas normalizadas de `Proceso` y `Biblioteca` son exactamente iguales.
- Los eventos históricos de los últimos 7 días con esa misma condición se resuelven automáticamente.
- No se confía en `%TEMP%`, NSIS, `Un_A.exe` ni ningún nombre concreto. Una biblioteca distinta cargada desde una ruta modificable sigue alertando.
- La versión reportada por Agent/UI pasa a `1.6.2-R9-HF9`.

## Qué no cambia

- Los ejecutables temporales sin firma siguen pudiendo generar `GX-UNSIGNED-USERPATH-PROCESS` u otras reglas.
- Las DLL realmente distintas del proceso siguen siendo evaluadas por `GX-UNTRUSTED-DLL`.
