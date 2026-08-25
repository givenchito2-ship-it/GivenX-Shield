# Política de seguridad

## Versiones mantenidas

La rama `main` y la release pública más reciente reciben correcciones. Las versiones Beta anteriores pueden conservarse solo para recuperación; no se consideran mantenidas.

## Reportar una vulnerabilidad

No abras un issue público. Utiliza **Security > Report a vulnerability** en GitHub para crear un aviso privado.

Incluye:

- versión exacta y versión de Windows;
- descripción del impacto;
- pasos mínimos de reproducción;
- registros censurados;
- una prueba segura que no contenga malware funcional ni datos ajenos.

No envíes API keys, contraseñas, cookies, tokens, certificados privados, volcados de LSASS, archivos de cuarentena ni muestras de malware. Si la vulnerabilidad implica una clave expuesta, revócala antes de reportarla.

## Alcance

Son de especial interés: evasión de confirmaciones, restauración insegura de cuarentena, rutas arbitrarias, inyección de comandos, abuso de privilegios, actualización no verificada, fuga de secretos DPAPI y manipulación de la cadena GitHub/SignPath.

Los falsos positivos normales deben reportarse como error, sin adjuntar el archivo si contiene información privada.
