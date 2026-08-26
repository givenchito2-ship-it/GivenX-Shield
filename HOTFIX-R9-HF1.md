# GivenX Shield 1.6.2-R9 HF1

Hotfix centrado en reducir falsos positivos sin bajar el nivel de seguridad.

## Qué corrige

- OneDrive: `OneDrive.exe`, `FileCoAuth.exe`, `OneDrive.Sync.Service.exe` y `Microsoft.SharePoint.exe` solo se consideran actividad conocida cuando están dentro de `%LOCALAPPDATA%\Microsoft\OneDrive` y conservan una firma Authenticode válida de Microsoft.
- La caché de verificación de OneDrive ya no conserva indefinidamente un fallo transitorio de firma: resultados negativos se reintentan pronto.
- Sysmon: `engines\sysmon\Sysmon64.exe` se acepta como motor oficial si conserva una firma Authenticode válida de Microsoft, aunque el archivo de hashes local haya quedado desactualizado.
- El panel R9 HF1 vuelve a evaluar eventos conocidos y resuelve automáticamente falsos positivos heredados aunque el agente residente todavía sea una versión anterior.
- La puntuación y el estado mostrados por el panel se recalculan después de retirar eventos conocidos, evitando `PELIGRO 95/100` causado únicamente por un falso positivo ya verificable.
- La regla `GX-USERPATH-NETWORK` agrupa por ejecutable en vez de crear una alerta nueva por cada IP de destino. Los IOC confirmados siguen conservando destino/DNS en su identidad.
- El estado compartido ahora informa la versión del agente residente. El panel muestra `Agente: NO REPORTADA` cuando está leyendo un agente antiguo.

## Qué NO se oculta

- Un `GivenX.UI.exe` sin firma ejecutado desde `Downloads` sigue apareciendo como `REVISAR`. Durante las pruebas unsigned esto es intencional. La release firmada e instalada en `Program Files` no debe depender de esa excepción.
- Binarios de OneDrive con nombre correcto pero firma inválida/no verificable no se permiten automáticamente.
- Sysmon que no conserve una firma válida de Microsoft no se considera confiable solo por llamarse `Sysmon64.exe`.

## Prueba recomendada

1. Copiar los archivos de este hotfix sobre el repositorio R9.
2. Hacer commit y push.
3. Esperar el workflow `Compilar y verificar` de GitHub Actions.
4. Descargar el artifact unsigned solo para pruebas controladas; no desactivar Smart App Control.
5. Abrir la UI HF1 y comprobar que el panel muestra la versión del agente.
6. Si el agente instalado todavía es anterior, es normal que muestre `NO REPORTADA`; OneDrive/Sysmon verificados deberían limpiarse del panel.
7. Cuando SignPath entregue la firma, instalar la release completa para que UI y Agent queden ambos en HF1.
