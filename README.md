# GivenX Shield 1.6.2-R9

GivenX Shield es una capa defensiva experimental para Windows 10/11 x64. Complementa al antivirus registrado en Windows Security Center —Microsoft Defender, Kaspersky u otro— con vigilancia de procesos, persistencia, conexiones, Sysmon, reglas YARA, consultas por hash y respuesta confirmada.

> GivenX Shield no sustituye a un antivirus certificado, no garantiza detectar todos los ataques y no debe utilizarse para analizar malware real fuera de una máquina virtual aislada.

## Qué cambia en R9

R9 cierra la rama 1.6.2 con correcciones de estabilidad, falsos positivos y una cadena de lanzamiento verificable:

- las alertas de integridad se reabren si la protección vuelve a degradarse;
- cancelar un análisis cancela realmente la operación en vez de reportar un error ficticio;
- las actividades verificadas como benignas se limpian en caliente, sin reiniciar el agente;
- las ráfagas de archivos se procesan con deduplicación y concurrencia limitada para reducir picos;
- el watcher de Windows usa un búfer mayor y genera una advertencia si pierde eventos;
- repositorio limpio con GPL-3.0, política de seguridad, contribuciones y exclusión de secretos;
- compilación automática en GitHub Actions;
- configuración para firma Authenticode patrocinada por SignPath para proyectos de código abierto;
- separación estricta entre código fuente, artefacto sin firma y release firmada;
- firma del agente, la interfaz y cinco scripts PowerShell de instalación;
- instalador transaccional que usa los binarios firmados sin recompilarlos;
- comprobación del mismo certificado en agente, interfaz y scripts antes de preparar la instalación;
- manifiesto SHA-256 generado después de la firma;
- la instalación anterior permanece intacta si falta una firma, Smart App Control bloquea la candidata o la prueba previa falla.

## Capas defensivas actuales

- antivirus principal detectado mediante Windows Security Center;
- Microsoft Defender como proveedor integrado cuando está activo;
- YARA local con reglas defensivas para RAT, bots, stealers, keyloggers, mineros y persistencia;
- VirusTotal por hash, sin subir archivos automáticamente;
- ThreatFox, URLhaus, YARAify y MalwareBazaar mediante la Auth-Key de abuse.ch;
- telemetría Sysmon para procesos, red, DNS, registro y carga de módulos;
- correlación local, historial, lista segura, cuarentena cifrada y bloqueos reversibles;
- respuesta automática desactivada por defecto; las acciones destructivas requieren confirmación.

Las claves personales se guardan mediante DPAPI ligadas al usuario de Windows. Ninguna clave de VirusTotal, abuse.ch, certificado o archivo de cuarentena pertenece al repositorio.

## Compilar el código

Requisitos:

- Windows 10/11 x64;
- .NET 8 SDK;
- PowerShell 5.1 o posterior.

Ejecuta:

```powershell
./verify-build.ps1
```

El resultado queda en `publish-r9`. Esa compilación es **sin firma** y sirve para revisión o para enviarla a SignPath; no debe instalarse directamente en un equipo con Control inteligente de aplicaciones activo.

## Crear la release firmada

El flujo está preparado en `.github/workflows/signpath-release.yml`. Solo debe ejecutarse después de que SignPath acepte el proyecto y existan estas opciones en GitHub:

- secreto `SIGNPATH_API_TOKEN`;
- variable `SIGNPATH_ORGANIZATION_ID`;
- variable `SIGNPATH_PROJECT_SLUG`;
- variable `SIGNPATH_SIGNING_POLICY_SLUG`;
- configuración de artefacto `givenx-windows` copiada desde `.signpath/artifact-configurations/givenx-windows.xml`.

El flujo compila, firma, verifica y produce `GivenX_Shield_1_6_2_R9_Signed.zip`. Consulta [docs/GITHUB-Y-SIGNPATH.md](docs/GITHUB-Y-SIGNPATH.md).

## Instalar una release oficial

1. Descarga y extrae por completo el ZIP cuyo nombre termina en `_Signed.zip`.
2. Revisa `release-r9/release-metadata.json` y `SHA256SUMS.txt`.
3. Ejecuta `INSTALAR-GIVENX.cmd`.
4. No desactives Microsoft Defender ni Control inteligente de aplicaciones.

El paquete de código fuente de GitHub no contiene `release-r9` y el instalador lo rechazará de forma segura. Para una compilación local firmada con un certificado propio existe `CONFIGURAR-FIRMA.cmd`, pero no es necesaria para el flujo público de SignPath.

## Desarrollo responsable

- Lee [SECURITY.md](SECURITY.md) antes de reportar una vulnerabilidad.
- Lee [CONTRIBUTING.md](CONTRIBUTING.md) antes de enviar cambios.
- No publiques muestras de malware, credenciales, API keys, cookies, volcados de memoria ni registros sin censurar.
- Las reglas y acciones nuevas deben incluir pruebas contra falsos positivos.

## Licencia

Copyright © 2026 GivenX Shield contributors. Proyecto iniciado por Rony (GivenX).

El código se distribuye bajo GNU General Public License v3.0 o posterior. Consulta [LICENSE](LICENSE).

## Code signing policy

Free code signing provided by SignPath.io, certificate by SignPath Foundation.

### Team roles

- Committer: givenchito2-ship-it
- Reviewer: givenchito2-ship-it
- Approver: givenchito2-ship-it

Only official GivenX Shield releases built from the source code in this repository may be submitted for code signing.

Every release submitted for signing must be built through the project's GitHub Actions workflow and manually approved before signing.

### Privacy

GivenX Shield is designed to operate locally on the user's Windows computer.

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

