# Publicar GivenX Shield y solicitar firma gratuita

Esta guía separa dos momentos: primero publicar el código; después solicitar el patrocinio de firma. No pegues API keys ni tokens en archivos del repositorio.

## 1. Crear el repositorio con GitHub Desktop

1. Extrae el paquete `GivenX_Shield_1_6_2_R9_GitHub_Ready` en una carpeta nueva.
2. En GitHub Desktop selecciona **Add an Existing Repository from your local drive**.
3. Elige la carpeta que contiene `GivenXShield.sln`, `README.md` y `.github`.
4. Si GitHub Desktop indica que todavía no es un repositorio, usa **create a repository here**.
5. Nombre recomendado: `GivenX-Shield`.
6. No marques **Initialize this repository with a README**, porque R9 ya lo incluye.
7. Crea el primer commit y pulsa **Publish repository**.
8. El repositorio debe ser público para solicitar el programa gratuito de código abierto.

Antes de publicar, GitHub Desktop no debe mostrar `signing-config.json`, archivos PFX/P12/PEM/KEY, carpetas `bin`, `obj`, `publish-*`, `release-*`, `engines` ni archivos `secret-*.bin`.

## 2. Verificar la primera compilación

En GitHub abre **Actions > Compilar y verificar**. El flujo compila R9 en un runner alojado por GitHub y guarda un artefacto sin firma durante 14 días. Ese artefacto no es instalable.

## 3. Solicitar SignPath para código abierto

Solicita acceso desde el programa de código abierto de SignPath e indica:

- repositorio público de GivenX Shield;
- licencia GPL-3.0-or-later;
- ejecutables Windows x64 en .NET 8;
- necesidad de Authenticode para `GivenX.Agent.exe`, `GivenX.UI.exe` y scripts PowerShell;
- compilación en GitHub-hosted runners;
- configuración propuesta en `.signpath/artifact-configurations/givenx-windows.xml`.

SignPath decidirá si el proyecto cumple sus requisitos. El certificado y la política de firma quedan controlados por su servicio; la clave privada no se descarga ni se guarda en GitHub.

## 4. Configurar GitHub después de la aceptación

En **Settings > Secrets and variables > Actions** agrega:

| Tipo | Nombre | Valor |
| --- | --- | --- |
| Secret | `SIGNPATH_API_TOKEN` | Token de SignPath |
| Variable | `SIGNPATH_ORGANIZATION_ID` | ID de la organización |
| Variable | `SIGNPATH_PROJECT_SLUG` | Slug asignado al proyecto |
| Variable | `SIGNPATH_SIGNING_POLICY_SLUG` | Política aprobada, por ejemplo `release-signing` |

Nunca pegues el token en un issue, README, commit o captura pública.

En SignPath crea o importa la configuración de artefacto con slug `givenx-windows` usando el XML incluido. Vincula el sistema confiable **GitHub.com** al proyecto y autoriza el repositorio cuando SignPath lo solicite.

## 5. Crear una release firmada

1. Abre **Actions > Crear release firmada con SignPath**.
2. Pulsa **Run workflow**.
3. GitHub compilará R9 y enviará el artefacto a SignPath.
4. SignPath firmará dos EXE y cinco scripts PowerShell.
5. El flujo comprobará todas las firmas y el mismo certificado.
6. Descarga el artefacto `GivenX-Shield-1.6.2-R9-Signed`.

El archivo final es `GivenX_Shield_1_6_2_R9_Signed.zip`. Solo ese ZIP es candidato a publicarse en **Releases**.

## Referencias oficiales

- [SignPath para proyectos de código abierto](https://signpath.io/solutions/open-source-community)
- [Integración oficial de SignPath con GitHub](https://docs.signpath.io/trusted-build-systems/github)
- [Configuraciones de artefacto SignPath](https://docs.signpath.io/artifact-configuration/)
- [Agregar un proyecto existente con GitHub Desktop](https://docs.github.com/en/desktop/adding-and-cloning-repositories/adding-an-existing-project-to-github-using-github-desktop)
