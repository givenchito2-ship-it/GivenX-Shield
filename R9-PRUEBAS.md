# GivenX Shield 1.6.2-R9 — pruebas recomendadas

Esta lista valida la R9 sin desactivar Microsoft Defender, Smart App Control ni otras protecciones de Windows.

## 1. Compilación

En Windows 10/11 x64 con .NET 8 SDK:

```powershell
./verify-build.ps1
```

Debe terminar sin errores y crear `publish-r9`. Esa salida es **sin firma** y no es la release instalable oficial.

## 2. Cancelación de análisis

1. Abre GivenX Shield.
2. Inicia un análisis de una carpeta suficientemente grande.
3. Pulsa **Cancelar** mientras el análisis está activo.
4. La interfaz debe indicar que el análisis fue cancelado; no debe convertir la cancelación en un error de VirusTotal, YARA, Defender u otro motor.

## 3. Carga durante ráfagas de archivos

1. Con el agente activo, compila GivenX o copia una carpeta con muchos archivos dentro de Descargas.
2. Comprueba en el Administrador de tareas que el agente no dispara una cantidad ilimitada de análisis simultáneos.
3. Los archivos repetidos de una misma ruta no deben encolar trabajo duplicado mientras ya exista un análisis pendiente.

## 4. Integridad recuperable

La R9 corrige un caso en el que una comprobación que había quedado marcada como resuelta podía ocultarse si luego volvía a fallar. Para validarlo sin modificar binarios:

1. Haz la prueba solo sobre una instalación de prueba de GivenX.
2. En el Programador de tareas, deshabilita temporalmente **GivenX Shield UI**. No deshabilites Defender ni otras protecciones.
3. Espera al siguiente ciclo de integridad (aproximadamente un minuto): debe aparecer la revisión **Inicio del panel desactivado**.
4. Vuelve a habilitar **GivenX Shield UI** y espera otro ciclo: el hallazgo debe quedar resuelto.
5. Deshabilita una segunda vez la misma tarea: la revisión debe reaparecer.
6. Vuelve a habilitarla al terminar.

## 5. GitHub

Al subir R9 a `main`, el workflow **Compilar y verificar** debe quedar en verde y publicar el artefacto `GivenX-1.6.2-R9-unsigned`.

No publiques ese artefacto como instalador final. La release distribuible debe salir del flujo de firma y terminar en `GivenX_Shield_1_6_2_R9_Signed.zip`.

## 6. Regla de seguridad

Si una prueba requiere desactivar antivirus, Smart App Control, firewall o protecciones equivalentes para “hacer que funcione”, detén la prueba y revisa la causa. R9 está diseñada para convivir con esas protecciones, no para saltárselas.
