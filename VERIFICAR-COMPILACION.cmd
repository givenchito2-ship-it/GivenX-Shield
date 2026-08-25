@echo off
setlocal EnableExtensions
chcp 65001 >nul
title GivenX Shield 1.6.2-R9 - Verificacion segura
echo.
echo  GIVENX SHIELD 1.6.2-R9 - VERIFICACION SEGURA
echo  Esta prueba NO modifica la version instalada.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0verify-build.ps1"
set "RESULT=%ERRORLEVEL%"
echo.
if not "%RESULT%"=="0" (
  echo  NO INSTALAR. Toma una captura completa de esta ventana.
) else (
  echo  La compilacion termino correctamente.
  echo  Solo instala si arriba aparece: LISTA PARA INSTALAR.
  echo  Esta prueba verifica el codigo. La instalacion publica requiere la release firmada por SignPath.
)
echo.
pause
exit /b %RESULT%
