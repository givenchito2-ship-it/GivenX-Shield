@echo off
setlocal EnableExtensions
title GivenX Shield - Reparacion segura de alertas conocidas
fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
echo.
echo  GIVENX SHIELD - REPARACION SEGURA DE DATOS
echo  No reemplaza ejecutables ni desactiva protecciones de Windows.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0repair-current-alerts.ps1"
set "RESULT=%ERRORLEVEL%"
echo.
if not "%RESULT%"=="0" echo  La reparacion no se completo. Toma una captura completa.
pause
exit /b %RESULT%
