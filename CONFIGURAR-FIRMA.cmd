@echo off
setlocal EnableExtensions
title GivenX Shield 1.6.2-R9 - Configurar firma local
echo.
echo  GIVENX SHIELD 1.6.2-R9 - CONFIGURAR FIRMA LOCAL OPCIONAL
echo  Este asistente no solicita ni exporta tu clave privada.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0configure-signing.ps1"
set "RESULT=%ERRORLEVEL%"
echo.
if not "%RESULT%"=="0" echo No se guardo la configuracion de firma.
pause
exit /b %RESULT%
