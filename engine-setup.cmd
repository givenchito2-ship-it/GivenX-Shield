@echo off
setlocal
chcp 65001 >nul
title GivenX Shield - Motores oficiales
echo.
echo  GivenX Shield 1.6.2-R9 - Instalador de motores
echo  Esta ventana permanecera abierta hasta que presiones una tecla.
echo.
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0engine-setup.ps1"
set "givenx_result=%ERRORLEVEL%"
echo.
if not "%givenx_result%"=="0" echo El instalador devolvio el codigo %givenx_result%.
echo Presiona una tecla para cerrar esta ventana.
pause >nul
exit /b %givenx_result%
