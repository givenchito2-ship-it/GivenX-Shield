@echo off
setlocal
title GivenX Shield Beta - Instalador
fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
echo.
echo  GivenX Shield Beta Unificada 1.6.2-R9
echo  Verificando, preparando e instalando de forma transaccional.
echo  R9 usa la release firmada por SignPath sin volver a compilarla.
echo  La version actual no se tocara si falta la firma o Windows bloquea la candidata.
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-install.ps1"
if errorlevel 1 (
  echo.
  echo La instalacion no se completo. La version anterior fue conservada o restaurada.
  echo Toma una captura completa del error.
)
pause
endlocal
