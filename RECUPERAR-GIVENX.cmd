@echo off
setlocal EnableExtensions
chcp 65001 >nul
title GivenX Shield 1.6.2-R9 - Recuperacion segura
fltmc >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "INSTALL=%ProgramFiles%\GivenX Shield"
set "BACKUP=%ProgramData%\GivenXShield\PreviousVersion"
set "STAGING=%ProgramData%\GivenXShield\RecoveryStagingR9"

echo.
echo  GIVENX SHIELD 1.6.2-R9 - RECUPERACION SEGURA
echo.
echo [1/6] Deteniendo las tareas de GivenX...
schtasks /Change /TN "GivenX Shield Agent" /DISABLE >nul 2>&1
schtasks /Change /TN "GivenX Shield UI" /DISABLE >nul 2>&1
schtasks /Change /TN "GivenX Shield Watchdog" /DISABLE >nul 2>&1
schtasks /End /TN "GivenX Shield Agent" >nul 2>&1
schtasks /End /TN "GivenX Shield UI" >nul 2>&1
schtasks /End /TN "GivenX Shield Watchdog" >nul 2>&1
taskkill /F /T /IM GivenX.Agent.exe >nul 2>&1
taskkill /F /T /IM GivenX.UI.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo [2/6] Comprobando el respaldo...
if not exist "%BACKUP%\GivenX.Agent.exe" goto :NO_BACKUP
if not exist "%BACKUP%\GivenX.UI.exe" goto :NO_BACKUP

echo [3/6] Preparando una copia verificada...
if exist "%STAGING%" rmdir /S /Q "%STAGING%" >nul 2>&1
mkdir "%STAGING%" >nul 2>&1
robocopy "%BACKUP%" "%STAGING%" /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 goto :COPY_ERROR
if not exist "%STAGING%\GivenX.Agent.exe" goto :COPY_ERROR
if not exist "%STAGING%\GivenX.UI.exe" goto :COPY_ERROR

echo [4/6] Retirando la instalacion incompleta...
if exist "%INSTALL%" rmdir /S /Q "%INSTALL%" >nul 2>&1
if exist "%INSTALL%" goto :LOCKED

echo [5/6] Restaurando la version anterior...
mkdir "%INSTALL%" >nul 2>&1
robocopy "%STAGING%" "%INSTALL%" /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP >nul
if errorlevel 8 goto :RESTORE_ERROR
if not exist "%INSTALL%\GivenX.Agent.exe" goto :RESTORE_ERROR
if not exist "%INSTALL%\GivenX.UI.exe" goto :RESTORE_ERROR

echo [6/6] Reactivando el radar...
schtasks /Change /TN "GivenX Shield Agent" /ENABLE >nul 2>&1
schtasks /Change /TN "GivenX Shield UI" /ENABLE >nul 2>&1
start "" "%INSTALL%\GivenX.Agent.exe"
start "" "%INSTALL%\GivenX.UI.exe"
echo.
echo ============================================================
echo  RECUPERACION COMPLETADA. GIVENX FUE RESTAURADO.
echo ============================================================
echo.
pause
exit /b 0

:NO_BACKUP
echo.
echo ERROR: El respaldo anterior no contiene los dos ejecutables.
echo No se modifico la carpeta instalada.
goto :FAILED

:COPY_ERROR
echo.
echo ERROR: Windows no pudo copiar o verificar el respaldo.
echo No se modifico la carpeta instalada.
goto :FAILED

:LOCKED
echo.
echo ERROR: Windows todavia mantiene bloqueada la carpeta de GivenX.
echo Reinicia Windows y ejecuta este mismo archivo nuevamente.
goto :FAILED

:RESTORE_ERROR
echo.
echo ERROR: No se pudo completar la copia hacia Archivos de programa.
goto :FAILED

:FAILED
echo.
if exist "%INSTALL%\GivenX.Agent.exe" if exist "%INSTALL%\GivenX.UI.exe" (
  echo Reactivando la instalacion que sigue disponible...
  schtasks /Change /TN "GivenX Shield Agent" /ENABLE >nul 2>&1
  schtasks /Change /TN "GivenX Shield UI" /ENABLE >nul 2>&1
  start "" "%INSTALL%\GivenX.Agent.exe"
  start "" "%INSTALL%\GivenX.UI.exe"
  echo La instalacion existente fue reactivada.
  echo.
)
echo Toma una captura de esta ventana antes de cerrarla.
pause
exit /b 1

endlocal
