@echo off
setlocal
cd /d "%~dp0"
set "PS_SCRIPT=%~dp0installer\EazyConnect-Setup.ps1"
if not exist "%PS_SCRIPT%" set "PS_SCRIPT=%~dp0EazyConnect-Setup.ps1"

if not exist "%PS_SCRIPT%" (
    echo ERROR: Could not locate EazyConnect-Setup.ps1 next to this launcher.
    pause
    exit /b 1
)

where pwsh >nul 2>nul
if %errorlevel%==0 (
    start "" pwsh -NoProfile -ExecutionPolicy Bypass -STA -File "%PS_SCRIPT%"
) else (
    start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -File "%PS_SCRIPT%"
)
endlocal
