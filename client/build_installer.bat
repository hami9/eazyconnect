@echo off
REM Build installer using Inno Setup Compiler (ISCC.exe)
SETLOCAL

REM Find ISCC in PATH
SET "ISCC="
for /F "usebackq tokens=*" %%I in (`where ISCC.exe 2^>nul`) do SET "ISCC=%%~I"
if "%ISCC%"=="" (
  echo Inno Setup Compiler (ISCC.exe) not found in PATH.
  echo Please install Inno Setup: https://jrsoftware.org/isinfo.php
  exit /b 1
)

REM Build the single-file exe first (automated)
echo Building single-file exes with PyInstaller...
call make_windows_exe.bat
if ERRORLEVEL 1 (
  echo make_windows_exe.bat failed. Fix build errors first.
  exit /b %ERRORLEVEL%
)

REM Ensure dist exists
if not exist dist (
  echo dist\ not found after build. Aborting.
  exit /b 1
)

REM Copy server cert if available
if not exist cert.pem (
  if exist ..\server\certs\cert.pem (
    echo Copying cert from server\certs\cert.pem
    copy /Y ..\server\certs\cert.pem cert.pem >nul
  ) else (
    echo Warning: cert.pem not found in client or server\certs. Installer will be built without cert.
  )
)

REM Ensure install script exists (it should be in this folder)
if not exist install_cert_windows.ps1 (
  echo Warning: install_cert_windows.ps1 not found in client folder.
)

echo Running Inno Setup (ISCC)...
"%ISCC%" installer.iss
if ERRORLEVEL 1 (
  echo Installer build failed.
  exit /b %ERRORLEVEL%
)
echo Installer built under installer_build\

echo.
echo Tip: to run this build with Administrator privileges (required to add system routes or register services), run build_installer_admin.ps1 which will elevate and execute this script.

ENDLOCAL
