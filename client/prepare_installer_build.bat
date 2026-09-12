@echo off
REM Prepare installer_build folder with files required for Inno Setup compilation
setlocal
REM Resolve script directory and create installer_build inside it
set SCRIPTDIR=%~dp0
set OUTDIR=%SCRIPTDIR%installer_build
if exist "%OUTDIR%" rd /s /q "%OUTDIR%"
mkdir "%OUTDIR%"

echo Copying built EXE...
REM Look for built EXE in several likely locations
set EXE_SRC1=%~dp0dist\\eazyconnect-client.exe
set EXE_SRC2=%~dp0..\\dist\\eazyconnect-client.exe
set EXE_SRC3=%~dp0..\\..\\dist\\eazyconnect-client.exe
if exist "%EXE_SRC1%" (
  copy /Y "%EXE_SRC1%" "%OUTDIR%\\" >nul
) else if exist "%EXE_SRC2%" (
  copy /Y "%EXE_SRC2%" "%OUTDIR%\\" >nul
) else if exist "%EXE_SRC3%" (
  copy /Y "%EXE_SRC3%" "%OUTDIR%\\" >nul
) else (
  echo ERROR: eazyconnect-client.exe not found in expected dist locations. Build the EXE first with make_windows_exe.bat
  exit /b 1
)

echo Copying scripts and resources...
for %%f in (install_cert_windows.ps1 post_install.ps1 installer.iss icon.ico) do (
  if exist "%~dp0%%f" copy /Y "%~dp0%%f" "%OUTDIR%\\" >nul
)

REM Copy cert if present in server
if exist "%~dp0..\server\certs\cert.pem" (
  copy /Y "%~dp0..\server\certs\cert.pem" "%OUTDIR%\\" >nul
) else (
  echo Note: server cert not found; installer will be built without cert.pem unless you place it in client\ or server\certs\
)

echo Prepared %OUTDIR% with required files.
echo To compile installer, install Inno Setup and run:
echo   ISCC.exe installer.iss
echo from inside the %OUTDIR% folder.
endlocal
