@echo off
REM Build one-file executables for client using PyInstaller
python -m pip install pyinstaller
pyinstaller --onefile client\client.py --name eazyconnect-client
if %ERRORLEVEL% neq 0 (
	echo Failed to build eazyconnect-client
	exit /b %ERRORLEVEL%
)

pyinstaller --onefile --windowed --name eazyconnect-gui client\gui_main.py
if %ERRORLEVEL% neq 0 (
	echo Failed to build eazyconnect-gui
	exit /b %ERRORLEVEL%
)

echo Build finished. Check dist\eazyconnect-client.exe and dist\eazyconnect-gui.exe
