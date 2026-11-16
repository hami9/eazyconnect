[Setup]
AppId={{7E8E6E42-9A55-4B1C-8A0A-E42C12000210}
AppName=EazyConnect
AppVersion=0.2.1
AppPublisher=EazyConnect Contributors
AppPublisherURL=https://github.com/hami9/eazyconnect
DefaultDirName={localappdata}\Programs\EazyConnect
DefaultGroupName=EazyConnect
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\installer_out
OutputBaseFilename=EazyConnect-Setup-v0.2.1-windows-x86_64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern dark
SetupIconFile=eazyconnect.ico
UninstallDisplayIcon={app}\eazyconnect-ui.exe

[Types]
Name: "client"; Description: "Client Workstation (Native UI + CLI)"
Name: "server"; Description: "Master Server (HTTPS Relay + Discovery)"
Name: "full"; Description: "Full Bundle (Master Server + Native UI + CLI)"

[Components]
Name: "ui"; Description: "Native Desktop UI (eazyconnect-ui.exe)"; Types: client full
Name: "cli"; Description: "CLI Client & Hardware Bridge (eazyconnect-client.exe)"; Types: client full
Name: "server"; Description: "Master Server & Blind Relay (eazyconnect-server.exe)"; Types: server full
Name: "wizard"; Description: "Prerequisite & VPN Setup UI (EazyConnect-Setup.ps1)"; Types: client server full

[Files]
Source: "..\target\release\eazyconnect-ui.exe"; DestDir: "{app}"; Components: ui; Flags: ignoreversion
Source: "..\target\release\eazyconnect-client.exe"; DestDir: "{app}"; Components: cli; Flags: ignoreversion
Source: "..\target\release\eazyconnect-server.exe"; DestDir: "{app}"; Components: server; Flags: ignoreversion
Source: "EazyConnect-Setup.ps1"; DestDir: "{app}\installer"; Components: wizard; Flags: ignoreversion
Source: "..\Setup-EazyConnect.bat"; DestDir: "{app}"; Components: wizard; Flags: ignoreversion
Source: "eazyconnect.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\docs\vpn-guide.md"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\EazyConnect Control Center"; Filename: "{app}\eazyconnect-ui.exe"; IconFilename: "{app}\eazyconnect.ico"; Components: ui
Name: "{group}\EazyConnect Prerequisite & Setup Wizard"; Filename: "{app}\Setup-EazyConnect.bat"; IconFilename: "{app}\eazyconnect.ico"; Components: wizard
Name: "{autodesktop}\EazyConnect"; Filename: "{app}\eazyconnect-ui.exe"; IconFilename: "{app}\eazyconnect.ico"; Components: ui; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a Desktop shortcut for EazyConnect Native UI"; GroupDescription: "Shortcuts:"
Name: "launchwizard"; Description: "Open EazyConnect Setup & Prerequisite UI to configure Master/Client & Firewall"; GroupDescription: "Post-install:"; Flags: unchecked

[Run]
Filename: "{app}\eazyconnect-ui.exe"; Description: "Launch EazyConnect Native UI"; Flags: nowait postinstall skipifsilent; Components: ui
Filename: "{app}\Setup-EazyConnect.bat"; Description: "Run EazyConnect Prerequisite & Setup Wizard"; Flags: nowait postinstall skipifsilent; Tasks: launchwizard
