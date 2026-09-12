[Setup]
AppName=EazyConnect Client
AppVersion=0.1
DefaultDirName={pf}\EazyConnect
DefaultGroupName=EazyConnect
DisableProgramGroupPage=yes
OutputDir=..\installer_build
OutputBaseFilename=EazyConnect-Installer
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
SetupIconFile=icon.ico

[Files]
Source: "dist\\eazyconnect-client.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "cert.pem"; DestDir: "{app}"; Flags: ignoreversion
Source: "install_cert_windows.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "post_install.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\EazyConnect"; Filename: "{app}\\eazyconnect-client.exe"; IconFilename: "{app}\\icon.ico"

[Run]
; Run the post-install script elevated (installer requests admin)
Filename: "powershell.exe"; Parameters: "-ExecutionPolicy Bypass -File \"{app}\\post_install.ps1\""; Flags: runhidden shellexec postinstall skipifsilent
