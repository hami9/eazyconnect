<#
.SYNOPSIS
    Builds release binaries for EazyConnect (server, client, UI), generates a lightweight icon,
    assembles a portable installer bundle, and compiles Inno Setup `.exe` if ISCC.exe is installed.
#>
[CmdletBinding()]
param(
    [switch]$SkipCargoBuild
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$OutDir = Join-Path $RepoRoot 'installer_out'
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

# 1. Generate compact 32x32 PNG-inside-ICO icon if missing
$IconPath = Join-Path $PSScriptRoot 'eazyconnect.ico'
if (-not (Test-Path $IconPath)) {
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object System.Drawing.Bitmap 64, 64
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::FromArgb(255, 13, 18, 30))

    $penOuter = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 31, 242, 138)), 4
    $g.DrawRectangle($penOuter, 8, 8, 48, 48)
    $brushInner = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 0, 154, 162))
    $g.FillRectangle($brushInner, 18, 18, 28, 28)
    $penOuter.Dispose(); $brushInner.Dispose(); $g.Dispose()

    $msPng = New-Object System.IO.MemoryStream
    $bmp.Save($msPng, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytes = $msPng.ToArray()
    $msPng.Dispose(); $bmp.Dispose()

    $fs = [System.IO.File]::Create($IconPath)
    $bw = New-Object System.IO.BinaryWriter($fs)
    $bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]1)
    $bw.Write([byte]64); $bw.Write([byte]64); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$pngBytes.Length)
    $bw.Write([uint32]22)
    $bw.Write($pngBytes)
    $bw.Close(); $fs.Close()
    Write-Host "Generated icon: $IconPath" -ForegroundColor Cyan
}

# 2. Build Release binaries
if (-not $SkipCargoBuild) {
    Write-Host "Building release binaries (eazyconnect-server, eazyconnect-client, eazyconnect-ui)..." -ForegroundColor Cyan
    cargo build --manifest-path (Join-Path $RepoRoot 'Cargo.toml') --release --bins
    if ($LASTEXITCODE -ne 0) { throw "Cargo release build failed." }
}

# 3. Assemble portable folder ready to copy cleanly to any PC
$PortableDir = Join-Path $OutDir 'EazyConnect-Portable'
if (Test-Path $PortableDir) { Remove-Item $PortableDir -Recurse -Force }
New-Item -ItemType Directory -Path (Join-Path $PortableDir 'installer') -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $PortableDir 'docs') -Force | Out-Null

foreach ($bin in @('eazyconnect-ui.exe', 'eazyconnect-client.exe', 'eazyconnect-server.exe')) {
    $src = Join-Path $RepoRoot "target\release\$bin"
    if (Test-Path $src) {
        Copy-Item $src (Join-Path $PortableDir $bin) -Force
    }
}
Copy-Item (Join-Path $RepoRoot 'Setup-EazyConnect.bat') (Join-Path $PortableDir 'Setup-EazyConnect.bat') -Force
Copy-Item (Join-Path $PSScriptRoot 'EazyConnect-Setup.ps1') (Join-Path $PortableDir 'installer\EazyConnect-Setup.ps1') -Force
Copy-Item $IconPath (Join-Path $PortableDir 'installer\eazyconnect.ico') -Force
$LogoPng = Join-Path $RepoRoot 'crates\eazyconnect-ui\assets\logo.png'
if (Test-Path $LogoPng) {
    Copy-Item $LogoPng (Join-Path $PortableDir 'installer\logo.png') -Force
}
Copy-Item (Join-Path $RepoRoot 'README.md') (Join-Path $PortableDir 'docs\README.md') -Force
Copy-Item (Join-Path $RepoRoot 'docs\vpn-guide.md') (Join-Path $PortableDir 'docs\vpn-guide.md') -Force

Write-Host "Portable setup bundle assembled at: $PortableDir" -ForegroundColor Green

# 4. Compile Inno Setup .exe if ISCC.exe is present
$IsccCandidates = @(
    (Get-Command iscc -ErrorAction SilentlyContinue | ForEach-Object { $_.Source }),
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if ($IsccCandidates) {
    Write-Host "Compiling Inno Setup installer with: $IsccCandidates" -ForegroundColor Cyan
    & $IsccCandidates (Join-Path $PSScriptRoot 'eazyconnect.iss')
    if ($LASTEXITCODE -ne 0) { throw "ISCC.exe exited with $LASTEXITCODE" }
    Write-Host "Installer EXE generated inside $OutDir" -ForegroundColor Green
} else {
    Write-Host "Inno Setup 6 (ISCC.exe) not found; portable bundle created cleanly. Run Setup-EazyConnect.bat to install Inno Setup 6 or deploy directly." -ForegroundColor Yellow
}
