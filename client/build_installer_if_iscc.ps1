# Checks for Inno Setup Compiler (ISCC.exe) in common locations or PATH
# and runs it against installer.iss in the current folder's staging.

$possible = @(
    'ISCC.exe',
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe'
)

$iscc = $null
foreach ($p in $possible) {
    try {
        $full = (Get-Command $p -ErrorAction SilentlyContinue).Source
        if ($full) { $iscc = $full; break }
    } catch { }
    if (Test-Path $p) { $iscc = $p; break }
}

if (-not $iscc) {
    Write-Error "ISCC.exe not found. Install Inno Setup and ensure ISCC.exe is on PATH or in a standard location."
    Write-Output "Download: https://jrsoftware.org/isinfo.php"
    exit 2
}

$iss = Join-Path (Get-Location) 'installer.iss'
if (-not (Test-Path $iss)) {
    Write-Error "installer.iss not found in current directory: $iss"
    exit 3
}

Write-Output "Using ISCC.exe: $iscc"
& $iscc $iss
