<#
Runs the `build_installer.bat` with elevated privileges. If not elevated, relaunches itself as administrator.
#>
function Is-Administrator {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Is-Administrator)) {
    Write-Host 'Not running as administrator - relaunching with elevation...'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    # Build arguments safely by concatenation to avoid quoting/parsing issues
    $psi.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        exit 0
    } catch {
        Write-Error 'Elevation canceled by user. Aborting.'
        exit 1
    }
}

# Running elevated: invoke the batch build script
$bat = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath 'build_installer.bat'
if (-not (Test-Path $bat)) {
    Write-Error "Could not find build_installer.bat at $bat"
    exit 1
}

Write-Host ("Running: {0} (elevated)" -f $bat)
& cmd.exe /c $bat
if ($LASTEXITCODE -ne 0) {
    Write-Error ("Build script failed with exit code {0}" -f $LASTEXITCODE)
    exit $LASTEXITCODE
}
Write-Host 'Build completed.'
