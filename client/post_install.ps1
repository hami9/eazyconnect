<#
  EazyConnect post-install script
  - Prompts to choose Master (server) or Client (node)
  - Master: attempts to generate self-signed certs and create a scheduled task to run the server on logon (requires Python)
  - Client: prompts for master URL, writes a `config.json` under %APPDATA%\eazyconnect, installs cert if present, creates a Startup shortcut, and warns about VPN connectivity
#>

Write-Host "EazyConnect post-install configuration`n"

$role = Read-Host "Choose role: 1) Master (server)  2) Client (node) -- enter 1 or 2"

if ($role -eq '1') {
    Write-Host "Selected: Master (server)"
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Host "Python not found in PATH. Please install Python 3.9+ and the server dependencies before continuing.`n" -ForegroundColor Yellow
        Write-Host "Server files are expected to be placed next to the installer in ..\server\"
        exit 0
    }

    $scriptPath = Join-Path $PSScriptRoot "..\server\generate_selfsigned.py"
    if (Test-Path $scriptPath) {
        Write-Host "Generating self-signed certs..."
        python $scriptPath
    } else {
        Write-Host "generate_selfsigned.py not found at $scriptPath" -ForegroundColor Yellow
    }

    $serverPy = Join-Path $PSScriptRoot "..\server\main.py"
    if (Test-Path $serverPy) {
        $python = (Get-Command python).Source
        $taskName = "EazyConnect-Master"
        $tr = "`"$python`" `"$serverPy`""
        Write-Host "Creating scheduled task to run server on logon (task name: $taskName)"
        schtasks /Create /SC ONLOGON /TN $taskName /TR $tr /RL HIGHEST /F | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Host "Scheduled task created." } else { Write-Host "Failed to create scheduled task." -ForegroundColor Red }
    } else {
        Write-Host "server main script not found at $serverPy. Copy server files here to enable automatic startup." -ForegroundColor Yellow
    }

} else {
    Write-Host "Selected: Client (node)"
    $appDir = $PSScriptRoot
    $exe = Join-Path $appDir "eazyconnect-client.exe"

    $master = Read-Host "Enter master URL (e.g. https://192.168.1.2:8000 or https://master.local:8000)"
    if (-not $master) { Write-Host "No master provided, aborting client configuration."; exit 0 }

    $cfgDir = Join-Path $env:APPDATA "eazyconnect"
    if (-not (Test-Path $cfgDir)) { New-Item -ItemType Directory -Path $cfgDir | Out-Null }
    $configPath = Join-Path $cfgDir "config.json"
    $cfg = @{ master = $master; verify = $true; username = ""; token = "" } | ConvertTo-Json
    Set-Content -Path $configPath -Value $cfg -Encoding UTF8
    Write-Host "Wrote configuration to $configPath"

    $cert = Join-Path $appDir "cert.pem"
    if (Test-Path $cert) {
        Write-Host "Installing certificate to CurrentUser\Root..."
        powershell -ExecutionPolicy Bypass -File (Join-Path $appDir "install_cert_windows.ps1") -CertPath $cert
    } else {
        Write-Host "No cert.pem found in application folder; skipping local install." -ForegroundColor Yellow
    }

    if (Test-Path $exe) {
        try {
            $WshShell = New-Object -ComObject WScript.Shell
            $startup = [Environment]::GetFolderPath("Startup")
            $lnkPath = Join-Path $startup "EazyConnect.lnk"
            $lnk = $WshShell.CreateShortcut($lnkPath)
            $lnk.TargetPath = $exe
            $lnk.WorkingDirectory = $appDir
            $lnk.Save()
            Write-Host "Created Startup shortcut: $lnkPath"
        } catch {
            Write-Host "Failed to create Startup shortcut: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Client executable not found at $exe. You can run the client manually." -ForegroundColor Yellow
    }

    # VPN detection: look for common VPN adapter names
    $vpnAdapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'VPN|TAP|Tun|WireGuard|OpenVPN|Cisco' -or $_.Name -match 'VPN|TAP|Tun|WireGuard|OpenVPN|Cisco' }
    if ($vpnAdapters -and $vpnAdapters.Count -gt 0) {
        Write-Host "VPN adapter(s) detected: $($vpnAdapters.Name -join ', ')" -ForegroundColor Yellow
        Write-Host "If clients use VPN, ensure the master address you entered is reachable from client networks (use public IP or hostname or proper routing)."
        Write-Host "Testing connectivity to master..."
        try { Invoke-WebRequest -Uri $master -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop; Write-Host "Connection to master succeeded." } catch { Write-Host "Unable to reach master from this network. You may need port forwarding, public IP, or VPN routing adjustments." -ForegroundColor Red }
        
        # Attempt to prefer Wi-Fi interface for master traffic instead of disabling VPN.
        try {
            $uri = [uri]$master
            $host = $uri.Host
        } catch {
            # If user entered an IP only
            $host = $master
        }

        Write-Host "Resolving master host: $host"
        try {
            $addrs = [System.Net.Dns]::GetHostAddresses($host) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
            if ($addrs -and $addrs.Count -gt 0) {
                $masterIp = $addrs[0].IPAddressToString
                Write-Host "Master resolved to $masterIp"

                # Find Wi-Fi adapter
                $wifi = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceDescription -match 'Wireless|Wi-Fi|WLAN' -or $_.Name -match 'Wi-Fi|Wireless|WLAN' } | Select-Object -First 1
                if ($wifi) {
                    Write-Host "Found Wi-Fi adapter: $($wifi.Name) (ifIndex: $($wifi.ifIndex))"
                    $ipcfg = Get-NetIPConfiguration -InterfaceIndex $wifi.ifIndex
                    $gw = $ipcfg.IPv4DefaultGateway.NextHop
                    if ($gw) {
                        Write-Host "Wi-Fi gateway: $gw"

                        # Check admin
                        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                        $routeCmd = "route ADD $masterIp MASK 255.255.255.255 $gw IF $($wifi.ifIndex) -p"
                        if ($isAdmin) {
                            Write-Host "Adding persistent route to prefer Wi-Fi for master: $routeCmd"
                            cmd.exe /c $routeCmd | Out-Null
                            if ($LASTEXITCODE -eq 0) { Write-Host "Route added." } else { Write-Host "Failed to add route. Try running this script as Administrator: $routeCmd" -ForegroundColor Red }
                        } else {
                            Write-Host "Not running as Administrator. Cannot add persistent route automatically." -ForegroundColor Yellow
                            Write-Host "Run the following command as Administrator to force master traffic over Wi-Fi:`n$routeCmd"
                        }
                    } else {
                        Write-Host "Could not determine Wi-Fi gateway. Manual routing may be required." -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "Wi-Fi adapter not found. Cannot add route automatically." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Could not resolve master host to an IPv4 address." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Error while attempting to resolve/add route: $_" -ForegroundColor Red
        }
    }
}

Write-Host "Post-install configuration complete.`n"
