$out = Join-Path $env:TEMP 'inno_setup_installer.exe'
Write-Output "Downloading Inno Setup installer to: $out"
$headers = @{ 'User-Agent' = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' }
Invoke-WebRequest -Uri 'https://jrsoftware.org/download.php/is.exe' -OutFile $out -Headers $headers -UseBasicParsing -MaximumRedirection 5
$size = (Get-Item $out -ErrorAction SilentlyContinue).Length
Write-Output "Downloaded size: $size bytes"
if ($size -lt 200000) {
	Write-Warning "Downloaded file is small; the site may have returned an HTML redirect. Falling back to direct file URL."
	$direct = 'https://files.jrsoftware.org/is/6.2.1/is-6.2.1-unicode.exe'
	Write-Output "Downloading direct installer: $direct"
	Invoke-WebRequest -Uri $direct -OutFile $out -Headers $headers -UseBasicParsing -MaximumRedirection 5
	$size = (Get-Item $out -ErrorAction SilentlyContinue).Length
	Write-Output "Downloaded size: $size bytes"
}

if (-not (Test-Path $out)) {
	Write-Error "Installer download failed."
	exit 1
}

Write-Output "Launching installer (UAC prompt expected)"
Start-Process -FilePath $out -Verb RunAs
