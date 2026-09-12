param(
    [string]$CertPath = "..\server\certs\cert.pem"
)
if (-Not (Test-Path $CertPath)) {
    Write-Error "Certificate not found: $CertPath"
    exit 1
}
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import((Resolve-Path $CertPath).Path)
Write-Output "Installing certificate to CurrentUser\Root..."
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "CurrentUser"
$store.Open("ReadWrite")
$store.Add($cert)
$store.Close()
Write-Output "Certificate installed. You may need to restart applications to trust the self-signed cert."
