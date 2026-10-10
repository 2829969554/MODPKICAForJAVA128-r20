$log = 'C:\Users\28299\Desktop\modpkica4JAVA\tmp\reimport_log.txt'
$lines = New-Object System.Collections.Generic.List[string]
try {
    $pfx = 'C:\Users\28299\Desktop\modpkica4JAVA\PKI\b53080_client_2048.pfx'
    $pw = ConvertTo-SecureString '12345678' -AsPlainText -Force
    $cert = Import-PfxCertificate -FilePath $pfx -CertStoreLocation 'Cert:\LocalMachine\My' -Password $pw -Exportable
    $lines.Add("IMPORT_OK subject=$($cert.Subject) sn=$($cert.SerialNumber) thumb=$($cert.Thumbprint)")
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
    if ($rsa -is [System.Security.Cryptography.RSACng]) {
        $lines.Add("KEYTYPE=CNG provider=$($rsa.Key.Provider.Provider)")
    } elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
        $lines.Add("KEYTYPE=CSP")
    } else {
        $lines.Add("KEYTYPE=$($rsa.GetType().Name)")
    }
    $lines.Add("EXITCODE=0")
} catch {
    $lines.Add("IMPORT_FAIL: $($_.Exception.Message)")
    $lines.Add("EXITCODE=1")
}
[IO.File]::WriteAllLines($log, $lines, (New-Object Text.UTF8Encoding $false))
