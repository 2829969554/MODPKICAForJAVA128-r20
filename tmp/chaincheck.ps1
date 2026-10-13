$ErrorActionPreference = "Stop"
$leaf = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$PWD\tmp\chain0.der")
Write-Host "Leaf: $($leaf.Subject)"
Write-Host "Leaf key size: $($leaf.PublicKey.Key.KeySize)"
$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
$chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
$chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
$ok = $chain.Build($leaf)
Write-Host "Chain.Build = $ok"
Write-Host "ChainStatus:"
$chain.ChainStatus | ForEach-Object { Write-Host ("   " + $_.Status + " : " + $_.StatusInformation.Trim()) }
Write-Host "Elements:"
$chain.ChainElements | ForEach-Object {
  Write-Host ("   " + $_.Certificate.Subject + "  key=" + $_.Certificate.PublicKey.Key.KeySize + " bits  chainStatus=[" +
    (($_.ChainElementStatus | ForEach-Object { $_.Status }) -join ", ") + "]")
}
