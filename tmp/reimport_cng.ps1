$ErrorActionPreference = 'Stop'
# 1) 删除旧的 CSP 私钥证书
& certutil -delstore My 7927C712EB3B0E9A08B0D1B88F3A5CF70FCB9792 2>&1 | Out-Null
# 2) 用 CNG 方式重新导入（Import-PfxCertificate 默认 KSP）
$pfx = 'C:\Users\28299\Desktop\modpkica4JAVA\PKI\b53080_client_2048.pfx'
$pw = ConvertTo-SecureString '12345678' -AsPlainText -Force
$cert = Import-PfxCertificate -FilePath $pfx -CertStoreLocation 'Cert:\LocalMachine\My' -Password $pw -Exportable
Write-Output "导入完成: $($cert.Subject) 序列号=$($cert.SerialNumber)"
# 3) 检查私钥 provider
try {
    $key = $cert.GetRSAPrivateKey()
    Write-Output "私钥算法: $($key.KeyAlgorithm) Provider=$($key.ToString())"
} catch {
    Write-Output "GetRSAPrivateKey 失败: $($_.Exception.Message)"
}
# 4) 通过 CNG 接口查看 provider 名
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($rsa -is [System.Security.Cryptography.RSACng]) {
    Write-Output "私钥类型: RSACng (CNG) Provider=$($rsa.Key.Provider.Provider)"
} elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
    Write-Output "私钥类型: RSACryptoServiceProvider (CSP)"
} else {
    Write-Output "私钥类型: $($rsa.GetType().Name)"
}
