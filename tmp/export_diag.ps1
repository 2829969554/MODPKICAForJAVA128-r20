$out = New-Object System.Collections.Generic.List[string]
$out.Add("########## CAPI2 20:54:35-20:55:20 ##########")
$evts = Get-WinEvent -LogName 'Microsoft-Windows-CAPI2/Operational' -MaxEvents 400 -ErrorAction SilentlyContinue
foreach ($e in $evts) {
    if ($e.TimeCreated -ge [datetime]'2026-10-10 20:54:35' -and $e.TimeCreated -le [datetime]'2026-10-10 20:55:20') {
        $out.Add("[$($e.TimeCreated)] Id=$($e.Id) Lv=$($e.Level)")
        try { $xml=[xml]$e.ToXml() } catch { $out.Add("  XML parse fail"); continue }
        $ud = $xml.Event.UserData
        if ($ud) {
            $node = $ud.FirstChild
            if ($node) {
                $proc = $node.EventAuxInfo.ProcessName
                $out.Add("  Process: $proc")
                if ($node.Certificate -and $node.Certificate.subjectName) { $out.Add("  Cert: $($node.Certificate.subjectName)") }
                $chain = $node.CertificateChain
                if ($chain) {
                    $ts = $chain.TrustStatus
                    $out.Add("  ChainError: $($ts.ErrorStatus)  Result=$($node.Result)")
                } else {
                    $out.Add("  Result=$($node.Result)")
                }
            }
        }
        $out.Add("-----")
    }
}
$out.Add("")
$out.Add("########## IKEEXT 最近 15 ##########")
foreach ($e in (Get-WinEvent -LogName 'Microsoft-Windows-IKEEXT/Operational' -MaxEvents 15 -ErrorAction SilentlyContinue)) {
    $out.Add("[$($e.TimeCreated)] Id=$($e.Id) Lv=$($e.Level): $($e.Message -replace '\s+',' ' | Out-String)")
}
$out.Add("")
$out.Add("########## Application RasClient 最近 8 ##########")
foreach ($e in (Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='RasClient'} -MaxEvents 8 -ErrorAction SilentlyContinue)) {
    $out.Add("[$($e.TimeCreated)] Id=$($e.Id): $($e.Message -replace '\s+',' ' | Out-String)")
}
[IO.File]::WriteAllLines('C:\Users\28299\Desktop\modpkica4JAVA\tmp\diag_all.txt', $out, (New-Object Text.UTF8Encoding $false))
Write-Output "DONE $($out.Count)"
