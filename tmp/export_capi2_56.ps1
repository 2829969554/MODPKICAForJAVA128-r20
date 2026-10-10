$out = New-Object System.Collections.Generic.List[string]
$out.Add("########## CAPI2 20:56:15-20:57:10 ##########")
$evts = Get-WinEvent -LogName 'Microsoft-Windows-CAPI2/Operational' -MaxEvents 600 -ErrorAction SilentlyContinue
foreach ($e in $evts) {
    if ($e.TimeCreated -ge [datetime]'2026-10-10 20:56:15' -and $e.TimeCreated -le [datetime]'2026-10-10 20:57:10') {
        $out.Add("[$($e.TimeCreated)] Id=$($e.Id) Lv=$($e.Level)")
        try { $xml=[xml]$e.ToXml() } catch { continue }
        $node = $xml.Event.UserData.FirstChild
        if ($node) {
            $out.Add("  Process: $($node.EventAuxInfo.ProcessName)")
            if ($node.Certificate) { $out.Add("  Cert: $($node.Certificate.subjectName)") }
            $out.Add("  Result: $($node.Result)")
        }
        $out.Add("-----")
    }
}
[IO.File]::WriteAllLines('C:\Users\28299\Desktop\modpkica4JAVA\tmp\capi2_56.txt', $out, (New-Object Text.UTF8Encoding $false))
Write-Output "DONE $($out.Count)"
