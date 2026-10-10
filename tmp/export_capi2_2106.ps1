$out = New-Object System.Collections.Generic.List[string]
$out.Add("########## CAPI2 21:06:00-21:07:10 ##########")
$evts = Get-WinEvent -LogName 'Microsoft-Windows-CAPI2/Operational' -MaxEvents 800 -ErrorAction SilentlyContinue
foreach ($e in $evts) {
    if ($e.TimeCreated -ge [datetime]'2026-10-10 21:06:00' -and $e.TimeCreated -le [datetime]'2026-10-10 21:07:10') {
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
$out.Add("########## RasTls 21:05-21:07 ##########")
foreach ($e in (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-EapMethods-RasTls/Operational'; StartTime=[datetime]'2026-10-10 21:05:00'; EndTime=[datetime]'2026-10-10 21:07:10'} -ErrorAction SilentlyContinue)) {
    $out.Add("[$($e.TimeCreated)] Id=$($e.Id): $($e.Message -replace '\s+',' ' | Out-String)")
}
[IO.File]::WriteAllLines('C:\Users\28299\Desktop\modpkica4JAVA\tmp\capi2_2106.txt', $out, (New-Object Text.UTF8Encoding $false))
Write-Output "DONE $($out.Count)"
