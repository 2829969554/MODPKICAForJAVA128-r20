$evts = Get-WinEvent -LogName 'Microsoft-Windows-CAPI2/Operational' -MaxEvents 100 -ErrorAction SilentlyContinue
$out = New-Object System.Collections.Generic.List[string]
foreach ($e in $evts) {
    if ($e.Id -eq 11 -or $e.Level -le 3) {
        $out.Add("=== [$($e.TimeCreated)] Id=$($e.Id) Lv=$($e.Level) ===")
        $out.Add($e.ToXml())
        $out.Add("")
    }
}
[IO.File]::WriteAllLines('C:\Users\28299\Desktop\modpkica4JAVA\tmp\capi2_xml.txt', $out, (New-Object Text.UTF8Encoding $false))
Write-Output "DONE $($out.Count)"
