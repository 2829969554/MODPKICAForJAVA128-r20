$evts = Get-WinEvent -LogName 'Microsoft-Windows-CAPI2/Operational' -MaxEvents 80 -ErrorAction SilentlyContinue
$out = New-Object System.Collections.Generic.List[string]
foreach ($e in $evts) {
    $out.Add("[$($e.TimeCreated)] Id=$($e.Id) Lv=$($e.Level) Provider=$($e.ProviderName)")
    $lines = ($e.Message -split "`n") | Select-Object -First 20
    foreach ($l in $lines) { $out.Add($l) }
    $out.Add("-----")
}
[IO.File]::WriteAllLines('C:\Users\28299\Desktop\modpkica4JAVA\tmp\capi2.txt', $out, (New-Object Text.UTF8Encoding $false))
Write-Output "EXPORT_DONE $($out.Count)"
