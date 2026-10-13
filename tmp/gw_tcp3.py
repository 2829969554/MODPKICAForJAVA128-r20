# -*- coding: utf-8 -*-
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return (o.read() + e.read()).decode('utf-8','replace')
out = run("pkill -f tcpdump 2>/dev/null; sleep 1; "
          "setsid tcpdump -i any -s 0 -w /tmp/ios_radius_r28.pcap 'port 1812 or port 1813' >/dev/null 2>&1 < /dev/null & "
          "setsid tcpdump -i any -s 0 -w /tmp/ios_ike_r28.pcap 'port 500 or port 4500' >/dev/null 2>&1 < /dev/null & "
          "sleep 2; ps aux | grep tcpdump | grep -v grep | awk '{print $2, $11, $12, $13}'")
print(out)
cli.close()
