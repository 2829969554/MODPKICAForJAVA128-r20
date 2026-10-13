# -*- coding: utf-8 -*-
"""拉取网关抓包 pcap 并做初步分析（iOS<->网关 4500, 网关<->RADIUS 1812）。"""
import paramiko, sys, io

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

GW, USER, PWD = "10.255.228.225", "root", "root"
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect(GW, 22, USER, PWD, timeout=10, allow_agent=False, look_for_keys=False)

def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print(run("ls -la /tmp/ios_radius.pcap"))
print(run("tcpdump -r /tmp/ios_radius.pcap -n 2>/dev/null | head -40"))
cli.close()
