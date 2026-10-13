# -*- coding: utf-8 -*-
"""直接 dump 4500 双向前几个包 hex。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("=== 出向 (GW->iOS) 前 3 个包 ===")
print(run("tcpdump -r /tmp/ios_radius.pcap -nn -X -s 0 -c 3 'src 10.255.228.225 and dst 10.255.228.120 and udp port 4500' 2>/dev/null | head -40"))
print("=== 入向 (iOS->GW) 前 3 个包 ===")
print(run("tcpdump -r /tmp/ios_radius.pcap -nn -X -s 0 -c 3 'src 10.255.228.120 and dst 10.255.228.225 and udp port 4500' 2>/dev/null | head -40"))
cli.close()
