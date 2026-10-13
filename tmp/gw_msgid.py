# -*- coding: utf-8 -*-
"""确认 IKE_AUTH[I]（iOS入向）与 IKE_AUTH[R]（网关出向）的载荷类型/Flags。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 1) 抓一个 msgid=1 的 IKE_AUTH[R] 完整 hex（0x2e 载荷）
print("=== msgid=1 IKE_AUTH[R] 出向 hex（前 64B） ===")
print(run("tcpdump -r /tmp/ios_radius.pcap -nn -X -s 0 'src 10.255.228.225 and dst 10.255.228.120 and udp port 4500' 2>/dev/null | awk '/msgid 00000001: child_sa  ikev2_auth\\[R\\]/{f=1} f{print; c++} c>12{exit}'"))
# 2) 抓一个 msgid=1 的 IKE_AUTH[I] 入向 hex（看 iOS 的载荷类型）
print("=== msgid=1 IKE_AUTH[I] 入向 hex（前 64B） ===")
print(run("tcpdump -r /tmp/ios_radius.pcap -nn -X -s 0 'src 10.255.228.120 and dst 10.255.228.225 and udp port 4500' 2>/dev/null | awk '/msgid 00000001: child_sa  ikev2_auth\\[I\\]/{f=1} f{print; c++} c>14{exit}'"))
cli.close()
