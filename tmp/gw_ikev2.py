# -*- coding: utf-8 -*-
"""用 tcpdump -v 解析 4500 出向 IKE_AUTH[R] 的载荷类型。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print(run("tcpdump -r /tmp/ios_radius.pcap -nn -v -s 0 'src 10.255.228.225 and dst 10.255.228.120 and udp port 4500' 2>/dev/null | grep -E 'isakmp|EAP|eap|payload|NONESP' | head -30"))
print("=== 反向：iOS -> 网关 4500 入向 ===")
print(run("tcpdump -r /tmp/ios_radius.pcap -nn -v -s 0 'src 10.255.228.120 and dst 10.255.228.225 and udp port 4500' 2>/dev/null | grep -E 'isakmp|EAP|eap|payload' | head -20"))
cli.close()
