# -*- coding: utf-8 -*-
"""网关上直接 dump 1812 Access-Challenge 的 EAP-Message 属性字节。"""
import paramiko, sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 找 13:36:44.894 的 Access-Challenge 290B（ClientHello 的响应）
print(run("tcpdump -r /tmp/ios_radius.pcap -nn -X -s 0 'src 10.255.228.55 and dst 10.255.228.225 and udp port 1812' 2>/dev/null | sed -n '/13:36:44.894/,/13:36:44.898/p' | head -25"))
cli.close()
