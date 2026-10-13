# -*- coding: utf-8 -*-
"""精确解析 pcap：提取 GW->iOS 的 IKE_AUTH[R] 中 EAP 载荷完整字节，
   以及 RADIUS Access-Challenge 中 EAP-Message 属性字节，逐字节对比。"""
import paramiko, sys, io, struct, binascii
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# 先在网关上用 tcpdump -w 单独导出关键包（4500 出向 13:36:44.898 + 1812 入向 13:36:44.894）
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 导出两个关键包为 hexdump 文本：1812 In (13:36:44.894) 和 4500 Out (13:36:44.898)
print("=== RADIUS Access-Challenge (In 1812, 290B) 完整字节 ===")
print(run("tcpdump -r /tmp/ios_radius.pcap -nn -X -s 0 'src 10.255.228.55 and dst 10.255.228.225 and udp port 1812' 2>/dev/null | head -30"))
print("=== IKE_AUTH[R] (Out 4500, 316B) 尾部 60B ===")
print(run("tcpdump -r /tmp/ios_radius.pcap -nn -X -s 0 'src 10.255.228.225 and dst 10.255.228.120 and udp port 4500 and greater 300' 2>/dev/null | head -40"))
cli.close()
