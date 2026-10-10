# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)

def run(cmd, t=25):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print('=== 抓包文件 ===')
print(run('ls -la /tmp/vpn_cap.pcap 2>/dev/null || echo NO_CAP'))
print('=== tcpdump 进程 ===')
print(run('pgrep -f tcpdump | head -3 || echo NONE'))
print('=== 包数量 ===')
print(run('tcpdump -r /tmp/vpn_cap.pcap 2>/dev/null | wc -l'))
print('=== 简要包流（前80行） ===')
print(run('tcpdump -r /tmp/vpn_cap.pcap -nn 2>/dev/null | head -80'))
print('=== IKE/EAP 详情（过滤4500双向） ===')
print(run('tcpdump -r /tmp/vpn_cap.pcap -nn -vvv 2>/dev/null | grep -E "IKE|EAP|isakmp" | head -80'))
cli.close()
