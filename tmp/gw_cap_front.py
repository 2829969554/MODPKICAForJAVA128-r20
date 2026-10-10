# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)

def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 前台 50 秒抓包（阻塞），抓 10.255.228.55 的 IKE 流量并落盘 hex
out = run('rm -f /tmp/cap_x.txt; timeout 50 tcpdump -i any -nn -s 0 -X "host 10.255.228.55 and (udp port 4500 or udp port 500)" > /tmp/cap_x.txt 2>&1; echo CAP_DONE; wc -l /tmp/cap_x.txt')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_cap_result.txt', 'w', encoding='utf-8') as f:
    f.write(out)
    f.write('\n===== 抓包内容 =====\n')
    f.write(run('cat /tmp/cap_x.txt'))
cli.close()
print('DONE')
