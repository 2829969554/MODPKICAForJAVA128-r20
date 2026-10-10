# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
out = []
out.append('=== which tcpdump ===\n' + run('which tcpdump || echo NOT_INSTALLED'))
out.append('=== pgrep tcpdump ===\n' + run('pgrep -a tcpdump || echo NONE'))
out.append('=== pcap files ===\n' + run('ls -la /tmp/*.pcap 2>&1 || echo NONE'))
out.append('=== 尝试启动 ===\n' + run('nohup tcpdump -i any -s 0 -w /tmp/radius_eap.pcap port 1812 >/tmp/td1.log 2>&1 & echo bg=$!'))
import time; time.sleep(2)
out.append('=== 启动后 ===\n' + run('pgrep -a tcpdump || echo NONE; ls -la /tmp/radius_eap.pcap 2>&1'))
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_td.txt','w',encoding='utf-8') as f:
    f.write(''.join(out))
cli.close(); print('DONE')
