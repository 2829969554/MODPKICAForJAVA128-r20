# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)

def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

lines = []
lines.append('=== vpn_cap.pcap ===')
lines.append(run('ls -la /tmp/vpn_cap.pcap 2>/dev/null || echo NO_CAP'))
lines.append('=== tcpdump 进程 ===')
lines.append(run('pgrep -af tcpdump | head -3 || echo NONE'))
lines.append('=== tcpdump.log ===')
lines.append(run('cat /tmp/tcpdump.log 2>/dev/null | head -5 || echo NO_LOG'))

with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_state.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines))
cli.close()
print('DONE')
