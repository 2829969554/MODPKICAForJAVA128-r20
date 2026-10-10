# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_tail.txt','w',encoding='utf-8') as f:
    f.write('=== charon.log 最后 40 行 ===\n')
    f.write(run('tail -40 /var/log/charon.log 2>/dev/null'))
    f.write('\n=== date ===\n')
    f.write(run('date'))
    f.write('\n=== journalctl 最后 20 行 ===\n')
    f.write(run('journalctl -u strongswan --no-pager -n 20 2>/dev/null'))
cli.close(); print('DONE')
