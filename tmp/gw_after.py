# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_after.txt','w',encoding='utf-8') as f:
    f.write(run('journalctl -u strongswan --no-pager --since "21:14:25" 2>/dev/null | tail -60'))
    f.write('\n=== charon.log TLS 后续 ===\n')
    f.write(run('grep -nE "TLS|CHILD|installed|Access-Accept|EAP/RES|deleting" /var/log/charon.log 2>/dev/null | tail -25'))
    f.write('\n=== SAS ===\n')
    f.write(run('swanctl --list-sas 2>&1 | grep -vE "plugin|failed|requires" | head -20'))
cli.close(); print('DONE')
