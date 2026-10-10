# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_eaptls_2139.txt','w',encoding='utf-8') as f:
    f.write(run('grep -nE "21:39:4|21:39:5" /var/log/charon.log 2>/dev/null | grep -iE "eap|tls|radius|fail|auth|payload|reject" | tail -40'))
    f.write('\n=== journalctl 21:39 ===\n')
    f.write(run('journalctl -u strongswan --no-pager --since "21:39:39" --until "21:39:45" 2>/dev/null | tail -30'))
cli.close(); print('DONE')
