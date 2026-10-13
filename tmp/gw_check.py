# -*- coding: utf-8 -*-
import paramiko, traceback, sys

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    c.connect('10.255.228.225', username='root', password='root', timeout=10)
    print('SSH connected')
    cmds = [
        'journalctl -u strongswan --since "10 minutes ago" --no-pager | tail -n 80',
        'ipsec statusall 2>/dev/null | head -n 30',
        'grep -v "^#" /etc/strongswan.d/charon/eap-radius.conf 2>/dev/null',
    ]
    for cmd in cmds:
        stdin, stdout, stderr = c.exec_command(cmd, timeout=25)
        out = stdout.read().decode('utf-8', 'replace')
        err = stderr.read().decode('utf-8', 'replace')
        print('=== CMD:', cmd[:70])
        print(out[:4500] if out.strip() else err[:1000])
    c.close()
except Exception as e:
    traceback.print_exc()
