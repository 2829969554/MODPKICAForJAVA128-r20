# -*- coding: utf-8 -*-
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return (o.read() + e.read()).decode('utf-8','replace')
out = run("ls -la /var/log/strongswan* 2>&1; ls -la /var/log/charon* 2>&1; journalctl -u strongswan --no-pager -n 200 2>&1 | tail -80")
print(out)
cli.close()
