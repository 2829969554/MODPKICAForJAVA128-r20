# -*- coding: utf-8 -*-
import paramiko, time
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    time.sleep(1)
    return (o.read() + e.read()).decode('utf-8','replace')
print(run("journalctl -u strongswan --no-pager -n 120 2>&1 | tail -100"))
cli.close()
