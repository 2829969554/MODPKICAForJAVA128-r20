# -*- coding: utf-8 -*-
import paramiko, sys, io, traceback
try:
    cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
    i,o,e = cli.exec_command("echo SSH_OK && openssl x509 -in /tmp/certs/root.crt -noout -subject 2>&1", timeout=30)
    out = o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
    print(out)
    cli.close()
except Exception as ex:
    print("EXC:", repr(ex))
