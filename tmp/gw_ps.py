# -*- coding: utf-8 -*-
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
i,o,e = cli.exec_command("ps aux | grep tcpdump | grep -v grep; ls -la /tmp/*.pcap 2>&1", timeout=30)
print((o.read() + e.read()).decode('utf-8','replace'))
cli.close()
