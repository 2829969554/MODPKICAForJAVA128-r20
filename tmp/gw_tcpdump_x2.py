# -*- coding: utf-8 -*-
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
cmd = r"""tcpdump -r /tmp/ios_radius_r28.pcap -nn -X -c 2 'udp port 1812' 2>&1 | tail -40"""
i,o,e = cli.exec_command(cmd, timeout=40)
out = (o.read() + e.read()).decode('utf-8','replace')
print(out)
cli.close()
