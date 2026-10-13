# -*- coding: utf-8 -*-
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
cmd = r"""tcpdump -r /tmp/ios_radius_r28.pcap -nn -X 'udp port 1812 and src host 10.255.228.55' > /tmp/rdump_x.txt 2>&1; wc -l /tmp/rdump_x.txt; head -60 /tmp/rdump_x.txt"""
i,o,e = cli.exec_command(cmd, timeout=60)
print((o.read() + e.read()).decode('utf-8','replace'))
cli.close()
