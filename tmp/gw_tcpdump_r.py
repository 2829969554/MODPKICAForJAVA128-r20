# -*- coding: utf-8 -*-
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
i,o,e = cli.exec_command("which tcpdump && tcpdump -r /tmp/ios_radius_r28.pcap -nn -c 8 'udp port 1812' 2>&1; echo ---IKE---; tcpdump -r /tmp/ios_ike_r28.pcap -nn -c 6 'udp port 4500' 2>&1", timeout=40)
print((o.read() + e.read()).decode('utf-8','replace'))
cli.close()
