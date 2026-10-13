# -*- coding: utf-8 -*-
import paramiko
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=60):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return (o.read() + e.read()).decode('utf-8','replace')
out = run("tcpdump -r /tmp/ios_ike_r28.pcap -nn -X 'udp port 4500 and src host 10.255.228.225 and greater 100' > /tmp/ike_out_x.txt 2>&1; wc -l /tmp/ike_out_x.txt")
out += run("head -120 /tmp/ike_out_x.txt")
print(out)
cli.close()
