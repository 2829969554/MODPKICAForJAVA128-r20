# -*- coding: utf-8 -*-
import paramiko, time
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=90):
    i,o,e = cli.exec_command(cmd, timeout=t)
    time.sleep(2)
    return (o.read() + e.read()).decode('utf-8','replace')
print(run("tcpdump -r /tmp/ios_ike_r28.pcap -nn -X 'udp port 4500 and src host 10.255.228.225 and greater 100' > /tmp/ike_out_x.txt 2>&1; echo OK; wc -l /tmp/ike_out_x.txt"))
cli.close()
