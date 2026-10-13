# -*- coding: utf-8 -*-
import paramiko, time
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=40):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return (o.read() + e.read()).decode('utf-8','replace')
out = run("nohup tcpdump -i any -s 0 -w /tmp/ios_ike_r28.pcap 'udp port 500 or udp port 4500' > /tmp/tcp2.log 2>&1 & echo started")
time.sleep(3)
out += run("ps aux | grep tcpdump | grep -v grep; ls -la /tmp/ios_*.pcap")
print(out)
cli.close()
