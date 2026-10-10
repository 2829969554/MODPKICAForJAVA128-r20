# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)
def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')
with open(r'C:\Users\28299\Desktop\modpkica4JAVA\tmp\gw_tcpdump.txt','w',encoding='utf-8') as f:
    f.write(run('pkill -f "tcpdump.*1812" 2>/dev/null; pkill -f "tcpdump.*4500" 2>/dev/null; sleep 1; nohup tcpdump -i any -s 0 -w /tmp/radius_eap.pcap "port 1812 or port 1813" >/dev/null 2>&1 & nohup tcpdump -i any -s 0 -w /tmp/ike_eap.pcap "port 500 or port 4500" >/dev/null 2>&1 & sleep 1; echo "tcpdump started"; ls -la /tmp/*.pcap 2>&1'))
cli.close(); print('DONE')
