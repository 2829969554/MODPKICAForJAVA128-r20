# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)

def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 用 setsid 完全脱离会话，180 秒抓包
out = run('pkill -f "tcpdump -i any" 2>/dev/null; rm -f /tmp/vpn_cap.pcap; setsid bash -c "timeout 180 tcpdump -i any -s 0 -w /tmp/vpn_cap.pcap \\"udp port 4500 or udp port 500 or udp port 1812\\" >/tmp/tcpdump.log 2>&1" < /dev/null & echo LAUNCHED; sleep 3; ls -la /tmp/vpn_cap.pcap 2>/dev/null || echo NOFILE; cat /tmp/tcpdump.log 2>/dev/null | head -3')
print(out)
cli.close()
