# -*- coding: utf-8 -*-
import paramiko, io, sys
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=15, allow_agent=False, look_for_keys=False)

def run(cmd, t=30):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 清旧文件，启动 180 秒抓包并立即验证文件可写
print(run('pkill -f "tcpdump -i any" 2>/dev/null; rm -f /tmp/vpn_cap.pcap; nohup timeout 180 tcpdump -i any -s 0 -w /tmp/vpn_cap.pcap "udp port 4500 or udp port 500 or udp port 1812" >/tmp/tcpdump.log 2>&1 & echo STARTED; sleep 2; ls -la /tmp/vpn_cap.pcap 2>/dev/null || echo NOFILE_YET; pgrep -f tcpdump | head -2'))
cli.close()
