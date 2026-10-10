# -*- coding: utf-8 -*-
import paramiko, io, sys, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)

def run(cmd, t=15):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

print("tcpdump:", run("which tcpdump || echo NONE"))
# 清旧包，启动 90 秒后台抓包
run("rm -f /tmp/vpn_cap.pcap; nohup timeout 90 tcpdump -i any -s 0 -w /tmp/vpn_cap.pcap 'udp port 4500 or udp port 500' >/dev/null 2>&1 & echo CAP_STARTED; sleep 1; pgrep -f tcpdump | head -2")
print("抓包已启动（90秒窗口）。请现在在 Windows 上点击连接。")
cli.close()
