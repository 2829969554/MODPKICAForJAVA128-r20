# -*- coding: utf-8 -*-
# 在网关上启动 tcpdump 抓 RADIUS 1812 流量（网关 <-> 本机 RADIUS）
import paramiko, sys

GW = "10.255.228.225"
USER = "root"
PWD = "root"

def run(cmd):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(GW, username=USER, password=PWD, timeout=10)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=30)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    c.close()
    return out, err

# 1. 检查 tcpdump 是否存在并杀旧抓包
out, err = run("which tcpdump; pkill -f 'tcpdump.*1812' 2>/dev/null; echo KILLED")
print("CHECK:", out.strip(), err.strip())

# 2. 启动后台抓包：抓 1812/1813 全部流量到 pcap
out, err = run("nohup tcpdump -i any -s 0 -w /tmp/radius_win11.pcap 'udp port 1812 or udp port 1813' >/tmp/tcp_radius.log 2>&1 & echo PID=$!")
print("START:", out.strip(), err.strip())
