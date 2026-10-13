# -*- coding: utf-8 -*-
"""在 strongSwan 网关(10.255.228.225)上启动 tcpdump 后台抓包：
   1) iOS(10.255.228.120) <-> 网关 的 IKEv2(EAP) 流量 (udp 4500)
   2) 网关 <-> RADIUS(10.255.228.55) 的 1812 流量
   抓包保存到 /tmp/ios_radius.pcap，等待用户 iOS 重试后停止分析。"""
import paramiko, sys, time

GW = "10.255.228.225"
USER = "root"
PWD = "root"

def main():
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(GW, username=USER, password=PWD, timeout=10)
    cmds = [
        "which tcpdump || echo NO_TCPDUMP",
        "pkill -f 'tcpdump.*ios_radius' 2>/dev/null || true",
        "rm -f /tmp/ios_radius.pcap",
        "nohup tcpdump -i any -s 0 -w /tmp/ios_radius.pcap "
        "'(host 10.255.228.120) or (host 10.255.228.55 and udp port 1812)' "
        ">/dev/null 2>&1 & echo CAP_STARTED",
        "sleep 2",
        "pgrep -af tcpdump | head -3",
        "ls -la /tmp/ios_radius.pcap 2>/dev/null || echo 'pcap 尚未生成'",
    ]
    for c in cmds:
        stdin, stdout, stderr = cli.exec_command(c, timeout=15)
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        print(f"$ {c}\n{out}\n{err}")
    cli.close()
    print("=== 抓包已启动，请 iOS 重试连接，然后告诉我 ===")

if __name__ == "__main__":
    main()
