# -*- coding: utf-8 -*-
"""重跑 eapol_test 完整输出 + 网关 tcpdump 抓 1812 双向。"""
import paramiko, sys, io, time
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

cli = paramiko.SSHClient(); cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect('10.255.228.225', 22, 'root', 'root', timeout=10, allow_agent=False, look_for_keys=False)
def run(cmd, t=120):
    i,o,e = cli.exec_command(cmd, timeout=t)
    return o.read().decode('utf-8','replace') + e.read().decode('utf-8','replace')

# 后台开抓包
run("rm -f /tmp/eapol_cap.pcap; nohup tcpdump -i any -s 0 -w /tmp/eapol_cap.pcap 'udp port 1812' >/dev/null 2>&1 & echo $!")
time.sleep(2)
print("=== eapol_test 完整输出 ===")
out = run("cd /tmp && timeout 40 eapol_test -c /tmp/eap-tls.conf -a 10.255.228.55 -p 1812 -s mytestkey -t 30 2>&1", t=60)
print(out)
time.sleep(2)
# 停抓包
run("pkill -f 'tcpdump -i any -s 0 -w /tmp/eapol_cap.pcap' 2>/dev/null; echo stopped")
print("=== 抓包文件 ===")
print(run("ls -la /tmp/eapol_cap.pcap"))
print("=== tcpdump -X 解析（1812 双向） ===")
print(run("tcpdump -r /tmp/eapol_cap.pcap -nn -X -s 0 'udp port 1812' 2>/dev/null | head -80"))
cli.close()
